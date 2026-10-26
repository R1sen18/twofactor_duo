<?php

declare(strict_types=1);

namespace OCA\TwoFactorDuo;

class Web {
  public $duo_ikey;
	public $duo_skey;
  public $duo_host;
  public $callback;
  /** cURL error of the last failed request to Duo, for diagnostics. */
  public $last_error = null;

  /** Duo's own CA list (from duosecurity/duo_universal_php); the only roots trusted for Duo's API. */
  const DUO_CERTS    = __DIR__ . "/duo_certs.pem";
  /** Identifies this app to Duo. Duo blocks outdated SDK versions by user agent, so don't pose as its SDK. */
  const USER_AGENT    = "Nextcloud-twofactor_duo/2.2.1";
  const URL_TOKEN    = "/oauth/v1/token";
  const URL_HEALTH    = "/oauth/v1/health_check";
  const URL_AUTHORIZE = "/oauth/v1/authorize";
  const LEEWAY        = 60;
	
	function __construct($ikey, $skey, $host, $call){
		$this->duo_ikey = $ikey;
		$this->duo_skey = $skey;
		$this->duo_host = $host;
		$this->callback = $call;
	}
  private function gen_duo($payload, $sec){
    $segments = [];
    $header = array('alg'=>'HS512','typ'=>'JWT');
    $segments[] = $this->base64UrlEncode(json_encode($header));
    $segments[] = $this->base64UrlEncode(json_encode($payload));
    $signing_input = implode('.', $segments);
    $signature = hash_hmac('SHA512', $signing_input, $sec, true);
    $segments[] = $this->base64UrlEncode($signature);
    return implode('.', $segments);
	}
  private function val_duo($token, $sec) {
    if(!is_string($token) || substr_count($token, '.') !== 2) return null;
    [$base64UrlHeader, $base64UrlPayload, $signatureProvided] = explode('.', $token);

    // Sign the segments exactly as received; re-encoding decoded data is lossy.
    $signature = hash_hmac('SHA512', $base64UrlHeader . "." . $base64UrlPayload, $sec, true);
    if(!hash_equals($this->base64UrlEncode($signature), $signatureProvided)) return null;

    $header = json_decode((string)base64_decode(strtr($base64UrlHeader, '-_', '+/')), true);
    if(!is_array($header) || ($header['alg'] ?? '') !== 'HS512') return null;

    $payloadData = json_decode((string)base64_decode(strtr($base64UrlPayload, '-_', '+/')), true);
    if(!is_array($payloadData)) return null;
    if(!isset($payloadData['exp']) || $payloadData['exp'] + self::LEEWAY < time()){
      return null;
    }
    return $payloadData;
  }
  private function base64UrlEncode($text, $mode=true){
    if($mode) return str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($text));
    else return str_replace('=', '', strtr(base64_encode($text), '+/', '-_'));
  }
  
  private function curl_duo_v4($endpoint, $request){
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, "https://".$this->duo_host.$endpoint);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($request));
    curl_setopt($ch, CURLOPT_PROTOCOLS, CURLPROTO_HTTPS);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
    // Pin Duo's CA list like Duo's SDK: a CA path that doesn't exist keeps the system store out.
    curl_setopt($ch, CURLOPT_CAINFO, self::DUO_CERTS);
    curl_setopt($ch, CURLOPT_CAPATH, __DIR__ . "/.no-system-ca-path");
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 10);
    curl_setopt($ch, CURLOPT_TIMEOUT, 20);
    curl_setopt($ch, CURLOPT_USERAGENT, self::USER_AGENT." php/".PHP_VERSION);
    $res = curl_exec($ch);
    $this->last_error = is_string($res) ? null : curl_error($ch);
    curl_close($ch);
    if(!is_string($res)) return null;
    return json_decode($res, true);
  }
  private function jwt_payload($audience){
    $current_date = time();
    $payload = ["iss" => $this->duo_ikey, "sub" => $this->duo_ikey,
                "aud" => $audience, "jti" => $this->rand_str(),
                "iat" => $current_date, "exp" => $current_date + 300];
    return $this->gen_duo($payload, $this->duo_skey);
  }
  public function rand_str($state_length=36){
    $ALPHANUMERICS = array_merge(range('A', 'Z'), range('a', 'z'), range(0, 9));
    $state = "";
    for($i = 0; $i < $state_length; ++$i) {
      $state = $state.$ALPHANUMERICS[random_int(0, count($ALPHANUMERICS) - 1)];
    }
    return $state;
  }

  public function check(){
    $audience = "https://".$this->duo_host.self::URL_HEALTH;
    $payload = $this->jwt_payload($audience);
    $request = ["client_id" => $this->duo_ikey, "client_assertion" => $payload];
    $result = $this->curl_duo_v4(self::URL_HEALTH, $request);
    return $result;
  }
  public function auth($username, $state=false){
    if(!$state) $state = $this->rand_str();
    $current_date = time();
    $payload = [
      'scope' => 'openid',
      'redirect_uri' => $this->callback,
      'client_id' => $this->duo_ikey,
      'iss' => $this->duo_ikey,
      'aud' => "https://".$this->duo_host,
      'exp' => $current_date + 300,
      'state' => $state,
      'response_type' => 'code',
      'duo_uname' => $username,
      'use_duo_code_attribute' => true
    ];

    $request = $this->gen_duo($payload, $this->duo_skey);
    $allArgs = [
      'response_type' => 'code',
      'client_id' => $this->duo_ikey,
      'scope' => 'openid',
      'redirect_uri' => $this->callback,
      'request' => $request
    ];

    $arguments = http_build_query($allArgs);
    return "https://".$this->duo_host.self::URL_AUTHORIZE."?".$arguments;
  }
  public function get_result($duoCode, $username){
    $audience = "https://".$this->duo_host.self::URL_TOKEN;
    $payload = $this->jwt_payload($audience);
    $request = ["grant_type" => 'authorization_code',
                "code" => $duoCode,
                "redirect_uri" => $this->callback,
                "client_id" => $this->duo_ikey,
                "client_assertion_type" => "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "client_assertion" => $payload];
    $result = $this->curl_duo_v4(self::URL_TOKEN, $request);
    return $result;
  }
  public function decode($duoCode, $username){
    $res = $this->get_result($duoCode, $username);

    if(!is_array($res)) return ['err_msg' => "No response from Duo."];
    if(isset($res['error'])) return $res;
    else {
      $err_msg = "null";
      $required_keys = ["id_token", "access_token", "expires_in", "token_type"];
      foreach($required_keys as $key) {
        if(!isset($res[$key])) {
          return ['err_msg' => "Result missing expected data."];
        }
      }
      if($res["token_type"] !== "Bearer"){
        $err_msg = "Result missing expected data.";
      }

      $token = $this->val_duo($res['id_token'], $this->duo_skey);
      if(!is_array($token)) return ['err_msg' => "Invalid or expired id_token."];

      $required_token_key = ["exp", "iat", "iss", "aud"];
      foreach($required_token_key as $key) {
        if(!isset($token[$key])) {
          $err_msg = "Result missing expected data.";
        }
      }
      if($token['aud'] !== $this->duo_ikey) {
        $err_msg = "Result missing expected data.";
      }
      if(($token['iss'] ?? null) !== "https://".$this->duo_host.self::URL_TOKEN) {
        $err_msg = "The id_token was not issued by ".$this->duo_host.".";
      }
      if(!isset($token['preferred_username']) || $token['preferred_username'] !== $username) {
        $err_msg = "The username is invalid.";
      }
      $token['err_msg'] = $err_msg;
      return $token;
    }
  }
}
