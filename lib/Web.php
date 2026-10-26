<?php

declare(strict_types=1);

namespace OCA\TwoFactorDuo;

/**
 * Minimal client for Duo's Universal Prompt (OIDC authorization code flow with a
 * client_assertion JWT), equivalent to duosecurity/duo_universal_php.
 */
class Web {
  public $duo_ikey;
  public $duo_skey;
  public $duo_host;
  public $callback;
  /** cURL error of the last failed request to Duo, for diagnostics. */
  public $last_error = null;

  /** Duo's own CA list (from duosecurity/duo_universal_php); the only roots trusted for Duo's API. */
  const DUO_CERTS     = __DIR__ . "/duo_certs.pem";
  /** Identifies this app to Duo. Duo blocks outdated SDK versions by user agent, so don't pose as its SDK. */
  const USER_AGENT    = "Nextcloud-twofactor_duo/2.3.0";
  const URL_TOKEN     = "/oauth/v1/token";
  const URL_HEALTH    = "/oauth/v1/health_check";
  const URL_AUTHORIZE = "/oauth/v1/authorize";
  const LEEWAY        = 60;

  function __construct($ikey, #[\SensitiveParameter] $skey, $host, $call){
    $this->duo_ikey = $ikey;
    $this->duo_skey = $skey;
    $this->duo_host = $host;
    $this->callback = $call;
  }

  private function gen_duo($payload, #[\SensitiveParameter] $sec){
    $segments = [];
    $header = array('alg'=>'HS512','typ'=>'JWT');
    $segments[] = $this->base64UrlEncode(json_encode($header));
    $segments[] = $this->base64UrlEncode(json_encode($payload));
    $signing_input = implode('.', $segments);
    $signature = hash_hmac('SHA512', $signing_input, $sec, true);
    $segments[] = $this->base64UrlEncode($signature);
    return implode('.', $segments);
  }

  private function val_duo($token, #[\SensitiveParameter] $sec) {
    if(!is_string($token) || substr_count($token, '.') !== 2) return null;
    [$base64UrlHeader, $base64UrlPayload, $signatureProvided] = explode('.', $token);

    // Sign the segments exactly as received; re-encoding decoded data is lossy.
    $signature = hash_hmac('SHA512', $base64UrlHeader . "." . $base64UrlPayload, $sec, true);
    if(!hash_equals($this->base64UrlEncode($signature), $signatureProvided)) return null;

    $header = json_decode((string)base64_decode(strtr($base64UrlHeader, '-_', '+/')), true);
    if(!is_array($header) || ($header['alg'] ?? '') !== 'HS512') return null;

    $payloadData = json_decode((string)base64_decode(strtr($base64UrlPayload, '-_', '+/')), true);
    if(!is_array($payloadData)) return null;

    // Time claims, with the same 60 s leeway as Duo's SDK.
    $now = time();
    $exp = $payloadData['exp'] ?? null;
    if(!$this->is_numeric_date($exp) || $exp + self::LEEWAY < $now) return null;
    foreach(['iat', 'nbf'] as $claim) {
      if(!array_key_exists($claim, $payloadData)) continue;
      if(!$this->is_numeric_date($payloadData[$claim]) || $payloadData[$claim] > $now + self::LEEWAY) return null;
    }
    return $payloadData;
  }

  private function is_numeric_date($value){
    return is_int($value) || is_float($value);
  }

  private function base64UrlEncode($text){
    return str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($text));
  }

  private function curl_duo_v4($endpoint, $request){
    $this->last_error = null;
    $ch = curl_init();
    // Pin Duo's CA list like Duo's SDK: CAPATH points to a path that can never exist, so the
    // system store stays out. If a TLS backend refuses these options, don't talk to Duo at all.
    $pinned = curl_setopt($ch, CURLOPT_CAINFO, self::DUO_CERTS)
      && curl_setopt($ch, CURLOPT_CAPATH, '/dev/null/' . bin2hex(random_bytes(8)))
      && curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true)
      && curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2)
      && curl_setopt($ch, CURLOPT_PROTOCOLS, CURLPROTO_HTTPS);
    if(!$pinned) {
      $this->last_error = 'cannot restrict TLS to Duo\'s CA list (' . curl_error($ch) . ')';
      curl_close($ch);
      return null;
    }
    curl_setopt($ch, CURLOPT_URL, "https://".$this->duo_host.$endpoint);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($request));
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 10);
    curl_setopt($ch, CURLOPT_TIMEOUT, 20);
    curl_setopt($ch, CURLOPT_USERAGENT, self::USER_AGENT." php/".PHP_VERSION);
    $res = curl_exec($ch);
    if(!is_string($res)) $this->last_error = curl_error($ch);
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

  /** Random [A-Za-z0-9] string from a CSPRNG; used for state, nonce and jti. */
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
    return $this->curl_duo_v4(self::URL_HEALTH, $request);
  }

  /**
   * URL of Duo's prompt. $state comes back in the redirect; $nonce comes back inside the signed
   * id_token and ties Duo's answer to this login attempt.
   */
  public function auth($username, $state, $nonce){
    $current_date = time();
    $payload = [
      'scope' => 'openid',
      'redirect_uri' => $this->callback,
      'client_id' => $this->duo_ikey,
      'iss' => $this->duo_ikey,
      'aud' => "https://".$this->duo_host,
      'exp' => $current_date + 300,
      'state' => $state,
      'nonce' => $nonce,
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

    return "https://".$this->duo_host.self::URL_AUTHORIZE."?".http_build_query($allArgs);
  }

  public function get_result(#[\SensitiveParameter] $duoCode){
    $audience = "https://".$this->duo_host.self::URL_TOKEN;
    $payload = $this->jwt_payload($audience);
    $request = ["grant_type" => 'authorization_code',
                "code" => $duoCode,
                "redirect_uri" => $this->callback,
                "client_id" => $this->duo_ikey,
                "client_assertion_type" => "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "client_assertion" => $payload];
    return $this->curl_duo_v4(self::URL_TOKEN, $request);
  }

  /**
   * Exchanges the code and validates the id_token. Returns the token claims with err_msg "null"
   * if everything checks out, Duo's error response, or ['err_msg' => reason].
   */
  public function decode(#[\SensitiveParameter] $duoCode, $username, #[\SensitiveParameter] $nonce){
    $res = $this->get_result($duoCode);

    if(!is_array($res)) return ['err_msg' => "No response from Duo."];
    if(isset($res['error'])) return $res;

    foreach(["id_token", "access_token", "expires_in", "token_type"] as $key) {
      if(!isset($res[$key])) return ['err_msg' => "Result missing expected data."];
    }
    if($res["token_type"] !== "Bearer") return ['err_msg' => "Result missing expected data."];

    $token = $this->val_duo($res['id_token'], $this->duo_skey);
    if(!is_array($token)) return ['err_msg' => "Invalid or expired id_token."];

    $err_msg = "null";
    foreach(["exp", "iat", "iss", "aud"] as $key) {
      if(!isset($token[$key])) $err_msg = "Result missing expected data.";
    }
    if(($token['aud'] ?? null) !== $this->duo_ikey) {
      $err_msg = "Result missing expected data.";
    }
    if(($token['iss'] ?? null) !== "https://".$this->duo_host.self::URL_TOKEN) {
      $err_msg = "The id_token was not issued by ".$this->duo_host.".";
    }
    if(!is_string($nonce) || $nonce === '' || !is_string($token['nonce'] ?? null) || !hash_equals($nonce, $token['nonce'])) {
      $err_msg = "The nonce does not belong to this login attempt.";
    }
    if(!isset($token['preferred_username']) || $token['preferred_username'] !== $username) {
      $err_msg = "The username is invalid.";
    }
    $token['err_msg'] = $err_msg;
    return $token;
  }
}
