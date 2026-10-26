<?php
// Web::decode() against canned token endpoint answers, request details,
// and (with --online) real requests to Duo with fake credentials.
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';

use OCA\TwoFactorDuo\Web;

$secret = str_repeat('k', 40);
$host = 'api-00000000.duosecurity.com';
$ikey = 'DIABCDEFGHIJKLMNOP12';
$b64u = fn (string $s): string => rtrim(strtr(base64_encode($s), '+/', '-_'), '=');
$jwt = function (array $claims) use ($secret, $b64u): string {
	$h = $b64u(json_encode(['alg' => 'HS512', 'typ' => 'JWT']));
	$p = $b64u(json_encode($claims));
	return "$h.$p." . $b64u(hash_hmac('sha512', "$h.$p", $secret, true));
};

/** Web whose token endpoint answer is canned. */
class CannedWeb extends Web {
	public ?array $tokenResponse = null;
	public function get_result($duoCode) {
		return $this->tokenResponse;
	}
}

$nonce = str_repeat('n', 64);
$claims = ['iss' => "https://$host/oauth/v1/token", 'aud' => $ikey, 'iat' => time(), 'exp' => time() + 300, 'nonce' => $nonce,
	'preferred_username' => 'j.maier', 'auth_result' => ['result' => 'allow', 'status' => 'allow', 'status_msg' => 'Login Successful']];
$decode = function (array $idToken, array $response = [], ?string $expectedNonce = null) use ($jwt, $secret, $host, $ikey, $nonce): array {
	$web = new CannedWeb($ikey, $secret, $host, 'https://x/cb');
	$web->tokenResponse = $response + ['id_token' => $jwt($idToken), 'access_token' => 'a', 'expires_in' => 300, 'token_type' => 'Bearer'];
	try {
		return $web->decode('code', 'j.maier', $expectedNonce ?? $nonce);
	} catch (Throwable $e) {
		return ['err_msg' => 'threw ' . get_class($e) . ': ' . $e->getMessage()];
	}
};

section('Authorization request sent to Duo');
$call = 'https://cloud.example.com/apps/twofactor_duo/callback';
$state = str_repeat('s', 36);
$url = (new Web($ikey, $secret, $host, $call))->auth('j.maier', $state, $nonce);
parse_str((string)parse_url($url, PHP_URL_QUERY), $query);
[$h, $p, $signature] = explode('.', $query['request'] ?? '..');
$request = json_decode((string)base64_decode(strtr($p, '-_', '+/')), true) ?: [];
expect('goes to Duo\'s authorize endpoint', str_starts_with($url, "https://$host/oauth/v1/authorize?"), $url);
expect('request JWT is signed with the client secret (HS512)', hash_equals($b64u(hash_hmac('sha512', "$h.$p", $secret, true)), $signature));
expect('request carries state, nonce and username', ($request['state'] ?? '') === $state && ($request['nonce'] ?? '') === $nonce
	&& ($request['duo_uname'] ?? '') === 'j.maier', json_encode($request));
expect('request is for this client and expires within 5 minutes', ($request['client_id'] ?? '') === $ikey && ($request['aud'] ?? '') === "https://$host"
	&& ($request['exp'] ?? 0) > time() && $request['exp'] <= time() + 300);
expect('redirect_uri is CALL', ($query['redirect_uri'] ?? '') === $call && ($request['redirect_uri'] ?? '') === $call);

section('decode() with canned Duo answers');
$result = $decode($claims);
expect('valid answer accepted', $result['err_msg'] === 'null' && $result['auth_result']['result'] === 'allow', json_encode($result));
$result = $decode(['iss' => 'https://evil.example/oauth/v1/token'] + $claims);
expect('foreign issuer rejected', str_contains($result['err_msg'], 'not issued by'), $result['err_msg']);
expect('missing issuer rejected', $decode(array_diff_key($claims, ['iss' => 1]))['err_msg'] !== 'null');
expect('other audience rejected', $decode(['aud' => 'DIOTHER00000000000000'] + $claims)['err_msg'] !== 'null');
expect('missing audience rejected (without a PHP warning)', $decode(array_diff_key($claims, ['aud' => 1]))['err_msg'] !== 'null');
expect('other username rejected', $decode(['preferred_username' => 'admin'] + $claims)['err_msg'] === 'The username is invalid.');
expect('token_type other than Bearer rejected', $decode($claims, ['token_type' => 'mac'])['err_msg'] !== 'null');

section('Nonce: Duo\'s answer must belong to this login attempt');
$nonceError = 'The nonce does not belong to this login attempt.';
expect('answer for another attempt rejected', $decode($claims, [], str_repeat('x', 64))['err_msg'] === $nonceError);
expect('answer without nonce rejected', $decode(array_diff_key($claims, ['nonce' => 1]))['err_msg'] === $nonceError);
expect('nonce of another type rejected', $decode(['nonce' => 12345] + $claims)['err_msg'] === $nonceError);
expect('empty expected nonce never matches', $decode(['nonce' => ''] + $claims, [], '')['err_msg'] === $nonceError);

section('Time claims');
$expired = 'Invalid or expired id_token.';
expect('iat in the future rejected', $decode(['iat' => time() + 600] + $claims)['err_msg'] === $expired);
expect('nbf in the future rejected', $decode(['nbf' => time() + 600] + $claims)['err_msg'] === $expired);
expect('nbf in the past accepted', $decode(['nbf' => time() - 10] + $claims)['err_msg'] === 'null');
expect('exp that is not a number rejected (no TypeError)', $decode(['exp' => 'tomorrow'] + $claims)['err_msg'] === $expired);
expect('missing iat rejected', $decode(array_diff_key($claims, ['iat' => 1]))['err_msg'] !== 'null');

section('Errors from Duo');
$web = new CannedWeb($ikey, $secret, $host, 'https://x/cb');
$web->tokenResponse = ['error' => 'invalid_grant', 'error_description' => 'expired'];
expect('token endpoint error passed through', ($web->decode('code', 'j.maier', $nonce)['error'] ?? '') === 'invalid_grant');
$web->tokenResponse = null;
expect('no answer from Duo handled', ($web->decode('code', 'j.maier', $nonce)['err_msg'] ?? '') === 'No response from Duo.');

section('Request details');
preg_match('#<version>([^<]+)</version>#', (string)file_get_contents(dirname(__DIR__) . '/appinfo/info.xml'), $version);
expect('user agent names this app, not Duo\'s SDK', !str_contains(Web::USER_AGENT, 'duo_universal_php') && str_starts_with(Web::USER_AGENT, 'Nextcloud-twofactor_duo/'), Web::USER_AGENT);
expect('user agent version matches appinfo/info.xml', Web::USER_AGENT === 'Nextcloud-twofactor_duo/' . ($version[1] ?? '?'), $version[1] ?? '?');
expect('CA bundle contains 15 certificates', substr_count((string)file_get_contents(Web::DUO_CERTS), 'BEGIN CERTIFICATE') === 15);
expect('CA bundle contains no private keys', !str_contains((string)file_get_contents(Web::DUO_CERTS), 'PRIVATE KEY'));

if (ONLINE) {
	section('Live requests to Duo (fake credentials, pinned CA list)');
	$web = new Web($ikey, $secret, $host, 'https://example.com/apps/twofactor_duo/callback');
	$health = $web->check();
	expect('health check: TLS ok, Duo answers invalid_client', is_array($health) && ($health['message'] ?? '') === 'invalid_client', json_encode($health) . ' ' . $web->last_error);
	$token = $web->get_result('fakecode000000000000000000000000');
	expect('token endpoint: TLS ok, form body understood (OAuth error, not ACCESS_FORBIDDEN)',
		is_array($token) && in_array($token['error'] ?? '', ['invalid_client', 'invalid_grant'], true), json_encode($token) . ' ' . $web->last_error);

	// letsencrypt.org has a valid certificate from ISRG, which is in the system store but not in Duo's list.
	$ch = curl_init('https://letsencrypt.org/');
	curl_setopt_array($ch, [CURLOPT_NOBODY => true, CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 15]);
	expect('letsencrypt.org is valid with the system CA store', curl_exec($ch) !== false, curl_error($ch));
	$foreign = new Web($ikey, $secret, 'letsencrypt.org', 'x');
	expect('... but refused with the pinned Duo CA list', $foreign->check() === null && str_contains((string)$foreign->last_error, 'SSL certificate problem'), (string)$foreign->last_error);
}

finish();
