<?php
// Validation of Duo's id_token (Web::val_duo) with tokens signed the way Duo signs them.
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';

use OCA\TwoFactorDuo\Web;

$secret = 'test-client-secret-0123456789abcdefghijklmn';
$b64u = fn (string $s): string => rtrim(strtr(base64_encode($s), '+/', '-_'), '=');
$sign = function (array $header, array $payload, string $key) use ($b64u): string {
	$h = $b64u(json_encode($header));
	$p = $b64u(json_encode($payload));
	return "$h.$p." . $b64u(hash_hmac('sha512', "$h.$p", $key, true));
};

$web = new Web('DIXXXXXXXXXXXXXXXXXX', $secret, 'api-test.duosecurity.com', 'https://x/cb');
$valDuo = new ReflectionMethod($web, 'val_duo');

$header = ['alg' => 'HS512', 'typ' => 'JWT'];
// Realistic claims; '?' and '>' force '-' and '_' into the base64url encoding, which 1.x mishandled.
$claims = ['iss' => 'https://api-test.duosecurity.com/oauth/v1/token', 'aud' => 'DIXXXXXXXXXXXXXXXXXX',
	'sub' => 'robin', 'preferred_username' => 'robin', 'iat' => time(), 'exp' => time() + 300,
	'auth_result' => ['result' => 'allow', 'status' => 'allow', 'status_msg' => 'Login Successful??>>'],
	'auth_context' => ['access_device' => ['hostname' => '>>>???~~~']]];

$good = $sign($header, $claims, $secret);
[$goodHeader, $goodPayload, $goodSignature] = explode('.', $good);

$cases = [
	'valid token whose payload contains - and _' => [$good, true],
	'signed with another secret' => [$sign($header, $claims, 'other-secret'), false],
	'payload swapped after signing' => [$goodHeader . '.' . $b64u(json_encode(['preferred_username' => 'admin'] + $claims)) . '.' . $goodSignature, false],
	'expired 2 minutes ago' => [$sign($header, ['exp' => time() - 120] + $claims, $secret), false],
	'expires in 30 s (inside the leeway)' => [$sign($header, ['exp' => time() + 30] + $claims, $secret), true],
	'without exp' => [$sign($header, array_diff_key($claims, ['exp' => 1]), $secret), false],
	'alg=none with empty signature' => [$b64u(json_encode(['alg' => 'none'])) . ".$goodPayload.", false],
	'alg=HS256 header (signed with HS512)' => [$sign(['alg' => 'HS256', 'typ' => 'JWT'], $claims, $secret), false],
	'not a JWT' => ['not-a-jwt', false],
];

section('Web::val_duo()');
expect('test token really contains - or _ in its payload', strpbrk($goodPayload, '-_') !== false);
foreach ($cases as $name => [$token, $shouldAccept]) {
	$result = $valDuo->invoke($web, $token, $secret);
	$accepted = is_array($result) && ($result['preferred_username'] ?? null) === 'robin'
		&& ($result['auth_result']['result'] ?? null) === 'allow';
	expect($name . ': ' . ($shouldAccept ? 'accepted' : 'rejected'), $accepted === $shouldAccept);
}

finish();
