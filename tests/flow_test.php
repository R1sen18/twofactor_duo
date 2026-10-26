<?php
// The whole login in one session: challenge page -> Duo -> callback -> POST /login/challenge/duo,
// with a fake Duo client. Covers success, every logged failure reason, the push-loop protection,
// and the security properties of the callback and the stored approval.
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';

use OCA\TwoFactorDuo\Command\Check;
use OCA\TwoFactorDuo\Controller\CallbackController;
use OCA\TwoFactorDuo\Provider\DuoProvider;
use OCA\TwoFactorDuo\Web;
use OCP\AppFramework\Http\RedirectResponse;
use OCP\AppFramework\Http\TemplateResponse;
use OCP\Authentication\TwoFactorAuth\IProvider;

/** Duo client that never touches the network. */
class FakeWeb extends Web {
	public static ?array $decodeResult = null;
	public static array $health = ['stat' => 'OK'];
	/** Nonce the callback passed to decode(), to check it is the one sent to Duo. */
	public static ?string $decodedWithNonce = null;
	public function check() {
		return self::$health;
	}
	public function auth($username, $state, $nonce) {
		return "https://duo.test/authorize?state=$state&nonce=$nonce&u=$username";
	}
	public function decode($duoCode, $username, $nonce) {
		self::$decodedWithNonce = $nonce;
		return self::$decodeResult;
	}
}
class TestProvider extends DuoProvider {
	protected function createWeb(array $config): Web {
		return new FakeWeb('i', 's', 'h', 'c');
	}
}
class TestCallback extends CallbackController {
	protected function createWeb(array $config): Web {
		return new FakeWeb('i', 's', 'h', 'c');
	}
}

$config = new FakeConfig(['twofactor_duo' => ['IKEY' => 'DIABCDEFGHIJKLMNOP12', 'SKEY' => str_repeat('s', 40),
	'HOST' => 'api-0.duosecurity.com', 'CALL' => 'https://cloud.example.com/apps/twofactor_duo/callback']]);
$allow = ['err_msg' => 'null', 'preferred_username' => 'j.maier',
	'auth_result' => ['result' => 'allow', 'status' => 'allow', 'status_msg' => 'Login Successful']];
$user = new FakeUser('j.maier');
$clock = new FakeTimeFactory();

$session = new FakeSession();
$session->set('two_factor_auth_uid', 'j.maier');
$log = new FakeLogger();
$provider = new TestProvider($config, $session, new FakeTemplateManager(), $log, $clock);

$showChallenge = function () use ($provider, $user): FakeTemplate {
	OCP\Util::$scripts = [];
	return $provider->getTemplate($user);
};
$duoRedirect = function (array $params) use ($config, $session, $log, $clock): TemplateResponse|RedirectResponse {
	OCP\Util::$scripts = [];
	return (new TestCallback('twofactor_duo', new FakeRequest($params), $config, $session, new FakeUrlGenerator(), $log, $clock))->index();
};
$queryOf = function (FakeTemplate $page): array {
	parse_str((string)parse_url($page->vars['duo_url'], PHP_URL_QUERY), $query);
	return $query;
};
$autoRedirects = fn (): bool => in_array('twofactor_duo/challenge', OCP\Util::$scripts, true);
$problemsLogged = fn (): int => count(array_filter($log->lines, fn ($l) => preg_match('/^(warning|error):/', $l)));

section('1. Successful login');
$page = $showChallenge();
expect('first visit redirects to Duo automatically', $page->vars['notice'] === '' && $autoRedirects());
['state' => $state, 'nonce' => $nonce] = $queryOf($page);
expect('state and nonce stored in the session and sent to Duo', $state !== '' && strlen($nonce) === 64
	&& $session->get(DuoProvider::SESSION_STATE) === $state && $session->get(DuoProvider::SESSION_NONCE) === $nonce);
FakeWeb::$decodeResult = $allow;
$response = $duoRedirect(['duo_code' => 'code', 'state' => $state]);
expect('Duo\'s answer is checked against the nonce sent to Duo', FakeWeb::$decodedWithNonce === $nonce);
expect('state and nonce are single-use', $session->get(DuoProvider::SESSION_STATE) === null && $session->get(DuoProvider::SESSION_NONCE) === null);
expect('approval stored with uid and time', $session->get(DuoProvider::SESSION_RESULT) === ['uid' => 'j.maier', 'time' => $clock->time]);
expect('callback logs the success', str_contains($log->last(), 'info: Duo authentication succeeded for j.maier'), $log->last());
expect('callback page posts to core\'s solveChallenge', $response instanceof TemplateResponse && $response->params['action'] === '/index.php/login/challenge/duo');
expect('callback page queues callback.js', in_array('twofactor_duo/callback', OCP\Util::$scripts, true));
expect('verifyChallenge() accepts', $provider->verifyChallenge($user, 'duo'));
expect('no failure flag left behind', $session->get(DuoProvider::SESSION_FAILED) === null);

section('2. The approval is bound to the user, single-use and short-lived');
$approve = fn (int $age, string $uid = 'j.maier') => $session->set(DuoProvider::SESSION_RESULT, ['uid' => $uid, 'time' => $clock->time - $age]);
$approve(0);
expect('another user is rejected', !$provider->verifyChallenge(new FakeUser('mallory'), 'duo'));
expect('... and the approval is consumed by that attempt', $session->get(DuoProvider::SESSION_RESULT) === null);
$approve(0);
expect('accepted once', $provider->verifyChallenge($user, 'duo'));
expect('... but not twice', !$provider->verifyChallenge($user, 'duo'));
$approve(DuoProvider::RESULT_TTL);
expect('accepted at exactly ' . DuoProvider::RESULT_TTL . ' s', $provider->verifyChallenge($user, 'duo'));
$approve(DuoProvider::RESULT_TTL + 1);
expect('rejected after ' . DuoProvider::RESULT_TTL . ' s', !$provider->verifyChallenge($user, 'duo'));
expect('... with a warning', str_contains($log->last(), 'that was 121 s old'), $log->last());
$approve(-30);
expect('approval from the future rejected', !$provider->verifyChallenge($user, 'duo'));
$session->set(DuoProvider::SESSION_RESULT, 'j.maier');
expect('approval in the old (2.2) format rejected', !$provider->verifyChallenge($user, 'duo'));
$approve(0);
$showChallenge();
expect('a new prompt discards an approval that was never submitted', !$provider->verifyChallenge($user, 'duo'));

section('3. Duo denies the login: no push loop');
$session->data = ['two_factor_auth_uid' => 'j.maier'];
$state = $queryOf($showChallenge())['state'];
FakeWeb::$decodeResult = ['err_msg' => 'null', 'preferred_username' => 'j.maier',
	'auth_result' => ['result' => 'deny', 'status' => 'deny', 'status_msg' => 'Login denied']];
$duoRedirect(['duo_code' => 'code', 'state' => $state]);
expect('reason logged', str_contains($log->last(), 'warning: Duo authentication failed for j.maier: Duo did not allow the login (result "deny", status "Login denied")'), $log->last());
expect('verifyChallenge() rejects', !$provider->verifyChallenge($user, 'duo'));
$page = $showChallenge();
expect('next challenge page shows a notice and Try again', $page->vars['notice'] !== '' && $page->vars['duo_url'] !== '');
expect('... and does NOT redirect to Duo on its own', !$autoRedirects());
expect('failure flag consumed', $session->get(DuoProvider::SESSION_FAILED) === null);
FakeWeb::$decodeResult = $allow;
$duoRedirect(['duo_code' => 'code', 'state' => $queryOf($page)['state']]);
expect('Try again then succeeds', $provider->verifyChallenge($user, 'duo'));

section('4. Logged failure reasons (answers to this session\'s own prompt)');
$cases = [
	'Duo error parameter' => [['error' => 'access_denied', 'error_description' => 'User denied'], $allow,
		'Duo returned an error: access_denied User denied'],
	'username mismatch' => [['duo_code' => 'code'], ['err_msg' => 'The username is invalid.', 'preferred_username' => 'jmaier@example.com', 'auth_result' => ['result' => 'allow']],
		'token validation failed: The username is invalid. Duo authenticated "jmaier@example.com", Nextcloud expected "j.maier".'],
	'nonce mismatch' => [['duo_code' => 'code'], ['err_msg' => 'The nonce does not belong to this login attempt.', 'preferred_username' => 'j.maier'],
		'token validation failed: The nonce does not belong to this login attempt.'],
	'token endpoint error' => [['duo_code' => 'code'], ['error' => 'ACCESS_FORBIDDEN', 'error_description' => 'Client duo_universal_php version 1.0.2 is deprecated'],
		'Duo\'s token endpoint returned ACCESS_FORBIDDEN (Client duo_universal_php version 1.0.2 is deprecated)'],
	'expired id_token' => [['duo_code' => 'code'], ['err_msg' => 'Invalid or expired id_token.'], 'token validation failed: Invalid or expired id_token.'],
	'missing duo_code' => [[], $allow, 'missing duo_code'],
];
foreach ($cases as $name => [$params, $decodeResult, $expected]) {
	$state = $queryOf($showChallenge())['state'];
	FakeWeb::$decodeResult = $decodeResult;
	$duoRedirect($params + ['state' => $state]);
	expect("$name: logged", str_contains($log->last(), $expected), $log->last());
	expect("$name: login rejected", !$provider->verifyChallenge($user, 'duo'));
}
$state = $queryOf($showChallenge())['state'];
$duoRedirect(['state' => $state, 'error' => "access_denied\nFAKE LOG LINE", 'error_description' => str_repeat('A', 5000)]);
expect('Duo text is kept on one line in the log', !str_contains($log->last(), "\n") && str_contains($log->last(), 'access_denied FAKE LOG LINE'), $log->last());
expect('... and shortened', strlen($log->last()) < 600 && str_contains($log->last(), 'AAAA…'), (string)strlen($log->last()));

section('5. Requests that don\'t answer this session\'s prompt are ignored');
$log->lines = [];
$anonymous = new FakeSession();
$response = (new TestCallback('twofactor_duo', new FakeRequest(['error' => 'x', 'error_description' => 'spoofed log entry']), $config, $anonymous,
	new FakeUrlGenerator(), $log, $clock))->index();
expect('anonymous request: redirected away', $response instanceof RedirectResponse);
expect('... nothing logged as a warning (no log flooding)', $problemsLogged() === 0, implode(' | ', $log->lines));
expect('... session untouched', $anonymous->data === []);

$session->data = ['two_factor_auth_uid' => 'j.maier'];
$state = $queryOf($showChallenge())['state'];
$log->lines = [];
$response = $duoRedirect(['state' => 'forged', 'error' => 'access_denied']);
expect('forged state: redirected to the challenge page', $response instanceof RedirectResponse
	&& str_contains($response->getRedirectURL(), '/login/challenge/duo'));
expect('... the real prompt is not cancelled', $session->get(DuoProvider::SESSION_STATE) === $state && $session->get(DuoProvider::SESSION_FAILED) === null);
expect('... nothing logged as a warning', $problemsLogged() === 0, implode(' | ', $log->lines));
expect('missing state: ignored too', $duoRedirect(['duo_code' => 'code']) instanceof RedirectResponse && $session->get(DuoProvider::SESSION_STATE) === $state);
FakeWeb::$decodeResult = $allow;
$duoRedirect(['duo_code' => 'code', 'state' => $state]);
expect('the real answer still works afterwards', $provider->verifyChallenge($user, 'duo'));

section('6. Duo\'s redirect never arrives');
$session->data = ['two_factor_auth_uid' => 'j.maier'];
$showChallenge();               // prompt started, the browser never comes back
$page = $showChallenge();       // user lands on the challenge page again
expect('no automatic redirect, Try again shown', $page->vars['notice'] !== '' && !$autoRedirects());
expect('warning about the missing callback logged', str_contains($log->last(), 'was not completed'), $log->last());

section('7. Health check fails');
$session->data = ['two_factor_auth_uid' => 'j.maier'];
FakeWeb::$health = ['stat' => 'FAIL', 'code' => 40301, 'message' => 'invalid_client', 'message_detail' => 'Integration type does not support frameless access.'];
$page = $showChallenge();
expect('error shown, no Duo link', $page->vars['error'] !== '' && $page->vars['duo_url'] === '');
expect('Duo\'s reason logged', str_contains($log->last(), 'Duo health check failed: invalid_client Integration type does not support frameless access.'), $log->last());
FakeWeb::$health = ['stat' => 'OK'];

section('8. A broken configuration fails closed');
foreach (['incomplete config' => ['twofactor_duo' => ['AKEY' => 'x']], 'no config' => []] as $name => $values) {
	$broken = new TestProvider(new FakeConfig($values), new FakeSession(), new FakeTemplateManager(), $log, $clock);
	expect("$name: Duo still required (not stored as disabled)", $broken->isTwoFactorAuthEnabledForUser($user));
	$page = $broken->getTemplate($user);
	expect("$name: login blocked with an error", $page->vars['error'] !== '' && $page->vars['duo_url'] === '');
	expect("$name: logged as error", str_starts_with($log->last(), 'error: Duo is enabled but its configuration is missing'), $log->last());
	expect("$name: verifyChallenge() rejects", !$broken->verifyChallenge($user, 'duo'));
}

section('9. Interfaces, routing and hardening attributes');
expect('DuoProvider implements IProvider', $provider instanceof IProvider);
expect('DuoProvider has no custom CSP (the API it used is gone in NC35)', !method_exists(DuoProvider::class, 'getCSP'));
$index = new ReflectionMethod(CallbackController::class, 'index');
$attributes = [];
foreach ($index->getAttributes() as $attribute) {
	$attributes[$attribute->getName()] = $attribute;
}
expect('callback: #[NoTwoFactorRequired]', isset($attributes['OCP\AppFramework\Http\Attribute\NoTwoFactorRequired']));
expect('callback: @NoTwoFactorRequired annotation for NC < 34', (bool)preg_match('/^\h+\*\h+@NoTwoFactorRequired\b/m', (string)$index->getDocComment()));
expect('callback: public, no CSRF token, writable session', !array_diff_key(array_flip(['OCP\AppFramework\Http\Attribute\PublicPage',
	'OCP\AppFramework\Http\Attribute\NoCSRFRequired', 'OCP\AppFramework\Http\Attribute\UseSession']), $attributes));
foreach (['AnonRateLimit', 'UserRateLimit'] as $limit) {
	$attribute = $attributes["OCP\\AppFramework\\Http\\Attribute\\$limit"] ?? null;
	$instance = $attribute?->newInstance();
	expect("callback: #[$limit] 10 per 300 s", $instance !== null && $instance->getLimit() === 10 && $instance->getPeriod() === 300);
}

$sensitive = [
	[Web::class, '__construct', 'skey'], [Web::class, 'gen_duo', 'sec'], [Web::class, 'val_duo', 'sec'],
	[Web::class, 'get_result', 'duoCode'], [Web::class, 'decode', 'duoCode'], [Web::class, 'decode', 'nonce'],
	[DuoProvider::class, 'isValidConfig', 'config'], [DuoProvider::class, 'createWeb', 'config'],
	[CallbackController::class, 'createWeb', 'config'], [CallbackController::class, 'verify', 'duoCode'], [CallbackController::class, 'verify', 'nonce'],
	[Check::class, 'checkConfig', 'config'], [Check::class, 'checkDuo', 'config'],
];
foreach ($sensitive as [$class, $method, $parameter]) {
	$marked = false;
	foreach ((new ReflectionMethod($class, $method))->getParameters() as $p) {
		if ($p->getName() === $parameter) {
			$marked = $p->getAttributes(SensitiveParameter::class) !== [];
		}
	}
	expect(sprintf('%s::%s($%s) hidden in stack traces', substr(strrchr($class, '\\'), 1), $method, $parameter), $marked);
}

finish();
