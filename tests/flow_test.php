<?php
// The whole login in one session: challenge page -> Duo -> callback -> POST /login/challenge/duo,
// with a fake Duo client. Covers success, every logged failure reason and the push-loop protection.
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';

use OCA\TwoFactorDuo\Controller\CallbackController;
use OCA\TwoFactorDuo\Provider\DuoProvider;
use OCA\TwoFactorDuo\Web;
use OCP\Authentication\TwoFactorAuth\IProvider;

/** Duo client that never touches the network. */
class FakeWeb extends Web {
	public static ?array $decodeResult = null;
	public static array $health = ['stat' => 'OK'];
	public function check() {
		return self::$health;
	}
	public function auth($username, $state = false) {
		return "https://duo.test/authorize?state=$state&u=$username";
	}
	public function decode($duoCode, $username) {
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

$session = new FakeSession();
$session->set('two_factor_auth_uid', 'j.maier');
$log = new FakeLogger();
$provider = new TestProvider($config, $session, new FakeTemplateManager(), $log);

$showChallenge = function () use ($provider, $user): FakeTemplate {
	OCP\Util::$scripts = [];
	return $provider->getTemplate($user);
};
$duoRedirect = function (array $params) use ($config, $session, $log) {
	OCP\Util::$scripts = [];
	return (new TestCallback('twofactor_duo', new FakeRequest($params), $config, $session, new FakeUrlGenerator(), $log))->index();
};
$stateOf = function (FakeTemplate $page): string {
	parse_str((string)parse_url($page->vars['duo_url'], PHP_URL_QUERY), $query);
	return $query['state'] ?? '';
};
$autoRedirects = fn (): bool => in_array('twofactor_duo/challenge', OCP\Util::$scripts, true);

section('1. Successful login');
$page = $showChallenge();
expect('first visit redirects to Duo automatically', $page->vars['notice'] === '' && $autoRedirects());
$state = $stateOf($page);
expect('state stored in the session and sent to Duo', $state !== '' && $session->get(DuoProvider::SESSION_STATE) === $state);
FakeWeb::$decodeResult = $allow;
$response = $duoRedirect(['duo_code' => 'code', 'state' => $state]);
expect('callback stores the approved uid', $session->get(DuoProvider::SESSION_RESULT) === 'j.maier');
expect('callback logs the success', str_contains($log->last(), 'info: Duo authentication succeeded for j.maier'), $log->last());
expect('callback page posts to core\'s solveChallenge', $response->params['action'] === '/index.php/login/challenge/duo');
expect('callback page queues callback.js', in_array('twofactor_duo/callback', OCP\Util::$scripts, true));
expect('callback page is rendered as guest page', $response->templateName === 'callback' && $response->renderAs === 'guest');
expect('verifyChallenge() accepts', $provider->verifyChallenge($user, 'duo'));
expect('no failure flag left behind', $session->get(DuoProvider::SESSION_FAILED) === null);

section('2. Approved uid is bound to the user and single-use');
$session->set(DuoProvider::SESSION_RESULT, 'j.maier');
expect('another user is rejected', !$provider->verifyChallenge(new FakeUser('mallory'), 'duo'));
expect('result consumed by that attempt', $session->get(DuoProvider::SESSION_RESULT) === null);
$session->set(DuoProvider::SESSION_RESULT, 'j.maier');
expect('accepted once', $provider->verifyChallenge($user, 'duo'));
expect('... but not twice', !$provider->verifyChallenge($user, 'duo'));

section('3. Duo denies the login: no push loop');
$state = $stateOf($showChallenge());
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
$duoRedirect(['duo_code' => 'code', 'state' => $stateOf($page)]);
expect('Try again then succeeds', $provider->verifyChallenge($user, 'duo'));

section('4. Logged failure reasons');
$cases = [
	'Duo error parameter' => [['error' => 'access_denied', 'error_description' => 'User denied'], $allow,
		'Duo returned an error: access_denied User denied'],
	'username mismatch' => [null, ['err_msg' => 'The username is invalid.', 'preferred_username' => 'jmaier@example.com', 'auth_result' => ['result' => 'allow']],
		'token validation failed: The username is invalid. Duo authenticated "jmaier@example.com", Nextcloud expected "j.maier".'],
	'token endpoint error' => [null, ['error' => 'ACCESS_FORBIDDEN', 'error_description' => 'Client duo_universal_php version 1.0.2 is deprecated'],
		'Duo\'s token endpoint returned ACCESS_FORBIDDEN (Client duo_universal_php version 1.0.2 is deprecated)'],
	'expired id_token' => [null, ['err_msg' => 'Invalid or expired id_token.'], 'token validation failed: Invalid or expired id_token.'],
	'forged state' => [['duo_code' => 'code', 'state' => 'forged'], $allow, 'state does not match'],
	'missing duo_code' => [['state' => '{state}'], $allow, 'missing duo_code or state'],
];
foreach ($cases as $name => [$params, $decodeResult, $expected]) {
	$state = $stateOf($showChallenge());
	FakeWeb::$decodeResult = $decodeResult;
	$params ??= ['duo_code' => 'code', 'state' => $state];
	if (($params['state'] ?? '') === '{state}') {
		$params['state'] = $state;
	}
	$duoRedirect($params);
	expect("$name: logged", str_contains($log->last(), $expected), $log->last());
	expect("$name: login rejected", !$provider->verifyChallenge($user, 'duo'));
}
$state = $stateOf($showChallenge());
$session->remove('two_factor_auth_uid');
$duoRedirect(['duo_code' => 'code', 'state' => $state]);
expect('session lost: logged', str_contains($log->last(), '(no pending login): no pending two-factor login in this session'), $log->last());

section('5. Duo\'s redirect never arrives');
$session->data = ['two_factor_auth_uid' => 'j.maier'];
$showChallenge();               // prompt started, the browser never comes back
$page = $showChallenge();       // user lands on the challenge page again
expect('no automatic redirect, Try again shown', $page->vars['notice'] !== '' && !$autoRedirects());
expect('warning about the missing callback logged', str_contains($log->last(), 'was not completed'), $log->last());

section('6. Health check fails');
$session->data = ['two_factor_auth_uid' => 'j.maier'];
FakeWeb::$health = ['stat' => 'FAIL', 'code' => 40301, 'message' => 'invalid_client', 'message_detail' => 'Integration type does not support frameless access.'];
$page = $showChallenge();
expect('error shown, no Duo link', $page->vars['error'] !== '' && $page->vars['duo_url'] === '');
expect('Duo\'s reason logged', str_contains($log->last(), 'Duo health check failed: invalid_client Integration type does not support frameless access.'), $log->last());
FakeWeb::$health = ['stat' => 'OK'];

section('7. Interfaces and routing attributes');
expect('DuoProvider implements IProvider', $provider instanceof IProvider);
expect('DuoProvider has no custom CSP (the API it used is gone in NC35)', !method_exists(DuoProvider::class, 'getCSP'));
$index = new ReflectionMethod(CallbackController::class, 'index');
$attributes = array_map(fn ($a) => $a->getName(), $index->getAttributes());
expect('callback: #[NoTwoFactorRequired]', in_array('OCP\AppFramework\Http\Attribute\NoTwoFactorRequired', $attributes, true));
expect('callback: @NoTwoFactorRequired annotation for NC < 34', (bool)preg_match('/^\h+\*\h+@NoTwoFactorRequired\b/m', (string)$index->getDocComment()));
expect('callback: public, no CSRF token, writable session', !array_diff(['OCP\AppFramework\Http\Attribute\PublicPage',
	'OCP\AppFramework\Http\Attribute\NoCSRFRequired', 'OCP\AppFramework\Http\Attribute\UseSession'], $attributes));
expect('provider disabled with incomplete config', !(new DuoProvider(new FakeConfig(['twofactor_duo' => ['AKEY' => 'x']]),
	$session, new FakeTemplateManager(), $log))->isTwoFactorAuthEnabledForUser($user));

finish();
