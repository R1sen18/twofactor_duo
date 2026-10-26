<?php

declare(strict_types=1);

namespace OCA\TwoFactorDuo\Controller;

use OCA\TwoFactorDuo\Provider\DuoProvider;
use OCA\TwoFactorDuo\Web;
use OCP\AppFramework\Controller;
use OCP\AppFramework\Http\Attribute\NoCSRFRequired;
use OCP\AppFramework\Http\Attribute\NoTwoFactorRequired;
use OCP\AppFramework\Http\Attribute\PublicPage;
use OCP\AppFramework\Http\Attribute\UseSession;
use OCP\AppFramework\Http\TemplateResponse;
use OCP\IConfig;
use OCP\IRequest;
use OCP\ISession;
use OCP\IURLGenerator;
use OCP\Util;
use Psr\Log\LoggerInterface;

/**
 * Receives the redirect back from Duo's Universal Prompt.
 *
 * The user is still in the "pending 2FA" state here, so the route must be a
 * public page and exempt from core's TwoFactorMiddleware, which otherwise
 * redirects every non-challenge controller back to the challenge page. We verify the Duo code against the pending user, store the
 * outcome in the session, and then hand control back to core by POSTing to
 * the regular /login/challenge/duo endpoint, which calls
 * DuoProvider::verifyChallenge().
 */
class CallbackController extends Controller {
	/** Session key core uses for the user whose 2FA challenge is pending. */
	private const CORE_PENDING_UID = 'two_factor_auth_uid';

	public function __construct(
		string $appName,
		IRequest $request,
		private IConfig $config,
		private ISession $session,
		private IURLGenerator $urlGenerator,
		private LoggerInterface $logger,
	) {
		parent::__construct($appName, $request);
	}

	/**
	 * Annotation for Nextcloud < 34, which doesn't have the attribute yet:
	 * @NoTwoFactorRequired
	 */
	#[PublicPage]
	#[NoCSRFRequired]
	#[NoTwoFactorRequired]
	#[UseSession]
	public function index(): TemplateResponse {
		$duoCode = (string)$this->request->getParam('duo_code', '');
		$state = (string)$this->request->getParam('state', '');

		$uid = $this->session->get(self::CORE_PENDING_UID);
		$expectedState = $this->session->get(DuoProvider::SESSION_STATE);
		$this->session->remove(DuoProvider::SESSION_STATE);
		$this->session->remove(DuoProvider::SESSION_RESULT);

		$failure = $this->verify($uid, $duoCode, $state, $expectedState);
		if ($failure === null) {
			$this->session->set(DuoProvider::SESSION_RESULT, $uid);
			$this->session->remove(DuoProvider::SESSION_FAILED);
			$this->logger->info('Duo authentication succeeded for {uid}', ['app' => DuoProvider::APP_ID, 'uid' => $uid]);
		} else {
			// Tells the next challenge page not to start a new Duo prompt on its own.
			$this->session->set(DuoProvider::SESSION_FAILED, true);
			$this->logger->warning('Duo authentication failed for {uid}: {reason}', [
				'app' => DuoProvider::APP_ID,
				'uid' => is_string($uid) && $uid !== '' ? $uid : '(no pending login)',
				'reason' => $failure,
			]);
		}

		Util::addScript(DuoProvider::APP_ID, 'callback');
		$action = $this->urlGenerator->linkToRoute(
			'core.TwoFactorChallenge.solveChallenge',
			['challengeProviderId' => DuoProvider::PROVIDER_ID],
		);
		return new TemplateResponse(
			DuoProvider::APP_ID,
			'callback',
			['action' => $action],
			TemplateResponse::RENDER_AS_GUEST,
		);
	}

	/**
	 * @return string|null why the Duo response was rejected, or null if it is valid
	 */
	private function verify(mixed $uid, string $duoCode, string $state, mixed $expectedState): ?string {
		$duoError = (string)$this->request->getParam('error', '');
		if ($duoError !== '') {
			return trim("Duo returned an error: $duoError " . (string)$this->request->getParam('error_description', ''));
		}
		if (!is_string($uid) || $uid === '') {
			return 'no pending two-factor login in this session. The session expired, or the browser did not send'
				. ' the Nextcloud session cookie with Duo\'s redirect (CALL must use the same host as the login page)';
		}
		if ($duoCode === '' || $state === '') {
			return 'Duo\'s redirect is missing duo_code or state';
		}
		// Reject responses that don't belong to the prompt we started (OAuth CSRF).
		if (!is_string($expectedState)) {
			return 'no Duo prompt was started in this session (the challenge page was not shown, or the session was lost)';
		}
		if (!hash_equals($expectedState, $state)) {
			return 'state does not match the Duo prompt started in this session (several Duo prompts were open, or the request was forged)';
		}

		$config = $this->config->getSystemValue(DuoProvider::APP_ID, null);
		if (!DuoProvider::isValidConfig($config)) {
			return 'the configuration is incomplete; run occ twofactor_duo:check';
		}

		$web = $this->createWeb($config);
		$res = $web->decode($duoCode, $uid);

		if (!is_array($res)) {
			return 'no usable response from Duo\'s token endpoint';
		}
		if (isset($res['error'])) {
			$detail = $res['error_description'] ?? $res['message_detail'] ?? '';
			return 'Duo\'s token endpoint returned ' . $res['error'] . ($detail !== '' ? " ($detail)" : '')
				. ($web->last_error ? ': ' . $web->last_error : '');
		}
		if (($res['err_msg'] ?? '') !== 'null') {
			$reason = 'token validation failed: ' . ($res['err_msg'] ?? 'unknown error');
			if ($web->last_error) {
				$reason .= ' (' . $web->last_error . ')';
			}
			if (isset($res['preferred_username']) && $res['preferred_username'] !== $uid) {
				$reason .= sprintf(' Duo authenticated "%s", Nextcloud expected "%s".', $res['preferred_username'], $uid);
			}
			return $reason;
		}
		$result = $res['auth_result']['result'] ?? '';
		if ($result !== 'allow') {
			return sprintf('Duo did not allow the login (result "%s", status "%s")',
				$result, $res['auth_result']['status_msg'] ?? $res['auth_result']['status'] ?? '');
		}
		return null;
	}

	protected function createWeb(array $config): Web {
		return new Web($config['IKEY'], $config['SKEY'], $config['HOST'], $config['CALL']);
	}
}
