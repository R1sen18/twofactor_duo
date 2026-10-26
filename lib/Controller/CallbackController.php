<?php

declare(strict_types=1);

namespace OCA\TwoFactorDuo\Controller;

use OCA\TwoFactorDuo\Provider\DuoProvider;
use OCA\TwoFactorDuo\Web;
use OCP\AppFramework\Controller;
use OCP\AppFramework\Http\Attribute\NoCSRFRequired;
use OCP\AppFramework\Http\Attribute\PublicPage;
use OCP\AppFramework\Http\Attribute\UseSession;
use OCP\AppFramework\Http\TemplateResponse;
use OCP\IConfig;
use OCP\IRequest;
use OCP\ISession;
use OCP\IURLGenerator;
use OCP\Util;

/**
 * Receives the redirect back from Duo's Universal Prompt.
 *
 * The user is still in the "pending 2FA" state here, so the route must be a
 * public page. We verify the Duo code against the pending user, store the
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
	) {
		parent::__construct($appName, $request);
	}

	#[PublicPage]
	#[NoCSRFRequired]
	#[UseSession]
	public function index(): TemplateResponse {
		$duoCode = (string)$this->request->getParam('duo_code', '');
		$state = (string)$this->request->getParam('state', '');

		$uid = $this->session->get(self::CORE_PENDING_UID);
		$expectedState = $this->session->get(DuoProvider::SESSION_STATE);
		$this->session->remove(DuoProvider::SESSION_STATE);
		$this->session->remove(DuoProvider::SESSION_RESULT);

		if ($this->verify($uid, $duoCode, $state, $expectedState)) {
			$this->session->set(DuoProvider::SESSION_RESULT, $uid);
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

	private function verify(mixed $uid, string $duoCode, string $state, mixed $expectedState): bool {
		if (!is_string($uid) || $uid === '' || $duoCode === '' || $state === '') {
			return false;
		}
		// Reject responses that don't belong to the prompt we started (OAuth CSRF).
		if (!is_string($expectedState) || !hash_equals($expectedState, $state)) {
			return false;
		}

		$config = $this->config->getSystemValue(DuoProvider::APP_ID, null);
		if (!DuoProvider::isValidConfig($config)) {
			return false;
		}

		$web = new Web($config['IKEY'], $config['SKEY'], $config['HOST'], $config['CALL']);
		$res = $web->decode($duoCode, $uid);

		return is_array($res)
			&& ($res['err_msg'] ?? '') === 'null'
			&& ($res['auth_result']['result'] ?? '') === 'allow';
	}
}
