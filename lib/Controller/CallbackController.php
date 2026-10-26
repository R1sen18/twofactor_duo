<?php

declare(strict_types=1);

namespace OCA\TwoFactorDuo\Controller;

use OCA\TwoFactorDuo\Provider\DuoProvider;
use OCA\TwoFactorDuo\Web;
use OCP\AppFramework\Controller;
use OCP\AppFramework\Http\Attribute\AnonRateLimit;
use OCP\AppFramework\Http\Attribute\NoCSRFRequired;
use OCP\AppFramework\Http\Attribute\NoTwoFactorRequired;
use OCP\AppFramework\Http\Attribute\PublicPage;
use OCP\AppFramework\Http\Attribute\UserRateLimit;
use OCP\AppFramework\Http\Attribute\UseSession;
use OCP\AppFramework\Http\RedirectResponse;
use OCP\AppFramework\Http\TemplateResponse;
use OCP\AppFramework\Utility\ITimeFactory;
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
 * redirects every non-challenge controller back to the challenge page. We verify
 * the Duo code against the pending user, store the outcome in the session, and
 * then hand control back to core by POSTing to the regular /login/challenge/duo
 * endpoint, which calls DuoProvider::verifyChallenge().
 */
class CallbackController extends Controller {
	/** Session key core uses for the user whose 2FA challenge is pending. */
	private const CORE_PENDING_UID = 'two_factor_auth_uid';
	/** Longest piece of request- or Duo-supplied text written to the log. */
	private const LOG_TEXT_LIMIT = 200;

	public function __construct(
		string $appName,
		IRequest $request,
		private IConfig $config,
		private ISession $session,
		private IURLGenerator $urlGenerator,
		private LoggerInterface $logger,
		private ITimeFactory $timeFactory,
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
	#[AnonRateLimit(limit: 10, period: 300)]
	#[UserRateLimit(limit: 10, period: 300)]
	public function index(): TemplateResponse|RedirectResponse {
		$uid = $this->session->get(self::CORE_PENDING_UID);
		$expectedState = $this->session->get(DuoProvider::SESSION_STATE);
		$state = (string)$this->request->getParam('state', '');

		// Only Duo's answer to the prompt this session started may change anything. Anything else
		// (a forged link, a stale tab, a scanner) leaves the session alone and isn't logged as a warning.
		if (!is_string($uid) || $uid === '' || !is_string($expectedState) || $state === ''
			|| !hash_equals($expectedState, $state)) {
			$this->logger->debug('Ignored a Duo callback that does not match a Duo prompt started in this session'
				. ' (no pending login, or wrong or missing state)', ['app' => DuoProvider::APP_ID]);
			return new RedirectResponse($this->urlGenerator->linkToRoute(
				'core.TwoFactorChallenge.showChallenge',
				['challengeProviderId' => DuoProvider::PROVIDER_ID],
			));
		}

		$nonce = $this->session->get(DuoProvider::SESSION_NONCE);
		$this->session->remove(DuoProvider::SESSION_STATE);
		$this->session->remove(DuoProvider::SESSION_NONCE);
		$this->session->remove(DuoProvider::SESSION_RESULT);

		$failure = $this->verify($uid, (string)$this->request->getParam('duo_code', ''), $nonce);
		if ($failure === null) {
			$this->session->set(DuoProvider::SESSION_RESULT, ['uid' => $uid, 'time' => $this->timeFactory->getTime()]);
			$this->session->remove(DuoProvider::SESSION_FAILED);
			$this->logger->info('Duo authentication succeeded for {uid}', ['app' => DuoProvider::APP_ID, 'uid' => $uid]);
		} else {
			// Tells the next challenge page not to start a new Duo prompt on its own.
			$this->session->set(DuoProvider::SESSION_FAILED, true);
			$this->logger->warning('Duo authentication failed for {uid}: {reason}', [
				'app' => DuoProvider::APP_ID,
				'uid' => $uid,
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
	 * Called only after state matched, so the request answers this session's own prompt.
	 *
	 * @return string|null why the Duo response was rejected, or null if it is valid
	 */
	private function verify(string $uid, #[\SensitiveParameter] string $duoCode, #[\SensitiveParameter] mixed $nonce): ?string {
		$duoError = (string)$this->request->getParam('error', '');
		if ($duoError !== '') {
			return trim('Duo returned an error: ' . self::clip($duoError) . ' '
				. self::clip($this->request->getParam('error_description', '')));
		}
		if ($duoCode === '') {
			return 'Duo\'s redirect is missing duo_code';
		}
		if (!is_string($nonce) || $nonce === '') {
			return 'no nonce was stored for this Duo prompt';
		}

		$config = $this->config->getSystemValue(DuoProvider::APP_ID, null);
		if (!DuoProvider::isValidConfig($config)) {
			return 'the configuration is incomplete; run occ twofactor_duo:check';
		}

		$web = $this->createWeb($config);
		$res = $web->decode($duoCode, $uid, $nonce);

		if (!is_array($res)) {
			return 'no usable response from Duo\'s token endpoint';
		}
		if (isset($res['error'])) {
			$detail = self::clip($res['error_description'] ?? $res['message_detail'] ?? '');
			return 'Duo\'s token endpoint returned ' . self::clip($res['error']) . ($detail !== '' ? " ($detail)" : '')
				. ($web->last_error ? ': ' . self::clip($web->last_error) : '');
		}
		if (($res['err_msg'] ?? '') !== 'null') {
			$reason = 'token validation failed: ' . self::clip($res['err_msg'] ?? 'unknown error');
			if ($web->last_error) {
				$reason .= ' (' . self::clip($web->last_error) . ')';
			}
			if (isset($res['preferred_username']) && $res['preferred_username'] !== $uid) {
				$reason .= sprintf(' Duo authenticated "%s", Nextcloud expected "%s".', self::clip($res['preferred_username']), $uid);
			}
			return $reason;
		}
		$result = $res['auth_result']['result'] ?? '';
		if ($result !== 'allow') {
			return sprintf('Duo did not allow the login (result "%s", status "%s")',
				self::clip($result), self::clip($res['auth_result']['status_msg'] ?? $res['auth_result']['status'] ?? ''));
		}
		return null;
	}

	/** Single-line, length-limited text for the log. */
	private static function clip(mixed $value): string {
		$text = is_scalar($value) ? (string)$value : (string)json_encode($value);
		$text = (string)preg_replace('/[\x00-\x1F\x7F]+/', ' ', $text);
		return mb_strlen($text) > self::LOG_TEXT_LIMIT ? mb_substr($text, 0, self::LOG_TEXT_LIMIT) . '…' : $text;
	}

	protected function createWeb(#[\SensitiveParameter] array $config): Web {
		return new Web($config['IKEY'], $config['SKEY'], $config['HOST'], $config['CALL']);
	}
}
