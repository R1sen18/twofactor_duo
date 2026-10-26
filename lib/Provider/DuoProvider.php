<?php

declare(strict_types=1);

namespace OCA\TwoFactorDuo\Provider;

use OCA\TwoFactorDuo\Web;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\Authentication\TwoFactorAuth\IProvider;
use OCP\IConfig;
use OCP\ISession;
use OCP\IUser;
use OCP\Template\ITemplate;
use OCP\Template\ITemplateManager;
use OCP\Util;
use Psr\Log\LoggerInterface;

/**
 * No custom CSP needed: the challenge page sends the browser to Duo with a
 * top-level redirect (no iframe) and only loads this app's own script.
 */
class DuoProvider implements IProvider {
	public const APP_ID = 'twofactor_duo';
	public const PROVIDER_ID = 'duo';
	/** OAuth state of the Duo prompt we started, checked in the callback. */
	public const SESSION_STATE = 'twofactor_duo_state';
	/** OIDC nonce of that prompt; must come back inside Duo's signed id_token. */
	public const SESSION_NONCE = 'twofactor_duo_nonce';
	/** ['uid' => …, 'time' => …] of a login Duo approved, set by the callback. */
	public const SESSION_RESULT = 'twofactor_duo_result';
	/** Set when the last attempt failed, so the next challenge page doesn't start a new prompt by itself. */
	public const SESSION_FAILED = 'twofactor_duo_failed';
	/** Seconds an approval stays usable; the callback page submits it right away. */
	public const RESULT_TTL = 120;

	public function __construct(
		private IConfig $config,
		private ISession $session,
		private ITemplateManager $templateManager,
		private LoggerInterface $logger,
		private ITimeFactory $timeFactory,
	) {
	}

	public static function isValidConfig(#[\SensitiveParameter] mixed $config): bool {
		if (!is_array($config)) {
			return false;
		}
		foreach (['IKEY', 'SKEY', 'HOST', 'CALL'] as $key) {
			if (empty($config[$key]) || !is_string($config[$key])) {
				return false;
			}
		}
		return true;
	}

	private function getConfig(): ?array {
		$config = $this->config->getSystemValue(self::APP_ID, null);
		return self::isValidConfig($config) ? $config : null;
	}

	public function getId(): string {
		return self::PROVIDER_ID;
	}

	public function getDisplayName(): string {
		return 'Duo Security';
	}

	public function getDescription(): string {
		return 'Authenticate with Duo Universal Prompt';
	}

	public function getTemplate(IUser $user): ITemplate {
		$tmpl = $this->templateManager->getTemplate(self::APP_ID, 'challenge');
		$tmpl->assign('duo_url', '');
		$tmpl->assign('error', '');
		$tmpl->assign('notice', '');

		// A new prompt invalidates any approval from an earlier one that was never submitted.
		$this->session->remove(self::SESSION_RESULT);

		$config = $this->getConfig();
		if ($config === null) {
			$this->logger->error('Duo is enabled but its configuration is missing or incomplete; nobody can pass Duo.'
				. ' Run occ twofactor_duo:check.', ['app' => self::APP_ID]);
			$tmpl->assign('error', 'Duo is not configured on this server.');
			return $tmpl;
		}

		// A failed attempt, or a prompt whose callback never arrived, must not start the next prompt
		// automatically: that sends endless pushes to the user's phone.
		$failed = $this->session->get(self::SESSION_FAILED) === true;
		$unfinished = $this->session->get(self::SESSION_STATE) !== null;
		$this->session->remove(self::SESSION_FAILED);
		if ($unfinished && !$failed) {
			$this->logger->warning('The previous Duo prompt for {uid} was not completed: the user went back, or Duo\'s redirect'
				. ' to the CALL URL never reached the app. If this happens on every login, check CALL with occ twofactor_duo:check.',
				['app' => self::APP_ID, 'uid' => $user->getUID()]);
		}

		$web = $this->createWeb($config);
		$health = $web->check();
		if (!is_array($health) || ($health['stat'] ?? '') !== 'OK') {
			$this->logger->warning('Duo health check failed: {reason}', [
				'app' => self::APP_ID,
				'reason' => is_array($health)
					? trim(($health['message'] ?? $health['error'] ?? 'unknown') . ' ' . ($health['message_detail'] ?? $health['error_description'] ?? ''))
					: ($web->last_error ?: 'no usable response'),
			]);
			$tmpl->assign('error', 'Duo Security is currently unreachable. Please try again later.');
			return $tmpl;
		}

		$state = $web->rand_str();
		$nonce = $web->rand_str(64);
		$this->session->set(self::SESSION_STATE, $state);
		$this->session->set(self::SESSION_NONCE, $nonce);
		$tmpl->assign('duo_url', $web->auth($user->getUID(), $state, $nonce));
		if ($failed || $unfinished) {
			$tmpl->assign('notice', 'The Duo sign-in was not completed. Try again, or contact your administrator if this keeps happening.');
		} else {
			Util::addScript(self::APP_ID, 'challenge');
		}
		return $tmpl;
	}

	public function verifyChallenge(IUser $user, string $challenge): bool {
		// The real verification happened in CallbackController; $challenge is unused.
		$result = $this->session->get(self::SESSION_RESULT);
		$this->session->remove(self::SESSION_RESULT);

		$age = is_array($result) && is_int($result['time'] ?? null) ? $this->timeFactory->getTime() - $result['time'] : null;
		$passed = $age !== null && $age >= 0 && $age <= self::RESULT_TTL
			&& is_string($result['uid'] ?? null) && hash_equals($user->getUID(), $result['uid']);
		if (!$passed) {
			$this->session->set(self::SESSION_FAILED, true);
			if ($age !== null && $age > self::RESULT_TTL) {
				$this->logger->warning('Rejected a Duo approval for {uid} that was {age} s old (limit {ttl} s)',
					['app' => self::APP_ID, 'uid' => $user->getUID(), 'age' => $age, 'ttl' => self::RESULT_TTL]);
			}
		}
		return $passed;
	}

	protected function createWeb(#[\SensitiveParameter] array $config): Web {
		return new Web($config['IKEY'], $config['SKEY'], $config['HOST'], $config['CALL']);
	}

	/**
	 * Always true, even when the configuration is broken (fail closed). Core asks this only once per
	 * user and stores the answer forever, so returning false for a broken config would exempt every
	 * user who logs in meanwhile from Duo permanently. getTemplate() blocks the login instead.
	 */
	public function isTwoFactorAuthEnabledForUser(IUser $user): bool {
		return true;
	}
}
