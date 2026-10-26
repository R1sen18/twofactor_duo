<?php

declare(strict_types=1);

namespace OCA\TwoFactorDuo\Provider;

use OCA\TwoFactorDuo\Web;
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
	/** UID that successfully passed Duo, set by the callback. */
	public const SESSION_RESULT = 'twofactor_duo_result';
	/** Set when the last attempt failed, so the next challenge page doesn't start a new prompt by itself. */
	public const SESSION_FAILED = 'twofactor_duo_failed';

	public function __construct(
		private IConfig $config,
		private ISession $session,
		private ITemplateManager $templateManager,
		private LoggerInterface $logger,
	) {
	}

	public static function isValidConfig(mixed $config): bool {
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

		$config = $this->getConfig();
		if ($config === null) {
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
		$this->session->set(self::SESSION_STATE, $state);
		$tmpl->assign('duo_url', $web->auth($user->getUID(), $state));
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
		$passed = is_string($result) && hash_equals($user->getUID(), $result);
		if (!$passed) {
			$this->session->set(self::SESSION_FAILED, true);
		}
		return $passed;
	}

	protected function createWeb(array $config): Web {
		return new Web($config['IKEY'], $config['SKEY'], $config['HOST'], $config['CALL']);
	}

	public function isTwoFactorAuthEnabledForUser(IUser $user): bool {
		return $this->getConfig() !== null;
	}
}
