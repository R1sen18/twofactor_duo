<?php

declare(strict_types=1);

namespace OCA\TwoFactorDuo\Provider;

use OCA\TwoFactorDuo\Web;
use OCP\AppFramework\Http\ContentSecurityPolicy;
use OCP\Authentication\TwoFactorAuth\IProvider;
use OCP\Authentication\TwoFactorAuth\IProvidesCustomCSP;
use OCP\IConfig;
use OCP\ISession;
use OCP\IUser;
use OCP\Template\ITemplate;
use OCP\Template\ITemplateManager;
use OCP\Util;

class DuoProvider implements IProvider, IProvidesCustomCSP {
	public const APP_ID = 'twofactor_duo';
	public const PROVIDER_ID = 'duo';
	/** OAuth state of the Duo prompt we started, checked in the callback. */
	public const SESSION_STATE = 'twofactor_duo_state';
	/** UID that successfully passed Duo, set by the callback. */
	public const SESSION_RESULT = 'twofactor_duo_result';

	public function __construct(
		private IConfig $config,
		private ISession $session,
		private ITemplateManager $templateManager,
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

	public function getCSP(): ContentSecurityPolicy {
		$csp = new ContentSecurityPolicy();
		$csp->addAllowedChildSrcDomain('https://*.duosecurity.com');
		$csp->addAllowedStyleDomain('https://*.duosecurity.com');
		$csp->addAllowedFrameDomain('https://*.duosecurity.com');
		return $csp;
	}

	public function getTemplate(IUser $user): ITemplate {
		$tmpl = $this->templateManager->getTemplate(self::APP_ID, 'challenge');
		$tmpl->assign('duo_url', '');
		$tmpl->assign('error', '');

		$config = $this->getConfig();
		if ($config === null) {
			$tmpl->assign('error', 'Duo is not configured on this server.');
			return $tmpl;
		}

		$web = new Web($config['IKEY'], $config['SKEY'], $config['HOST'], $config['CALL']);
		$health = $web->check();
		if (!is_array($health) || ($health['stat'] ?? '') !== 'OK') {
			$tmpl->assign('error', 'Duo Security is currently unreachable. Please try again later.');
			return $tmpl;
		}

		$state = $web->rand_str();
		$this->session->set(self::SESSION_STATE, $state);
		$tmpl->assign('duo_url', $web->auth($user->getUID(), $state));
		Util::addScript(self::APP_ID, 'challenge');
		return $tmpl;
	}

	public function verifyChallenge(IUser $user, string $challenge): bool {
		// The real verification happened in CallbackController; $challenge is unused.
		$result = $this->session->get(self::SESSION_RESULT);
		$this->session->remove(self::SESSION_RESULT);
		return is_string($result) && hash_equals($user->getUID(), $result);
	}

	public function isTwoFactorAuthEnabledForUser(IUser $user): bool {
		return $this->getConfig() !== null;
	}
}
