<?php

declare(strict_types=1);

namespace OCA\TwoFactorDuo\Command;

use OCA\TwoFactorDuo\Provider\DuoProvider;
use OCA\TwoFactorDuo\Web;
use OCP\Authentication\TwoFactorAuth\IRegistry;
use OCP\IConfig;
use OCP\IUser;
use OCP\IUserManager;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * occ twofactor_duo:check — validate the configuration, the callback URL and
 * the Duo credentials, and find users for whom core has stored Duo as disabled.
 */
class Check extends Command {
	private const CALLBACK_PATH = '/apps/twofactor_duo/callback';
	private const KNOWN_KEYS = ['IKEY', 'SKEY', 'HOST', 'CALL'];
	private const LIST_LIMIT = 10;

	private int $errors = 0;
	private int $warnings = 0;
	private OutputInterface $output;

	public function __construct(
		private IConfig $config,
		private IRegistry $registry,
		private IUserManager $userManager,
	) {
		parent::__construct();
	}

	protected function configure(): void {
		$this->setName('twofactor_duo:check')
			->setDescription('Validate the Duo configuration and test the credentials against Duo')
			->addOption('offline', null, InputOption::VALUE_NONE, 'Skip the request to Duo')
			->addOption('reset-states', null, InputOption::VALUE_NONE,
				'Clear the stored Duo state of all users so it is re-evaluated at their next login');
	}

	protected function execute(InputInterface $input, OutputInterface $output): int {
		$this->output = $output;
		$this->errors = 0;
		$this->warnings = 0;

		$config = $this->config->getSystemValue(DuoProvider::APP_ID, null);

		$this->section('Configuration (config.php: \'' . DuoProvider::APP_ID . '\')');
		$this->checkConfig($config);

		if (is_array($config) && !empty($config['CALL']) && is_string($config['CALL'])) {
			$this->section('Callback URL (CALL)');
			$this->checkCallback($config['CALL']);
		}

		$valid = DuoProvider::isValidConfig($config);
		if ($valid && !$input->getOption('offline')) {
			$this->section('Duo API (' . $config['HOST'] . ')');
			$this->checkDuo($config);
		}

		$this->section('User states');
		if ($input->getOption('reset-states')) {
			$this->resetStates($valid);
		} else {
			$this->checkStates($valid);
		}

		$output->writeln('');
		if ($this->errors > 0) {
			$output->writeln(sprintf('<error>%d error(s), %d warning(s). Users cannot sign in with Duo until the errors are fixed.</error>', $this->errors, $this->warnings));
			return Command::FAILURE;
		}
		$output->writeln(sprintf('<info>No errors, %d warning(s).</info>', $this->warnings));
		return Command::SUCCESS;
	}

	private function checkConfig(mixed $config): void {
		if ($config === null) {
			$this->fail('Not configured. Add the \'' . DuoProvider::APP_ID . '\' array to config.php (see README).');
			return;
		}
		if (!is_array($config)) {
			$this->fail('\'' . DuoProvider::APP_ID . '\' must be an array with IKEY, SKEY, HOST and CALL.');
			return;
		}

		foreach (self::KNOWN_KEYS as $key) {
			if (!isset($config[$key]) || !is_string($config[$key]) || trim($config[$key]) === '') {
				$this->fail("$key is missing or empty.");
			} elseif (trim($config[$key]) !== $config[$key]) {
				$this->fail("$key has leading or trailing whitespace.");
			}
		}

		$ikey = $config['IKEY'] ?? null;
		if (is_string($ikey) && $ikey !== '') {
			if (preg_match('/^DI[A-Z0-9]{18}$/', $ikey)) {
				$this->ok("IKEY (Client ID): $ikey");
			} else {
				$this->warn("IKEY (Client ID) '$ikey' doesn't look like a Duo Client ID (20 characters starting with 'DI').");
			}
		}

		$skey = $config['SKEY'] ?? null;
		if (is_string($skey) && $skey !== '') {
			if (strlen($skey) === 40) {
				$this->ok('SKEY (Client secret): set, 40 characters');
			} else {
				$this->warn('SKEY (Client secret) has ' . strlen($skey) . ' characters; Duo Client secrets have 40.');
			}
		}

		$host = $config['HOST'] ?? null;
		if (is_string($host) && $host !== '') {
			if (str_contains($host, '://') || str_contains($host, '/')) {
				$this->fail("HOST must be the hostname only, e.g. api-xxxxxxxx.duosecurity.com, not '$host'.");
			} elseif (preg_match('/^api-[a-z0-9]+\.duo(security|federal)\.com$/i', $host)) {
				$this->ok("HOST (API hostname): $host");
			} else {
				$this->warn("HOST '$host' doesn't look like a Duo API hostname (api-xxxxxxxx.duosecurity.com).");
			}
		}

		foreach (array_diff(array_keys($config), self::KNOWN_KEYS) as $extra) {
			$hint = $extra === 'AKEY' ? ' (only used by the old Duo Web SDK v2 app; safe to remove)' : '';
			$this->warn("Unknown key '$extra' is ignored$hint.");
		}
	}

	private function checkCallback(string $call): void {
		$parts = parse_url($call);
		if (!is_array($parts) || empty($parts['scheme']) || empty($parts['host'])) {
			$this->fail("CALL '$call' is not an absolute URL.");
			return;
		}

		$scheme = strtolower($parts['scheme']);
		if ($scheme === 'http') {
			$this->warn('CALL uses http://. Use https:// so the Duo code isn\'t sent in clear text.');
		} elseif ($scheme !== 'https') {
			$this->fail("CALL must start with https://, not $scheme://.");
		}

		$path = $parts['path'] ?? '';
		if (str_ends_with($path, self::CALLBACK_PATH) && !isset($parts['query'])) {
			$this->ok("CALL: $call");
		} elseif (str_contains($path, '/login/callback/')) {
			$this->fail('CALL still points to the 1.x URL. Change it to <your-nextcloud-url>' . self::CALLBACK_PATH . '.');
		} else {
			$this->fail('CALL must end with ' . self::CALLBACK_PATH . ' (no query string).');
		}

		$cliUrl = rtrim((string)$this->config->getSystemValue('overwrite.cli.url', ''), '/');
		if ($cliUrl === '') {
			$this->warn('overwrite.cli.url is not set, so CALL can\'t be compared with your Nextcloud URL.');
		} else {
			$expected = [$cliUrl . self::CALLBACK_PATH, $cliUrl . '/index.php' . self::CALLBACK_PATH];
			if (in_array($this->normalizeUrl($call), array_map($this->normalizeUrl(...), $expected), true)) {
				$this->ok('CALL matches overwrite.cli.url');
			} else {
				$this->warn("CALL doesn't match overwrite.cli.url ($cliUrl). Expected $expected[0]"
					. " (or $expected[1] without pretty URLs).");
			}
		}

		$host = strtolower($parts['host']);
		$hostWithPort = isset($parts['port']) ? $host . ':' . $parts['port'] : $host;
		$trusted = $this->config->getSystemValue('trusted_domains', []);
		if (!is_array($trusted)) {
			$trusted = [];
		}
		if ($this->isTrustedDomain($hostWithPort, $trusted)) {
			$this->ok("$hostWithPort is in trusted_domains");
		} else {
			$this->fail("$hostWithPort is not in trusted_domains, so Nextcloud would reject Duo's redirect.");
		}
	}

	private function checkDuo(array $config): void {
		if (!is_readable(Web::DUO_CERTS)) {
			$this->fail('CA bundle ' . Web::DUO_CERTS . ' is missing or unreadable.');
			return;
		}

		$web = new Web($config['IKEY'], $config['SKEY'], $config['HOST'], $config['CALL']);
		$res = $web->check();

		if (!is_array($res)) {
			$reason = $web->last_error ?: 'invalid response';
			$this->fail("Duo could not be reached: $reason");
			return;
		}
		if (($res['stat'] ?? '') === 'OK') {
			$this->ok('Health check passed: Duo accepted IKEY, SKEY and HOST');
			return;
		}

		$details = array_filter([
			isset($res['code']) ? 'code ' . $res['code'] : null,
			$res['message'] ?? $res['error'] ?? null,
			$res['message_detail'] ?? $res['error_description'] ?? null,
		], fn ($v) => is_scalar($v) && $v !== '');
		$this->fail('Duo rejected the health check: ' . ($details ? implode(', ', $details) : json_encode($res)));
	}

	/**
	 * Core asks the provider only once per user whether Duo is enabled and stores
	 * the answer. Users who logged in while the config was incomplete stay
	 * "disabled" even after it is fixed.
	 */
	private function checkStates(bool $valid): void {
		$enabled = 0;
		$disabled = [];
		$this->userManager->callForSeenUsers(function (IUser $user) use (&$enabled, &$disabled): void {
			$state = $this->registry->getProviderStates($user)[DuoProvider::PROVIDER_ID] ?? null;
			if ($state === true) {
				$enabled++;
			} elseif ($state === false) {
				$disabled[] = $user->getUID();
			}
		});

		$this->ok("$enabled user(s) have Duo enabled");
		if ($disabled === []) {
			$this->ok($valid
				? 'No users are stored as disabled; everyone else gets Duo at their next login'
				: 'No users are stored as disabled');
			return;
		}

		$shown = implode(', ', array_slice($disabled, 0, self::LIST_LIMIT));
		$more = count($disabled) > self::LIST_LIMIT ? sprintf(' and %d more', count($disabled) - self::LIST_LIMIT) : '';
		$this->warn(sprintf('%d user(s) have Duo stored as disabled and will NOT be asked for Duo: %s%s.',
			count($disabled), $shown, $more));
		$this->output->writeln('         Fix the config, then run: occ twofactor_duo:check --reset-states');
	}

	private function resetStates(bool $valid): void {
		if (!$valid || $this->errors > 0) {
			$this->fail('Not resetting: fix the errors above first, or the states would be stored as disabled again.');
			return;
		}
		$this->registry->cleanUp(DuoProvider::PROVIDER_ID);
		$this->ok('Cleared the stored Duo state of all users; everyone gets Duo at their next login');
	}

	/** Same matching rules as Nextcloud's trusted_domains check. */
	private function isTrustedDomain(string $host, array $trusted): bool {
		foreach ($trusted as $pattern) {
			if (!is_string($pattern)) {
				continue;
			}
			$regex = '/^' . str_replace('\*', '[-\.a-zA-Z0-9]*', preg_quote($pattern, '/')) . '$/i';
			if (preg_match($regex, $host)) {
				return true;
			}
		}
		return false;
	}

	private function normalizeUrl(string $url): string {
		$parts = parse_url($url);
		if (!is_array($parts) || !isset($parts['scheme'], $parts['host'])) {
			return $url;
		}
		$port = isset($parts['port']) ? ':' . $parts['port'] : '';
		return strtolower($parts['scheme'] . '://' . $parts['host']) . $port . rtrim($parts['path'] ?? '', '/');
	}

	private function section(string $title): void {
		$this->output->writeln('');
		$this->output->writeln("<comment>$title</comment>");
	}

	private function ok(string $message): void {
		$this->output->writeln("  <info>[OK]</info>   $message");
	}

	private function warn(string $message): void {
		$this->warnings++;
		$this->output->writeln("  <comment>[WARN]</comment> $message");
	}

	private function fail(string $message): void {
		$this->errors++;
		$this->output->writeln("  <error>[FAIL]</error> $message");
	}
}
