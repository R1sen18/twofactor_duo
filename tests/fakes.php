<?php
// In-memory implementations of the Nextcloud services the app depends on.
declare(strict_types=1);

// The app is deployed as a git clone, so this file is reachable over HTTP.
if (PHP_SAPI !== 'cli') {
	http_response_code(404);
	exit;
}

use OCP\Authentication\TwoFactorAuth\IProvider;
use OCP\Authentication\TwoFactorAuth\IRegistry;

class FakeUser implements OCP\IUser {
	public function __construct(private string $uid) {
	}
	public function getUID(): string {
		return $this->uid;
	}
}

class FakeConfig implements OCP\IConfig {
	public function __construct(public array $values) {
	}
	public function getSystemValue($key, $default = '') {
		return $this->values[$key] ?? $default;
	}
}

class FakeSession implements OCP\ISession {
	public array $data = [];
	public function set(string $key, $value) {
		$this->data[$key] = $value;
	}
	public function get(string $key) {
		return $this->data[$key] ?? null;
	}
	public function remove(string $key) {
		unset($this->data[$key]);
	}
}

class FakeUserManager implements OCP\IUserManager {
	public function __construct(private array $uids) {
	}
	public function callForSeenUsers(\Closure $callback) {
		foreach ($this->uids as $uid) {
			if ($callback(new FakeUser($uid)) === false) {
				break;
			}
		}
	}
}

class FakeRegistry implements IRegistry {
	/** Provider ids passed to cleanUp(). */
	public array $cleaned = [];
	public function __construct(public array $states) {
	}
	public function getProviderStates(OCP\IUser $user): array {
		return $this->states[$user->getUID()] ?? [];
	}
	public function enableProviderFor(IProvider $provider, OCP\IUser $user) {
	}
	public function disableProviderFor(IProvider $provider, OCP\IUser $user) {
	}
	public function cleanUp(string $providerId) {
		$this->cleaned[] = $providerId;
		$this->states = [];
	}
}

class FakeTemplate implements OCP\Template\ITemplate {
	public array $vars = [];
	public function fetchPage(?array $additionalParams = null): string {
		return '';
	}
	public function printPage(): void {
	}
	public function assign(string $key, mixed $value): void {
		$this->vars[$key] = $value;
	}
	public function append(string $key, mixed $value): void {
		$this->vars[$key][] = $value;
	}
}

class FakeTemplateManager implements OCP\Template\ITemplateManager {
	public function getTemplate(string $app, string $name, string $renderAs = '', bool $registerCall = true): OCP\Template\ITemplate {
		return new FakeTemplate();
	}
}

class FakeRequest implements OCP\IRequest {
	public function __construct(private array $params) {
	}
	public function getParam(string $key, $default = null) {
		return $this->params[$key] ?? $default;
	}
}

class FakeUrlGenerator implements OCP\IURLGenerator {
	public function linkToRoute(string $routeName, array $arguments = []): string {
		return '/index.php/login/challenge/' . $arguments['challengeProviderId'];
	}
}

/** Records log lines with {placeholders} filled in. */
class FakeLogger implements Psr\Log\LoggerInterface {
	public array $lines = [];
	public function emergency(string|\Stringable $message, array $context = []): void {
		$this->log('emergency', $message, $context);
	}
	public function alert(string|\Stringable $message, array $context = []): void {
		$this->log('alert', $message, $context);
	}
	public function critical(string|\Stringable $message, array $context = []): void {
		$this->log('critical', $message, $context);
	}
	public function error(string|\Stringable $message, array $context = []): void {
		$this->log('error', $message, $context);
	}
	public function warning(string|\Stringable $message, array $context = []): void {
		$this->log('warning', $message, $context);
	}
	public function notice(string|\Stringable $message, array $context = []): void {
		$this->log('notice', $message, $context);
	}
	public function info(string|\Stringable $message, array $context = []): void {
		$this->log('info', $message, $context);
	}
	public function debug(string|\Stringable $message, array $context = []): void {
		$this->log('debug', $message, $context);
	}
	public function log($level, string|\Stringable $message, array $context = []): void {
		$this->lines[] = $level . ': ' . preg_replace_callback('/\{(\w+)\}/',
			fn (array $m): string => (string)($context[$m[1]] ?? $m[0]), (string)$message);
	}
	public function last(): string {
		return $this->lines === [] ? '' : $this->lines[array_key_last($this->lines)];
	}
}

/** Clock the test sets explicitly. */
class FakeTimeFactory implements OCP\AppFramework\Utility\ITimeFactory {
	public function __construct(public int $time = 1_800_000_000) {
	}
	public function getTime(): int {
		return $this->time;
	}
	public function now(): \DateTimeImmutable {
		return (new \DateTimeImmutable())->setTimestamp($this->time);
	}
	public function getDateTime(string $time = 'now', ?\DateTimeZone $timezone = null): \DateTime {
		return (new \DateTime())->setTimestamp($this->time);
	}
	public function withTimeZone(\DateTimeZone $timezone): static {
		return $this;
	}
	public function getTimeZone(?string $timezone = null): \DateTimeZone {
		return new \DateTimeZone($timezone ?? 'UTC');
	}
}

class FakeInput implements Symfony\Component\Console\Input\InputInterface {
	public function __construct(private array $options) {
	}
	public function getOption(string $name): mixed {
		return $this->options[$name] ?? false;
	}
}

/** Prints command output indented, without console markup. */
class FakeOutput implements Symfony\Component\Console\Output\OutputInterface {
	public function writeln(string|iterable $messages, int $options = 0): void {
		foreach (is_iterable($messages) ? $messages : [$messages] as $message) {
			echo '    | ' . preg_replace('#</?(info|comment|error)>#', '', (string)$message) . "\n";
		}
	}
}
