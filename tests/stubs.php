<?php
// Minimal stand-ins for the Nextcloud (OCP), Symfony Console and PSR-3 APIs the app uses,
// so the tests run without a Nextcloud installation.
//
// Keep every signature identical to nextcloud/server stable35. A stand-in that still had a
// method Nextcloud had removed (ContentSecurityPolicy::addAllowedChildSrcDomain) once let the
// tests pass while the challenge page crashed on a real server.
declare(strict_types=1);

namespace {
	// The app is deployed as a git clone, so this file is reachable over HTTP.
	if (PHP_SAPI !== 'cli') {
		http_response_code(404);
		exit;
	}
}

namespace Psr\Log {
	interface LoggerInterface {
		public function emergency(string|\Stringable $message, array $context = []): void;
		public function alert(string|\Stringable $message, array $context = []): void;
		public function critical(string|\Stringable $message, array $context = []): void;
		public function error(string|\Stringable $message, array $context = []): void;
		public function warning(string|\Stringable $message, array $context = []): void;
		public function notice(string|\Stringable $message, array $context = []): void;
		public function info(string|\Stringable $message, array $context = []): void;
		public function debug(string|\Stringable $message, array $context = []): void;
		public function log($level, string|\Stringable $message, array $context = []): void;
	}
}

namespace Psr\Clock {
	interface ClockInterface {
		public function now(): \DateTimeImmutable;
	}
}

namespace Symfony\Component\Console\Input {
	interface InputInterface {
		public function getOption(string $name): mixed;
	}
	class InputOption {
		public const VALUE_NONE = 1;
	}
}

namespace Symfony\Component\Console\Output {
	interface OutputInterface {
		public function writeln(string|iterable $messages, int $options = 0): void;
	}
}

namespace Symfony\Component\Console\Command {
	class Command {
		public const SUCCESS = 0;
		public const FAILURE = 1;
		private ?string $name = null;
		public function __construct(?string $name = null) {
			$this->configure();
		}
		protected function configure(): void {
		}
		public function setName(string $name): static {
			$this->name = $name;
			return $this;
		}
		public function getName(): ?string {
			return $this->name;
		}
		public function setDescription(string $description): static {
			return $this;
		}
		public function addOption(string $name, string|array|null $shortcut = null, ?int $mode = null, string $description = '', mixed $default = null): static {
			return $this;
		}
	}
}

namespace OCP {
	interface IUser {
		public function getUID(): string;
	}
	interface IConfig {
		public function getSystemValue($key, $default = '');
	}
	interface ISession {
		public function set(string $key, $value);
		public function get(string $key);
		public function remove(string $key);
	}
	interface IUserManager {
		public function callForSeenUsers(\Closure $callback);
	}
	interface IRequest {
		public function getParam(string $key, $default = null);
	}
	interface IURLGenerator {
		public function linkToRoute(string $routeName, array $arguments = []): string;
	}
	class Util {
		/** Scripts queued with addScript(), for assertions. */
		public static array $scripts = [];
		public static function addScript(string $application, ?string $file = null, string $afterAppId = 'core', bool $prepend = false): void {
			self::$scripts[] = "$application/$file";
		}
	}
}

namespace OCP\Template {
	interface ITemplate {
		public function fetchPage(?array $additionalParams = null): string;
		public function printPage(): void;
		public function assign(string $key, mixed $value): void;
		public function append(string $key, mixed $value): void;
	}
	interface ITemplateManager {
		public function getTemplate(string $app, string $name, string $renderAs = '', bool $registerCall = true): ITemplate;
	}
}

namespace OCP\AppFramework\Utility {
	interface ITimeFactory extends \Psr\Clock\ClockInterface {
		public function getTime(): int;
		public function getDateTime(string $time = 'now', ?\DateTimeZone $timezone = null): \DateTime;
		public function withTimeZone(\DateTimeZone $timezone): static;
		public function getTimeZone(?string $timezone = null): \DateTimeZone;
	}
}

namespace OCP\AppFramework\Http {
	abstract class Response {
	}
	class RedirectResponse extends Response {
		public function __construct(private string $redirectURL, public int $status = 303, public array $headers = []) {
		}
		public function getRedirectURL(): string {
			return $this->redirectURL;
		}
	}
	class TemplateResponse extends Response {
		public const RENDER_AS_GUEST = 'guest';
		public const RENDER_AS_BLANK = '';
		public const RENDER_AS_BASE = 'base';
		public const RENDER_AS_USER = 'user';
		public const RENDER_AS_ERROR = 'error';
		public const RENDER_AS_PUBLIC = 'public';
		public function __construct(
			public string $appName,
			public string $templateName,
			public array $params = [],
			public string $renderAs = self::RENDER_AS_USER,
			public int $status = 200,
			public array $headers = [],
		) {
		}
	}
}

namespace OCP\AppFramework\Http\Attribute {
	#[\Attribute(\Attribute::TARGET_METHOD)] class PublicPage {}
	#[\Attribute(\Attribute::TARGET_METHOD)] class NoCSRFRequired {}
	#[\Attribute(\Attribute::TARGET_METHOD)] class UseSession {}
	#[\Attribute(\Attribute::TARGET_METHOD)] class NoTwoFactorRequired {}
	abstract class ARateLimit {
		public function __construct(protected int $limit, protected int $period) {
		}
		public function getLimit(): int {
			return $this->limit;
		}
		public function getPeriod(): int {
			return $this->period;
		}
	}
	#[\Attribute(\Attribute::TARGET_METHOD)] class AnonRateLimit extends ARateLimit {}
	#[\Attribute(\Attribute::TARGET_METHOD)] class UserRateLimit extends ARateLimit {}
}

namespace OCP\AppFramework {
	abstract class Controller {
		public function __construct(protected string $appName, protected \OCP\IRequest $request) {
		}
	}
}

namespace OCP\Authentication\TwoFactorAuth {
	use OCP\IUser;
	use OCP\Template\ITemplate;

	interface IProvider {
		public function getId(): string;
		public function getDisplayName(): string;
		public function getDescription(): string;
		public function getTemplate(IUser $user): ITemplate;
		public function verifyChallenge(IUser $user, string $challenge): bool;
		public function isTwoFactorAuthEnabledForUser(IUser $user): bool;
	}
	interface IRegistry {
		public function getProviderStates(IUser $user): array;
		public function enableProviderFor(IProvider $provider, IUser $user);
		public function disableProviderFor(IProvider $provider, IUser $user);
		public function cleanUp(string $providerId);
	}
}
