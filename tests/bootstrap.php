<?php
// Shared setup for the test files: Nextcloud stand-ins, fakes, autoloader and assertions.
declare(strict_types=1);

// The app is deployed as a git clone, so this folder is reachable under /apps/twofactor_duo/tests/.
if (PHP_SAPI !== 'cli') {
	http_response_code(404);
	exit;
}

require __DIR__ . '/stubs.php';
require __DIR__ . '/fakes.php';

spl_autoload_register(function (string $class): void {
	$prefix = 'OCA\\TwoFactorDuo\\';
	if (str_starts_with($class, $prefix)) {
		require dirname(__DIR__) . '/lib/' . str_replace('\\', '/', substr($class, strlen($prefix))) . '.php';
	}
});

// Any warning, notice or deprecation fails the run, so PHP upgrades surface here first.
error_reporting(E_ALL);
set_error_handler(function (int $errno, string $message, string $file, int $line): never {
	throw new ErrorException($message, 0, $errno, $file, $line);
});

/** Tests that call Duo's real API (with fake credentials) only run with --online. */
define('ONLINE', in_array('--online', $_SERVER['argv'] ?? [], true));

$GLOBALS['failures'] = 0;

function section(string $title): void {
	echo "\n== $title ==\n";
}

function expect(string $name, bool $condition, string $details = ''): void {
	if (!$condition) {
		$GLOBALS['failures']++;
	}
	echo ($condition ? '  [PASS] ' : '  [FAIL] ') . $name . ($condition || $details === '' ? '' : "  -- $details") . "\n";
}

function finish(): never {
	$failures = $GLOBALS['failures'];
	echo $failures ? "\n$failures check(s) FAILED\n" : "\nall checks passed\n";
	exit($failures ? 1 : 0);
}
