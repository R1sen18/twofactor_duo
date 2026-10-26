<?php
// Runs every tests/*_test.php in its own PHP process.
// Usage: php tests/run.php [--online]
//   --online  also run the checks that call Duo's real API with fake credentials
declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
	http_response_code(404);
	exit;
}

$args =implode(' ', array_map('escapeshellarg', array_slice($argv, 1)));
$failed = [];

foreach (glob(__DIR__ . '/*_test.php') as $test) {
	echo '### ' . basename($test) . "\n";
	passthru(escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg($test) . ($args !== '' ? " $args" : ''), $exitCode);
	if ($exitCode !== 0) {
		$failed[] = basename($test);
	}
	echo "\n";
}

echo $failed === [] ? "All test files passed.\n" : 'FAILED: ' . implode(', ', $failed) . "\n";
exit($failed === [] ? 0 : 1);
