<?php
// occ twofactor_duo:check against good and broken configurations.
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';

use OCA\TwoFactorDuo\Command\Check;

$good = [
	'twofactor_duo' => ['IKEY' => 'DIABCDEFGHIJKLMNOP12', 'SKEY' => str_repeat('s', 40),
		'HOST' => 'api-00000000.duosecurity.com', 'CALL' => 'https://cloud.example.com/apps/twofactor_duo/callback'],
	'overwrite.cli.url' => 'https://cloud.example.com/',
	'trusted_domains' => ['localhost', '*.example.com'],
];
$states = ['alice' => ['duo' => true, 'totp' => true], 'bob' => ['duo' => false], 'carol' => []];
$users = new FakeUserManager(['alice', 'bob', 'carol']);

function runCheck(array $config, array $options, FakeRegistry $registry, FakeUserManager $users): int {
	$command = new Check(new FakeConfig($config), $registry, $users);
	$exitCode = (new ReflectionMethod($command, 'execute'))->invoke($command, new FakeInput($options), new FakeOutput());
	echo "    exit=$exitCode\n";
	return $exitCode;
}

section('A: valid config, --offline, bob stored as disabled');
$registry = new FakeRegistry($states);
expect('exit 0 (warnings only)', runCheck($good, ['offline' => true], $registry, $users) === 0);
expect('states untouched', $registry->cleaned === []);

section('B: valid config, --offline --reset-states');
$registry = new FakeRegistry($states);
expect('exit 0', runCheck($good, ['offline' => true, 'reset-states' => true], $registry, $users) === 0);
expect('cleanUp(duo) called once', $registry->cleaned === ['duo']);

section('C: 1.x-style config (AKEY, https:// in HOST, old CALL, untrusted host), --reset-states');
$old = $good;
$old['twofactor_duo'] = ['IKEY' => 'DIABCDEFGHIJKLMNOP12', 'SKEY' => str_repeat('s', 40), 'AKEY' => str_repeat('a', 40),
	'HOST' => 'https://api-00000000.duosecurity.com', 'CALL' => 'https://nc.other.org/login/callback/duo'];
$registry = new FakeRegistry($states);
expect('exit 1', runCheck($old, ['offline' => true, 'reset-states' => true], $registry, $users) === 1);
expect('reset refused while errors remain', $registry->cleaned === []);

section('D: no configuration');
expect('exit 1', runCheck(['trusted_domains' => ['x']], ['offline' => true], new FakeRegistry([]), new FakeUserManager([])) === 1);

section('E: CALL without pretty URLs, http, custom port, no overwrite.cli.url');
$config = $good;
unset($config['overwrite.cli.url']);
$config['twofactor_duo']['CALL'] = 'http://cloud.example.com:8443/index.php/apps/twofactor_duo/callback';
$config['trusted_domains'] = ['cloud.example.com:8443'];
expect('exit 0 with warnings', runCheck($config, ['offline' => true], new FakeRegistry([]), $users) === 0);

section('F: USERNAME => email, all users have their own fixed address');
$config = $good;
$config['twofactor_duo']['USERNAME'] = 'email';
$fixed = new FakeUserManager([new FakeUser('alice', 'alice@example.com'), new FakeUser('bob', 'bob@example.com')]);
expect('exit 0', runCheck($config, ['offline' => true], new FakeRegistry([]), $fixed) === 0);

section('G: USERNAME => email, missing, editable and shared addresses, --reset-states');
$mixed = new FakeUserManager([new FakeUser('alice', 'alice@example.com'), new FakeUser('bob'),
	new FakeUser('carol', 'carol@example.com', true), new FakeUser('dave', 'alice@example.com')]);
$registry = new FakeRegistry($states);
expect('exit 1', runCheck($config, ['offline' => true, 'reset-states' => true], $registry, $mixed) === 1);
expect('reset refused while errors remain', $registry->cleaned === []);

section('H: USERNAME with an unknown value');
$config['twofactor_duo']['USERNAME'] = 'mail';
expect('exit 1', runCheck($config, ['offline' => true], new FakeRegistry([]), $users) === 1);

if (ONLINE) {
	section('I: real Duo health check with fake credentials');
	expect('exit 1 (Duo rejects the fake credentials)', runCheck($good, [], new FakeRegistry([]), $users) === 1);
}

finish();
