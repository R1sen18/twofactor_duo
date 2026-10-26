<?php

declare(strict_types=1);

/**
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * App-owned callback route. Duo's Universal Prompt redirects the browser back
 * here (GET) after authentication. The route lives under /apps/twofactor_duo/
 * so that NO Nextcloud core files need to be patched.
 */

return [
	'routes' => [
		['name' => 'callback#index', 'url' => '/callback', 'verb' => 'GET'],
	],
];
