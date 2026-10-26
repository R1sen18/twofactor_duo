# Duo Universal Prompt 2FA for Nextcloud

Two-factor authentication with the [Duo Universal Prompt](https://duo.com/docs/universal-prompt-update-guide) (Duo Web SDK v4) for Nextcloud 32–35.

This is a reworked fork of [tilyanPristka/twofactor_duo](https://github.com/tilyanPristka/twofactor_duo). Version 2.0 works on current Nextcloud releases **without patching any Nextcloud core files**.

| | |
|---|---|
| Nextcloud | 32 – 35 |
| PHP | 8.1+ (tested with 8.4) |
| Core patches | none |

## Installation
1. Copy this repository to `nextcloud/apps/twofactor_duo` (or to a custom apps directory). The folder name must be `twofactor_duo`.
   ```bash
   cd /var/www/nextcloud/apps
   git clone <this-repo-url> twofactor_duo
   chown -R www-data:www-data twofactor_duo
   ```
2. Add the configuration below to `config/config.php`.
3. Enable the app:
   ```bash
   sudo -u www-data php occ app:enable twofactor_duo
   ```

## Configuration
In the [Duo Admin Panel](https://admin.duosecurity.com), protect a new **Web SDK** application and copy its Client ID, Client secret and API hostname.

```php
'twofactor_duo' => [
    'IKEY' => 'Client ID',
    'SKEY' => 'Client secret',
    'HOST' => 'api-xxxxxxxx.duosecurity.com',
    'CALL' => 'https://cloud.example.com/apps/twofactor_duo/callback',
  ],
```

- `CALL` is where Duo sends the browser back to. Use your Nextcloud base URL followed by `/apps/twofactor_duo/callback`.
  If Nextcloud runs without pretty URLs, use `https://cloud.example.com/index.php/apps/twofactor_duo/callback` instead.
- Once all four values are set, the provider is active for **every user**. If any value is missing, the provider stays disabled.
- Keep the Client secret out of version control. `config.php` is the right place for it.

## How it works
1. After the password step, the challenge page sends the browser to the Duo Universal Prompt. It stores a random OAuth `state` in the session first.
2. Duo redirects back to `/apps/twofactor_duo/callback`. The app owns this route, so core doesn't need patching. The callback:
   - checks that `state` matches the session,
   - exchanges `duo_code` for an id_token at Duo's token endpoint (TLS is verified against the bundled `lib/duo_certs.pem`),
   - validates the token's HS512 signature, expiry, audience and `preferred_username` against the user who is waiting for 2FA.
3. The callback page submits Nextcloud's regular `/login/challenge/duo` form. Core then calls `verifyChallenge()`, which reads the result from the session and finishes the login.

Nextcloud's brute-force protection and rate limits on the challenge endpoint still apply.

## Upgrading from 1.x
- Change `CALL` from `…/login/callback/duo` to `…/apps/twofactor_duo/callback`.
- Remove the 1.x edits to `core/routes.php`, `IProvider.php`, `Manager.php` and `BackupCodesProvider.php`. Reinstalling or upgrading Nextcloud restores the original files. On Nextcloud 32+, those patches no longer apply anyway.

## Changes compared to 1.x
- **No core patches.** An app-owned callback route replaces the edits to core routes and type hints.
- **Nextcloud 32+ APIs:** uses `ITemplateManager` / `ITemplate` instead of the deprecated `OCP\Template`.
- **JWT validation fix:** 1.x ran plain `base64_decode()` on base64url segments. That dropped `-` and `_` characters, so genuine Duo tokens were rejected. The signature is now computed over the segments exactly as received and compared in constant time. `alg` must be `HS512`.
- **Leeway fix:** 1.x rejected tokens during their last 60 seconds of validity. They are now accepted until 60 seconds after `exp`.
- **OAuth `state` is now checked.** 1.x ignored it.
- **Fails closed:** network errors and incomplete Duo responses now reject the login instead of throwing PHP errors.
- The certificate bundle is found by absolute path, so the app works from custom app directories.
- The Duo redirect works without inline scripts, so Nextcloud's default CSP stays intact.

## Development
```bash
find . -name '*.php' -not -path './.git/*' -exec php -l {} \;
```

## Credits and licence
Original app by Muhammad Ardyansyah / [tilyanPristka](https://github.com/tilyanPristka) (see [AUTHORS.md](AUTHORS.md)).
Licensed under the GNU AGPL v3 (see [LICENSE](LICENSE)).
