# Security policy

This app is a second factor for Nextcloud logins, so security reports are welcome and handled first.

## Reporting a vulnerability
Please report vulnerabilities **privately**:

1. Use GitHub's private reporting: **Security → Report a vulnerability** on
   https://github.com/R1sen18/twofactor_duo/security/advisories/new
2. If that isn't available, open an issue that only says you have a security report and asks for a
   private contact. Don't include any details.

Please include the app and Nextcloud versions, what an attacker can achieve, and the steps to reproduce.

## Supported versions
Only the latest release on the `main` branch gets security fixes.

## Scope
In scope: this app's code: the Duo flow, the callback, the `occ twofactor_duo:check` command and the
files shipped in this repository.

Out of scope, report these upstream instead:
- Nextcloud itself: https://hackerone.com/nextcloud
- Duo Security: https://duo.com/support/security-and-reliability
- Configuration of a particular Duo account (policies, bypass status, New User Policy)
