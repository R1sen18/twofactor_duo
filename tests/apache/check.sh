#!/usr/bin/env bash
# Checks the app's .htaccess with a real Apache in front of Nextcloud's own .htaccess (stable35),
# with and without pretty URLs, laid out like a server that runs the app as a git clone:
#   - .git, .github and tests must not be readable over HTTP,
#   - the app's assets and Nextcloud's front controller (/apps/twofactor_duo/callback) must still work.
# Needs root (sudo) and apache2; meant for CI (GitHub's Ubuntu runners ship Apache).
set -euo pipefail

APP_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
PORT=8089
BASE="http://127.0.0.1:$PORT"
ROOT="$(mktemp -d)"
FAILURES=0

# --- web root that looks like a Nextcloud install -------------------------------------------
mkdir -p "$ROOT/apps"
cp -a "$APP_DIR" "$ROOT/apps/twofactor_duo"
# Stand-in for Nextcloud's index.php; Apache has no PHP here, so it's served as text.
echo 'FRONT-CONTROLLER' > "$ROOT/index.php"
curl -fsSL https://raw.githubusercontent.com/nextcloud/server/stable35/.htaccess > "$ROOT/htaccess.base"
# The section `occ maintenance:update:htaccess` appends when htaccess.RewriteBase is "/".
cat > "$ROOT/htaccess.pretty" <<'EOF'
#### DO NOT CHANGE ANYTHING ABOVE THIS LINE ####
ErrorDocument 403 /index.php/error/403
ErrorDocument 404 /index.php/error/404
<IfModule mod_rewrite.c>
  Options -MultiViews
  RewriteRule ^core/js/oc.js$ index.php [PT,E=PATH_INFO:$1]
  RewriteRule ^core/preview.png$ index.php [PT,E=PATH_INFO:$1]
  RewriteCond %{REQUEST_FILENAME} !\.(css|js|mjs|svg|gif|ico|jpg|jpeg|png|webp|html|otf|ttf|woff2?|map|webm|mp4|mp3|ogg|wav|flac|wasm|tflite)$
  RewriteCond %{REQUEST_FILENAME} !/core/ajax/update\.php
  RewriteCond %{REQUEST_FILENAME} !/core/img/(favicon\.ico|manifest\.json)$
  RewriteCond %{REQUEST_FILENAME} !/(cron|public|remote|status)\.php
  RewriteCond %{REQUEST_FILENAME} !/ocs/v(1|2)\.php
  RewriteCond %{REQUEST_FILENAME} !/robots\.txt
  RewriteCond %{REQUEST_FILENAME} !/(ocs-provider|updater)/
  RewriteCond %{REQUEST_URI} !^/\.well-known/(acme-challenge|pki-validation)/.*
  RewriteCond %{REQUEST_FILENAME} !/richdocumentscode(_arm64)?/proxy.php$
  RewriteRule . index.php [PT,E=PATH_INFO:$1]
  RewriteBase /
  <IfModule mod_env.c>
    SetEnv front_controller_active true
    <IfModule mod_dir.c>
      DirectorySlash off
    </IfModule>
  </IfModule>
</IfModule>
EOF
chmod -R a+rX "$ROOT"

# --- Apache -------------------------------------------------------------------------------
command -v apache2ctl >/dev/null || { sudo apt-get update -qq && sudo apt-get install -y -qq apache2 >/dev/null; }
sudo a2enmod -q rewrite headers env dir mime alias setenvif >/dev/null
sudo tee /etc/apache2/sites-available/nc-test.conf >/dev/null <<EOF
Listen $PORT
<VirtualHost *:$PORT>
  DocumentRoot $ROOT
  <Directory $ROOT>
    Options FollowSymLinks
    AllowOverride All
    Require all granted
  </Directory>
</VirtualHost>
EOF
sudo a2ensite -q nc-test >/dev/null
sudo apache2ctl configtest
sudo systemctl restart apache2

# --- checks ---------------------------------------------------------------------------------
# blocked PATH TEXT: the response must not contain TEXT, which only the real file contains.
blocked() {
  local body code
  body="$(curl -s -o - -w '\n%{http_code}' "$BASE$1")"; code="${body##*$'\n'}"
  if grep -qF -- "$2" <<<"$body"; then
    echo "  [FAIL] $1 is readable (HTTP $code)"; FAILURES=$((FAILURES + 1))
  else
    echo "  [PASS] $1 not readable (HTTP $code)"
  fi
}
# served PATH TEXT: the response must contain TEXT.
served() {
  local body code
  body="$(curl -s -o - -w '\n%{http_code}' "$BASE$1")"; code="${body##*$'\n'}"
  if grep -qF -- "$2" <<<"$body"; then
    echo "  [PASS] $1 works (HTTP $code)"
  else
    echo "  [FAIL] $1 broken (HTTP $code)"; FAILURES=$((FAILURES + 1))
  fi
}
check_protected_paths() {
  blocked /apps/twofactor_duo/.git/config '[core]'
  blocked /apps/twofactor_duo/.git/HEAD 'ref: refs/'
  blocked /apps/twofactor_duo/.github/workflows/tests.yml 'runs-on:'
  blocked /apps/twofactor_duo/tests/run.php 'passthru('
  blocked /apps/twofactor_duo/tests/apache/check.sh 'FAILURES'
  served /apps/twofactor_duo/js/challenge.js 'DOMContentLoaded'
}

echo "== Nextcloud without pretty URLs =="
cp "$ROOT/htaccess.base" "$ROOT/.htaccess"
check_protected_paths

echo "== Nextcloud with pretty URLs (front controller) =="
cat "$ROOT/htaccess.base" "$ROOT/htaccess.pretty" > "$ROOT/.htaccess"
check_protected_paths
served '/apps/twofactor_duo/callback?state=x&duo_code=y' 'FRONT-CONTROLLER'

echo "== Control: without the app's .htaccess, .git is exposed (so the checks above mean something) =="
cp "$ROOT/htaccess.base" "$ROOT/.htaccess"
rm "$ROOT/apps/twofactor_duo/.htaccess"
if curl -s "$BASE/apps/twofactor_duo/.git/config" | grep -qF '[core]'; then
  echo "  [PASS] .git/config readable without the app's .htaccess"
else
  echo "  [FAIL] control: .git/config not readable even without the app's .htaccess"; FAILURES=$((FAILURES + 1))
fi

echo
if [ "$FAILURES" -gt 0 ]; then echo "$FAILURES check(s) FAILED"; exit 1; fi
echo "all checks passed"
