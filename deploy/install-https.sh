#!/usr/bin/env bash
# Install Watchtower's private CA, TLS certificate refresh, and nginx proxy.
# Idempotent and safe to re-run during upgrades.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_CONFIG=/etc/watchtower/watchtower.toml

echo "[+] Installing private HTTPS endpoint..."

# Free port 80 before nginx's package post-install attempts to start it.
watchtower_was_active=false
if systemctl is-active --quiet watchtower.service 2>/dev/null; then
  watchtower_was_active=true
  if ! sudo systemctl stop watchtower.service; then
    echo "Watchtower required systemd's forced stop; continuing the controlled HTTPS transition" >&2
  fi
fi

if ! command -v nginx >/dev/null 2>&1; then
  sudo apt-get update -qq
  sudo apt-get install -y --no-install-recommends nginx openssl
fi

sudo install -o root -g root -m 0755 \
  "$SCRIPT_DIR/watchtower-cert-refresh.sh" /usr/local/sbin/watchtower-cert-refresh
sudo install -o root -g root -m 0644 \
  "$SCRIPT_DIR/watchtower-cert-refresh.service" /etc/systemd/system/watchtower-cert-refresh.service
sudo install -o root -g root -m 0644 \
  "$SCRIPT_DIR/watchtower-cert-refresh.timer" /etc/systemd/system/watchtower-cert-refresh.timer
sudo /usr/local/sbin/watchtower-cert-refresh

sudo install -o root -g root -m 0644 \
  "$SCRIPT_DIR/watchtower-nginx.conf" /etc/nginx/sites-available/watchtower
sudo ln -sfn /etc/nginx/sites-available/watchtower /etc/nginx/sites-enabled/watchtower
sudo rm -f /etc/nginx/sites-enabled/default

if [ ! -f "$APP_CONFIG" ]; then
  echo "Watchtower config is missing: $APP_CONFIG" >&2
  exit 1
fi
if [ ! -f "$APP_CONFIG.pre-https" ]; then
  sudo cp -a "$APP_CONFIG" "$APP_CONFIG.pre-https"
fi

# Keep the unencrypted application socket private; nginx is the only LAN
# listener. Upgrade old configs that relied on ApiCfg defaults as well as
# configs that already have an explicit [api] section.
if grep -q '^\[api\]' "$APP_CONFIG"; then
  sudo sed -i '/^\[api\]/,/^\[/ {
    s/^host[[:space:]]*=.*/host = "127.0.0.1"/
    s/^port[[:space:]]*=.*/port = 8080/
  }' "$APP_CONFIG"
else
  printf '\n[api]\nhost = "127.0.0.1"\nport = 8080\n' | sudo tee -a "$APP_CONFIG" >/dev/null
fi

sudo nginx -t
sudo systemctl daemon-reload
sudo systemctl enable watchtower-cert-refresh.timer nginx.service >/dev/null

# Start Watchtower even if it was inactive: a completed deploy should always
# leave both halves of the endpoint available.
if systemctl cat watchtower.service >/dev/null 2>&1; then
  sudo systemctl start watchtower.service
elif [ "$watchtower_was_active" = true ]; then
  echo "watchtower.service disappeared during HTTPS installation" >&2
  exit 1
fi
sudo systemctl restart nginx.service
sudo systemctl start watchtower-cert-refresh.timer

echo "[+] HTTPS ready. Trust http://watchtower.local/watchtower-ca.crt once, then use https://watchtower.local/"
