#!/usr/bin/env bash
# Deploy Watchtower to the Pi from the Windows host.
# Usage: ./deploy/deploy.sh [hostname]
set -euo pipefail

HOST="${1:-watchtower.local}"
USER_=admin
APP_DIR=/opt/watchtower
SVC=watchtower.service

echo "[+] rsync source -> $HOST:$APP_DIR"
ssh "$USER_@$HOST" "sudo install -d -o $USER_ -g $USER_ $APP_DIR"
rsync -az --delete \
  --exclude '.venv' --exclude '__pycache__' --exclude '.pytest_cache' \
  --exclude '*.db' --exclude '.git' \
  ./ "$USER_@$HOST:$APP_DIR/"

echo "[+] (re)creating venv and installing project"
ssh "$USER_@$HOST" "cd $APP_DIR && \
  if ! command -v uv >/dev/null 2>&1; then \
    curl -LsSf https://astral.sh/uv/install.sh | sh; \
    export PATH=\"\$HOME/.local/bin:\$PATH\"; \
  fi; \
  uv venv && uv sync --frozen 2>/dev/null || uv sync"

echo "[+] installing config (only if not already present)"
ssh "$USER_@$HOST" "test -f /etc/watchtower/watchtower.toml || \
  sudo cp $APP_DIR/config/watchtower.example.toml /etc/watchtower/watchtower.toml; \
  sudo chown $USER_:$USER_ /etc/watchtower/watchtower.toml"

echo "[+] installing systemd units"
ssh "$USER_@$HOST" "sudo cp $APP_DIR/deploy/$SVC /etc/systemd/system/$SVC && \
  if [ -f $APP_DIR/deploy/bt-hci1-up.service ]; then \
    sudo cp $APP_DIR/deploy/bt-hci1-up.service /etc/systemd/system/bt-hci1-up.service; \
    sudo systemctl enable bt-hci1-up.service 2>&1 | tail -1 || true; \
  fi; \
  sudo systemctl daemon-reload && \
  sudo systemctl enable $SVC"

echo "[+] (re)starting service"
ssh "$USER_@$HOST" "sudo systemctl restart $SVC"
sleep 3
ssh "$USER_@$HOST" "systemctl is-active $SVC && \
  sudo journalctl -u $SVC -n 30 --no-pager"

echo "[+] deployed."
