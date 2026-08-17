#!/usr/bin/env bash
# Idempotent Pi-side system setup. Safe to re-run.
set -euo pipefail

echo "[+] Updating apt index..."
sudo apt-get update -qq

echo "[+] Installing system packages..."
sudo apt-get install -y --no-install-recommends \
  python3-pip python3-venv python3-dev \
  bluez bluez-tools libbluetooth-dev \
  rtl-sdr librtlsdr-dev rtl-433 \
  sqlite3 \
  build-essential pkg-config \
  rsync git curl iw network-manager dnsmasq-base openssl nginx

echo "[+] Ensuring core services are enabled at boot..."
# bluetooth + NetworkManager are dependencies of watchtower.service.
sudo systemctl enable bluetooth.service NetworkManager.service ssh.service 2>&1 | tail -3 || true

echo "[+] Adding 'admin' to bluetooth group (requires re-login to take effect)..."
sudo usermod -aG bluetooth admin || true

echo "[+] Installing bt-hci1-up unit (auto-up for an optional USB BT adapter)..."
# Idempotent: only installs if the unit file is missing or has changed.
# The unit no-ops on systems without an hci1 device, so it's safe to enable
# unconditionally.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "$SCRIPT_DIR/bt-hci1-up.service" ]; then
  sudo install -m 644 "$SCRIPT_DIR/bt-hci1-up.service" /etc/systemd/system/bt-hci1-up.service
  sudo systemctl daemon-reload
  sudo systemctl enable bt-hci1-up.service 2>&1 | tail -1 || true
fi

echo "[+] Blacklisting kernel DVB driver (else rtl-sdr can't claim USB)..."
sudo tee /etc/modprobe.d/blacklist-rtl.conf >/dev/null <<'EOF'
blacklist dvb_usb_rtl28xxu
blacklist rtl2832
blacklist rtl2830
EOF

echo "[+] Installing rtl-sdr udev rules so non-root users can use the dongles..."
sudo tee /etc/udev/rules.d/20-rtlsdr.rules >/dev/null <<'EOF'
SUBSYSTEM=="usb", ATTRS{idVendor}=="0bda", ATTRS{idProduct}=="2838", GROUP="plugdev", MODE="0666"
EOF
sudo udevadm control --reload-rules
sudo udevadm trigger

echo "[+] Creating /var/lib/watchtower and /etc/watchtower owned by admin..."
sudo install -d -o admin -g admin -m 0755 /var/lib/watchtower
sudo install -d -o admin -g admin -m 0755 /etc/watchtower
sudo install -d -o admin -g admin -m 0755 /var/log/watchtower

echo "[+] Adding /usr/sbin and ~/.local/bin to admin's interactive PATH..."
# `iw` lives in /usr/sbin which Debian doesn't put on non-root users' PATH by default;
# `uv` is installed at ~/.local/bin via the astral installer.
sudo tee /etc/profile.d/watchtower-admin-path.sh >/dev/null <<'EOF'
# Watchtower: ensure admin has iw + uv on interactive PATH
if [ "$(id -un)" = "admin" ]; then
    case ":$PATH:" in
        *":/usr/sbin:"*) :;;
        *) PATH="/usr/sbin:$PATH";;
    esac
    case ":$PATH:" in
        *":$HOME/.local/bin:"*) :;;
        *) PATH="$HOME/.local/bin:$PATH";;
    esac
    export PATH
fi
EOF
sudo chmod 0644 /etc/profile.d/watchtower-admin-path.sh

echo "[+] Installing durable Wi-Fi recovery..."
if [ -f "$SCRIPT_DIR/install-wifi-recovery.sh" ]; then
  bash "$SCRIPT_DIR/install-wifi-recovery.sh"
fi

echo "[+] Installing private HTTPS endpoint..."
if [ -f "$SCRIPT_DIR/install-https.sh" ] && [ -f /etc/watchtower/watchtower.toml ]; then
  bash "$SCRIPT_DIR/install-https.sh"
fi

echo "[+] Done. Verify with: rtl_test -t (must reload modules / reboot if blacklist was new)"
