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
  rsync git curl iw

echo "[+] Ensuring core services are enabled at boot..."
# bluetooth + NetworkManager are dependencies of watchtower.service.
sudo systemctl enable bluetooth.service NetworkManager.service ssh.service 2>&1 | tail -3 || true

echo "[+] Adding 'admin' to bluetooth group (requires re-login to take effect)..."
sudo usermod -aG bluetooth admin || true

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

echo "[+] Done. Verify with: rtl_test -t (must reload modules / reboot if blacklist was new)"
