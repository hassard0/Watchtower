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
  rsync git curl

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

echo "[+] Done. Verify with: rtl_test -t (must reload modules / reboot if blacklist was new)"
