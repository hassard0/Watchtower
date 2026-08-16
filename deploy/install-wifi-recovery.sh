#!/usr/bin/env bash
# Install durable NetworkManager recovery and migrate Raspberry Pi Imager's
# first-boot Wi-Fi configuration when no saved Wi-Fi profile exists.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RECONNECT_SCRIPT="$SCRIPT_DIR/watchtower-wifi-reconnect.sh"
RECONNECT_SERVICE="$SCRIPT_DIR/watchtower-wifi-reconnect.service"
RECONNECT_TIMER="$SCRIPT_DIR/watchtower-wifi-reconnect.timer"
CONFIG_HELPER="$SCRIPT_DIR/watchtower-wifi-config"
CONFIG_SERVICE="$SCRIPT_DIR/watchtower-wifi-config.service"
CONFIG_PATH="$SCRIPT_DIR/watchtower-wifi-config.path"
TMPFILES_CONFIG="$SCRIPT_DIR/watchtower-wifi.conf"

sudo install -m 0755 "$RECONNECT_SCRIPT" /usr/local/sbin/watchtower-wifi-reconnect
sudo install -m 0644 "$RECONNECT_SERVICE" /etc/systemd/system/watchtower-wifi-reconnect.service
sudo install -m 0644 "$RECONNECT_TIMER" /etc/systemd/system/watchtower-wifi-reconnect.timer
sudo install -m 0755 "$CONFIG_HELPER" /usr/local/sbin/watchtower-wifi-config
sudo install -m 0644 "$CONFIG_SERVICE" /etc/systemd/system/watchtower-wifi-config.service
sudo install -m 0644 "$CONFIG_PATH" /etc/systemd/system/watchtower-wifi-config.path
sudo install -m 0644 "$TMPFILES_CONFIG" /etc/tmpfiles.d/watchtower-wifi.conf

sudo install -d -o admin -g admin -m 0755 /etc/watchtower
if [ ! -s /etc/watchtower/wifi-admin.token ]; then
    sudo sh -c 'umask 077; openssl rand -hex 24 > /etc/watchtower/wifi-admin.token'
fi
sudo chown admin:admin /etc/watchtower/wifi-admin.token
sudo chmod 0600 /etc/watchtower/wifi-admin.token
sudo systemd-tmpfiles --create /etc/tmpfiles.d/watchtower-wifi.conf

# Debian's renderer-only netplan file may be shipped world-readable, which
# makes every boot emit warnings even though it contains no credentials.
if [ -f /lib/netplan/00-network-manager-all.yaml ]; then
    sudo chmod 0600 /lib/netplan/00-network-manager-all.yaml
fi

# Raspberry Pi Imager leaves the requested network in this cloud-init file.
# On some Debian/Pi images it is not carried into NetworkManager. Preserve it
# as root-only netplan input so credentials never enter this repository.
if ! nmcli -t -f TYPE connection show 2>/dev/null | grep -Eq '^(wifi|802-11-wireless)$'; then
    if [ -f /boot/firmware/network-config ] && grep -q '^[[:space:]]*wifis:' /boot/firmware/network-config; then
        echo "[+] Migrating Raspberry Pi Imager Wi-Fi configuration into netplan..."
        sudo install -m 0600 /boot/firmware/network-config /etc/netplan/60-watchtower-wifi.yaml
        sudo netplan generate
        sudo nmcli connection reload
    else
        echo "[!] No saved Wi-Fi profile or Raspberry Pi Imager Wi-Fi configuration found."
    fi
fi

sudo systemctl daemon-reload
sudo systemctl enable --now watchtower-wifi-reconnect.timer
sudo systemctl enable --now watchtower-wifi-config.path
sudo systemctl start watchtower-wifi-reconnect.service
