#!/usr/bin/env bash
# Reconnect wlan0 to any saved NetworkManager Wi-Fi profile.
# Intended to run from watchtower-wifi-reconnect.timer.
set -u

IFACE="${WATCHTOWER_WIFI_IFACE:-wlan0}"

log() {
    echo "watchtower-wifi: $*"
}

if ! command -v nmcli >/dev/null 2>&1; then
    log "NetworkManager CLI is not installed"
    exit 0
fi

if [ ! -e "/sys/class/net/$IFACE" ]; then
    log "interface $IFACE is not present"
    exit 0
fi

rfkill unblock wifi >/dev/null 2>&1 || true
nmcli radio wifi on >/dev/null 2>&1 || true
nmcli device set "$IFACE" managed yes >/dev/null 2>&1 || true

connection="$(nmcli -g GENERAL.CONNECTION device show "$IFACE" 2>/dev/null || true)"
if [ -n "$connection" ] && [ "$connection" != "--" ]; then
    exit 0
fi

nmcli device wifi rescan ifname "$IFACE" >/dev/null 2>&1 || true

profiles=()
while IFS=: read -r uuid type; do
    case "$type" in
        wifi|802-11-wireless) profiles+=("$uuid") ;;
    esac
done < <(nmcli -t -f UUID,TYPE connection show 2>/dev/null)

if [ "${#profiles[@]}" -eq 0 ]; then
    log "no saved Wi-Fi profiles; add one with nmcli or rerun deploy/install-wifi-recovery.sh"
    exit 0
fi

for uuid in "${profiles[@]}"; do
    name="$(nmcli -g connection.id connection show uuid "$uuid" 2>/dev/null || echo "$uuid")"
    # Zero means retry forever in NetworkManager. Disabling Wi-Fi power save
    # avoids a common source of long-idle Raspberry Pi disconnects.
    nmcli connection modify uuid "$uuid" \
        connection.autoconnect yes \
        connection.autoconnect-retries 0 \
        802-11-wireless.powersave 2 >/dev/null 2>&1 || true
    log "attempting saved profile $name"
    if nmcli --wait 25 connection up uuid "$uuid" ifname "$IFACE" >/dev/null 2>&1; then
        log "connected $IFACE using $name"
        exit 0
    fi
done

log "no saved Wi-Fi profile connected; timer will retry"
exit 0
