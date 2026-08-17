#!/usr/bin/env bash
# Reconnect wlan0 to saved client profiles, or expose a recovery hotspot.
# Intended to run from watchtower-wifi-reconnect.timer.
set -u

IFACE="${WATCHTOWER_WIFI_IFACE:-wlan0}"
AP_NAME="${WATCHTOWER_AP_NAME:-Watchtower Setup}"
AP_SSID="${WATCHTOWER_AP_SSID:-Watchtower}"
AP_ADDRESS="${WATCHTOWER_AP_ADDRESS:-10.42.0.1/24}"
CLIENT_RETRY_SEC="${WATCHTOWER_CLIENT_RETRY_SEC:-300}"
STATE_DIR="/run/watchtower-wifi-recovery"
LAST_RETRY="$STATE_DIR/last-client-retry"
SCAN_CACHE="/run/watchtower-wifi/scan-cache.txt"

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
if [ -n "$connection" ] && [ "$connection" != "--" ] && [ "$connection" != "$AP_NAME" ]; then
    exit 0
fi

mkdir -p "$STATE_DIR"
if [ "$connection" = "$AP_NAME" ] && [ -e "$LAST_RETRY" ]; then
    now="$(date +%s)"
    last="$(cat "$LAST_RETRY" 2>/dev/null || echo 0)"
    case "$last" in (*[!0-9]*|'') last=0 ;; esac
    if [ $((now - last)) -lt "$CLIENT_RETRY_SEC" ]; then
        exit 0
    fi
fi

# A single radio cannot remain an AP while it scans/joins infrastructure
# networks. Every few minutes, briefly drop recovery mode and retry clients.
if [ "$connection" = "$AP_NAME" ]; then
    log "pausing recovery hotspot to retry saved networks"
    nmcli --wait 10 connection down id "$AP_NAME" >/dev/null 2>&1 || true
fi
date +%s > "$LAST_RETRY"

nmcli device wifi rescan ifname "$IFACE" >/dev/null 2>&1 || true

# A single radio generally cannot scan other channels while remaining an AP.
# Preserve the fresh infrastructure scan for the recovery GUI, then refresh
# it again on every periodic client retry.
mkdir -p "$(dirname "$SCAN_CACHE")"
scan_temp="${SCAN_CACHE}.tmp"
if nmcli -t --escape yes -f IN-USE,SSID,SIGNAL,SECURITY,FREQ,CHAN \
        device wifi list ifname "$IFACE" --rescan no > "$scan_temp" 2>/dev/null; then
    chown admin:admin "$scan_temp" 2>/dev/null || true
    chmod 0600 "$scan_temp"
    mv -f "$scan_temp" "$SCAN_CACHE"
else
    rm -f "$scan_temp"
fi

profiles=()
while IFS=: read -r uuid type; do
    case "$type" in
        wifi|802-11-wireless)
            name="$(nmcli -g connection.id connection show uuid "$uuid" 2>/dev/null || true)"
            mode="$(nmcli -g 802-11-wireless.mode connection show uuid "$uuid" 2>/dev/null || true)"
            if [ "$name" != "$AP_NAME" ] && [ "$mode" != "ap" ]; then
                profiles+=("$uuid")
            fi
            ;;
    esac
done < <(nmcli -t -f UUID,TYPE connection show 2>/dev/null)

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

if ! nmcli -g connection.id connection show id "$AP_NAME" >/dev/null 2>&1; then
    log "creating open $AP_SSID recovery hotspot at $AP_ADDRESS"
    if ! nmcli connection add type wifi ifname "$IFACE" con-name "$AP_NAME" ssid "$AP_SSID" >/dev/null 2>&1; then
        log "could not create recovery hotspot profile"
        exit 0
    fi
fi

# NetworkManager shared mode provides NAT, DNS forwarding, and DHCP leases.
# autoconnect stays disabled so this profile never wins over a known network.
nmcli connection modify id "$AP_NAME" \
    connection.autoconnect no \
    802-11-wireless.mode ap \
    802-11-wireless.band bg \
    ipv4.method shared \
    ipv4.addresses "$AP_ADDRESS" \
    ipv6.method disabled >/dev/null 2>&1 || true

log "no saved Wi-Fi profile connected; starting open $AP_SSID recovery hotspot"
if nmcli --wait 25 connection up id "$AP_NAME" ifname "$IFACE" >/dev/null 2>&1; then
    log "recovery hotspot active; open http://${AP_ADDRESS%/*}/ to configure Wi-Fi"
else
    log "recovery hotspot failed to start; timer will retry"
fi
exit 0
