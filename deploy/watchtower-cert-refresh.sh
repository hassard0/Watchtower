#!/usr/bin/env bash
# Create/refresh Watchtower's private-CA TLS certificate.
# The CA is created once. The leaf certificate is replaced when the Pi's
# hostname/IP set changes or when fewer than 30 days of validity remain.
set -euo pipefail

TLS_DIR=/etc/watchtower/tls
CA_KEY="$TLS_DIR/watchtower-ca.key"
CA_CERT="$TLS_DIR/watchtower-ca.crt"
LEAF_KEY="$TLS_DIR/watchtower.key"
LEAF_CERT="$TLS_DIR/watchtower.crt"
SAN_HASH="$TLS_DIR/watchtower.san.sha256"

umask 077
install -d -o root -g root -m 0755 "$TLS_DIR"

if { [ -e "$CA_KEY" ] && [ ! -e "$CA_CERT" ]; } \
   || { [ ! -e "$CA_KEY" ] && [ -e "$CA_CERT" ]; }; then
  echo "Watchtower TLS CA is incomplete; refusing to replace its trust identity" >&2
  exit 1
fi

if [ ! -f "$CA_KEY" ]; then
  openssl genrsa -out "$CA_KEY" 3072
  openssl req -x509 -new -sha256 -days 3650 \
    -key "$CA_KEY" -out "$CA_CERT" \
    -subj "/CN=Watchtower Private CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "subjectKeyIdentifier=hash"
  chmod 0600 "$CA_KEY"
  chmod 0644 "$CA_CERT"
fi

short_host="$(hostname -s | tr -cd 'A-Za-z0-9.-')"
fqdn="$(hostname -f 2>/dev/null | tr -cd 'A-Za-z0-9.-' || true)"
san_parts=("DNS:watchtower.local")
[ -z "$short_host" ] || san_parts+=("DNS:$short_host" "DNS:$short_host.local")
[ -z "$fqdn" ] || san_parts+=("DNS:$fqdn")
san_parts+=("IP:127.0.0.1" "IP:10.42.0.1")

for address in $(hostname -I 2>/dev/null || true); do
  # Track LAN IPv4 addresses. Temporary IPv6 privacy addresses would cause
  # needless certificate churn; the stable mDNS name covers IPv6 clients.
  if [[ "$address" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    san_parts+=("IP:$address")
  fi
done

# Sort and de-duplicate SANs so output remains stable across invocations.
san="$(printf '%s\n' "${san_parts[@]}" | sort -u | paste -sd, -)"
new_hash="$(printf '%s' "$san" | sha256sum | awk '{print $1}')"
old_hash="$(cat "$SAN_HASH" 2>/dev/null || true)"

if [ -f "$LEAF_KEY" ] && [ -f "$LEAF_CERT" ] \
   && [ "$new_hash" = "$old_hash" ] \
   && openssl x509 -checkend 2592000 -noout -in "$LEAF_CERT" >/dev/null 2>&1; then
  exit 0
fi

tmp_dir="$(mktemp -d "$TLS_DIR/.refresh.XXXXXX")"
trap 'rm -rf -- "$tmp_dir"' EXIT

if [ ! -f "$LEAF_KEY" ]; then
  openssl genrsa -out "$tmp_dir/watchtower.key" 3072
  install -o root -g root -m 0600 "$tmp_dir/watchtower.key" "$LEAF_KEY"
fi

openssl req -new -sha256 -key "$LEAF_KEY" \
  -out "$tmp_dir/watchtower.csr" -subj "/CN=watchtower.local"
cat >"$tmp_dir/watchtower.ext" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=$san
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EOF
openssl x509 -req -sha256 -days 397 \
  -in "$tmp_dir/watchtower.csr" \
  -CA "$CA_CERT" -CAkey "$CA_KEY" -CAcreateserial \
  -extfile "$tmp_dir/watchtower.ext" \
  -out "$tmp_dir/watchtower.crt"

install -o root -g root -m 0644 "$tmp_dir/watchtower.crt" "$LEAF_CERT"
printf '%s\n' "$new_hash" >"$tmp_dir/watchtower.san.sha256"
install -o root -g root -m 0644 "$tmp_dir/watchtower.san.sha256" "$SAN_HASH"

if systemctl is-active --quiet nginx.service 2>/dev/null; then
  nginx -t
  systemctl reload nginx.service
fi
