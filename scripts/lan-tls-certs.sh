#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT_DIR"

read_env_value() {
  local key=$1
  awk -F= -v key="$key" '$1 == key { sub(/^[^=]*=/, ""); print; exit }' .env.lan
}

if (($# == 2)); then
  LAN_IP=$1
  TAILSCALE_ADDRESS=$2
elif (($# == 0)) && [[ -f .env.lan ]]; then
  LAN_IP=$(read_env_value LAN_BIND_ADDRESS)
  TAILSCALE_ADDRESS=$(read_env_value TAILSCALE_ADDRESS)
else
  printf '%s\n' 'Usage: scripts/lan-tls-certs.sh [LAN_IPV4 TAILSCALE_IPV4]' >&2
  exit 2
fi

is_ipv4() {
  local value=$1 octet
  [[ "$value" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  IFS=. read -r -a octets <<< "$value"
  for octet in "${octets[@]}"; do
    ((10#$octet <= 255)) || return 1
  done
}

if ! is_ipv4 "$LAN_IP" || ! is_ipv4 "$TAILSCALE_ADDRESS"; then
  printf '%s\n' 'Both certificate addresses must be valid IPv4 addresses.' >&2
  exit 1
fi

IFS=. read -r lan1 lan2 _ _ <<< "$LAN_IP"
if ! ((10#$lan1 == 10 || (10#$lan1 == 172 && 10#$lan2 >= 16 && 10#$lan2 <= 31) || (10#$lan1 == 192 && 10#$lan2 == 168))); then
  printf '%s\n' 'The LAN address must be in an RFC1918 private range.' >&2
  exit 1
fi
IFS=. read -r tail1 tail2 _ _ <<< "$TAILSCALE_ADDRESS"
if ! ((10#$tail1 == 100 && 10#$tail2 >= 64 && 10#$tail2 <= 127)); then
  printf '%s\n' 'The Tailscale address must be in 100.64.0.0/10.' >&2
  exit 1
fi
if ! command -v openssl >/dev/null 2>&1; then
  printf '%s\n' 'OpenSSL is required to create LAN TLS certificates.' >&2
  exit 1
fi

RUNTIME_DIR=.runtime
CA_CERT="$RUNTIME_DIR/lan-ca.crt"
CA_KEY="$RUNTIME_DIR/lan-ca.key"
TLS_CERT="$RUNTIME_DIR/lan-tls.crt"
TLS_KEY="$RUNTIME_DIR/lan-tls.key"
mkdir -p "$RUNTIME_DIR"
chmod 700 "$RUNTIME_DIR"
umask 077
TEMP_DIR=$(mktemp -d "$RUNTIME_DIR/lan-tls.XXXXXX")
trap 'rm -rf "$TEMP_DIR"' EXIT

if [[ -f "$CA_CERT" && -f "$CA_KEY" ]]; then
  :
elif [[ -e "$CA_CERT" || -e "$CA_KEY" ]]; then
  printf '%s\n' 'The LAN CA certificate and key must both exist; refusing to replace either.' >&2
  exit 1
else
  openssl req -x509 -newkey rsa:3072 -nodes -sha256 -days 3650 \
    -keyout "$TEMP_DIR/lan-ca.key" -out "$TEMP_DIR/lan-ca.crt" \
    -subj '/CN=VulnStream LAN Root CA' \
    -addext 'basicConstraints=critical,CA:TRUE,pathlen:0' \
    -addext 'keyUsage=critical,keyCertSign,cRLSign'
  install -m 600 "$TEMP_DIR/lan-ca.key" "$CA_KEY"
  install -m 644 "$TEMP_DIR/lan-ca.crt" "$CA_CERT"
fi

openssl req -new -newkey rsa:2048 -nodes \
  -keyout "$TEMP_DIR/lan-tls.key" -out "$TEMP_DIR/lan-tls.csr" \
  -subj '/CN=VulnStream LAN'
cat > "$TEMP_DIR/lan-tls.ext" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=IP:$LAN_IP,IP:$TAILSCALE_ADDRESS
EOF
openssl x509 -req -in "$TEMP_DIR/lan-tls.csr" \
  -CA "$CA_CERT" -CAkey "$CA_KEY" \
  -CAserial "$RUNTIME_DIR/lan-ca.srl" -CAcreateserial \
  -out "$TEMP_DIR/lan-tls.crt" -days 365 -sha256 \
  -extfile "$TEMP_DIR/lan-tls.ext"
openssl verify -CAfile "$CA_CERT" "$TEMP_DIR/lan-tls.crt"
openssl x509 -in "$TEMP_DIR/lan-tls.crt" -noout -checkip "$LAN_IP" >/dev/null
openssl x509 -in "$TEMP_DIR/lan-tls.crt" -noout -checkip "$TAILSCALE_ADDRESS" >/dev/null
install -m 600 "$TEMP_DIR/lan-tls.key" "$TLS_KEY"
install -m 644 "$TEMP_DIR/lan-tls.crt" "$TLS_CERT"
chmod 600 "$RUNTIME_DIR/lan-ca.srl"
printf 'LAN TLS certificate renewed: %s\n' "$TLS_CERT"
openssl x509 -in "$TLS_CERT" -noout -enddate
