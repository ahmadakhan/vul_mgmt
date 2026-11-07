#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$ROOT_DIR"

if [[ "$(uname -s)" != Linux ]]; then
  printf '%s\n' 'This installer supports Linux hosts.' >&2
  exit 1
fi
if ! command -v docker >/dev/null 2>&1 || ! docker compose version >/dev/null 2>&1; then
  printf '%s\n' 'Docker Engine and the Docker Compose v2 plugin are required.' >&2
  exit 1
fi
if ! docker info >/dev/null 2>&1; then
  printf '%s\n' 'Docker is not running or the current user cannot access its daemon.' >&2
  exit 1
fi
if ! command -v openssl >/dev/null 2>&1; then
  printf '%s\n' 'OpenSSL is required to generate deployment secrets.' >&2
  exit 1
fi
if [[ -e .env.lan ]]; then
  printf '%s\n' '.env.lan already exists. Refusing to replace existing LAN deployment credentials.' >&2
  exit 1
fi

is_ipv4() {
  local value=$1 octet
  [[ "$value" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  IFS=. read -r -a octets <<< "$value"
  for octet in "${octets[@]}"; do
    ((10#$octet <= 255)) || return 1
  done
}

read -r -p 'Private LAN IPv4 address for this server: ' LAN_IP
if ! is_ipv4 "$LAN_IP"; then
  printf '%s\n' 'Enter a valid IPv4 address.' >&2
  exit 1
fi
IFS=. read -r lan1 lan2 _ _ <<< "$LAN_IP"
if ! ((10#$lan1 == 10 || (10#$lan1 == 172 && 10#$lan2 >= 16 && 10#$lan2 <= 31) || (10#$lan1 == 192 && 10#$lan2 == 168))); then
  printf '%s\n' 'The LAN address must be in an RFC1918 private range.' >&2
  exit 1
fi

read -r -p 'Tailscale IPv4 address for this server: ' TAILSCALE_ADDRESS
if ! is_ipv4 "$TAILSCALE_ADDRESS"; then
  printf '%s\n' 'Enter a valid Tailscale IPv4 address.' >&2
  exit 1
fi
IFS=. read -r tail1 tail2 _ _ <<< "$TAILSCALE_ADDRESS"
if ! ((10#$tail1 == 100 && 10#$tail2 >= 64 && 10#$tail2 <= 127)); then
  printf '%s\n' 'The Tailscale address must be in 100.64.0.0/10.' >&2
  exit 1
fi

printf 'Initial administrator password (14-128 characters): '
IFS= read -r -s ADMIN_PASSWORD
printf '\n'
if (( ${#ADMIN_PASSWORD} < 14 || ${#ADMIN_PASSWORD} > 128 )); then
  printf '%s\n' 'The administrator password must contain 14-128 characters.' >&2
  exit 1
fi
if [[ "$ADMIN_PASSWORD" =~ [[:space:]]$ ]]; then
  printf '%s\n' 'The administrator password cannot end with whitespace.' >&2
  exit 1
fi

POSTGRES_PASSWORD=$(openssl rand -hex 32)
APP_DB_PASSWORD=$(openssl rand -hex 32)
ENCRYPTION_KEY=$(openssl rand -base64 32 | tr -d '\n')
METRICS_TOKEN=$(openssl rand -hex 32)
ML_SIGNING_KEY=$(openssl rand -hex 32)
APP_ORIGIN="https://${TAILSCALE_ADDRESS}"

umask 077
mkdir -p .runtime
chmod 700 .runtime
bash ./scripts/lan-tls-certs.sh "$LAN_IP" "$TAILSCALE_ADDRESS"

cat > .env.lan <<EOF
APP_HOST=$TAILSCALE_ADDRESS
APP_ORIGIN=$APP_ORIGIN
LAN_BIND_ADDRESS=$LAN_IP
TAILSCALE_ADDRESS=$TAILSCALE_ADDRESS
POSTGRES_PORT=5434
POSTGRES_PASSWORD=$POSTGRES_PASSWORD
APP_DB_PASSWORD=$APP_DB_PASSWORD
ENCRYPTION_KEY=$ENCRYPTION_KEY
METRICS_TOKEN=$METRICS_TOKEN
ML_SIGNING_KEY=$ML_SIGNING_KEY
BOOTSTRAP_RECOMMENDED_FEEDS=false
LOG_LEVEL=standard
SMTP_HOST=
SMTP_PORT=465
SMTP_USER=
SMTP_PASSWORD=
SMTP_FROM=
EOF
chmod 600 .env.lan
printf '%s' "$METRICS_TOKEN" > .runtime/metrics.token
chmod 600 .runtime/metrics.token
unset POSTGRES_PASSWORD APP_DB_PASSWORD ENCRYPTION_KEY METRICS_TOKEN ML_SIGNING_KEY

compose=(docker compose --project-name vulnstream-lan)
if [[ -f .env.production ]]; then
  compose+=(--env-file .env.production)
fi
compose+=(--env-file .env.lan -f compose.yaml -f compose.lan.yaml)
"${compose[@]}" config --quiet
"${compose[@]}" up -d --build --scale app=1 --wait --wait-timeout 300
printf '%s' "$ADMIN_PASSWORD" | "${compose[@]}" exec -T app node server-dist/create-user.js admin ADMIN
unset ADMIN_PASSWORD
"${compose[@]}" ps
printf 'LAN installation complete. Open https://%s or https://%s\n' "$LAN_IP" "$TAILSCALE_ADDRESS"
printf '%s\n' 'Install .runtime/lan-ca.crt in each client trust store. Keep .runtime/lan-ca.key private.'
printf '%s\n' 'HTTP on port 80 redirects to HTTPS on port 443.'