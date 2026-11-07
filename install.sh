#!/usr/bin/env bash
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$ROOT_DIR"

if [ "$(uname -s)" != Linux ]; then
  printf '%s\n' 'This installer supports Linux hosts. Use Docker Compose directly on other platforms.' >&2
  exit 1
fi
if ! command -v docker >/dev/null 2>&1; then
  printf '%s\n' 'Docker Engine is required. Install Docker Engine and the Compose plugin, then rerun this installer.' >&2
  exit 1
fi
if ! docker compose version >/dev/null 2>&1; then
  printf '%s\n' 'Docker Compose v2 is required (docker compose plugin).' >&2
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
if [ -e .env.production ]; then
  printf '%s\n' '.env.production already exists. Refusing to replace production credentials.' >&2
  exit 1
fi

printf 'Public application hostname (DNS must point to this host): '
IFS= read -r APP_HOST
case "$APP_HOST" in
  ''|*[!A-Za-z0-9.-]*)
    printf '%s\n' 'Enter a hostname containing only letters, digits, dots, and hyphens.' >&2
    exit 1
    ;;
esac

printf 'Initial administrator password (14-128 characters): '
IFS= read -r -s ADMIN_PASSWORD
printf '\n'
if [ "${#ADMIN_PASSWORD}" -lt 14 ] || [ "${#ADMIN_PASSWORD}" -gt 128 ]; then
  printf '%s\n' 'The administrator password must contain 14-128 characters.' >&2
  exit 1
fi
case "$ADMIN_PASSWORD" in
  *[[:space:]])
    printf '%s\n' 'The administrator password cannot end with whitespace.' >&2
    exit 1
    ;;
esac

POSTGRES_PASSWORD=$(openssl rand -hex 32)
APP_DB_PASSWORD=$(openssl rand -hex 32)
ENCRYPTION_KEY=$(openssl rand -base64 32 | tr -d '\n')
METRICS_TOKEN=$(openssl rand -hex 32)
ML_SIGNING_KEY=$(openssl rand -hex 32)

umask 077
cat > .env.production <<EOF
APP_HOST=$APP_HOST
POSTGRES_PASSWORD=$POSTGRES_PASSWORD
APP_DB_PASSWORD=$APP_DB_PASSWORD
ENCRYPTION_KEY=$ENCRYPTION_KEY
METRICS_TOKEN=$METRICS_TOKEN
ML_SIGNING_KEY=$ML_SIGNING_KEY
PROMETHEUS_PORT=9091
BOOTSTRAP_RECOMMENDED_FEEDS=false
LOG_LEVEL=standard
SMTP_HOST=
SMTP_PORT=465
SMTP_USER=
SMTP_PASSWORD=
SMTP_FROM=
EGRESS_ALLOWED_HOSTS_EXTRA=
EOF
chmod 600 .env.production

mkdir -p .runtime
chmod 700 .runtime
printf '%s' "$METRICS_TOKEN" > .runtime/metrics.token
chmod 600 .runtime/metrics.token
unset POSTGRES_PASSWORD APP_DB_PASSWORD ENCRYPTION_KEY METRICS_TOKEN ML_SIGNING_KEY

docker compose --env-file .env.production config --quiet
docker compose --env-file .env.production up -d --build --scale app=2 --wait --wait-timeout 300

printf '%s' "$ADMIN_PASSWORD" | docker compose --env-file .env.production exec -T app \
  node server-dist/create-user.js admin ADMIN
unset ADMIN_PASSWORD

docker compose --env-file .env.production ps
printf 'Installation complete. Open https://%s and sign in as admin.\n' "$APP_HOST"