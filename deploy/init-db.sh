#!/bin/sh
set -eu
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<'SQL'
\getenv app_password APP_DB_PASSWORD
CREATE ROLE vulnstream_app LOGIN PASSWORD :'app_password';
GRANT CONNECT ON DATABASE vulnstream TO vulnstream_app;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
SQL
