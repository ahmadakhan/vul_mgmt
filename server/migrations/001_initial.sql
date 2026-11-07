CREATE TABLE IF NOT EXISTS schema_migrations(version integer PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS users (
  id uuid PRIMARY KEY, username text NOT NULL UNIQUE, password_hash text NOT NULL,
  role text NOT NULL CHECK(role IN ('ADMIN','OPERATOR','VIEWER')), disabled boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS sessions (
  token_hash text PRIMARY KEY, user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  csrf text NOT NULL, expires_at timestamptz NOT NULL, absolute_expires_at timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_expiry ON sessions(expires_at);
CREATE TABLE IF NOT EXISTS login_attempts (
  key text PRIMARY KEY, attempts integer NOT NULL, window_start timestamptz NOT NULL
);
CREATE TABLE IF NOT EXISTS records (
  kind text NOT NULL, id text NOT NULL, data jsonb NOT NULL, updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY(kind,id)
);
CREATE INDEX IF NOT EXISTS records_recent ON records(kind,updated_at DESC);
CREATE TABLE IF NOT EXISTS audit (
  seq bigserial PRIMARY KEY, data jsonb NOT NULL
);
CREATE OR REPLACE FUNCTION prevent_audit_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'Audit records are append-only'; END $$;
DROP TRIGGER IF EXISTS audit_immutable ON audit;
CREATE TRIGGER audit_immutable BEFORE UPDATE OR DELETE ON audit FOR EACH ROW EXECUTE FUNCTION prevent_audit_mutation();
CREATE TABLE IF NOT EXISTS outbox (
  id uuid PRIMARY KEY, dedupe_key text NOT NULL UNIQUE, channel text NOT NULL CHECK(channel IN ('email','webhook')),
  target_id text NOT NULL, advisory_id text NOT NULL, payload jsonb NOT NULL,
  status text NOT NULL DEFAULT 'QUEUED' CHECK(status IN ('QUEUED','SENDING','ACCEPTED','FAILED')),
  attempts integer NOT NULL DEFAULT 0, next_attempt timestamptz NOT NULL DEFAULT now(),
  locked_at timestamptz, lock_token uuid, error text, provider_id text,
  review_approved boolean NOT NULL DEFAULT false,
  priority smallint NOT NULL DEFAULT 0,
  created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS outbox_due ON outbox(status,next_attempt);
CREATE INDEX IF NOT EXISTS outbox_priority ON outbox(status,priority DESC,next_attempt);
CREATE TABLE IF NOT EXISTS scheduler_state (id integer PRIMARY KEY CHECK(id=1), last_run timestamptz, heartbeat timestamptz);
INSERT INTO scheduler_state(id) VALUES(1) ON CONFLICT DO NOTHING;
INSERT INTO schema_migrations(version) VALUES(1) ON CONFLICT DO NOTHING;
