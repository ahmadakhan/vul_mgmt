-- Delivery fairness and audit immutability guards.
--
-- Pending jobs are grouped by target so a failing endpoint can be backed off
-- without scanning the whole queue. The partial predicate keeps the index small
-- and avoids indexing terminal history.
CREATE INDEX IF NOT EXISTS outbox_target_pending
  ON outbox(channel, target_id, status)
  WHERE status IN ('QUEUED','SENDING');

-- Row-level UPDATE/DELETE protection does not fire for TRUNCATE. Add a
-- statement-level trigger so bulk truncation cannot bypass the audit chain.
CREATE OR REPLACE FUNCTION prevent_audit_truncate() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'Audit records are append-only'; END $$;
DROP TRIGGER IF EXISTS audit_no_truncate ON audit;
CREATE TRIGGER audit_no_truncate BEFORE TRUNCATE ON audit
  FOR EACH STATEMENT EXECUTE FUNCTION prevent_audit_truncate();

INSERT INTO schema_migrations(version) VALUES(7) ON CONFLICT DO NOTHING;
