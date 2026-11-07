-- Expand the status constraint to include REVIEW (security review gate) and
-- REJECTED (operator rejection). The column is added first so subsequent
-- constraint changes can reference it. Using NOT VALID avoids validating
-- existing rows during busy deployments; a follow-up VALIDATE CONSTRAINT can
-- run during maintenance. Existing rows remain valid under the expanded
-- constraint since they only contain pre-existing status values.
ALTER TABLE outbox ADD COLUMN IF NOT EXISTS review_approved boolean NOT NULL DEFAULT false;
ALTER TABLE outbox DROP CONSTRAINT IF EXISTS outbox_status_check;
ALTER TABLE outbox ADD CONSTRAINT outbox_status_check
  CHECK(status IN ('REVIEW','QUEUED','SENDING','ACCEPTED','FAILED','REJECTED')) NOT VALID;
INSERT INTO schema_migrations(version) VALUES(4) ON CONFLICT DO NOTHING;
