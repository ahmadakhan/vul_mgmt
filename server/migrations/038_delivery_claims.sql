-- AUD-001 / AUD-002: durable per-recipient delivery claims.
--
-- The finding record carries a single `reviewNotifiedAt` timestamp, so the first
-- recipient whose email was accepted marked the finding as announced for
-- everybody: a recipient added later never received it. The outbox scan that
-- replaced the global check is still a read-then-enqueue, so two concurrent
-- pipeline runs could both decide a finding was new and queue overlapping
-- batches.
--
-- This table is the database-enforced answer to "has THIS recipient been told
-- about THIS item?". One row per (recipient, kind, item):
--
--   CLAIMED  a consolidated message carrying the item is queued or in flight;
--            the claim expires so a crashed run cannot suppress the item forever.
--   DELIVERED the transport accepted the message; the claim is permanent and is
--            the deduplication record.
--
-- `reviewNotifiedAt` on the finding is retained for aggregate reporting and for
-- builds that predate this table, but it is no longer the deduplication key.
CREATE TABLE IF NOT EXISTS delivery_claims (
  recipient_id text NOT NULL,
  kind text NOT NULL CHECK (kind IN ('finding','article')),
  item_id text NOT NULL,
  state text NOT NULL CHECK (state IN ('CLAIMED','DELIVERED')),
  job_id uuid,
  claimed_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz,
  delivered_at timestamptz,
  PRIMARY KEY (recipient_id, kind, item_id)
);

-- Expiry sweep: only CLAIMED rows can expire, and they are the only rows the
-- recovery path has to look at.
CREATE INDEX IF NOT EXISTS delivery_claims_expiry
  ON delivery_claims(expires_at) WHERE state = 'CLAIMED';

INSERT INTO schema_migrations(version) VALUES(38) ON CONFLICT DO NOTHING;
