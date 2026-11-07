-- AUD-010: backfill recipient-specific delivery claims from retained outbox
-- history.
--
-- Migration 038 created `delivery_claims` empty: every finding or article an
-- existing build had already delivered looked un-claimed, so the next pipeline
-- run re-notified historical deliveries. This backfill imports the per-recipient
-- receipt from the only authoritative source that survives — the outbox row's
-- own `includedFindingIds` payload:
--
--   ACCEPTED  the transport confirmed delivery → a permanent DELIVERED receipt.
--   QUEUED /
--   SENDING   the message is still in flight → an active CLAIMED row owned by
--             that job, whose expiry follows the outbox lifecycle exactly like
--             any claim taken by the current queue (Finding 4: the clock cannot
--             reclaim an item while its job may still be delivered).
--
-- One row per (recipient, finding), preferring the newest accepted job: a
-- finding may have been carried by several batches over its lifetime, and the
-- most recent acceptance is the receipt that matters. The `ON CONFLICT` clause
-- only promotes an existing CLAIMED row to DELIVERED — a live claim taken by the
-- current build is never overwritten by history.
--
-- Known limitation (accepted, documented): rows that retention has already
-- removed, and legacy payloads without `includedFindingIds`, cannot be
-- reconstructed here. They require reconciliation against archived delivery
-- evidence. The global `reviewNotifiedAt` stamp on the finding is deliberately
-- NOT used: it is set by the first recipient's acceptance and would wrongly
-- suppress the finding for every recipient who has not received it (AUD-001).
--
-- News articles are NOT backfilled by this migration: historical news payloads
-- carried a different article identity format (URL without query string, see
-- AUD-008), and inferring them from `newsEvidence` would risk both false
-- duplicates and false suppression. The news ledger already survives outbox
-- retention; its historical records are reconciled separately.

WITH historical AS (
  SELECT
    o.target_id AS recipient_id,
    f.finding_id,
    o.id AS job_id,
    o.status,
    o.created_at,
    o.updated_at,
    ROW_NUMBER() OVER (
      PARTITION BY o.target_id, f.finding_id
      ORDER BY (o.status = 'ACCEPTED') DESC, o.updated_at DESC
    ) AS rn
  FROM outbox o
  CROSS JOIN LATERAL jsonb_array_elements_text(
    CASE
      WHEN jsonb_typeof(o.payload->'includedFindingIds') = 'array'
        THEN o.payload->'includedFindingIds'
      ELSE '[]'::jsonb
    END
  ) AS f(finding_id)
  WHERE o.channel = 'email'
    AND o.status IN ('ACCEPTED', 'QUEUED', 'SENDING')
)
INSERT INTO delivery_claims(
  recipient_id, kind, item_id, state, job_id,
  claimed_at, expires_at, delivered_at
)
SELECT
  recipient_id,
  'finding',
  finding_id,
  CASE WHEN status = 'ACCEPTED' THEN 'DELIVERED' ELSE 'CLAIMED' END,
  job_id,
  created_at,
  CASE WHEN status = 'ACCEPTED' THEN NULL ELSE now() + interval '6 hours' END,
  CASE WHEN status = 'ACCEPTED' THEN updated_at ELSE NULL END
FROM historical
WHERE rn = 1
ON CONFLICT (recipient_id, kind, item_id) DO UPDATE SET
  state = 'DELIVERED',
  job_id = EXCLUDED.job_id,
  delivered_at = EXCLUDED.delivered_at,
  expires_at = NULL
WHERE delivery_claims.state = 'CLAIMED'
  AND EXCLUDED.state = 'DELIVERED';

INSERT INTO schema_migrations(version) VALUES(39) ON CONFLICT DO NOTHING;
