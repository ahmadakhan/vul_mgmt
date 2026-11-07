-- 032 — bound re-claims of a poisoned pending advisory.
--
-- `claimPending` orders rows by `created_at,id` and skips only *live* leases, so
-- a payload that fails deterministically (validation, or a durability failure on
-- both fallback stores) is re-claimed and re-failed on every pass forever. There
-- was no attempt counter and no retirement path: the poison row occupied the
-- head of the queue indefinitely and, on a small estate, was the only work the
-- drain loop ever attempted.
--
-- The counter lets the claim query stop offering the row past
-- `MAX_PENDING_ATTEMPTS` (server/correlation/pending.ts). Rows are retained, not
-- deleted: an operator can still read the payload, replay it through the
-- dead-letter workflow, or drop it deliberately.
--
-- Existing rows start at 0. Backfilling from a lease count is impossible (the
-- lease is overwritten, not accumulated), so a row that was already looping
-- simply gets another 20 attempts after this migration — bounded, either way.

ALTER TABLE correlation_pending
  ADD COLUMN IF NOT EXISTS attempts integer NOT NULL DEFAULT 0;

INSERT INTO schema_migrations(version) VALUES(32) ON CONFLICT DO NOTHING;
