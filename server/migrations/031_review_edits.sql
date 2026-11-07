--
-- 031 — Review-time edits for EVERYONE-distribution advisory emails
--
-- When an advisory is queued to a recipient in the EVERYONE delivery group, the
-- job enters REVIEW status. Operators need to edit the rendered email body and
-- inject additional fields (e.g. an audience notice, a reviewer comment) before
-- the broader distribution is authorised. The edits are stored per-job so they
-- survive review re-opens and are applied to both the email HTML body and the
-- PDF attachment at delivery time.
--
-- The partial index on outbox (status='REVIEW' AND edits != '{}') is defined in
-- migrations/indexes/005_outbox_edits_review.sql — built CONCURRENTLY outside the
-- migration transaction because outbox is a live table in production.
--
ALTER TABLE outbox
  ADD COLUMN IF NOT EXISTS edits jsonb NOT NULL DEFAULT '{}'::jsonb;

INSERT INTO schema_migrations(version) VALUES(31) ON CONFLICT DO NOTHING;
