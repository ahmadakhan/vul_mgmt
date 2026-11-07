-- AUD-007: explicit delivery outcome on the outbox.
--
-- Resending decisions used to depend on matching error-message text and an empty
-- provider_id. That cannot distinguish a provable transport rejection (the
-- message was never delivered, so a resend cannot duplicate it) from an unknown
-- outcome (the send may have been accepted; a resend can duplicate it).
--
-- `delivery_outcome` records the transport's verdict explicitly:
--
--   NOT_ATTEMPTED  the job was queued but no transport attempt has started.
--   UNKNOWN        a transport attempt may have occurred (set before the provider
--                  is contacted, so a crash after acceptance still leaves the
--                  job in the safe state). Cleared only by provider evidence.
--   REJECTED       the transport provably refused the message.
--   ACCEPTED       the transport confirmed delivery.
--
-- Historical rows: an ACCEPTED status is exactly an accepted transport outcome.
-- FAILED rows keep UNKNOWN unless independent evidence proves non-delivery —
-- absence of evidence is not evidence of non-delivery, and guessing wrong here
-- is what produces duplicate emails.
ALTER TABLE outbox
  ADD COLUMN IF NOT EXISTS delivery_outcome text NOT NULL DEFAULT 'UNKNOWN'
    CHECK (delivery_outcome IN ('NOT_ATTEMPTED', 'REJECTED', 'UNKNOWN', 'ACCEPTED'));

-- Backfill: only the status the row carries today is evidence. An ACCEPTED
-- outbox row exists precisely because the transport confirmed the message.
UPDATE outbox SET delivery_outcome = 'ACCEPTED' WHERE status = 'ACCEPTED';

INSERT INTO schema_migrations(version) VALUES(40) ON CONFLICT DO NOTHING;
