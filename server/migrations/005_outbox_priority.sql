ALTER TABLE outbox ADD COLUMN IF NOT EXISTS priority smallint NOT NULL DEFAULT 0;
COMMENT ON COLUMN outbox.priority IS 'Higher values are delivered first: CISA_KEV=100, zero-day=50, routine=0';
-- Existing installations that applied 001 before the priority index was added
-- need the index created here as well; fresh installs already have it.
CREATE INDEX IF NOT EXISTS outbox_priority ON outbox(status, priority DESC, next_attempt);
INSERT INTO schema_migrations(version) VALUES(5) ON CONFLICT DO NOTHING;
