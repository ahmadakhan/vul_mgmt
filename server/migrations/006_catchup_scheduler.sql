ALTER TABLE scheduler_state ADD COLUMN IF NOT EXISTS next_catchup_run timestamptz;
INSERT INTO schema_migrations(version) VALUES(6) ON CONFLICT DO NOTHING;
