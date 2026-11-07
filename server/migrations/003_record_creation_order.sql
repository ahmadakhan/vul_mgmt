-- Keep a record's position stable when its data is edited or its health is tested.
-- Backfill from updated_at so existing rows retain their current relative order.
ALTER TABLE records ADD COLUMN IF NOT EXISTS created_at timestamptz;
UPDATE records SET created_at = updated_at WHERE created_at IS NULL;
ALTER TABLE records ALTER COLUMN created_at SET DEFAULT now();
ALTER TABLE records ALTER COLUMN created_at SET NOT NULL;
CREATE INDEX IF NOT EXISTS records_created_order ON records(kind, created_at DESC, id);
INSERT INTO schema_migrations(version) VALUES(3) ON CONFLICT DO NOTHING;
