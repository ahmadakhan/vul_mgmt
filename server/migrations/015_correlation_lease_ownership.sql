-- Only the application-owned work queue changes; native owner tables are untouched.
ALTER TABLE correlation_pending ADD COLUMN IF NOT EXISTS lease_token uuid;
INSERT INTO schema_migrations(version) VALUES(15) ON CONFLICT DO NOTHING;
