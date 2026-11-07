-- 030 — Add ML category to operational_events check constraint
-- Allows the ML subsystem to write structured operational events to the
-- retained log, visible in the System logs view under the ML tab.
ALTER TABLE operational_events
  DROP CONSTRAINT IF EXISTS operational_events_category_check,
  ADD CONSTRAINT operational_events_category_check
  CHECK (category IN ('PIPELINE','FEED','MATCHING','EMAIL','SYSTEM','ISSUE','EVENT','ML'));

INSERT INTO schema_migrations(version) VALUES(33) ON CONFLICT DO NOTHING;
