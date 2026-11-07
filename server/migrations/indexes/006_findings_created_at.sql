-- Recent-findings window used by the daily digest (server/dailyDigest.ts).
--
-- The digest selects findings whose created_at is inside the last 24 hours.
-- `records_created_order (kind, created_at DESC, id)` is ordered the wrong way
-- for this predicate: with created_at DESC nothing bounds the start of the scan,
-- so the planner narrows only by kind and then filters every finding by
-- timestamp. A partial index in ascending order lets the window be read as a
-- bounded range instead.
--
-- Partial and CONCURRENTLY: `records` is a live table, the index only covers the
-- findings kind, and the build must not hold a table lock that blocks ingestion
-- or delivery. IF NOT EXISTS keeps this idempotent for databases that already
-- have the index.
CREATE INDEX CONCURRENTLY IF NOT EXISTS records_findings_created_at
  ON records (created_at)
  WHERE kind = 'findings';
