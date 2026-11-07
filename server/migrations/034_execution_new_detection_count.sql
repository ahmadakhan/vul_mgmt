-- 034 — execution stats must count new detections, not every current match.
--
-- The pipeline re-derives all current matches on every run so it can refresh
-- applicability. That full count was stored in
-- records(kind='executions').data.stats.matchedWatchlist, so a run that
-- introduced no new finding still reported the whole corpus (for example
-- "11 findings" on every execution). Reconstruct the historical value from the
-- first "Matched inventory" timeline entry of each finding, which is stamped
-- with the detecting run's start time.

WITH runs AS (
  SELECT
    id,
    (data->>'startTime')::timestamptz AS started,
    CASE
      WHEN COALESCE(data->>'endTime', '') ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T'
        THEN (data->>'endTime')::timestamptz
      ELSE now()
    END AS ended
  FROM records
  WHERE kind = 'executions'
    AND data->>'startTime' ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T'
),
detections AS (
  SELECT
    run.id AS execution_id,
    count(
      DISTINCT COALESCE(finding.data->>'cveId', '') || ':' || COALESCE(finding.data->>'matchedAssetId', '')
    )::int AS detected
  FROM runs AS run
  JOIN records AS finding
    ON finding.kind = 'findings'
   AND finding.data->'timeline'->0->>'action' = 'Matched inventory'
   AND finding.data->'timeline'->0->>'timestamp' ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T'
   AND (finding.data->'timeline'->0->>'timestamp')::timestamptz BETWEEN run.started AND run.ended
  GROUP BY run.id
)
UPDATE records AS execution
SET data = jsonb_set(
  execution.data,
  '{stats,matchedWatchlist}',
  to_jsonb(COALESCE(detections.detected, 0)),
  true
)
FROM runs
LEFT JOIN detections ON detections.execution_id = runs.id
WHERE execution.kind = 'executions'
  AND execution.id = runs.id
  AND execution.data ? 'stats';

INSERT INTO schema_migrations(version) VALUES(34) ON CONFLICT DO NOTHING;
