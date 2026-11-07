-- Bounded lookup of active pipeline executions.
--
-- queueRun(), the worker's recovery sweep and the queued-execution selector all
-- asked "is there an execution in state QUEUED/RUNNING?" through list('executions'),
-- which loaded and de-serialised every run ever recorded. On a long-lived
-- installation that grew past the pool's 15 s statement timeout and turned
-- POST /api/pipeline into a 500. The queries are now bounded, and this partial
-- index lets PostgreSQL answer them from a handful of rows instead of a scan.
CREATE INDEX CONCURRENTLY IF NOT EXISTS records_executions_active
  ON records ((data->>'status'), updated_at DESC)
  WHERE kind = 'executions' AND data->>'status' IN ('QUEUED', 'RUNNING');
