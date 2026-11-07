-- Index for jobs that have pending edits while in review (see migration 031).
--
-- outbox is a live table in production, so the build must be CONCURRENTLY and
-- outside the migration transaction. The partial predicate keeps the index
-- proportional to the review-with-edits backlog (normally near-empty).

CREATE INDEX CONCURRENTLY IF NOT EXISTS outbox_edits_review
  ON outbox(created_at)
  WHERE status='REVIEW' AND edits != '{}'::jsonb;
