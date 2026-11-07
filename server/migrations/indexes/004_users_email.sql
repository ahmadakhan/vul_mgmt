-- Index build for the per-operator reset address (see migration 030).
--
-- `users` is populated on every live installation, so the build must be
-- CONCURRENTLY and outside the migration transaction. It backs the
-- case-insensitive address lookups the account list performs.
CREATE INDEX CONCURRENTLY IF NOT EXISTS users_email_lower
  ON users(lower(email));
