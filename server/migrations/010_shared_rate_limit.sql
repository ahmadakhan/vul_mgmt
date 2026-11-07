-- Shared mutation quota for multi-replica deployments.
--
-- The previous limiter kept a token bucket in process memory, so each replica
-- enforced its own burst allowance. The bucket now lives in PostgreSQL and is
-- consumed atomically, giving the installation one quota per operator.
CREATE TABLE IF NOT EXISTS rate_limit_buckets (
  bucket_key text PRIMARY KEY,
  tokens double precision NOT NULL,
  updated_at timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS rate_limit_buckets_updated_at
  ON rate_limit_buckets(updated_at);

-- Refill and consume in a single function call. The INSERT creates a full
-- bucket for a new key; the FOR UPDATE read serializes concurrent replicas; the
-- subsequent UPDATE persists the refilled balance. clock_timestamp() is taken
-- after the lock is acquired so time spent waiting is not lost.
CREATE OR REPLACE FUNCTION consume_rate_limit_token(
  p_key text,
  p_capacity double precision,
  p_refill_per_ms double precision
) RETURNS TABLE(allowed boolean, retry_after_ms integer)
LANGUAGE plpgsql AS $$
DECLARE
  v_tokens double precision;
  v_updated timestamptz;
  v_now timestamptz;
  v_refilled double precision;
BEGIN
  IF p_key IS NULL OR p_key = '' THEN
    RAISE EXCEPTION 'rate limit key must not be empty';
  END IF;
  IF p_capacity <= 0 OR p_refill_per_ms <= 0 THEN
    RAISE EXCEPTION 'rate limit capacity and refill rate must be positive';
  END IF;

  INSERT INTO rate_limit_buckets(bucket_key, tokens, updated_at)
  VALUES (p_key, p_capacity, clock_timestamp())
  ON CONFLICT (bucket_key) DO NOTHING;

  SELECT b.tokens, b.updated_at INTO v_tokens, v_updated
  FROM rate_limit_buckets b
  WHERE b.bucket_key = p_key
  FOR UPDATE;

  v_now := clock_timestamp();
  v_refilled := LEAST(
    p_capacity,
    v_tokens + GREATEST(0, EXTRACT(EPOCH FROM (v_now - v_updated)) * 1000) * p_refill_per_ms
  );

  IF v_refilled >= 1 THEN
    UPDATE rate_limit_buckets
    SET tokens = v_refilled - 1, updated_at = v_now
    WHERE bucket_key = p_key;
    -- Opportunistic pruning keeps the table bounded to recently active
    -- operators without a separate scheduler process.
    IF random() < 0.01 THEN
      DELETE FROM rate_limit_buckets WHERE updated_at < v_now - interval '1 day';
    END IF;
    RETURN QUERY SELECT true, 0;
  END IF;

  UPDATE rate_limit_buckets
  SET tokens = v_refilled, updated_at = v_now
  WHERE bucket_key = p_key;
  RETURN QUERY SELECT false, GREATEST(1, CEIL((1 - v_refilled) / p_refill_per_ms)::int);
END;
$$;

INSERT INTO schema_migrations(version) VALUES(10) ON CONFLICT DO NOTHING;
