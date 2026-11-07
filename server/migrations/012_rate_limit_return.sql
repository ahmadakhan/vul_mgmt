-- Prevent successful consumes from falling through and restoring the token.
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
    RETURN; -- RETURN QUERY appends a row; it does not exit PL/pgSQL.
  END IF;

  UPDATE rate_limit_buckets
  SET tokens = v_refilled, updated_at = v_now
  WHERE bucket_key = p_key;
  RETURN QUERY SELECT false, GREATEST(1, CEIL((1 - v_refilled) / p_refill_per_ms)::int);
END;
$$;

INSERT INTO schema_migrations(version) VALUES(12) ON CONFLICT DO NOTHING;
