-- Defensive casts for JSON payloads.
--
-- Collections are ordered and filtered in PostgreSQL, but `data->>'...'` values
-- originate from feeds, operator imports, and legacy rows written before the
-- current validation rules. A single malformed timestamp or numeric must not
-- abort an entire paginated listing with `invalid input syntax`. These helpers
-- return NULL for any value PostgreSQL cannot parse, so malformed rows sort
-- last or are excluded by a range filter instead of breaking the page.
CREATE OR REPLACE FUNCTION safe_timestamptz(value text)
RETURNS timestamptz
LANGUAGE plpgsql
IMMUTABLE
PARALLEL SAFE
AS $$
BEGIN
  IF value IS NULL OR value = '' THEN
    RETURN NULL;
  END IF;
  RETURN value::timestamptz;
EXCEPTION WHEN others THEN
  RETURN NULL;
END;
$$;

CREATE OR REPLACE FUNCTION safe_numeric(value text)
RETURNS numeric
LANGUAGE plpgsql
IMMUTABLE
PARALLEL SAFE
AS $$
BEGIN
  IF value IS NULL OR value = '' THEN
    RETURN NULL;
  END IF;
  RETURN value::numeric;
EXCEPTION WHEN others THEN
  RETURN NULL;
END;
$$;

INSERT INTO schema_migrations (version) VALUES (9);
