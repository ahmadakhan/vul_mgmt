--
-- 028 — make the defensive cast helpers genuinely parallel safe.
--
-- `safe_timestamptz` and `safe_numeric` (migration 009) wrap their casts in an
-- `EXCEPTION WHEN others` block so a single malformed feed value cannot abort a
-- listing. PL/pgSQL implements exception blocks with a subtransaction entry,
-- and PostgreSQL refuses to start a subtransaction inside a parallel worker:
--
--   ERROR: cannot start subtransactions during a parallel operation
--   CONTEXT: PL/pgSQL function safe_timestamptz(text) line 2
--
-- Both helpers were declared PARALLEL SAFE, so as soon as `records` was large
-- enough for the planner to choose a parallel aggregate (Threat Analytics &
-- Trends, and any other listing that filters or sorts on these helpers), the
-- query failed with a 500. `pg_input_is_valid` validates the text with the
-- type's own input function without raising, so the helpers can be plain SQL
-- with no exception block: invalid values still return NULL, and the planner
-- may now run them in parallel workers instead of losing parallelism (which is
-- what merely marking them PARALLEL RESTRICTED would have done).
CREATE OR REPLACE FUNCTION safe_timestamptz(value text)
RETURNS timestamptz
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
AS $$
  SELECT CASE
    WHEN value IS NULL OR value = '' THEN NULL
    WHEN pg_input_is_valid(value, 'timestamptz') THEN value::timestamptz
    ELSE NULL
  END;
$$;

CREATE OR REPLACE FUNCTION safe_numeric(value text)
RETURNS numeric
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
AS $$
  SELECT CASE
    WHEN value IS NULL OR value = '' THEN NULL
    WHEN pg_input_is_valid(value, 'numeric') THEN value::numeric
    ELSE NULL
  END;
$$;

INSERT INTO schema_migrations(version) VALUES(28) ON CONFLICT DO NOTHING;
