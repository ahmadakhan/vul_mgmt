-- Fix the version_satisfies() stub that shipped in the (never-executed)
-- 015_version_range_pushdown.sql. That file shared version number 15 with
-- 015_correlation_lease_ownership.sql and was silently skipped by the runner,
-- so none of its functions existed. This migration is self-contained: it
-- creates the helpers it depends on, so it is correct on a fresh database and
-- on one that was upgraded from any earlier build.
--
-- IMPORTANT: the TypeScript comparator (server/correlation/version.ts) remains
-- the single source of truth. This function exists ONLY to let the match-
-- candidate pushdown exclude pairs whose version is PROVABLY outside a purely
-- numeric interval. It must never claim a verdict the TypeScript path would
-- not produce, so it returns 'REVIEW' for anything it cannot resolve exactly:
-- prereleases, distribution suffixes, wildcards, 4-component versions, and
-- single-bound ranges (semver.validRange rejects those).

-- Portable normalization: strictly two or three numeric components.
CREATE OR REPLACE FUNCTION portable_version(version_text TEXT)
RETURNS TEXT LANGUAGE sql IMMUTABLE STRICT AS $$
  SELECT CASE
    WHEN lower(trim(both from $1)) ~ '^v?\d{1,9}(\.\d{1,9}){1,2}$'
      THEN regexp_replace(lower(trim(both from $1)), '^v', '')
    ELSE NULL
  END
$$;

-- Pack four base-10000 components into a bigint. Returns NULL when any
-- component overflows, which callers treat as "cannot order".
CREATE OR REPLACE FUNCTION version_ordinal(version_text TEXT)
RETURNS BIGINT LANGUAGE plpgsql IMMUTABLE STRICT AS $$
DECLARE
  clean TEXT;
  parts TEXT[];
  ordinal BIGINT := 0;
  part BIGINT;
BEGIN
  clean := lower(trim(both from version_text));
  parts := regexp_match(clean, '^(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:\.(\d+))?$');
  IF parts IS NULL THEN RETURN NULL; END IF;
  FOR i IN 1..4 LOOP
    IF parts[i] IS NOT NULL THEN
      part := parts[i]::BIGINT;
      IF part >= 10000 THEN RETURN NULL; END IF;
      ordinal := ordinal * 10000 + part;
    ELSE
      ordinal := ordinal * 10000;
    END IF;
  END LOOP;
  RETURN ordinal;
EXCEPTION WHEN OTHERS THEN
  RETURN NULL;
END;
$$;

CREATE OR REPLACE FUNCTION version_satisfies(version_text TEXT, range_text TEXT)
RETURNS TEXT LANGUAGE plpgsql IMMUTABLE STRICT AS $$
DECLARE
  clean_version TEXT;
  terms TEXT[];
  term TEXT;
  op TEXT;
  bound_text TEXT;
  v_ordinal BIGINT;
  bound_ordinal BIGINT;
  all_ops_ok BOOLEAN := TRUE;
  lower_bound_seen BOOLEAN := FALSE;
  upper_bound_seen BOOLEAN := FALSE;
BEGIN
  IF version_text IS NULL OR range_text IS NULL OR length(range_text) > 200 THEN
    RETURN 'REVIEW';
  END IF;

  -- Distribution/backport carve-out, matching distributionSuffix() in
  -- server/correlation/version.ts. A distro rebuild cannot be ordered against
  -- an upstream bound.
  IF version_text ~ '[-~](ubuntu|deb|el[0-9]|rhel|centos|amzn|suse)' THEN
    RETURN 'REVIEW';
  END IF;

  clean_version := lower(trim(both from version_text));
  clean_version := regexp_replace(clean_version, '^v', '');

  -- Strictly two or three numeric components: the only shape the TypeScript
  -- portableVersion() maps onto a semver triple without coercion ambiguity.
  IF clean_version !~ '^\d{1,9}\.\d{1,9}(\.\d{1,9})?$' THEN
    RETURN 'REVIEW';
  END IF;
  v_ordinal := version_ordinal(clean_version);
  IF v_ordinal IS NULL THEN
    RETURN 'REVIEW';
  END IF;

  terms := regexp_split_to_array(trim(range_text), '\s+');
  IF array_length(terms, 1) IS NULL OR array_length(terms, 1) > 8 THEN
    RETURN 'REVIEW';
  END IF;

  FOREACH term IN ARRAY terms LOOP
    -- Two or three numeric components, optional comparator, no prerelease.
    IF term !~ '^(>=|<=|>|<|=)?v?\d{1,9}\.\d{1,9}(\.\d{1,9})?$' THEN
      RETURN 'REVIEW';
    END IF;
    IF term ~ '^[><]=' THEN
      op := substring(term from 1 for 2);
      bound_text := substring(term from 3);
    ELSIF term ~ '^[><=]' THEN
      op := substring(term from 1 for 1);
      bound_text := substring(term from 2);
    ELSE
      op := '=';
      bound_text := term;
    END IF;
    bound_text := regexp_replace(bound_text, '^v', '');
    bound_ordinal := version_ordinal(bound_text);
    IF bound_ordinal IS NULL THEN
      RETURN 'REVIEW';
    END IF;

    CASE op
      WHEN '>'  THEN
        IF NOT (v_ordinal > bound_ordinal) THEN all_ops_ok := FALSE; END IF;
        lower_bound_seen := TRUE;
      WHEN '>=' THEN
        IF NOT (v_ordinal >= bound_ordinal) THEN all_ops_ok := FALSE; END IF;
        lower_bound_seen := TRUE;
      WHEN '<'  THEN
        IF NOT (v_ordinal < bound_ordinal) THEN all_ops_ok := FALSE; END IF;
        upper_bound_seen := TRUE;
      WHEN '<=' THEN
        IF NOT (v_ordinal <= bound_ordinal) THEN all_ops_ok := FALSE; END IF;
        upper_bound_seen := TRUE;
      WHEN '='  THEN
        IF NOT (v_ordinal = bound_ordinal) THEN all_ops_ok := FALSE; END IF;
    END CASE;
  END LOOP;

  -- A single-bound range is rejected by semver.validRange() in the TypeScript
  -- path, which therefore returns REVIEW. Match that: only a range with a
  -- lower AND an upper bound (or an exact identity) may return a verdict.
  IF NOT lower_bound_seen AND NOT upper_bound_seen THEN
    -- Every term was '=' (identity match).
    RETURN CASE WHEN all_ops_ok THEN 'AFFECTED' ELSE 'UNAFFECTED' END;
  END IF;
  IF NOT (lower_bound_seen AND upper_bound_seen) THEN
    RETURN 'REVIEW';
  END IF;

  RETURN CASE WHEN all_ops_ok THEN 'AFFECTED' ELSE 'UNAFFECTED' END;
EXCEPTION WHEN OTHERS THEN
  RETURN 'REVIEW';
END;
$$;

-- The pushdown functions are not part of the ingestion trust boundary.
REVOKE EXECUTE ON FUNCTION version_satisfies(TEXT, TEXT) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION portable_version(TEXT) FROM PUBLIC;

INSERT INTO schema_migrations(version) VALUES(20) ON CONFLICT DO NOTHING;
