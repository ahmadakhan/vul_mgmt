-- Harden the trigram fuzzy alias lookup introduced in migration 016.
--
-- History: the original 016 defined fuzzy_asset_lookup() using OR between
-- vendor and product similarity, so an article mentioning a popular vendor
-- pulled every asset from that vendor regardless of product. It also added
-- generated columns to the owner-managed `assets` table, which the protected-
-- schema contract forbids. Both were removed; no code called them. What
-- remains here is the alias lookup, which the 0.6 threshold and missing
-- minimum length allowed to fuzz 4-character tokens onto unrelated aliases
-- ("java" -> "kafka", "jboss"). It is now length-gated and
-- threshold-raised, and its PUBLIC grant is removed.

CREATE OR REPLACE FUNCTION fuzzy_alias_lookup(
  input_alias TEXT,
  max_distance INT DEFAULT 2,
  similarity_threshold REAL DEFAULT 0.75
)
RETURNS TABLE (
  alias TEXT,
  vendor TEXT,
  product TEXT,
  similarity REAL
) LANGUAGE plpgsql STABLE AS $$
DECLARE
  normalized_input TEXT;
BEGIN
  normalized_input := regexp_replace(lower(input_alias), '[^a-z0-9]', '', 'g');
  -- Short tokens have tiny trigram sets: a single edit moves similarity
  -- wildly. Refuse to fuzz below 6 normalized characters.
  IF normalized_input IS NULL OR length(normalized_input) < 6 THEN
    RETURN;
  END IF;
  RETURN QUERY
  SELECT a.alias, a.vendor, a.product,
         similarity(normalized_input, a.normalized_alias) AS sim
  FROM vendor_product_aliases a
  WHERE length(a.normalized_alias) >= 6
    AND similarity(normalized_input, a.normalized_alias) >= similarity_threshold
  ORDER BY similarity(normalized_input, a.normalized_alias) DESC
  LIMIT 5;
END;
$$;


-- Fuzzy helpers are operator-facing utilities, not part of the ingestion
-- trust boundary. The engine calls the exact-index lookups; no runtime
-- permission is needed for arbitrary sessions to fuzz the corpus.
REVOKE EXECUTE ON FUNCTION fuzzy_alias_lookup(TEXT, INT, REAL) FROM PUBLIC;

INSERT INTO schema_migrations(version) VALUES(19) ON CONFLICT DO NOTHING;
