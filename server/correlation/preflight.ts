import type { Db } from '../db.ts';
const contracts: Record<string, Record<string, readonly string[]>> = {
  assets: {
    id: ['uuid'],
    vendor: ['text', 'character varying'],
    product: ['text', 'character varying'],
    version: ['text', 'character varying'],
    cpe_23: ['text', 'character varying'],
    purl: ['text', 'character varying'],
  },
  unstructured_advisories: {
    id: ['uuid'],
    title: ['text', 'character varying'],
    content: ['text', 'character varying'],
    url: ['text', 'character varying'],
    fingerprint: ['character', 'character varying'],
    tsv_content: ['tsvector'],
    processed_at: ['timestamp with time zone', 'timestamp without time zone'],
  },
  vendor_product_aliases: {
    alias: ['text', 'character varying'],
    vendor: ['text', 'character varying'],
    product: ['text', 'character varying'],
  },
};

// `assets` is absent: it is owner-managed, and migration 011 never adds a
// unique index to it. Requiring one here rejected a perfectly valid
// installation before its first migration ran. Only the relations whose
// indexes the ON CONFLICT clauses actually depend on are listed.
const uniqueIndexes: Record<string, readonly string[]> = {
  unstructured_advisories: ['fingerprint', 'url'],
  vendor_product_aliases: ['alias'],
};

// Generated columns the preflight may demand are read from the registry that
// migration 025 populates from pg_attribute. Hard-coding `tsv_content` here was
// a false positive: a protected, owner-managed table may legitimately use a
// trigger-maintained tsvector, and `vendor_product_aliases.normalized_alias`
// exists only when pg_trgm was usable. Demanding either of those is not part of
// this module's contract — their absence is not a defect, it is an operator's
// build choice, and the full-text/alias code paths already degrade gracefully.
const generatedColumnsTable = 'correlation_generated_columns';

/**
 * Relations this module creates itself (migrations 011–024). Their constraint
 * and generated-column contracts are asserted here because the DDL already
 * exists on an upgraded installation. Owner-managed/protected tables
 * (`assets`, `unstructured_advisories`, `vendor_product_aliases`) are only
 * checked for presence and type: an operator's pre-existing table legitimately
 * uses a trigger-maintained tsvector or differently named checks, and this
 * module must never demand that it be rebuilt.
 */
const ownedRelations = new Set([
  'correlation_matches',
  'low_confidence_review_buffer',
  'correlation_dead_letters',
  'correlation_pending',
  'correlation_managed_assets',
  'correlation_policy',
  'pre_cve_clusters',
]);

export interface SchemaPreflight {
  compatible: boolean;
  tablesToCreate: string[];
  issues: string[];
}
/** Read-only. Reports identifiers/types only, never row contents or connection details. */
export async function correlationPreflight(db: Db): Promise<SchemaPreflight> {
  const columns = await db.query<{ table_name: string; column_name: string; data_type: string }>(
    `SELECT table_name,column_name,data_type FROM information_schema.columns WHERE table_schema=current_schema()
     AND table_name=ANY($1::text[])`,
    [Object.keys(contracts)],
  );
  const tablesToCreate: string[] = [],
    issues: string[] = [];
  for (const [table, fields] of Object.entries(contracts)) {
    const actual = columns.rows.filter((row) => row.table_name === table);
    if (!actual.length) {
      tablesToCreate.push(table);
      continue;
    }
    for (const [field, types] of Object.entries(fields)) {
      const column = actual.find((row) => row.column_name === field);
      if (!column) issues.push(`${table}.${field}: required column missing`);
      else if (!types.includes(column.data_type))
        issues.push(`${table}.${field}: incompatible type ${column.data_type}`);
    }
  }

  const existingTables = Array.from(
    new Set(columns.rows.filter((row) => row.column_name === 'id').map((row) => row.table_name)),
  );

  if (existingTables.length) {
    // --- Unique index verification ---
    // ON CONFLICT clauses require backing UNIQUE indexes. A missing index on
    // fingerprint or url turns a race condition into a hard 23505 error that
    // dead-letters the advisory instead of merging it.
    const indexRows = await db.query<{
      tablename: string;
      indexname: string;
      indexdef: string;
    }>(
      `SELECT tablename,indexname,indexdef FROM pg_indexes WHERE schemaname=current_schema() AND tablename=ANY($1)`,
      [existingTables],
    );

    const uniqueByTable = new Map<string, Set<string>>();
    for (const row of indexRows.rows) {
      const def = row.indexdef;
      const uniqueMatch = def.match(/CREATE UNIQUE INDEX \w+ ON \w+\.(\w+) (?:USING \w+ )?\(([^)]+)\)/);
      if (uniqueMatch) {
        const tbl = uniqueMatch[1];
        const colList = uniqueMatch[2]
          .split(',')
          .map((c) => c.trim().replace(/^.*\((.+)\)$/, '$1'))
          .join(',')
          .toLowerCase();
        uniqueByTable.set(tbl, (uniqueByTable.get(tbl) ?? new Set()).add(colList));
      }
    }

    for (const [table, cols] of Object.entries(uniqueIndexes)) {
      const actual = uniqueByTable.get(table);
      if (actual) {
        for (const col of cols) {
          if (!actual.has(col.toLowerCase()))
            issues.push(`${table}: missing unique index on ${col}`);
        }
      }
    }

    // --- Index validity verification ---
    // pg_index.indisvalid catches incomplete indexes from a crashed CREATE INDEX
    // CONCURRENTLY. An invalid index is never used for constraint enforcement.
    const invalidIndexRows = await db.query<{ indexname: string }>(
      // `index` is a reserved word in PostgreSQL; using it as a bare alias makes
      // `index.relname` parse as a column named "index". Alias it `idx`.
      `SELECT cls.relname AS indexname
       FROM pg_index idx
       JOIN pg_class cls ON cls.oid = idx.indexrelid
       JOIN pg_namespace ns ON ns.oid = cls.relnamespace
       WHERE ns.nspname = current_schema()
         AND idx.indisunique IS TRUE
         AND idx.indisvalid IS FALSE`,
    );
    for (const row of invalidIndexRows.rows)
      issues.push(`Unique index ${row.indexname}: not valid (incomplete CREATE INDEX CONCURRENTLY?)`);

    // --- Generated column verification ---
    // Only columns the owning migration registered as generated are checked, so
    // a trigger-maintained tsvector on a protected table or a pg_trgm-dependent
    // alias column is not a defect. The registry itself is created by migration
    // 025; before that migration runs there is nothing to verify.
    const registry = await db.query<{ name: string | null }>(
      `SELECT to_regclass($1)::text AS name`,
      [generatedColumnsTable],
    );
    if (registry.rows[0]?.name) {
      const genColumnRows = await db.query<{
        table_name: string;
        column_name: string;
        attgenerated: string;
      }>(
        `SELECT g.table_name, g.column_name, COALESCE(a.attgenerated,'') AS attgenerated
         FROM ${generatedColumnsTable} g
         JOIN pg_class c ON c.relname = g.table_name AND c.relnamespace = to_regnamespace(current_schema())
         LEFT JOIN pg_attribute a ON a.attrelid = c.oid AND a.attname = g.column_name AND a.attnum > 0
         WHERE c.oid IS NOT NULL`,
      );
      for (const row of genColumnRows.rows)
        if (row.attgenerated !== 's')
          issues.push(`${row.table_name}.${row.column_name}: registered as generated, found plain column`);
    }

    // --- CHECK constraint verification ---
    // Constraint definitions are read from the relation's own schema. Matching
    // only on `relname` is ambiguous once the search_path reaches a second
    // schema that also holds a table of that name.
    // `existingTables` only lists tables that expose an `id` column. The
    // confidence CHECKs live on `correlation_matches` (no `id`) and on the
    // review buffer, so the constraint lookup must name its relations directly
    // instead of reusing that projection's list.
    // Non-required CHECK constraints (e.g. the pinned singleton policy row) may
    // legitimately be absent on a pre-existing installation; only the
    // confidence allow-lists are part of the contract.
    const checkRows = await db.query<{
      table_name: string;
      check_clause: string;
    }>(
      `SELECT c.relname AS table_name,
              pg_get_constraintdef(con.oid) AS check_clause
       FROM pg_constraint con
       JOIN pg_class c ON c.oid = con.conrelid
       JOIN pg_namespace n ON n.oid = c.relnamespace
       WHERE n.nspname = current_schema()
         AND con.contype = 'c'
         AND c.relname = ANY(ARRAY['correlation_matches','low_confidence_review_buffer'])`,
    );
    // PostgreSQL stores the expression in its own form (`= ANY (ARRAY[...])`,
    // quoted identifiers, `::text` casts), so an exact-string comparison against
    // the source literal rejected a correct constraint. Reduce it to its
    // significant tokens (identifiers and quoted literals) and compare
    // semantically: the security property is "only these confidence values are
    // allowed", not the DDL spelling.
    const checkTokens = (clause: string) =>
      (clause.match(/[A-Za-z_][A-Za-z0-9_]*|'[^']*'/g) ?? []).map((t) =>
        t.replace(/^'|'$/g, '').toLowerCase(),
      );
    const checksByTable = new Map<string, Set<string>[]>();
    for (const row of checkRows.rows) {
      const list = checksByTable.get(row.table_name) ?? [];
      list.push(new Set(checkTokens(row.check_clause)));
      checksByTable.set(row.table_name, list);
    }
    const requiredChecks: Record<string, (tokens: Set<string>) => boolean> = {
      correlation_matches: (t) =>
        t.has('confidence') && t.has('any') && t.has('high') && t.has('medium') && !t.has('low'),
      low_confidence_review_buffer: (t) => t.has('confidence') && t.has('low'),
    };
    // Preflight also runs BEFORE the first migration (`migrate()` calls it at
    // server/db.ts:74), so an owned table that does not exist yet is created by
    // migration 011 with the correct constraints — that is not a violation.
    // Only an owned table that exists without them is.
    for (const [table, matches] of Object.entries(requiredChecks))
      if (
        ownedRelations.has(table) &&
        existingTables.includes(table) &&
        !(checksByTable.get(table) ?? []).some(matches)
      )
        issues.push(`${table}: missing required confidence CHECK constraint`);
  }

  return { compatible: issues.length === 0, tablesToCreate, issues };
}
