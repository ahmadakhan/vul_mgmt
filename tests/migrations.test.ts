import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdir, readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { REQUIRED_SCHEMA_VERSION, indexStatements } from '../server/db.ts';

const migrationsDir = fileURLToPath(new URL('../server/migrations/', import.meta.url));

async function migrationFiles(): Promise<string[]> {
  return (await readdir(migrationsDir)).filter((file) => /^\d+_.*\.sql$/.test(file)).sort();
}

test('every migration records its own schema version', async () => {
  for (const file of await migrationFiles()) {
    const version = Number(file.slice(0, 3));
    const sql = await readFile(path.join(migrationsDir, file), 'utf8');
    // Without this marker the migration is re-applied on every startup and the
    // production gate cannot distinguish an upgraded database from a stale one.
    assert.match(
      sql,
      new RegExp(`INSERT INTO schema_migrations\\s*\\(version\\)\\s*VALUES\\s*\\(\\s*${version}\\s*\\)`),
      `${file} must record schema version ${version}`,
    );
  }
});

test('the production schema gate tracks the newest migration', async () => {
  const versions = (await migrationFiles()).map((file) => Number(file.slice(0, 3)));
  assert.equal(REQUIRED_SCHEMA_VERSION, Math.max(...versions));
});

test('migration version numbers are unique', async () => {
  // Two files shared version 15 and two shared version 14. The runner executes
  // whichever name it hard-codes, so the other file was silently never applied
  // — including the one that created the version-comparison SQL functions.
  // A duplicate number is an unrecoverable deployment hazard, not a warning.
  const files = await migrationFiles();
  const seen = new Map<number, string>();
  for (const file of files) {
    const version = Number(file.slice(0, 3));
    const previous = seen.get(version);
    assert.equal(
      previous,
      undefined,
      `migration version ${version} is claimed by both ${previous} and ${file}`,
    );
    seen.set(version, file);
  }
  // Gaps are also a hazard: a version recorded in schema_migrations with no
  // file means a database was stamped by a build that no longer exists.
  const numbers = [...seen.keys()].sort((a, b) => a - b);
  for (let index = 0; index < numbers.length; index++)
    assert.equal(numbers[index], index + 1, `migration numbering has a gap at ${index + 1}`);
});

test('every migration file is applied by the directory-driven runner', async () => {
  // The runner now reads the migrations directory, so this guards the pattern
  // it matches: a file that does not fit NNN_name.sql is silently never
  // applied. The check is structural because the runner has no hard-coded
  // list to compare against.
  const files = await migrationFiles();
  assert.ok(files.length > 0);
  for (const file of files) assert.match(file, /^\d{3}_.+\.sql$/);
});

const indexesDir = fileURLToPath(new URL('../server/migrations/indexes/', import.meta.url));

test('no transactional migration builds an index inline on a populated relation', async () => {
  // A plain CREATE INDEX takes SHARE on the table for the whole build. The
  // migration runner wraps every file in one transaction, so an inline build
  // blocks live writers for its duration and every ingest worker (3500ms
  // statement timeout) rolls back, exhausts its retries and is dead-lettered.
  // PostgreSQL also rejects CONCURRENTLY inside that transaction outright.
  //
  // The hazard is proportional to the number of rows already present when the
  // build runs, so inline builds are classified by whether the same file
  // created the relation immediately beforehand (empty at that instant, and
  // therefore safe and instant) or targets a pre-existing one:
  //   - application tables (migrations 001-010) exist before the correlation
  //     pipeline is deployed;
  //   - `assets`, `unstructured_advisories` and `vendor_product_aliases` are
  //     owner-managed and may hold millions of rows on a live installation.
  // Everything else in this directory is created empty by its own migration.
  // A new index on an existing, populated relation must go to
  // migrations/indexes/ and be built CONCURRENTLY.
  const protectedTables = ['assets', 'unstructured_advisories', 'vendor_product_aliases'];
  const buildTarget = /CREATE\s+(?:UNIQUE\s+)?INDEX(?:\s+CONCURRENTLY)?(?:\s+IF\s+NOT\s+EXISTS)?\s+\S+\s+ON\s+(?:ONLY\s+)?(?:[a-z_"]+\.)?"?([a-z0-9_]+)"?/gi;
  for (const file of await migrationFiles()) {
    const version = Number(file.slice(0, 3));
    const sql = await readFile(path.join(migrationsDir, file), 'utf8');
    const withoutComments = sql.replace(/--[^\n]*/g, '');
    for (const match of withoutComments.matchAll(buildTarget)) {
      const table = match[1].toLowerCase();
      // A relation created empty earlier in the same file is safe to index
      // inline: the build is instant and no writer can be holding a row.
      const createdHere = new RegExp(
        `CREATE\\s+(?:UNLOGGED\\s+|TEMP(?:ORARY)?\\s+)?TABLE\\s+(?:IF\\s+NOT\\s+EXISTS\\s+)?(?:[a-z_\"]+\\.)?\"?${table}\"?`,
        'i',
      ).test(withoutComments);
      assert.ok(
        (createdHere && !protectedTables.includes(table)) || version <= 10,
        `${file} builds an inline index on ${table}, which is not created empty in this file; ` +
          'move it to migrations/indexes/ (CONCURRENTLY, outside the migration transaction)',
      );
    }
  }
});

test('every index build is CONCURRENTLY and statement-splittable', async () => {
  const files = (await readdir(indexesDir)).filter((file) => /^\d{3}_.*\.sql$/.test(file));
  assert.ok(files.length > 0, 'index migrations directory must not be empty');
  for (const file of files) {
    const sql = await readFile(path.join(indexesDir, file), 'utf8');
    const statements = indexStatements(sql);
    assert.ok(statements.length > 0, `${file} produced no executable statements`);
    for (const statement of statements) {
      assert.match(
        statement,
        /^CREATE\s+(?:UNIQUE\s+)?INDEX\s+CONCURRENTLY\s+IF\s+NOT\s+EXISTS\s+\S+/i,
        `${file} has a statement that is not an idempotent concurrent index build: ${statement.slice(0, 80)}`,
      );
    }
  }
});

test('the statement splitter respects string literals and comments', () => {
  const statements = indexStatements(
    `-- comment with ; and 'quote'
     CREATE INDEX CONCURRENTLY IF NOT EXISTS a ON t (lower(x));\n
     CREATE INDEX CONCURRENTLY IF NOT EXISTS b ON t (y) WHERE y <> 'a;b';`,
  );
  assert.equal(statements.length, 2);
  assert.ok(statements.every((statement) => !statement.startsWith('--')));
  assert.match(statements[1], /'a;b'/);
});

test('a comment semicolon or apostrophe alone cannot split a statement', () => {
  // The combined case above can pass while either path is broken: a semicolon in
  // prose only splits if comments are handled after splitting, and an apostrophe
  // only breaks the statement if quote tracking runs before comment removal.
  // Index files are heavily commented prose, so each is asserted on its own.
  const semicolon = indexStatements(
    '-- explain the build; it must not lock\nCREATE INDEX CONCURRENTLY IF NOT EXISTS a ON t (x);',
  );
  assert.equal(semicolon.length, 1, 'a semicolon inside a comment must not split the statement');
  assert.match(semicolon[0]!, /^CREATE INDEX CONCURRENTLY/);

  const apostrophe = indexStatements(
    "-- it protects the table's writers\nCREATE INDEX CONCURRENTLY IF NOT EXISTS b ON t (y);",
  );
  assert.equal(apostrophe.length, 1, "an apostrophe in a comment must not open a string literal");
  assert.match(apostrophe[0]!, /^CREATE INDEX CONCURRENTLY/);
});

test('index builds target columns their migrations actually create', async () => {
  // Index DDL runs after every schema migration commits, so a build referencing
  // a column no migration creates fails only on a brand-new database — the one
  // place a release is least likely to be exercised. Check the union of columns
  // declared by CREATE TABLE and added by ALTER TABLE ... ADD COLUMN.
  const created = new Map<string, Set<string>>();
  const addColumn = (table: string, column: string) => {
    const set = created.get(table) ?? new Set<string>();
    set.add(column.toLowerCase());
    created.set(table, set);
  };
  for (const file of await migrationFiles()) {
    const sql = (await readFile(path.join(migrationsDir, file), 'utf8')).replace(/--[^\n]*/g, '');
    for (const match of sql.matchAll(/CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?\"?([a-z0-9_]+)\"?\s*\(([\s\S]*?)\n\s*\);/gi)) {
      const table = match[1].toLowerCase();
      for (const column of match[2].matchAll(/^\s*\"?([a-z_][a-z0-9_]*)\"?\s+[a-z]/gim))
        addColumn(table, column[1]);
    }
    for (const match of sql.matchAll(
      /ALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?\"?([a-z0-9_]+)\"?([\s\S]*?);/gi,
    )) {
      const table = match[1].toLowerCase();
      for (const column of match[2].matchAll(/ADD\s+COLUMN\s+(?:IF\s+NOT\s+EXISTS\s+)?\"?([a-z_][a-z0-9_]*)\"?/gi))
        addColumn(table, column[1]);
    }
  }
  for (const file of (await readdir(indexesDir)).filter((name) => /^\d{3}_.*\.sql$/.test(name))) {
    for (const statement of indexStatements(await readFile(path.join(indexesDir, file), 'utf8'))) {
      const parsed = /ON\s+(?:ONLY\s+)?\"?([a-z0-9_]+)\"?\s*\(\s*(?:lower\()?\s*\"?([a-z_][a-z0-9_]*)\"?/i.exec(statement);
      if (!parsed) continue;
      const [table, column] = [parsed[1].toLowerCase(), parsed[2].toLowerCase()];
      // `sessions`/`records`-style tables outside the migration set are not
      // covered; only assert for tables this directory creates.
      if (!created.has(table)) continue;
      assert.ok(
        created.get(table)!.has(column),
        `${file} indexes ${table}.${column}, which no migration creates`,
      );
    }
  }
});
test('migration 026 retires legacy operational_events indexes without losing coverage', async () => {
  // A database created while the retired 014 was live carries a transactional
  // `operational_events_timestamp` and a duplicate `operational_events_tracking_id_idx`.
  // 026 must retire both, and must NEVER drop the canonical
  // `operational_events_occurred_at` / `operational_events_tracking` that the
  // concurrent runner owns -- an earlier draft did exactly that.
  const sql = await readFile(path.join(migrationsDir, '026_operational_events_indexes_concurrently.sql'), 'utf8');
  const withoutComments = sql.replace(/--[^\n]*/g, '');
  assert.doesNotMatch(
    withoutComments,
    /DROP INDEX (?!IF EXISTS)[^;]*operational_events_occurred_at(?!\w)/,
    '026 must not drop the canonical occurred_at index',
  );
  assert.doesNotMatch(
    withoutComments,
    /DROP INDEX (?!IF EXISTS)[^;]*operational_events_tracking\s*(?![\w])/,
    '026 must not drop the canonical tracking index',
  );
  // Every unguarded DROP of a legacy name must be inside a DO block whose IF
  // tests that a replacement exists. Check the two legacy names appear only
  // inside a conditional block.
  for (const legacy of ['operational_events_timestamp', 'operational_events_tracking_id_idx']) {
    const drops = [...withoutComments.matchAll(new RegExp(`DROP INDEX ${legacy}`, 'g'))];
    for (const drop of drops) {
      const before = withoutComments.slice(0, drop.index);
      assert.match(
        before.slice(before.lastIndexOf('DO $$')),
        /IF to_regclass\([^)]*\) IS NOT NULL\s+AND/,
        `${legacy} is dropped without a coverage guard`,
      );
    }
  }
});
