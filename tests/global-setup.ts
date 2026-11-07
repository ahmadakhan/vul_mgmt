import pg from 'pg';

/**
 * Vitest global setup.
 *
 * Database-backed suites opt in by reading `TEST_DATABASE_URL` at module load
 * (`skip: !process.env.TEST_DATABASE_URL`). Unit runs must not require a
 * PostgreSQL instance, so an explicitly configured database is required to be
 * reachable, while the fallback local URLs are probed best-effort and simply
 * leave database suites skipped when unavailable.
 *
 * The previous implementation exported `{ setup, teardown }` as a default
 * object, which Vitest rejects: a global setup module must default-export a
 * function whose return value is the teardown function.
 */
const FALLBACK_URLS = [
  'postgres://postgres:postgres@localhost:5433/vulnstream_test',
  'postgres://postgres:postgres@127.0.0.1:5433/vulnstream_test',
];

/** Schema names created by the database suites; only these are reclaimed. */
const LEAKED_SCHEMA_PATTERN = /^(?:(?:test|lifecycle)_[0-9a-f]{32}|test_schema_[0-9a-f]{16})$/;

async function probe(connectionString: string): Promise<pg.Pool> {
  const pool = new pg.Pool({
    connectionString,
    max: 1,
    connectionTimeoutMillis: 5000,
    application_name: 'vulnstream-test-global',
  });
  try {
    await pool.query('SELECT 1');
    return pool;
  } catch (error) {
    await pool.end().catch(() => {});
    throw error;
  }
}

export default async function setup(): Promise<() => Promise<void>> {
  const explicit = process.env.TEST_DATABASE_URL?.trim();
  let masterPool: pg.Pool | undefined;
  let connectionString: string | undefined;

  if (explicit) {
    try {
      masterPool = await probe(explicit);
      connectionString = explicit;
    } catch (error) {
      // An explicitly requested database is a hard requirement: failing here is
      // better than silently skipping every integration assertion.
      throw new Error(
        `TEST_DATABASE_URL is set but unreachable: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  } else {
    for (const candidate of FALLBACK_URLS) {
      try {
        masterPool = await probe(candidate);
        connectionString = candidate;
        break;
      } catch {
        // Try the next fallback.
      }
    }
  }

  if (!masterPool || !connectionString) {
    delete process.env.TEST_DATABASE_URL;
    delete process.env.__VULNSTREAM_TEST_MASTER_URL;
    // CI must not report green while every database assertion was skipped. A
    // local run without PostgreSQL keeps working (the suites skip cleanly); a
    // CI run opts into this guard so a missing database is a red build.
    if (process.env.CI === 'true' || process.env.VULNSTREAM_REQUIRE_TEST_DB === 'true') {
      // Fail the run before any suite starts. A thrown Error reaches Vite's
      // stack-trace formatter and aborts with an unrelated "code.charCodeAt"
      // startup error, which hides the real reason; a loud message plus a
      // non-zero exit code is deterministic across runners.
      console.error(
        '[test-global] No reachable test database, but CI/VULNSTREAM_REQUIRE_TEST_DB requires one.\n' +
          'Set TEST_DATABASE_URL to a disposable PostgreSQL database.',
      );
      process.exit(1);
    }
    console.warn(
      '[test-global] No reachable test database; database-backed suites will be skipped',
    );
    return async () => {};
  }

  // Inherited by forked workers, so suite modules see the resolved database.
  process.env.TEST_DATABASE_URL = connectionString;
  process.env.__VULNSTREAM_TEST_MASTER_URL = connectionString;

  const dbName = new URL(connectionString).pathname.replace(/^\//, '');
  console.log(`[test-global] Database ready: ${dbName}`);

  return async () => {
    try {
      const schemas = await masterPool.query<{ schema_name: string }>(
        "SELECT schema_name FROM information_schema.schemata WHERE schema_name LIKE 'test\\_%' OR schema_name LIKE 'lifecycle\\_%'",
      );
      for (const row of schemas.rows) {
        if (!LEAKED_SCHEMA_PATTERN.test(row.schema_name)) continue;
        await masterPool
          .query(`DROP SCHEMA IF EXISTS "${row.schema_name}" CASCADE`)
          .catch((error: unknown) =>
            console.error(
              `[test-global] Failed to drop schema ${row.schema_name}: ${error instanceof Error ? error.message : String(error)}`,
            ),
          );
      }
    } finally {
      await masterPool.end().catch(() => {});
    }
    console.log('[test-global] Cleanup complete');
  };
}
