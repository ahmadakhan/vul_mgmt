import pg from 'pg';
import { randomBytes } from 'node:crypto';
import { afterAll } from 'vitest';
import { migrate } from '../server/db.ts';

/**
 * Per-file isolated-schema support for Vitest.
 *
 * Tests that need PostgreSQL call `setupTestDatabase()` from their own
 * `beforeAll`. Provisioning stays opt-in so pure unit files never require a
 * database. The returned pool carries `search_path` in its connection options,
 * which means every connection the pool opens — including the one `migrate()`
 * checks out — is scoped to the isolated schema. Setting `search_path` with a
 * transaction-scoped `SET` on one pooled connection did not survive checkout of
 * a different connection and silently ran migrations against `public`.
 */

export interface TestSchemaContext {
  schemaName: string;
  connectionString: string;
  pool: pg.Pool;
}

let currentContext: TestSchemaContext | null = null;

export function useTestDatabase(): TestSchemaContext {
  if (!currentContext) {
    throw new Error(
      'Test database not initialized. Call `await setupTestDatabase()` from the file\'s beforeAll hook.',
    );
  }
  return currentContext;
}

function masterUrl(): string {
  const url = process.env.__VULNSTREAM_TEST_MASTER_URL || process.env.TEST_DATABASE_URL;
  if (!url) {
    throw new Error(
      'TEST_DATABASE_URL must be set for test database setup. ' +
        'Run with `TEST_DATABASE_URL=… npm run test:unit` or `npm run test:integration`.',
    );
  }
  return url;
}

/** Builds a URL whose every pooled connection uses the isolated schema. */
function schemaUrl(url: string, schemaName: string): string {
  const parsed = new URL(url);
  parsed.searchParams.set('options', `-c search_path=${schemaName},public`);
  return parsed.href;
}

export async function setupTestDatabase(): Promise<TestSchemaContext> {
  if (currentContext) return currentContext;

  const source = masterUrl();
  const schemaName = `test_schema_${randomBytes(8).toString('hex')}`;
  const admin = new pg.Client({
    connectionString: source,
    application_name: 'vulnstream-test-perfile',
  });

  await admin.connect();
  try {
    await admin.query(`CREATE SCHEMA "${schemaName}"`);
  } finally {
    await admin.end().catch(() => {});
  }

  const connectionString = schemaUrl(source, schemaName);
  const pool = new pg.Pool({
    connectionString,
    max: 2,
    connectionTimeoutMillis: 5000,
    application_name: `vulnstream-test-${schemaName.substring(0, 20)}`,
  });

  try {
    await migrate(pool);
  } catch (error) {
    await pool.end().catch(() => {});
    const cleanup = new pg.Client({ connectionString: source });
    await cleanup.connect().catch(() => {});
    await cleanup.query(`DROP SCHEMA IF EXISTS "${schemaName}" CASCADE`).catch(() => {});
    await cleanup.end().catch(() => {});
    throw error;
  }

  currentContext = { schemaName, connectionString, pool };
  (globalThis as Record<string, unknown>).__TEST_SCHEMA_NAME__ = schemaName;

  console.log(`[test-perfile] Created isolated schema: ${schemaName}`);
  return currentContext;
}

export async function teardownTestDatabase(): Promise<void> {
  const context = currentContext;
  if (!context) return;
  currentContext = null;
  delete (globalThis as Record<string, unknown>).__TEST_SCHEMA_NAME__;

  const { schemaName, pool } = context;
  await pool.end().catch(() => {});

  const source = process.env.__VULNSTREAM_TEST_MASTER_URL || process.env.TEST_DATABASE_URL;
  if (!source) return;

  const admin = new pg.Client({
    connectionString: source,
    application_name: 'vulnstream-test-teardown',
  });
  try {
    await admin.connect();
    await admin.query(`DROP SCHEMA IF EXISTS "${schemaName}" CASCADE`);
    console.log(`[test-perfile] Dropped isolated schema: ${schemaName}`);
  } catch (error) {
    console.error(
      `[test-perfile] Error dropping schema ${schemaName}: ${error instanceof Error ? error.message : String(error)}`,
    );
  } finally {
    await admin.end().catch(() => {});
  }
}

export async function getTestDb(): Promise<pg.Pool> {
  if (!currentContext?.pool) {
    throw new Error('Test database not initialized. Call `await setupTestDatabase()` first.');
  }
  return currentContext.pool;
}

// Runs per test file. A no-op unless that file provisioned a schema, and it
// must be registered here because setup files are the only per-file hook
// surface Vitest exposes outside the test module itself.
afterAll(teardownTestDatabase);
