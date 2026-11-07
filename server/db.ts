import { correlationPreflight } from './correlation/preflight.ts';
import { compileCustomizedTemplate, compileDailyDigestTemplate } from '../src/utils/templateCompiler.ts';
import pg, { type PoolClient } from 'pg';
import { readFile, readdir } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

export type { PoolClient };
import { randomUUID } from 'node:crypto';
import {
  emptyState,
  type AppState,
  type CollectionKind,
  type HeavyCollectionKind,
  COLLECTION_KINDS,
} from '../shared/state.ts';
import { chainAuditLogs, hashAuditLog, SortedMerkleAccumulator } from '../src/utils/cryptoChain.ts';
import type { AuditLog } from '../src/types/index.ts';
import { orderWatchlist } from '../src/utils/watchlist.ts';
import { auditContext, auditText } from './audit.ts';
export type Db = pg.Pool | PoolClient;

/**
 * Merge libpq options into a connection string without discarding the ones the
 * caller already set.
 *
 * pg replaces a URL connection string's `options` with the pool-level `options`
 * rather than combining them, so passing `search_path` via `?options=` and the
 * statement timeout via the pool silently dropped the search_path
 * (per-schema test suites and any multi-schema deployment). Appending with a
 * space is exactly how libpq combines repeated `-c key=value` settings.
 */
const withLibpqOption = (url: string, option: string): string => {
  try {
    const parsed = new URL(url);
    const existing = parsed.searchParams.get('options')?.trim();
    parsed.searchParams.set('options', existing ? `${existing} ${option}` : option);
    return parsed.toString();
  } catch {
    // Keyword/value connection strings are not URLs; keep them untouched. They
    // rarely carry libpq options, and rewriting them risks corrupting a value.
    return url;
  }
};

export const createPool = (url: string) => {
  // Server-side per-session guard. A pool property named `statement_timeout` is
  // not supported by pg and is silently dropped, which left every query
  // unbounded. Override per pool with POOL_STATEMENT_TIMEOUT_MS.
  const statementTimeout = process.env.POOL_STATEMENT_TIMEOUT_MS
    ? parseInt(process.env.POOL_STATEMENT_TIMEOUT_MS)
    : 15000;
  const pool = new pg.Pool({
    connectionString: withLibpqOption(url, `-c statement_timeout=${statementTimeout}`),
    max: process.env.POOL_MAX_CONNECTIONS ? parseInt(process.env.POOL_MAX_CONNECTIONS) : 25,
    connectionTimeoutMillis: process.env.POOL_CONNECTION_TIMEOUT_MS ? parseInt(process.env.POOL_CONNECTION_TIMEOUT_MS) : 5000,
    idleTimeoutMillis: process.env.POOL_IDLE_TIMEOUT_MS ? parseInt(process.env.POOL_IDLE_TIMEOUT_MS) : 30000,
    application_name: 'vulnstream',
    timezone: 'LOCAL',
    // Production optimizations
    allowExitOnIdle: true,
    // Connection lifecycle management
    maxLifetime: process.env.POOL_MAX_LIFETIME_MS ? parseInt(process.env.POOL_MAX_LIFETIME_MS) : 600000,
    // Connection health check configuration
    keepAlive: true,
    keepAliveDelay: process.env.POOL_KEEPALIVE_DELAY_MS ? parseInt(process.env.POOL_KEEPALIVE_DELAY_MS) : 5000,
  } as any);
  
  // Monitor connection pool health
  pool.on('connect', () => {
    console.log(JSON.stringify({
      level: 'info',
      event: 'database-pool-connected',
      timestamp: new Date().toISOString(),
      totalCount: pool.totalCount,
    }));
  });
  
  pool.on('acquire', () => {
    console.log(JSON.stringify({
      level: 'info',
      event: 'database-pool-acquired',
      timestamp: new Date().toISOString(),
      idleCount: pool.idleCount,
    }));
  });
  
  pool.on('remove', () => {
    console.log(JSON.stringify({
      level: 'warn',
      event: 'database-pool-connection-removed',
      timestamp: new Date().toISOString(),
      totalCount: pool.totalCount,
    }));
  });
  
  pool.on('error', (error) => {
    console.error(JSON.stringify({
      level: 'error',
      event: 'database-pool-error',
      error: (error as any).message,
      code: (error as any).code,
      timestamp: new Date().toISOString(),
    }));
  });
  
  return pool;
};
/**
 * Advisory locks are scoped to the database, not to the active schema. Mixing
 * in the schema keeps independent deployments (and isolated per-schema test
 * databases) that share one PostgreSQL database from blocking each other.
 * COALESCE covers a search_path whose first schema does not exist yet.
 */
export const schemaLockKey = 'hashtext(COALESCE(current_schema(), current_database()))';

/**
 * The newest migration this build depends on. Production startup refuses to
 * run against an older schema instead of failing later on a missing column.
 *
 * Bump this whenever a migration is added: `tests/migrations.test.ts` asserts
 * it matches the highest `NNN_*.sql` file, so a forgotten bump fails the suite
 * rather than shipping a build that boots against an un-migrated database.
 */
export const REQUIRED_SCHEMA_VERSION = 38;

/**
 * Migration files sorted by numeric prefix. Only plain `NNN_name.sql` entries
 * participate; anything else (README, retired migrations, editor backups) is
 * ignored rather than accidentally executed.
 */
async function migrationFiles(): Promise<{ version: number; name: string }[]> {
  const directory = fileURLToPath(new URL('./migrations/', import.meta.url));
  const entries = await readdir(directory);
  return entries
    .filter((name) => /^\d{3}_.*\.sql$/.test(name))
    .map((name) => ({ version: Number(name.slice(0, 3)), name }))
    .sort((a, b) => a.version - b.version);
}

/**
 * Non-transactional index builds.
 *
 * PostgreSQL refuses CREATE INDEX CONCURRENTLY inside a transaction block, and a
 * plain CREATE INDEX takes SHARE on the table for the entire build. On a large
 * live installation that blocks every INSERT/UPDATE for the duration, and ingest
 * workers run under a 3500ms statement timeout, so each one rolls back, burns
 * its retry ladder and is dead-lettered. A maintenance window is therefore not
 * an acceptable workaround: it converts an ordinary deploy into a loss window.
 *
 * So index DDL lives in ./migrations/indexes/*.sql and is applied here, one
 * statement at a time, on an autocommit connection. A concurrent build that
 * fails leaves an INVALID index behind (the catalogue row outlives the abort);
 * the retry path drops it before rebuilding. `preflight.ts` rejects any unique
 * index whose `indisvalid` is false, so an interrupted build cannot masquerade
 * as a satisfied ON CONFLICT target.
 */
async function indexMigrationFiles(): Promise<{ name: string; sql: string }[]> {
  const directory = fileURLToPath(new URL('./migrations/indexes/', import.meta.url));
  const entries = (await readdir(directory)).filter((name) => /^\d{3}_.*\.sql$/.test(name)).sort();
  return Promise.all(
    entries.map(async (name) => ({
      name,
      sql: await readFile(new URL(`./migrations/indexes/${name}`, import.meta.url), 'utf8'),
    })),
  );
}

/**
 * Strip comments and split on semicolons outside string literals.
 *
 * A `--` comment is consumed as a unit before quote tracking runs, so a
 * semicolon or an apostrophe inside it can neither split the statement nor open
 * a string literal. Index files are heavily commented prose, and both occur.
 */
export function indexStatements(sql: string): string[] {
  const statements: string[] = [];
  let current = '';
  let quoted = false;
  for (let index = 0; index < sql.length; index++) {
    const char = sql[index];
    if (!quoted && char === '-' && sql[index + 1] === '-') {
      while (index < sql.length && sql[index] !== '\n') index++;
      current += '\n';
      continue;
    }
    if (char === "'") quoted = !quoted;
    if (!quoted && char === ';') {
      if (current.trim()) statements.push(current.trim());
      current = '';
      continue;
    }
    current += char;
  }
  if (current.trim()) statements.push(current.trim());
  return statements;
}

const indexName = (statement: string): string | null =>
  /CREATE\s+(?:UNIQUE\s+)?INDEX\s+CONCURRENTLY\s+IF\s+NOT\s+EXISTS\s+"?([a-z0-9_]+)"?/i.exec(
    statement,
  )?.[1] ?? null;

/**
 * Unlock helper with observability.
 *
 * Session advisory locks acquired outside `transaction()` (the pipeline run
 * lock, the index-build lock) must be released on their own connection; this
 * wraps that unlock with structured logging so a failed release — which can
 * pin the lock until the connection dies — is visible in the process log.
 */
export async function safeAdvisoryUnlock(client: pg.PoolClient, lockClass: number | string, schemaKey: string, lockKey: string): Promise<boolean> {
  try {
    await client.query('SELECT pg_advisory_unlock($1, $2)', [lockClass, schemaKey]);
    console.log(JSON.stringify({
      level: 'info',
      event: 'advisory_unlock_success',
      lockClass,
      lockKey,
      timestamp: new Date().toISOString(),
    }));
    return true;
  } catch (error) {
    console.error(JSON.stringify({
      level: 'error',
      event: 'advisory_unlock_failed',
      lockClass,
      lockKey,
      error: (error as Error).message,
      timestamp: new Date().toISOString(),
    }));
    return false;
  }
}

/**
 * Build the correlation indexes concurrently. Runs on its own connection, in
 * autocommit mode, after the transactional migrations have committed: the
 * relations must exist first, and the tables must not be locked by this run.
 */
export async function applyIndexMigrations(pool: pg.Pool): Promise<void> {
  const client = await pool.connect();
  let failed = false;
  try {
    // A concurrent build waits for every transaction that already holds a
    // conflicting lock. Ingest transactions are short (3500ms statement / 5000ms
    // idle), so a generous lock timeout retries rather than aborting; the
    // statement timeout is the real ceiling for a multi-million-row build.
    await client.query("SET statement_timeout = '900000ms'");
    await client.query("SET lock_timeout = '30000ms'");
    await client.query('SELECT set_config($1, current_schema(), false)', ['search_path']);
    // Serialize concurrent deploys of the same schema. Separate from the
    // migration lock because this runs outside that transaction.
    await client.query(
      'SELECT pg_advisory_lock(800005, hashtext(COALESCE(current_schema(), current_database())))',
    );
    try {
      for (const file of await indexMigrationFiles()) {
        for (const statement of indexStatements(file.sql)) {
          await buildIndex(client, statement, file.name);
        }
      }
    } finally {
      await client
        .query('SELECT pg_advisory_unlock(800005, hashtext(COALESCE(current_schema(), current_database())))')
        .catch(() => {});
    }
  } catch (error) {
    failed = true;
    throw error;
  } finally {
    client.release(failed);
  }
}

/**
 * One CREATE INDEX CONCURRENTLY with the failure handling that statement class
 * actually needs. Returns false when the index is permanently unavailable in
 * this deployment (pg_trgm absent) rather than throwing, so an optimisation
 * cannot block a deploy.
 */
// Enhanced buildIndex function with improved error handling and logging
async function buildIndex(client: pg.PoolClient, statement: string, file: string): Promise<void> {
  const name = indexName(statement);
  // A cancelled or failed concurrent build leaves an INVALID index behind.
  // DROP INDEX CONCURRENTLY also runs outside a transaction, and the retry
  // must not trip over the stale catalogue entry.
  if (name) {
    const invalid = await client
      .query<{ invalid: boolean }>(
        `SELECT NOT i.indisvalid AS invalid
           FROM pg_index i
           JOIN pg_class c ON c.oid = i.indexrelid
           JOIN pg_namespace n ON n.oid = c.relnamespace
          WHERE c.relname = $1 AND n.nspname = ANY(current_schemas(true))`,
        [name],
      )
      .catch(() => ({ rows: [] as { invalid: boolean }[] }));
    if (invalid.rows[0]?.invalid) {
      await client.query(`DROP INDEX CONCURRENTLY IF EXISTS "${name}"`);
      console.log(JSON.stringify({
        level: 'warn',
        event: 'index.invalid_rebuilt',
        index: name,
        file,
        timestamp: new Date().toISOString(),
      }));
    }
  }
  // pg_trgm is optional, and migration 019 revoked the fuzzy helpers from
  // PUBLIC. Building a trigram index is therefore an optimisation that a
  // deployment may legitimately be unable to perform — a failed build must
  // never block the release. Probe resolution exactly as PostgreSQL will:
  // `gin_trgm_ops` must be an opclass name in the session's search_path
  // namespace set and its access method. A global catalogue lookup answers the
  // wrong question: in a multi-tenant database the extension is typically
  // installed once, in one schema, and remains invisible to every other
  // tenant's session.
  if (statement.includes('gin_trgm_ops')) {
    const available = await client
      .query<{ available: boolean }>(
        `SELECT EXISTS (
           SELECT 1 FROM pg_opclass o
           JOIN pg_namespace n ON n.oid = o.opcnamespace
           JOIN pg_am a ON a.oid = o.opcmethod
           WHERE o.opcname = 'gin_trgm_ops' AND a.amname = 'gin'
             AND n.nspname = ANY(current_schemas(true))
         ) AS available`,
      )
      .catch(() => ({ rows: [{ available: false }] }));
    if (!available.rows[0]?.available) {
      console.warn(JSON.stringify({
        level: 'warn',
        event: 'index.skipped',
        index: name,
        file,
        reason: 'gin_trgm_ops-unavailable',
        timestamp: new Date().toISOString(),
      }));
      return;
    }
  }
  for (let attempt = 0; attempt <= 2; attempt++) {
    try {
      await client.query(statement);
      console.log(JSON.stringify({
        level: 'info',
        event: 'index.build_success',
        index: name,
        file,
        timestamp: new Date().toISOString(),
      }));
      return;
    } catch (error) {
      const code = String((error as { code?: string }).code ?? '');
      // A cancelled or failed concurrent build leaves an INVALID index behind.
      // DROP INDEX CONCURRENTLY also runs outside a transaction, and the retry
      // must not trip over the stale catalogue entry.
      if (name) await client.query(`DROP INDEX CONCURRENTLY IF EXISTS "${name}"`).catch(() => {});
      // Lock timeout and deadlock are transient: a live writer held the table.
      if ((code === '55P03' || code === '40P01') && attempt < 2) {
        await new Promise((resolve) => setTimeout(resolve, 2000 * (attempt + 1)));
        continue;
      }
      // An owner-managed table that does not exist in this schema is not an
      // install defect. The correlation index set covers `assets`,
      // `unstructured_advisories` and `vendor_product_aliases`, which the
      // platform operator may provision separately (a fresh isolated schema —
      // including every per-suite test schema — legitimately has none of them).
      // Failing migration here aborted deploy/startup for an optional
      // integration. Record the miss and let the preflight report the absent
      // relation when a code path that needs it actually runs.
      if (code === '42P01') {
        console.warn(JSON.stringify({
          level: 'warn',
          event: 'index.skipped',
          index: name,
          file,
          reason: 'relation-absent',
          timestamp: new Date().toISOString(),
        }));
        return;
      }
      throw Object.assign(new Error(`Index build failed (${file}, ${name ?? 'unnamed'}): ${code}`), {
        cause: error,
      });
    }
  }
}

export async function migrate(pool: pg.Pool) {
  const client = await pool.connect();
  let failed = false;
  try {
    await client.query('BEGIN');
    // Fail fast instead of queueing behind long-running worker transactions and
    // stalling the application behind an AccessExclusive DDL lock.
    await client.query("SET LOCAL lock_timeout = '10000ms'");
    // Migrations may include index builds; do not inherit the 15-second API
    // statement timeout.
    await client.query("SET LOCAL statement_timeout = '300000ms'");
    // Extensions live in the database-global `pg_extension` catalog, not in the
    // per-schema search path. Two schemas migrating at the same time can both
    // see `pg_trgm` as absent and race on `CREATE EXTENSION`, failing with
    // `pg_extension_name_index`. Serialize migration transactions across
    // schemas; the per-schema lock below still allows independent operation
    // once migrations have completed.
    await client.query('SELECT pg_advisory_xact_lock(800004)');
    await client.query(`SELECT pg_advisory_xact_lock(800001, ${schemaLockKey})`);
    const nativeContract = await correlationPreflight(client);
    if (!nativeContract.compatible)
      throw new Error('Protected correlation schema incompatible: ' + nativeContract.issues.join('; '));
    // Apply every migration file in the directory, in version order. A
    // hard-coded list silently skipped files whenever two shared a version
    // number (014 and 015 each did) and had to be edited for every new
    // migration. Reading the directory makes the file the source of truth.
    // On a brand-new database schema_migrations does not exist yet; 001 creates
    // it. Probe the CURRENT schema only: `to_regclass('schema_migrations')`
    // resolves through the whole search_path, so on a multi-tenant database a
    // leftover row set in `public` made every tenant probe see "already at the
    // latest version" and commit an empty schema — every later statement then
    // failed with 42P01 and the tenant looked broken with no migration error.
    const exists = await client.query(
      "SELECT to_regclass(format('%I.schema_migrations', current_schema())) AS name",
    );
    const appliedVersions = new Set<number>(
      exists.rows[0].name
        ? (await client.query<{ version: number }>(`SELECT version FROM ${exists.rows[0].name}`)).rows.map(
            (row) => Number(row.version),
          )
        : [],
    );
    for (const { version, name } of await migrationFiles()) {
      if (appliedVersions.has(version)) continue;
      await client.query(await readFile(new URL(`./migrations/${name}`, import.meta.url), 'utf8'));
    }
    await client.query('COMMIT');
  } catch (e) {
    failed = true;
    // A failure here may mean the connection itself is broken (e.g. the BEGIN
    // never completed); do not let a secondary ROLLBACK error mask the real cause.
    await client.query('ROLLBACK').catch(() => {});
    throw e;
  } finally {
    // Passing the failure tells the pool to destroy a possibly-broken connection
    // instead of recycling it back into the pool for the next caller.
    client.release(failed);
  }
  // Only after the schema transaction commits: the relations exist, and the
  // CREATE INDEX CONCURRENTLY statements must not run inside a transaction.
  await applyIndexMigrations(pool);
}
export interface TransactionOptions {
  /**
   * Optional named advisory locks acquired for the duration of the transaction.
   * Locks are sorted before acquisition to prevent deadlocks between callers.
   * The previous single global 800002 lock serialized every write in the
   * installation; scoped locks let independent domains proceed concurrently.
   */
  locks?: string[];
  /**
   * Locks the caller already owns on another connection, in the same
   * `hashtext(name), schemaLockKey` namespace as `locks`.
   *
   * Some transactions have to acquire an advisory lock before opening the
   * transaction and then keep it while the transaction reads rows that other
   * holders lock in the opposite order (the pipeline stop path). Re-acquiring
   * them here would deadlock; declaring them is what keeps the documented
   * "acquire locks in alphabetical order" invariant true for every lock the
   * transaction depends on.
   */
  lockAcquired?: string[];
  /**
   * Cancels the work at the database rather than only abandoning the promise.
   *
   * A caller that stops waiting on a hung query still holds its pool connection
   * until the statement finishes, so a wedged statement can pin a connection
   * indefinitely and starve the pool of every other job. Aborting requests a
   * PostgreSQL cancel (and drops the connection as a backstop), so the timeout
   * releases the resource it exists to protect.
   */
  signal?: AbortSignal;
}

/**
 * Requests cancellation on a live backend.
 *
 * `pg` exposes no cancel API, so the cancel request is sent on the *same*
 * connection. If the connection is stuck that request cannot be delivered and
 * the backend keeps running, so the connection is destroyed once the socket no
 * longer responds. Destroying it returns it to the pool as broken and the
 * server terminates the orphaned backend when it notices the dropped socket.
 */
const CANCEL_REQUEST_TIMEOUT_MS = 2000;
/**
 * Cancels the running statement on a live backend.
 *
 * The cancel request must not share the connection whose statement is stuck: a
 * `pg` client serialises queries per connection, so `SELECT pg_cancel_backend()`
 * issued on that connection is queued behind the very statement it is meant to
 * cancel and is only sent once the statement finishes. It is therefore sent from
 * a second connection, which is available because the stuck one is still held.
 */
async function cancelBackend(pool: pg.Pool, db: PoolClient): Promise<void> {
  const pid = (db as unknown as { processID?: number }).processID;
  // `destroy` exists at runtime but is absent from the public typings.
  const destroy = () => {
    const client = db as unknown as { destroy?: () => void };
    if (typeof client.destroy === 'function') client.destroy();
  };
  if (!pid) {
    // No backend pid is visible yet (the connection has not been checked out or
    // the driver did not populate `processID`), so a cancel request cannot be
    // sent. Deliver the destroy-only backstop so the connection is not returned
    // to the pool in a half-open state, and make the unsent cancel observable.
    console.warn(
      JSON.stringify({
        level: 'warn',
        event: 'cancelBackend.no_pid',
        reason: 'pg processID unavailable; delivering destroy-only backstop',
      }),
    );
    destroy();
    return;
  }
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    // A reachable database answers immediately. An unreachable one never
    // answers, so race the cancel against a short deadline: a request that
    // cannot be delivered is exactly the case where the socket must be dropped.
    await Promise.race([
      pool.query(`SELECT pg_cancel_backend(${Number(pid)})`), // integer pid from the driver
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error('CANCEL_TIMEOUT')), CANCEL_REQUEST_TIMEOUT_MS);
        timer.unref?.();
      }),
    ]);
  } catch {
    // The cancel could not be delivered (timeout or transport failure): drop
    // the socket so the pool surfaces the broken connection and PostgreSQL
    // terminates the orphaned backend when it notices the dropped socket.
    console.warn(
      JSON.stringify({
        level: 'warn',
        event: 'cancelBackend.timeout',
        pid,
        reason: 'cancel request not delivered within deadline; destroying connection',
      }),
    );
    destroy();
  } finally {
    if (timer) clearTimeout(timer);
  }
}

export async function transaction<T>(
  pool: pg.Pool,
  fn: (db: PoolClient) => Promise<T>,
  client?: PoolClient,
  options: TransactionOptions = {},
): Promise<T> {
  const db = client || (await pool.connect());
  let failed = false;
  let connectionError: Error | undefined;
  const onError = (error: Error) => {
    connectionError = error;
    failed = true;
  };
  db.on('error', onError);
  const onAbort = () => {
    connectionError = new Error('Transaction cancelled: operation exceeded its deadline');
    failed = true;
    void cancelBackend(pool, db);
  };
  if (options.signal?.aborted) {
    db.removeListener('error', onError);
    if (!client) db.release(true);
    throw new Error('Transaction cancelled: operation exceeded its deadline');
  }
  options.signal?.addEventListener('abort', onAbort, { once: true });
  try {
    await db.query('BEGIN');
    // Named, transaction-scoped locks replace the former global mutation lock.
    // Row-level locks on the records being mutated provide the per-record
    // serialization that operators actually need. CRITICAL: acquire locks in
    // global alphabetical order to prevent deadlocks from inconsistent ordering
    // across different callers (e.g., schemaLockKey before pipeline-queue).
    for (const lock of [...(options.locks ?? [])].filter(
      (name) => !options.lockAcquired?.includes(name),
    ).sort())
      await db.query(`SELECT pg_advisory_xact_lock(hashtext($1), ${schemaLockKey})`, [lock]);
    const result = await fn(db);
    if (connectionError) throw connectionError;
    await db.query('COMMIT');
    return result;
  } catch (error) {
    failed = true;
    // ROLLBACK can itself fail when the connection is already broken; swallow
    // that secondary failure so the caller sees the original, more useful error.
    if (!connectionError) await db.query('ROLLBACK').catch(() => {});
    throw error;
  } finally {
    // Release with the failure flag so a connection left in a bad state by a
    // transport-level error is destroyed rather than returned to the pool,
    // where a future caller would otherwise inherit an unusable connection.
    if (!client) db.release(failed);
    db.removeListener('error', onError);
    options.signal?.removeEventListener('abort', onAbort);
  }
}
export async function put(db: Db, kind: string, id: string, data: unknown) {
  await db.query(
    'INSERT INTO records(kind,id,data) VALUES($1,$2,$3) ON CONFLICT(kind,id) DO UPDATE SET data=EXCLUDED.data,updated_at=now()',
    [kind, id, JSON.stringify(data)],
  );
}
export async function putMany(db: Db, kind: string, items: { id: string; data: unknown }[]) {
  // PostgreSQL permits at most 65,535 bind parameters. Bound statement size as
  // well, and coalesce repeated IDs so a batch never updates one row twice.
  const unique = [...new Map(items.map((item) => [item.id, item])).values()];
  for (let offset = 0; offset < unique.length; offset += 1000) {
    const values: unknown[] = [];
    const params = unique.slice(offset, offset + 1000).map((item, index) => {
      values.push(kind, item.id, JSON.stringify(item.data));
      const first = index * 3 + 1;
      return `($${first},$${first + 1},$${first + 2})`;
    });
    await db.query(
      `INSERT INTO records(kind,id,data) VALUES${params.join(',')} ON CONFLICT(kind,id) DO UPDATE SET data=EXCLUDED.data,updated_at=now() WHERE records.data IS DISTINCT FROM EXCLUDED.data`,
      values,
    );
  }
}
export async function get<T>(db: Db, kind: string, id: string): Promise<T | undefined> {
  return (await db.query('SELECT data FROM records WHERE kind=$1 AND id=$2', [kind, id])).rows[0]?.data;
}
/**
 * Fetch multiple records of the same kind in a single query. Returns a map of
 * id -> data for all ids that exist. Used to collapse N+1 read patterns.
 */
export async function getMany<T>(db: Db, kind: string, ids: readonly string[]): Promise<Map<string, T>> {
  if (!ids.length) return new Map();
  const rows = await db.query<{ id: string; data: T }>(
    'SELECT id,data FROM records WHERE kind=$1 AND id = ANY($2::text[])',
    [kind, [...ids]],
  );
  return new Map(rows.rows.map((row) => [row.id, row.data]));
}
/**
 * Reads a record while holding a row-level lock. Command handlers use this for
 * read-modify-write sequences so two concurrent operators cannot overwrite each
 * other's changes without taking the installation-wide lock.
 */
export async function getForUpdate<T>(db: Db, kind: string, id: string): Promise<T | undefined> {
  return (await db.query('SELECT data FROM records WHERE kind=$1 AND id=$2 FOR UPDATE', [kind, id])).rows[0]
    ?.data;
}
export async function list<T>(db: Db, kind: string, limit?: number): Promise<T[]> {
  const safeLimit = typeof limit === 'number' && Number.isFinite(limit) && limit > 0 ? Math.floor(limit) : null;
  return (
    await db.query(
      safeLimit !== null
        ? `SELECT data FROM records WHERE kind=$1 ${recordOrder} LIMIT $2`
        : `SELECT data FROM records WHERE kind=$1 ${recordOrder}`,
      safeLimit !== null ? [kind, safeLimit] : [kind],
    )
  ).rows.map((row) => row.data);
}
export async function remove(db: Db, kind: string, id: string) {
  return (await db.query('DELETE FROM records WHERE kind=$1 AND id=$2', [kind, id])).rowCount;
}
/** Batch delete of many records of one kind, in one parameterised statement
 * (audit finding #10). One round trip for N ids instead of N round trips;
 * used for the alias-reconciliation sweep, which can remove hundreds of rows
 * per run. An empty input is a no-op. */
export async function removeMany(db: Db, kind: string, ids: readonly string[]): Promise<number> {
  if (!ids.length) return 0;
  return (
    await db.query('DELETE FROM records WHERE kind=$1 AND id = ANY($2::text[])', [kind, [...ids]])
  ).rowCount ?? 0;
}
export async function appendAudit(
  db: Db,
  event: string,
  details: string,
  actor: string,
  category: AuditLog['category'] = 'SECURITY',
  level: AuditLog['level'] = 'INFO',
  ipAddress: string = '',
  context?: Partial<NonNullable<AuditLog['context']>>,
): Promise<void> {
  // Outside a transaction, wrap the read/insert pair so the audit lock is held
  // for the whole operation instead of being released after the lock statement.
  if (db instanceof pg.Pool)
    return transaction(db, (tx) => appendAudit(tx, event, details, actor, category, level, ipAddress, context));
  // The audit chain is a single linked list; a dedicated named lock serializes
  // only audit appends instead of every state mutation in the installation.
  await db.query(`SELECT pg_advisory_xact_lock(hashtext($1), ${schemaLockKey})`, ['audit-chain']);
  // Plain SELECT (no row lock). pg_advisory_xact_lock above already serializes
  // all audit-append calls per schema, so a row lock here was redundant; dropping
  // it lets the least-privilege runtime role read the chain head with table SELECT
  // only and never requires UPDATE on the tamper-sensitive audit table.
  const previous = (await db.query('SELECT data FROM audit ORDER BY seq DESC LIMIT 1')).rows[0]?.data;
  const entry = chainAuditLogs(
    [
      {
        id: randomUUID(),
        timestamp: new Date().toISOString(),
        category,
        level,
        event: auditText(event, 200),
        details: auditText(details, 12000),
        actor: auditText(actor, 160) || 'system',
        ipAddress: auditText(ipAddress, 128),
        context: auditContext(context, level),
        prevHash: '',
        hash: '',
      },
    ],
    previous?.hash,
  )[0];
  await db.query('INSERT INTO audit(data) VALUES($1)', [JSON.stringify(entry)]);
}
export interface StateOptions {
  /**
   * Maximum rows returned for a heavy collection. Omit a kind to return all of
   * its rows (internal callers only). `/api/state` always supplies limits.
   */
  limits?: Partial<Record<HeavyCollectionKind, number>>;
}

export async function verifyStoredAudit(pool: pg.Pool, signal?: AbortSignal) {
  return transaction(pool, async (db) => {
    await db.query('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY');
    await db.query('DECLARE audit_chain_cursor NO SCROLL CURSOR FOR SELECT data FROM audit ORDER BY seq ASC');
    let previousHash: string | undefined;
    let verified = true;
    let logCount = 0;
    while (true) {
      signal?.throwIfAborted();
      const batch = await db.query<{ data: AuditLog }>('FETCH FORWARD 256 FROM audit_chain_cursor');
      if (!batch.rowCount) break;
      for (const { data: log } of batch.rows) {
        verified = /^[a-f0-9]{64}$/.test(log.hash) &&
          log.hash === hashAuditLog(log) &&
          (previousHash === undefined || log.prevHash === previousHash) && verified;
        previousHash = log.hash;
        logCount++;
      }
    }
    await db.query('CLOSE audit_chain_cursor');
    await db.query(`DECLARE audit_hash_cursor NO SCROLL CURSOR FOR
      SELECT data->>'hash' AS hash FROM audit ORDER BY (data->>'hash') COLLATE "C",seq`);
    const root = new SortedMerkleAccumulator();
    while (true) {
      signal?.throwIfAborted();
      const batch = await db.query<{ hash: string }>('FETCH FORWARD 256 FROM audit_hash_cursor');
      if (!batch.rowCount) break;
      for (const row of batch.rows) root.add(String(row.hash ?? ''));
    }
    await db.query('CLOSE audit_hash_cursor');
    return { verified, merkleRoot: root.root(), logCount };
  }, undefined, { signal });
}

const recordOrder = "ORDER BY CASE WHEN kind='feeds' THEN created_at ELSE updated_at END DESC,id";

export async function state(db: Db, options: StateOptions = {}): Promise<AppState> {
  const snapshot = emptyState();
  const arrayKinds = Object.entries(snapshot)
    .filter(([, value]) => Array.isArray(value))
    .map(([kind]) => kind)
    .filter((kind) => kind !== 'auditLogs');
  const limits = options.limits ?? {};
  const bounded = Object.entries(limits)
    .filter(([, limit]) => typeof limit === 'number' && limit >= 0)
    .map(([kind]) => kind)
    .filter((kind) => kind !== 'auditLogs') as HeavyCollectionKind[];
  const boundedSet = new Set<string>(bounded);
  const rows: { kind: string; data: unknown }[] = [];
  const unbounded = arrayKinds.filter((kind) => !boundedSet.has(kind));
  if (unbounded.length)
    rows.push(
      ...(
        await db.query(`SELECT kind,data FROM records WHERE kind=ANY($1::text[]) ${recordOrder}`, [unbounded])
      ).rows,
    );
  // Batch all bounded heavy-collection fetches into a single query using a
  // ROW_NUMBER() window. Per-kind limits are applied via a CASE expression so
  // each collection respects its own bound without a separate query.
  if (bounded.length) {
    const kinds = bounded;
    const limitValues = kinds.map((kind) => Math.max(0, Math.floor(limits[kind]!)));
    const limitCase = kinds
      .map((kind, i) => `WHEN '${kind.replace(/'/g, "''")}' THEN $${i + 2}::int`)
      .join(' ');
    rows.push(
      ...(
        await db.query<{ kind: string; data: unknown }>(
          `SELECT kind,data FROM (
            SELECT kind,data,ROW_NUMBER() OVER (PARTITION BY kind ORDER BY ${recordOrder.slice(9)}) AS rn
            FROM records WHERE kind=ANY($1::text[])
          ) ranked WHERE rn <= CASE kind ${limitCase} ELSE 0 END`,
          [kinds, ...limitValues],
        )
      ).rows,
    );
  }
  // Audit rows live in their own append-only table. Keep the historical 500-row
  // default for internal snapshots; the browser always supplies an explicit limit.
  const auditLimit = limits.auditLogs === undefined ? 500 : Math.max(0, Math.floor(limits.auditLogs));
  if (auditLimit)
    rows.push(
      ...(await db.query('SELECT data FROM audit ORDER BY seq DESC LIMIT $1', [auditLimit])).rows.map(
        (row) => ({ kind: 'auditLogs', data: row.data }),
      ),
    );
  rows.push(
    ...(
      await db.query('SELECT kind,data FROM records WHERE kind=ANY($1::text[])', [
        ['settings', 'emailConfig', 'template'],
      ])
    ).rows,
  );
  for (const row of rows) {
    if (Array.isArray(snapshot[row.kind as keyof AppState]))
      (snapshot[row.kind as keyof AppState] as unknown[]).push(row.data);
    else if (row.kind === 'settings') snapshot.settings = row.data as AppState['settings'];
    else if (row.kind === 'emailConfig') snapshot.emailConfig = row.data as AppState['emailConfig'];
    else if (row.kind === 'template') Object.assign(snapshot, row.data);
  }
  // Keep inventory position tied to original creation time. PostgreSQL record
  // updates change updated_at, so using the generic query order made edits jump
  // to the top of the monitored-products table.
  snapshot.watchlist = orderWatchlist(snapshot.watchlist);
  // Saved branding is authoritative; regenerate HTML with the current layout so
  // existing installations receive layout fixes without losing customization.
  snapshot.advisoryTemplate =
    snapshot.customAdvisoryTemplate || compileCustomizedTemplate(snapshot.templateCustomization);
  snapshot.dailyDigestTemplate =
    snapshot.dailyDigestCustomTemplate || compileDailyDigestTemplate(snapshot.dailyDigestCustomization);
  await attachCounts(db, snapshot);
  return snapshot;
}

/**
 * Exact collection sizes and KPI aggregates. They are computed independently of
 * the bounded arrays so a large installation still shows truthful totals.
 */
async function attachCounts(db: Db, snapshot: AppState) {
  const rows = await db.query<{ name: string; value: string }>('SELECT name,value FROM state_metrics');
  const metrics = new Map(rows.rows.map((row) => [row.name, Number(row.value)]));
  for (const kind of COLLECTION_KINDS) snapshot.counts[kind] = metrics.get(`collection:${kind}`) ?? 0;
  snapshot.summary = {
    activeFindings: metrics.get('summary:activeFindings') ?? 0,
    criticalFindings: metrics.get('summary:criticalFindings') ?? 0,
    kevFindings: metrics.get('summary:kevFindings') ?? 0,
    deliveredEmails: metrics.get('summary:deliveredEmails') ?? 0,
  };
}

/** Pipeline-only snapshot avoids loading executions, delivery logs, recipients and audit history.
 *
 * `skipCveData` omits the CVE corpus from the single-query snapshot. The
 * pipeline already holds the full corpus in memory (loaded once outside the
 * commit, line-ref audit finding #11), so re-materializing the identical rows
 * inside the commit doubled peak memory and re-parsed every record. The
 * transaction path reconstructs `snapshot.cveData` from that in-memory copy
 * instead; other callers keep the unfiltered snapshot. */
export async function pipelineState(db: Db, opts?: { skipCveData?: boolean }): Promise<AppState> {
  const snapshot = emptyState();
  const kinds: string[] = [
    'settings',
    'watchlist',
    ...(opts?.skipCveData ? [] : (['cveData'] as const)),
    'findings',
    'alertedCves',
    'intelligenceArticles',
    'template',
  ];
  const rows = await db.query(
    'SELECT kind,data FROM records WHERE kind=ANY($1::text[]) ORDER BY updated_at DESC,id',
    [kinds],
  );
  for (const row of rows.rows) {
    if (Array.isArray(snapshot[row.kind as keyof AppState]))
      (snapshot[row.kind as keyof AppState] as unknown[]).push(row.data);
    else if (row.kind === 'settings') snapshot.settings = row.data;
    else if (row.kind === 'template') Object.assign(snapshot, row.data);
  }
  snapshot.advisoryTemplate =
    snapshot.customAdvisoryTemplate || compileCustomizedTemplate(snapshot.templateCustomization);
  snapshot.dailyDigestTemplate =
    snapshot.dailyDigestCustomTemplate || compileDailyDigestTemplate(snapshot.dailyDigestCustomization);
  return snapshot;
}
