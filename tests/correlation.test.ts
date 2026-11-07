import supertest from 'supertest';
import { createApp } from '../server/app.ts';
import { createUser } from '../server/auth.ts';
import { loadConfig } from '../server/config.ts';
import { CorrelationRuntime } from '../server/correlation/runtime.ts';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { mkdtemp, readdir, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Readable, Writable } from 'node:stream';
import pg from 'pg';
import { AdvisoryInputSchema } from '../server/correlation/validation.ts';
import { evaluateVersion } from '../server/correlation/version.ts';
import { advisoryRecords, AdvisoryStreamProcessor } from '../server/correlation/stream.ts';
import { extractText } from '../server/correlation/extraction.ts';
import { CorrelationTelemetry } from '../server/correlation/telemetry.ts';
import { DeadLetterQueue } from '../server/correlation/deadLetter.ts';
import { AdvisoryIngestor } from '../server/correlation/ingest.ts';
import { PipelineSupervisor } from '../server/correlation/supervisor.ts';
import { createPool, migrate, put, get } from '../server/db.ts';
import { decrypt } from '../server/secrets.ts';
import { DEFAULT_SETTINGS } from '../shared/state.ts';
const silent = () =>
  new CorrelationTelemetry(
    new Writable({
      write(_chunk, _encoding, callback) {
        callback();
      },
    }),
  );
const key = randomBytes(32).toString('base64');
const advisory = (overrides: Record<string, unknown> = {}) => ({
  title: 'Kubernetes vulnerability actively exploited',
  content: 'An unpatched zero-day vulnerability affects k8s.',
  url: 'https://example.org/security/1',
  ...overrides,
});

test('correlation boundary rejects oversized input, credential URLs and unknown fields', () => {
  assert.equal(AdvisoryInputSchema.safeParse(advisory()).success, true);
  for (const raw of [
    advisory({ title: 'x'.repeat(201) }),
    advisory({ content: 'x'.repeat(50001) }),
    advisory({ url: 'https://user:secret@example.org/' }),
    advisory({ url: 'javascript:alert(1)' }),
    advisory({ injected: 'value' }),
  ])
    assert.equal(AdvisoryInputSchema.safeParse(raw).success, false);
  assert.equal(AdvisoryInputSchema.parse(advisory({ title: '  trimmed  ' })).title, 'trimmed');
});
test('version ranges preserve release candidates and refuse vendor backport coercion', () => {
  assert.equal(evaluateVersion('1.9', '>=1.0 <2.0'), 'AFFECTED');
  assert.equal(evaluateVersion('2.0.0', '<2.0'), 'UNAFFECTED');
  assert.equal(evaluateVersion('2.0.0-rc.1', '>=2.0.0-rc.1 <2.0.0'), 'AFFECTED');
  assert.equal(evaluateVersion('1.2.3-0ubuntu0.22.04.1', '<2.0'), 'REVIEW');
  assert.equal(evaluateVersion('1.2.3-8.el8_6', '<2.0'), 'REVIEW');
  assert.equal(evaluateVersion('1.2.3+vendor.patch', '<2.0'), 'REVIEW');
  assert.equal(evaluateVersion('1.2.3', '*'), 'REVIEW');
  assert.equal(evaluateVersion('2.4.41-2', '<2.4.41'), 'REVIEW');
  assert.equal(evaluateVersion('2.4.41-2', '>=2.0.0 <2.4.41'), 'REVIEW');
  assert.equal(evaluateVersion('1.0.0-rc.1', '<1.0.0'), 'AFFECTED');
  assert.equal(evaluateVersion('1.0.0-beta', '<1.0.0'), 'AFFECTED');
  assert.equal(evaluateVersion('1.0.0-preview.2', '<1.0.0'), 'AFFECTED');
});
test('NDJSON framing survives arbitrary UTF-8 splits and bounds malformed giant frames', async () => {
  const payload = Buffer.from(JSON.stringify(advisory({ title: 'Kubernetes 漏洞' })) + '\n');
  const decoded: unknown[] = [];
  for await (const item of advisoryRecords(
    Readable.from(
      [...payload].map((byte) => Buffer.from([byte])),
      { objectMode: false },
    ),
  ))
    decoded.push(item);
  assert.equal((decoded[0] as { title: string }).title, 'Kubernetes 漏洞');
  const frames = [];
  for await (const item of advisoryRecords(
    Readable.from([Buffer.from('x'.repeat(300000) + '\n' + JSON.stringify(advisory()))], {
      objectMode: false,
    }),
  ))
    frames.push(item);
  assert.equal(frames.length, 2);
  assert.deepEqual(frames[0], { invalidFrame: 'OVERSIZED_NDJSON' });
});
test('extraction uses an isolated worker and routes CVE-free exploitation to review', async () => {
  const telemetry = silent();
  const early = await extractText('k8s zero-day vulnerability actively exploited', telemetry, randomUUID());
  assert.equal(early.zeroDay, true);
  const ranged = await extractText('k8s versions before 2.0 vulnerability', telemetry, randomUUID());
  assert.deepEqual(ranged.ranges, [{ productPhrase: 'k8s', range: '<2.0' }]);
  const published = await extractText(
    'CVE-2026-12345 vulnerability actively exploited',
    telemetry,
    randomUUID(),
  );
  assert.equal(published.zeroDay, false);
  assert.deepEqual(published.cveIds, ['CVE-2026-12345']);
  const controller = new AbortController();
  controller.abort();
  await assert.rejects(extractText('text', telemetry, randomUUID(), controller.signal));
});
test('dead-letter fallback encrypts payload before filesystem persistence', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'correlation-dlq-'));
  try {
    const queue = new DeadLetterQueue(directory, [key], silent());
    await queue.capture(
      { secret: 'sensitive-customer-value' },
      'VALIDATION_FAILED',
      randomUUID(),
      {} as pg.Pool,
    );
    const files = await readdir(directory);
    assert.equal(files.length, 1);
    const stored = await readFile(join(directory, files[0]), 'utf8');
    assert.equal(stored.includes('sensitive-customer-value'), false);
    const letter = JSON.parse(stored);
    assert.equal(
      JSON.parse(decrypt(letter.encryptedPayload, [key], 'correlation-dlq')).secret,
      'sensitive-customer-value',
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
test('telemetry persistence drains only the entries of the committing advisory', async () => {
  // The buffer is shared by every in-flight ingest in the worker. Draining all
  // of it on one commit silently discards (and misattributes) the logs of other
  // concurrent advisories.
  const telemetry = silent();
  const A = randomUUID();
  const B = randomUUID();
  telemetry.log('INFO', 'advisory.a.first', { trackingId: A });
  telemetry.log('INFO', 'advisory.b.first', { trackingId: B });
  telemetry.log('INFO', 'advisory.a.second', { trackingId: A });
  const inserted: unknown[][] = [];
  const client = {
    query: async (sql: string, values?: unknown[]) => {
      if (/INSERT INTO operational_events/.test(sql)) inserted.push(values ?? []);
      return { rows: [], rowCount: 0 };
    },
  } as unknown as import('pg').PoolClient;
  await telemetry.persistBeforeCommit(client, A);
  assert.equal(inserted.length, 1);
  // 15 bound parameters per entry, two entries for advisory a.
  assert.equal(inserted[0].length, 30);
  // Advisory b's entry survives for its own commit.
  assert.deepEqual(
    telemetry.logs.map((entry) => entry.event),
    ['advisory.b.first'],
    "another advisory's telemetry must stay buffered",
  );
});
test('standard verbosity suppresses only routine telemetry, never warnings or errors', () => {
  // The logging level must reduce volume without ever losing the evidence an
  // operator needs during an incident.
  const telemetry = silent();
  telemetry.verbosity = 'standard';
  telemetry.log('INFO', 'ingestion.started', { trackingId: randomUUID() });
  telemetry.log('INFO', 'ingestion.committed', { trackingId: randomUUID() });
  telemetry.log('INFO', 'extraction.completed', { trackingId: randomUUID() });
  // Never suppressible at any level:
  telemetry.log('WARN', 'database.transaction_retry', { trackingId: randomUUID(), attempt: 1 });
  telemetry.log('CRITICAL', 'extraction.isolated', { trackingId: randomUUID() });
  telemetry.log('INFO', 'dead_letter.spool_exhausted', { trackingId: randomUUID() });
  telemetry.log('INFO', 'validation.failed', { trackingId: randomUUID(), count: 2 });
  assert.deepEqual(
    telemetry.logs.map((entry) => entry.event),
    [
      'database.transaction_retry',
      'extraction.isolated',
      'dead_letter.spool_exhausted',
      'validation.failed',
    ],
    'WARN/CRITICAL and diagnostic prefixes must survive standard verbosity',
  );
  assert.equal(telemetry.suppressedByVerbosity, 3);

  // Verbose keeps everything.
  const verbose = silent();
  verbose.verbosity = 'verbose';
  verbose.log('INFO', 'ingestion.started', { trackingId: randomUUID() });
  verbose.log('INFO', 'ingestion.committed', { trackingId: randomUUID() });
  assert.equal(verbose.logs.length, 2);
  assert.equal(verbose.suppressedByVerbosity, 0);
});
test(
  'log verbosity setting controls durable telemetry volume end to end',
  { skip: !process.env.TEST_DATABASE_URL },
  async () => {
    // The setting must be applied before the first telemetry entry. Resolving it
    // later in the transaction meant the early entries were filtered under the
    // previous level and the advisory committed with an empty buffer.
    const master = createPool(process.env.TEST_DATABASE_URL!);
    const schema = 'correlation_verbosity_' + randomBytes(12).toString('hex');
    let pool: pg.Pool | undefined;
    try {
      await master.query(`CREATE SCHEMA ${schema}`);
      pool = new pg.Pool({
        connectionString: process.env.TEST_DATABASE_URL,
        options: `-c search_path=${schema}`,
        max: 3,
      });
      await migrate(pool);
      const mk = () => {
        const telemetry = silent();
        return {
          telemetry,
          ingestor: new AdvisoryIngestor(
            telemetry,
            new DeadLetterQueue(join(tmpdir(), 'vlq-' + randomBytes(6).toString('hex')), [key], telemetry),
          ),
        };
      };
      const rows = async () =>
        Number((await pool!.query('SELECT count(*)::int AS n FROM operational_events')).rows[0].n);
      const advisory = (tag: string) => ({
        title: 'Kubernetes actively exploited',
        content: 'An unpatched zero-day vulnerability affects k8s.',
        url: `https://example.org/verbosity/${tag}-${randomUUID()}`,
      });

      await put(pool, 'settings', 'main', { ...DEFAULT_SETTINGS, logVerbosity: 'standard' });
      const beforeStandard = await rows();
      assert.equal(await mk().ingestor.processIncomingAdvisory(advisory('std'), pool), 'PROCESSED');
      assert.equal(await rows(), beforeStandard, 'standard must not persist routine telemetry');

      await put(pool, 'settings', 'main', { ...DEFAULT_SETTINGS, logVerbosity: 'verbose' });
      const beforeVerbose = await rows();
      await mk().ingestor.processIncomingAdvisory(advisory('vrb'), pool);
      assert.ok(
        (await rows()) > beforeVerbose,
        'verbose must persist the per-advisory telemetry',
      );
    } finally {
      await pool?.end();
      await master.query(`DROP SCHEMA ${schema} CASCADE`);
      await master.end();
    }
  },
);
test('a full dead-letter spool must not silently discard the advisory', async () => {
  // The spool exists to guarantee a failed advisory is never lost. When it is
  // full, throwing loses the very record it was meant to protect; the caller
  // then reports a rejection instead of DEAD_LETTER and the stream aborts.
  const directory = await mkdtemp(join(tmpdir(), 'correlation-dlq-full-'));
  try {
    const queue = new DeadLetterQueue(directory, [key], silent());
    // Fill the spool to its documented ceiling (file i is the (i+1)th letter).
    for (let i = 0; i < 255; i++)
      await queue.capture({ i }, 'VALIDATION_FAILED', randomUUID(), {} as pg.Pool);
    assert.equal(await queue.capture({ i: 255 }, 'VALIDATION_FAILED', randomUUID(), {} as pg.Pool), 'SPOOLED');
    const outcome = await queue.capture({ overflow: true }, 'VALIDATION_FAILED', randomUUID(), {} as pg.Pool);
    assert.equal(
      outcome,
      'capacity',
      'a full spool must be reported so the caller can use the database fallback',
    );
    // Exactly the ceiling, no partial writes left behind.
    const files = (await readdir(directory)).filter((f) => f.endsWith('.json'));
    assert.equal(files.length, 256);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('database-only dead-letter mode stores encrypted payloads without creating spool files', async () => {
  const directory = join(tmpdir(), 'correlation-dlq-db-' + randomBytes(6).toString('hex'));
  let inserted: unknown[] | undefined;
  const pool = {
    query: async (query: string | { text: string; values?: unknown[] }, values: unknown[] = []) => {
      const sql = typeof query === 'string' ? query : query.text;
      assert.match(sql, /INSERT INTO correlation_dead_letters/);
      inserted = typeof query === 'string' ? values : query.values;
      return { rows: [] };
    },
  } as unknown as pg.Pool;
  const queue = new DeadLetterQueue(directory, [key], silent(), true);
  try {
    assert.equal(await queue.capture({ secret: 'private payload' }, 'VALIDATION_FAILED', randomUUID(), pool), 'DATABASE');
    assert.ok(inserted);
    assert.notEqual(inserted[3], JSON.stringify({ secret: 'private payload' }));
    assert.deepEqual(await readdir(directory).catch(() => []), []);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('database startup migration drains all bounded legacy dead-letter batches', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'correlation-dlq-migrate-'));
  let inserted = 0;
  const pool = {
    query: async (query: string | { text: string; values?: unknown[] }) => {
      const sql = typeof query === 'string' ? query : query.text;
      assert.match(sql, /INSERT INTO correlation_dead_letters/);
      inserted++;
      return { rows: [] };
    },
  } as unknown as pg.Pool;
  const telemetry = silent();
  const queue = new DeadLetterQueue(directory, [key], telemetry);
  const ingestor = new AdvisoryIngestor(telemetry, queue);
  try {
    for (let index = 0; index < 12; index++)
      await queue.capture({ index }, 'VALIDATION_FAILED', randomUUID(), pool);
    assert.equal(await ingestor.flushDeadLetters(pool), 12);
    assert.equal(inserted, 12);
    assert.equal((await readdir(directory)).filter((file) => file.endsWith('.json')).length, 0);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test(
  'native correlation transactions, schema coexistence and stream concurrency',
  { skip: !process.env.TEST_DATABASE_URL },
  async () => {
    const master = createPool(process.env.TEST_DATABASE_URL!);
    const schema = `correlation_test_${randomBytes(12).toString('hex')}`;
    const directory = await mkdtemp(join(tmpdir(), 'correlation-integration-'));
    let pool: pg.Pool | undefined;
    try {
      await master.query(`CREATE SCHEMA ${schema}`);
      pool = new pg.Pool({
        connectionString: process.env.TEST_DATABASE_URL,
        options: `-c search_path=${schema}`,
        max: 6,
        connectionTimeoutMillis: 2000,
      });
      await migrate(pool);
      await migrate(pool);
      const telemetry = silent();
      const queue = new DeadLetterQueue(directory, [key], telemetry);
      const ingestor = new AdvisoryIngestor(telemetry, queue);
      const assetId = randomUUID();
      await pool.query(
        `INSERT INTO assets(id,vendor,product,version,purl) VALUES($1,'kubernetes','kubernetes','1.28.0','pkg:generic/kubernetes@1.28.0')`,
        [assetId],
      );
      const results = await Promise.all(
        Array.from({ length: 8 }, () => ingestor.processIncomingAdvisory(advisory(), pool!)),
      );
      assert.equal(results.filter((result) => result === 'PROCESSED').length, 1);
      assert.equal((await pool.query('SELECT * FROM unstructured_advisories')).rowCount, 1);
      assert.equal((await pool.query('SELECT * FROM correlation_matches')).rows[0].confidence, 'MEDIUM');
      await ingestor.processIncomingAdvisory(
        advisory({ url: 'https://example.org/security/exact', purls: ['pkg:generic/kubernetes@1.28.0'] }),
        pool,
      );
      assert.equal(
        (await pool.query("SELECT * FROM correlation_matches WHERE confidence='HIGH'")).rowCount,
        1,
      );
      await ingestor.processIncomingAdvisory(
        advisory({
          url: 'https://example.org/security/backport',
          entities: [{ vendor: 'kubernetes', product: 'kubernetes', affectedRange: '<1.0.0' }],
        }),
        pool,
      );
      // Explicit structured range excludes the asset; alias text must not override it.
      assert.equal(
        (
          await pool.query(
            `SELECT m.* FROM correlation_matches m JOIN unstructured_advisories a ON a.id=m.advisory_id WHERE a.url='https://example.org/security/backport'`,
          )
        ).rowCount,
        0,
      );
      await ingestor.processIncomingAdvisory(
        advisory({
          url: 'https://example.org/security/unmapped',
          title: 'Unpatched zero-day vulnerability actively exploited',
          content: 'Unidentified software exploitation in the wild.',
        }),
        pool,
      );
      // The synthetic branch requires keyword *density*, not just two hits:
      // `signals / tokens >= 0.002` (extraction.ts). Four tokens with two signals
      // is dense enough; the reason and the unassigned assetId are what this
      // asserts, because an empty assetId is what routes the row to the
      // unassigned review queue.
      const synthetic = (
        await pool.query(
          `SELECT b.* FROM low_confidence_review_buffer b JOIN unstructured_advisories a ON a.id=b.advisory_id WHERE a.url='https://example.org/security/unmapped'`,
        )
      ).rows;
      assert.equal(synthetic.length, 1);
      assert.equal(synthetic[0].asset_id, null, 'an unassigned finding must not name an asset');
      assert.match(synthetic[0].reason, /unverified early intelligence/);
      const retryEngine = new (await import('../server/correlation/engine.ts')).TextCorrelationEngine();
      const correlate = retryEngine.correlate.bind(retryEngine);
      let attempts = 0;
      retryEngine.correlate = async (...args) => {
        if (++attempts === 1) throw Object.assign(new Error('serialization retry'), { code: '40001' });
        return correlate(...args);
      };
      const retryIngestor = new AdvisoryIngestor(telemetry, queue, retryEngine);
      assert.equal(
        await retryIngestor.processIncomingAdvisory(advisory({ url: 'https://example.org/retry' }), pool),
        'PROCESSED',
      );
      assert.equal(attempts, 2);
      assert.equal(
        (await pool.query("SELECT id FROM unstructured_advisories WHERE url='https://example.org/retry'"))
          .rowCount,
        1,
      );
      // URL conflict with a different fingerprint: the updated advisory must
      // MERGE into the existing row (title AND the stored fingerprint) instead
      // of dead-lettering on a 23505.
      //
      // This previously targeted https://example.org/security/1 and asserted
      // the title changed. The advisory() default text contains "versions" and
      // "vulnerable" together, which the translator now correctly refuses to
      // reduce to one interval, so no match was written for that URL and the
      // row it inspected had never existed — the title assertion then passed on
      // the first insert, testing nothing. Use a URL whose text yields a
      // deterministic match and assert on BOTH columns.
      const mergeUrl = 'https://example.org/security/exact';
      const mergedFingerprint = (
        await pool.query(
          `SELECT fingerprint FROM unstructured_advisories WHERE url=$1`,
          [mergeUrl],
        )
      ).rows[0].fingerprint;
      assert.equal(
        await ingestor.processIncomingAdvisory(
          advisory({ url: mergeUrl, title: 'UPDATED TITLE', purls: ['pkg:generic/kubernetes@1.28.0'] }),
          pool,
        ),
        'PROCESSED',
        'a retitled advisory at an existing URL is merged, not dead-lettered',
      );
      const merged = (
        await pool.query('SELECT title,fingerprint FROM unstructured_advisories WHERE url=$1', [mergeUrl])
      ).rows[0];
      assert.equal(merged.title, 'UPDATED TITLE', 'advisory content should be merged on URL conflict');
      assert.notEqual(
        merged.fingerprint,
        mergedFingerprint,
        'the URL-conflict merge must refresh the fingerprint, not keep the stale one',
      );
      // The refreshed fingerprint must be the idempotency key for the new title:
      // re-submitting the same retitled payload is a DUPLICATE, not a new row.
      assert.equal(
        await ingestor.processIncomingAdvisory(
          advisory({ url: mergeUrl, title: 'UPDATED TITLE', purls: ['pkg:generic/kubernetes@1.28.0'] }),
          pool,
        ),
        'DUPLICATE',
      );
      assert.equal(
        (await pool.query('SELECT count(*)::int AS n FROM unstructured_advisories WHERE url=$1', [mergeUrl]))
          .rows[0].n,
        1,
      );
      // A merge replaces the advisory's content, so it must retire the matches
      // that content no longer supports. correlation_matches is insert-only and
      // keyed (advisory_id, asset_id), so before this a retitled advisory kept
      // its old HIGH match forever even when the new body mentioned nothing.
      const mergeAdvisoryId = (
        await pool.query('SELECT id FROM unstructured_advisories WHERE url=$1', [mergeUrl])
      ).rows[0].id;
      await pool.query(
        `INSERT INTO correlation_matches(advisory_id,asset_id,vendor,product,confidence,reason)
         VALUES($1,$2,'kubernetes','kubernetes','HIGH','stale conclusion')`,
        [mergeAdvisoryId, randomUUID()],
      );
      assert.equal(
        await ingestor.processIncomingAdvisory(
          advisory({ url: mergeUrl, title: 'FULLY RETITLED', content: 'Unrelated product news.', purls: [] }),
          pool,
        ),
        'PROCESSED',
      );
      assert.equal(
        (
          await pool.query(
            "SELECT * FROM correlation_matches WHERE advisory_id=$1 AND reason='stale conclusion'",
            [mergeAdvisoryId],
          )
        ).rowCount,
        0,
        'a merge must retire matches its new content no longer supports',
      );
      // A crash between INSERT and the match writes leaves `processed_at` NULL.
      // Replaying that advisory must re-correlate it, not report DUPLICATE.
      // `processed_at=now()` is used rather than NULL: a NULL statement would
      // write the same value back and suppress the row lock.
      await pool.query('UPDATE unstructured_advisories SET processed_at=now() WHERE url=$1', [mergeUrl]);
      assert.equal(
        await ingestor.processIncomingAdvisory(
          advisory({ url: mergeUrl, title: 'FULLY RETITLED', content: 'Unrelated product news.', purls: [] }),
          pool,
        ),
        'DUPLICATE',
        'a completed advisory is a duplicate on replay',
      );
      // Simulate the crash window: the row exists, correlation never committed.
      await pool.query('UPDATE unstructured_advisories SET processed_at=NULL WHERE url=$1', [mergeUrl]);
      assert.equal(
        await ingestor.processIncomingAdvisory(
          advisory({ url: mergeUrl, title: 'FULLY RETITLED', content: 'Unrelated product news.', purls: [] }),
          pool,
        ),
        'PROCESSED',
        'an unprocessed advisory is merged and re-correlated instead of being dropped',
      );
      assert.notEqual(
        (
          await pool.query('SELECT processed_at FROM unstructured_advisories WHERE url=$1', [mergeUrl])
        ).rows[0].processed_at,
        null,
        'replay must complete the advisory it resumed',
      );
      // The review-queue cap bounds one advisory's review rows. The range must
      // be one that reaches the comparator: "vulnerable before 9.0.0" translates
      // to `<9.0.0`, which REVIEWs each 1.0.x asset because the bound is coarser
      // than the deployed four-part style is here (a REVIEW, not a guess).
      await pool.query('UPDATE correlation_policy SET review_row_cap=1 WHERE id=1');
      const cappedUrl = 'https://example.org/security/capped';
      const cappedBody = 'capvendor capproduct patched in 9.0.0';
      await ingestor.processIncomingAdvisory(
        advisory({ url: cappedUrl, title: 'capvendor capproduct flaw', content: cappedBody }),
        pool,
      );
      for (let index = 0; index < 3; index++)
        await pool.query(
          "INSERT INTO assets(vendor,product,version,purl) VALUES('capvendor','capproduct','1.0.0',$1)",
          [`pkg:generic/capproduct@1.0.${index}`],
        );
      // The article is versionless, so each of the three assets is a MEDIUM
      // match. Cap the review queue and pin the advisory's versionless matches
      // through the explicit-entity path (no alias table edit needed).
      // A range whose bound is a distro backport forces every asset to REVIEW,
      // which is the branch the review queue exists for.
      const reviewSource = 'https://example.org/security/capped-3';
      await pool.query('UPDATE correlation_policy SET review_row_cap=1 WHERE id=1');
      await ingestor.processIncomingAdvisory(
        advisory({
          url: reviewSource,
          title: 'capvendor capproduct flaw',
          content: 'capvendor capproduct flaw is under review',
          entities: [{ vendor: 'capvendor', product: 'capproduct', affectedRange: '>=1.0.0 <2.0.0-ubuntu1' }],
        }),
        pool,
      );
      const cappedRows = (
        await pool.query(
          'SELECT b.* FROM low_confidence_review_buffer b JOIN unstructured_advisories a ON a.id=b.advisory_id WHERE a.url=$1',
          [reviewSource],
        )
      ).rowCount;
      assert.equal(cappedRows, 1, 'review rows per advisory are bounded by review_row_cap');
      await pool.query('UPDATE correlation_policy SET review_row_cap=200 WHERE id=1');
      await ingestor.processIncomingAdvisory({ poison: 'customer-secret' }, pool);
      await queue.flush(pool);
      assert.equal((await pool.query('SELECT * FROM correlation_dead_letters')).rowCount, 1);
      assert.equal(JSON.stringify(telemetry.logs).includes('customer-secret'), false);
      const supervisor = new PipelineSupervisor(pool, ingestor);
      await pool.query('UPDATE correlation_policy SET concurrency_limit=8 WHERE id=1');
      supervisor.setConcurrency(8);
      supervisor.setMemoryProbe(() => 90);
      // Hysteresis on the rise: one sample is a transient allocation spike, not
      // sustained pressure. The first probe only arms the guard; the second,
      // after one probe interval, sheds.
      await supervisor.check();
      assert.equal(supervisor.health, 'HEALTHY', 'a single high sample must not shed');
      await new Promise((resolve) => setTimeout(resolve, 1050));
      await supervisor.check();
      assert.equal(supervisor.health, 'DEGRADED_BACKPRESSURE');
      assert.equal(supervisor.concurrencyLimit, 4);
      // HIGH keeps a floor under shedding. Assert ADMISSION, not a recomputed
      // constant: the previous version checked `Math.max(2, ceil(8/4))` against
      // itself, which passes no matter what canAdmit does.
      const admitted: string[] = [];
      const controllers = [0, 1, 2].map(() => new AbortController());
      for (const [index, controller] of controllers.entries()) {
        const outcome = await Promise.race([
          supervisor.acquire(`high-${index}`, controller, 'HIGH').then(() => 'admitted'),
          new Promise<string>((resolve) => setTimeout(() => resolve('queued'), 150)),
        ]);
        admitted.push(outcome);
      }
      assert.equal(
        admitted.filter((outcome) => outcome === 'admitted').length,
        2,
        `HIGH must keep two slots while shedding, got ${admitted.join(',')}`,
      );
      for (const controller of controllers) controller.abort();
      for (let index = 0; index < 3; index++) supervisor.release(`high-${index}`);
      supervisor.setMemoryProbe(() => 50);
      await supervisor.check();
      assert.equal(supervisor.health, 'HEALTHY');
      assert.equal(supervisor.concurrencyLimit, 8);
      // The circuit breaker must survive a process restart. A crash-loop previously
      // cleared a five-minute pause on every restart and poured admission straight
      // back into the outage that opened it. Write the shared row, then build a
      // FRESH supervisor (new process) and prove it honours the pause.
      await pool.query(
        "UPDATE correlation_policy SET circuit_open_until=now()+interval '5 minutes', circuit_reason='restart-probe' WHERE id=1",
      );
      const restarted = new PipelineSupervisor(pool, ingestor);
      await restarted.check();
      assert.equal(restarted.health, 'RECOVERING_DB_SEVERANCE');
      await assert.rejects(
        restarted.acquire('after-restart', new AbortController(), 'HIGH'),
        /Supervisor paused/,
        'a restarted process must honour a persisted breaker, not clear it',
      );
      // It must not clear the row either: a sibling replica may still be honouring it.
      assert.equal(
        (await pool.query(`SELECT circuit_open_until IS NOT NULL AS open FROM correlation_policy WHERE id=1`))
          .rows[0].open,
        true,
      );
      // An expired shared pause is lifted, so a breaker cannot outlive its outage.
      await pool.query("UPDATE correlation_policy SET circuit_open_until=now()-interval '1 second' WHERE id=1");
      await restarted.check();
      await restarted.check();
      assert.equal(restarted.health, 'HEALTHY');
      assert.equal(
        (await pool.query(`SELECT circuit_open_until IS NULL AS cleared FROM correlation_policy WHERE id=1`))
          .rows[0].cleared,
        true,
      );
      supervisor.setConcurrency(2);
      const processor = new AdvisoryStreamProcessor(supervisor);
      let max = 0;
      const original = ingestor.processIncomingAdvisory.bind(ingestor);
      ingestor.processIncomingAdvisory = async (...args) => {
        max = Math.max(max, supervisor.active.size);
        return original(...args);
      };
      await Promise.all(
        [1, 2].map((stream) =>
          processor.processAdvisoryStream(
            Readable.from(
              Array.from({ length: 4 }, (_, i) =>
                advisory({ url: `https://example.org/stream/${stream}/${i}` }),
              ),
            ),
            4,
            pool!,
          ),
        ),
      );
      assert.ok(max <= 2, `Global worker ceiling exceeded: ${max}`);
      await supervisor.stop();
      const config = loadConfig({
        NODE_ENV: 'test',
        DATABASE_URL: process.env.TEST_DATABASE_URL,
        APP_ORIGIN: 'http://localhost',
      METRICS_TOKEN: 'test-metrics-token-with-at-least-32-characters',
        ENCRYPTION_KEY: key,
        WORKER_ENABLED: 'false',
      });
      await createUser(pool, 'native-admin', 'Disposable-native-test-password-2026!', 'ADMIN');
      const runtime = new CorrelationRuntime(pool, [key], directory);
      const app = createApp(pool, config, async () => ({ status: 200, headers: {}, body: '[]' }), {
        correlation: runtime,
      });
      const agent = supertest.agent(app);
      const login = await agent
        .post('/api/login')
        .set('Origin', config.APP_ORIGIN)
        .send({ username: 'native-admin', password: 'Disposable-native-test-password-2026!' });
      assert.equal(login.status, 200);
      const csrf = login.body.csrfToken as string;
      assert.equal((await agent.get('/api/correlation')).status, 200);
      assert.equal((await agent.get('/metrics')).status,401);
      const metrics=await agent.get('/metrics').set('Authorization','Bearer '+config.METRICS_TOKEN);
      assert.equal(metrics.status,200);
      assert.match(metrics.text,/vulnstream_correlation_items_total/);
      assert.equal((await agent.get('/api/correlation/workflows')).status,200);

      assert.equal(
        (await agent.post('/api/correlation/concurrency').set('Origin', config.APP_ORIGIN).send({ limit: 3 }))
          .status,
        403,
      );
      assert.equal(
        (
          await agent
            .post('/api/correlation/concurrency')
            .set('Origin', config.APP_ORIGIN)
            .set('x-csrf-token', csrf)
            .send({ limit: 3 })
        ).status,
        200,
      );
      const accepted = await agent
        .post('/api/correlation/ingest')
        .set('Origin', config.APP_ORIGIN)
        .set('x-csrf-token', csrf)
        .send({
          ndjson: JSON.stringify(advisory({ url: 'https://example.org/durable-api' })) + '\n' +
            JSON.stringify(advisory({ url: 'https://example.org/durable-api-2' })),
        });
      assert.equal(accepted.status, 202);
      assert.equal(accepted.body.queued, 2);
      assert.equal((await pool.query('SELECT * FROM correlation_pending')).rowCount, 2);
      // A submission containing anything malformed is rejected as a whole,
      // before it is queued. Previously the malformed line was enqueued and the
      // caller was told "accepted": the worker then re-validated it, dead-
      // lettered it, and the record was gone with no feedback. The response names
      // the record and the rule, never the rejected value.
      const rejected = await agent
        .post('/api/correlation/ingest')
        .set('Origin', config.APP_ORIGIN)
        .set('x-csrf-token', csrf)
        .send({
          ndjson: JSON.stringify(advisory({ url: 'https://example.org/durable-api-3' })) + '\n{invalid json}',
        });
      assert.equal(rejected.status, 400);
      assert.equal(rejected.body.queued, 0);
      assert.equal(rejected.body.rejected.length, 1);
      assert.equal(rejected.body.rejected[0].record, 2);
      assert.equal(
        (await pool.query('SELECT * FROM correlation_pending')).rowCount,
        2,
        'a rejected submission must queue nothing',
      );
      assert.equal(
        JSON.stringify(rejected.body).includes('durable-api-3'),
        false,
        'the rejected value is not echoed',
      );
      // Existing product/CVE simulator keeps its original contract with the new runtime attached.
      const legacy = await agent
        .post('/api/correlation/simulate')
        .set('Origin', config.APP_ORIGIN)
        .set('x-csrf-token', csrf)
        .send({ vendor: 'kubernetes', product: 'kubernetes' });
      assert.equal(legacy.status, 200);
    } finally {
      await pool?.end();
      await master.query(`DROP SCHEMA ${schema} CASCADE`);
      await master.end();
      await rm(directory, { recursive: true, force: true });
    }
  },
);

test(
  'owner-managed inventory columns and rows survive migration unchanged',
  { skip: !process.env.TEST_DATABASE_URL },
  async () => {
    const master = createPool(process.env.TEST_DATABASE_URL!);
    const schema = 'correlation_owner_' + randomBytes(12).toString('hex');
    let pool: pg.Pool | undefined;
    try {
      await master.query(`CREATE SCHEMA ${schema}`);
      pool = new pg.Pool({
        connectionString: process.env.TEST_DATABASE_URL,
        options: `-c search_path=${schema}`,
      });
      await pool.query(
        `CREATE TABLE assets(id uuid PRIMARY KEY,vendor text,product text,version text,cpe_23 text,purl text,owner_tag text DEFAULT 'untouched')`,
      );
      await pool.query("INSERT INTO assets(id,vendor,product) VALUES($1,'owner','inventory')", [
        randomUUID(),
      ]);
      const before = (
        await pool.query(
          "SELECT column_name,data_type,column_default,is_nullable FROM information_schema.columns WHERE table_schema=$1 AND table_name='assets' ORDER BY ordinal_position",
          [schema],
        )
      ).rows;
      const rows = (await pool.query('SELECT * FROM assets')).rows;
      await migrate(pool);
      assert.deepEqual(
        (
          await pool.query(
            "SELECT column_name,data_type,column_default,is_nullable FROM information_schema.columns WHERE table_schema=$1 AND table_name='assets' ORDER BY ordinal_position",
            [schema],
          )
        ).rows,
        before,
      );
      assert.deepEqual((await pool.query('SELECT * FROM assets')).rows, rows);
    } finally {
      await pool?.end();
      await master.query(`DROP SCHEMA ${schema} CASCADE`);
      await master.end();
    }
  },
);
test(
  'telemetry rows carry the durable clock retention and the event reader use',
  { skip: !process.env.TEST_DATABASE_URL },
  async () => {
    const master = createPool(process.env.TEST_DATABASE_URL!);
    const schema = 'correlation_clock_' + randomBytes(12).toString('hex');
    let pool: pg.Pool | undefined;
    try {
      await master.query(`CREATE SCHEMA ${schema}`);
      pool = new pg.Pool({
        connectionString: process.env.TEST_DATABASE_URL,
        options: `-c search_path=${schema}`,
        max: 2,
      });
      await migrate(pool);
      const telemetry = silent();
      const trackingId = randomUUID();
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        // Use a diagnostic entry: standard verbosity deliberately suppresses
        // routine lifecycle chatter, and this test is about the clock, not
        // about which entries survive.
        telemetry.log('WARN', 'database.transaction_retry', { trackingId });
        await telemetry.persistBeforeCommit(client, trackingId);
        await client.query('COMMIT');
      } finally {
        client.release();
      }
      // The pipeline shape supplies neither clock.
      await pool.query(
        "INSERT INTO operational_events(category,level,code,message) VALUES('PIPELINE','INFO','pipeline.started','x')",
      );
      const rows = (
        await pool.query<{ occurred_at: Date | null; timestamp: Date | null }>(
          'SELECT occurred_at,"timestamp" FROM operational_events',
        )
      ).rows;
      assert.equal(rows.length, 2);
      for (const row of rows) {
        // occurred_at NULL is the defect: retention filters on it and the event
        // reader reports it, so such a row is both unreadable and immortal.
        assert.ok(row.occurred_at, 'every row must carry the durable clock');
        assert.ok(row.timestamp, 'every row must carry a telemetry clock');
      }
      // Retention as the sweeper performs it: it must match the rows.
      const swept = await pool.query(
        "DELETE FROM operational_events WHERE occurred_at < now() + interval '1 second'",
      );
      assert.equal(swept.rowCount, 2, 'retention must be able to see telemetry rows');
      // A caller cannot persist two contradictory clocks: timestamp wins, so
      // ordering and retention always agree.
      await pool.query(
        `INSERT INTO operational_events(category,level,code,message,"timestamp",occurred_at)
         VALUES('PIPELINE','INFO','x','x',now()-interval '1 hour',now())`,
      );
      const reconciled = (
        await pool.query<{ occurred_at: Date; timestamp: Date }>(
          "SELECT occurred_at,\"timestamp\" FROM operational_events WHERE code='x'",
        )
      ).rows[0];
      assert.equal(
        reconciled.occurred_at.getTime(),
        reconciled.timestamp.getTime(),
        'the durable clock must be derived from the telemetry clock',
      );
      // A deliberate correction to the durable clock must take effect and be
      // mirrored. An earlier version of the trigger reset it back to timestamp,
      // so the UPDATE reported success while changing nothing.
      const corrected = (
        await pool.query<{ occurred_at: Date; timestamp: Date }>(
          `UPDATE operational_events SET occurred_at = occurred_at - interval '1 day'
           WHERE code='x' RETURNING occurred_at,"timestamp"`,
        )
      ).rows[0];
      assert.ok(
        Date.now() - corrected.occurred_at.getTime() > 20 * 3600_000,
        'a maintenance correction to occurred_at must stick',
      );
      assert.equal(
        corrected.occurred_at.getTime(),
        corrected.timestamp.getTime(),
        'both clocks must move together',
      );
      // An unrelated column update must not touch either clock.
      const untouched = (
        await pool.query<{ occurred_at: Date }>(
          "UPDATE operational_events SET message='x2' WHERE code='x' RETURNING occurred_at",
        )
      ).rows[0];
      assert.equal(untouched.occurred_at.getTime(), corrected.occurred_at.getTime());
    } finally {
      await pool?.end();
      await master.query(`DROP SCHEMA ${schema} CASCADE`);
      await master.end();
    }
  },
);
