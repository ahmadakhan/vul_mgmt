/** Disposable, bounded benchmark. Never inserts benchmark records into the application schema. */
import { randomBytes, randomUUID } from 'node:crypto';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Readable, Writable } from 'node:stream';
import { performance } from 'node:perf_hooks';
import pg from 'pg';
import { createPool, migrate } from '../server/db.ts';
import { AdvisoryIngestor, type IngestionResult } from '../server/correlation/ingest.ts';
import { AdvisoryStreamProcessor } from '../server/correlation/stream.ts';
import { PipelineSupervisor } from '../server/correlation/supervisor.ts';
import { CorrelationTelemetry } from '../server/correlation/telemetry.ts';
import { DeadLetterQueue } from '../server/correlation/deadLetter.ts';
const items = Number(process.env.CORRELATION_BENCH_ITEMS || 500);
const concurrency = Number(process.env.CORRELATION_BENCH_CONCURRENCY || 4);
if (
  !Number.isInteger(items) ||
  items < 10 ||
  items > 100000 ||
  !Number.isInteger(concurrency) ||
  concurrency < 1 ||
  concurrency > 32
)
  throw new Error('Benchmark requires 10–100000 items and concurrency 1–32');
const connectionString = process.env.TEST_DATABASE_URL || process.env.DATABASE_URL;
if (!connectionString) throw new Error('TEST_DATABASE_URL or DATABASE_URL required');
const master = createPool(connectionString),
  schema = 'correlation_bench_' + randomBytes(12).toString('hex');
const directory = await mkdtemp(join(tmpdir(), 'correlation-bench-'));
let pool: pg.Pool | undefined;
try {
  await master.query(`CREATE SCHEMA ${schema}`);
  pool = new pg.Pool({
    connectionString,
    options: `-c search_path=${schema}`,
    max: Math.min(concurrency + 1, 12),
    connectionTimeoutMillis: 5000,
  });
  pool.on('error', () => {});
  await migrate(pool);
  const db = pool;
  await db.query(
    "INSERT INTO assets(id,vendor,product,version,purl) VALUES($1,'kubernetes','kubernetes','1.28.0','pkg:generic/kubernetes@1.28.0')",
    [randomUUID()],
  );
  const telemetry = new CorrelationTelemetry(
    new Writable({
      write(_c, _e, cb) {
        cb();
      },
    }),
  );
  const ingestor = new AdvisoryIngestor(
    telemetry,
    new DeadLetterQueue(directory, [randomBytes(32).toString('base64')], telemetry),
  );
  const supervisor = new PipelineSupervisor(db, ingestor);
  supervisor.setConcurrency(concurrency);
  const processor = new AdvisoryStreamProcessor(supervisor);
  const latencies: number[] = [];
  const original = ingestor.processIncomingAdvisory.bind(ingestor);
  let peakWorkers = 0,
    peakRss = process.memoryUsage().rss;
  const results: Record<IngestionResult, number> = { PROCESSED: 0, DUPLICATE: 0, DEAD_LETTER: 0, UNDURABLE: 0 };
  ingestor.processIncomingAdvisory = async (...args) => {
    const start = performance.now();
    peakWorkers = Math.max(peakWorkers, supervisor.active.size);
    const result = await original(...args);
    latencies.push(performance.now() - start);
    results[result]++;
    peakRss = Math.max(peakRss, process.memoryUsage().rss);
    return result;
  };
  async function* records() {
    for (let i = 0; i < items; i++) {
      const id = i % 10 === 9 ? i - 1 : i;
      yield {
        title: 'Kubernetes actively exploited vulnerability',
        content: 'An unpatched vulnerability affects k8s.',
        url: `https://example.invalid/benchmark/${id}`,
        purls: ['pkg:generic/kubernetes@1.28.0'],
      };
    }
  }
  const started = performance.now();
  await processor.processAdvisoryStream(Readable.from(records()), concurrency, db);
  const elapsedMs = performance.now() - started;
  latencies.sort((a, b) => a - b);
  const percentile = (p: number) =>
    latencies[Math.min(latencies.length - 1, Math.floor(latencies.length * p))];
  const unique = (await db.query('SELECT count(*)::int AS count FROM unstructured_advisories')).rows[0]
    .count as number;
  const report = {
    items,
    concurrency,
    elapsedMs: Math.round(elapsedMs),
    itemsPerSecond: items / (elapsedMs / 1000),
    latencyMs: { p50: percentile(0.5), p95: percentile(0.95), p99: percentile(0.99) },
    peakWorkers,
    peakRssMiB: peakRss / 1048576,
    results,
    uniqueArticles: unique,
    checks: {
      boundedWorkers: peakWorkers <= concurrency,
      noDeadLetters: results.DEAD_LETTER === 0,
      exactlyOnce: unique === items - Math.floor(items / 10) && results.DUPLICATE === Math.floor(items / 10),
    },
  };
  console.log(JSON.stringify(report, null, 2));
  if (process.env.CORRELATION_BENCH_REPORT)
    await writeFile(process.env.CORRELATION_BENCH_REPORT, JSON.stringify(report, null, 2) + '\n');
  if (Object.values(report.checks).some((value) => !value)) process.exitCode = 1;
  await supervisor.stop();
} finally {
  await pool?.end();
  await master.query(`DROP SCHEMA ${schema} CASCADE`);
  await master.end();
  await rm(directory, { recursive: true, force: true });
}
