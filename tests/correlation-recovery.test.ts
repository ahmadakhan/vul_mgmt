import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, connect, type Socket } from 'node:net';
import { randomBytes } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { Writable } from 'node:stream';
import pg from 'pg';
import { createPool, migrate } from '../server/db.ts';
import { AdvisoryIngestor } from '../server/correlation/ingest.ts';
import { DeadLetterQueue } from '../server/correlation/deadLetter.ts';
import { CorrelationTelemetry } from '../server/correlation/telemetry.ts';
import { PipelineSupervisor } from '../server/correlation/supervisor.ts';
import { correlationMetrics } from '../server/correlation/metrics.ts';
const database = process.env.TEST_DATABASE_URL;

test(
  'real TCP severance pauses admission and reconnects without touching other sessions',
  { skip: !database, timeout: 20000 },
  async () => {
    const master = createPool(database!);
    const schema = 'correlation_network_' + randomBytes(12).toString('hex');
    const directory = await mkdtemp(join(tmpdir(), 'correlation-network-'));
    const destination = new URL(database!);
    let disconnected = false;
    const sockets = new Set<Socket>();
    const proxy = createServer((client) => {
      if (disconnected) {
        client.destroy();
        return;
      }
      const upstream = connect(Number(destination.port || 5432), destination.hostname);
      sockets.add(client);
      sockets.add(upstream);
      client.on('error', () => upstream.destroy());
      upstream.on('error', () => client.destroy());
      client.on('close', () => {
        sockets.delete(client);
        upstream.destroy();
      });
      upstream.on('close', () => {
        sockets.delete(upstream);
        client.destroy();
      });
      client.pipe(upstream);
      upstream.pipe(client);
    });
    let pool: pg.Pool | undefined, supervisor: PipelineSupervisor | undefined;
    try {
      await master.query(`CREATE SCHEMA ${schema}`);
      const setup = new pg.Pool({ connectionString: database, options: `-c search_path=${schema}` });
      try {
        await migrate(setup);
      } finally {
        await setup.end();
      }
      await new Promise<void>((resolve) => proxy.listen(0, '127.0.0.1', resolve));
      const address = proxy.address();
      assert.ok(address && typeof address !== 'string');
      const target = new URL(database!);
      target.hostname = '127.0.0.1';
      target.port = String(address.port);
      pool = new pg.Pool({
        connectionString: target.href,
        options: `-c search_path=${schema}`,
        max: 2,
        connectionTimeoutMillis: 500,
      });
      pool.on('error', () => {});
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
      supervisor = new PipelineSupervisor(pool, ingestor);
      await supervisor.check();
      assert.equal(supervisor.health, 'HEALTHY');
      disconnected = true;
      for (const socket of sockets) socket.destroy();
      await delay(20);
      await supervisor.check();
      assert.equal(supervisor.health, 'RECOVERING_DB_SEVERANCE');
      // Metrics remain readable even with all data connections severed.
      assert.match(correlationMetrics(supervisor), /state="RECOVERING_DB_SEVERANCE"\} 1/);
      let admitted = false;
      const controller = new AbortController();
      const admission = supervisor.acquire('blocked-during-outage', controller).then(() => {
        admitted = true;
      });
      await delay(100);
      assert.equal(admitted, false);
      disconnected = false;
      await supervisor.check();
      await admission;
      assert.equal(supervisor.health, 'HEALTHY');
      supervisor.active.delete('blocked-during-outage');
      assert.equal(
        await ingestor.processIncomingAdvisory(
          {
            title: 'Recovered connection',
            content: 'Security research report.',
            url: 'https://example.org/recovered',
          },
          pool,
        ),
        'PROCESSED',
      );
      assert.equal(
        (await pool.query('SELECT count(*)::int AS count FROM unstructured_advisories')).rows[0].count,
        1,
      );
    } finally {
      await supervisor?.stop();
      await pool?.end();
      for (const socket of sockets) socket.destroy();
      await new Promise<void>((resolve) => proxy.close(() => resolve()));
      await master.query(`DROP SCHEMA ${schema} CASCADE`);
      await master.end();
      await rm(directory, { recursive: true, force: true });
    }
  },
);
