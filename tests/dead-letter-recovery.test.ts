import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { mkdtemp, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Writable } from 'node:stream';
import type { Pool } from 'pg';
import { DeadLetterQueue } from '../server/correlation/deadLetter.ts';
import { CorrelationTelemetry } from '../server/correlation/telemetry.ts';
import { decrypt } from '../server/secrets.ts';

const telemetry = () => new CorrelationTelemetry(new Writable({ write(_chunk, _encoding, callback) { callback(); } }));

test('independent spool flushers claim each file once and survive key rotation', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'dlq-lease-'));
  const retired = randomBytes(32).toString('base64');
  const current = randomBytes(32).toString('base64');
  const persisted: unknown[][] = [];
  const pool = { query: async (query: { values: unknown[] }) => {
    persisted.push(query.values);
    await new Promise<void>((resolve) => setTimeout(resolve, 10));
    return { rows: [] };
  } } as unknown as Pool;
  try {
    await new DeadLetterQueue(directory, [retired], telemetry()).capture({ title: 'Retained incident' }, 'DATABASE_UNAVAILABLE', randomUUID(), pool);
    await Promise.all(Array.from({ length: 8 }, () => new DeadLetterQueue(directory, [current, retired], telemetry()).flush(pool)));
    assert.equal(persisted.length, 1);
    assert.equal(decrypt(String(persisted[0][3]), [current, retired], 'correlation-dlq'), JSON.stringify({ title: 'Retained incident' }));
    assert.deepEqual(await readdir(directory), []);
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('failed spool persistence releases the lease and preserves the letter for retry', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'dlq-retry-'));
  const keys = [randomBytes(32).toString('base64')];
  const pool = { query: async () => { throw new Error('database unavailable'); } } as unknown as Pool;
  try {
    await new DeadLetterQueue(directory, keys, telemetry()).capture({ title: 'Retry incident' }, 'DATABASE_UNAVAILABLE', randomUUID(), pool);
    await assert.rejects(new DeadLetterQueue(directory, keys, telemetry()).flush(pool), /database unavailable/);
    assert.equal((await readdir(directory)).filter((name) => name.endsWith('.json')).length, 1);
    assert.ok((await readdir(directory)).every((name) => !name.endsWith('.lock')));
    let writes = 0;
    const recovered = { query: async () => { writes++; return { rows: [] }; } } as unknown as Pool;
    const recoveredTelemetry = telemetry();
    await new DeadLetterQueue(directory, keys, recoveredTelemetry).flush(recovered);
    assert.equal(writes, 1);
    assert.equal(recoveredTelemetry.deadLetterSpoolFiles, 0);
    assert.deepEqual(await readdir(directory), []);
  } finally { await rm(directory, { recursive: true, force: true }); }
});