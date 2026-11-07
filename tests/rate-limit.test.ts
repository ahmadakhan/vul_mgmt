import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { createPool, migrate } from '../server/db.ts';
import {
  consumeToken,
  createDatabaseRateLimiter,
  type TokenBucket,
} from '../server/rateLimit.ts';

const capacity = 5;
const refillPerMs = 2 / 60_000; // two tokens per minute

const drain = (now: number): TokenBucket => {
  let bucket: TokenBucket | undefined;
  for (let i = 0; i < capacity; i++) {
    const result = consumeToken(bucket, now, capacity, refillPerMs);
    assert.equal(result.allowed, true, `request ${i + 1} should be allowed`);
    bucket = result.bucket;
  }
  return bucket!;
};

test('a fresh bucket allows the full burst and rejects the next request', () => {
  const bucket = drain(0);
  const denied = consumeToken(bucket, 0, capacity, refillPerMs);
  assert.equal(denied.allowed, false);
  assert.ok(denied.retryAfterMs > 0);
});

test('denied requests do not reset fractional refill progress', () => {
  const bucket = drain(0);
  // Polling every 20 seconds must not discard the accumulated 20-second
  // fraction; after 60 seconds one token is available again.
  let current = bucket;
  for (const at of [10_000, 20_000]) {
    const result = consumeToken(current, at, capacity, refillPerMs);
    assert.equal(result.allowed, false);
    current = result.bucket;
  }
  const recovered = consumeToken(current, 30_000, capacity, refillPerMs);
  assert.equal(recovered.allowed, true);
});

test('refill never exceeds the bucket capacity', () => {
  const result = consumeToken({ tokens: 0, updatedAt: 0 }, 10 * 60_000, capacity, refillPerMs);
  assert.equal(result.allowed, true);
  assert.equal(result.bucket.tokens, capacity - 1);
});

test('retryAfter reflects the time needed for exactly one token', () => {
  const denied = consumeToken({ tokens: 0, updatedAt: 0 }, 0, capacity, refillPerMs);
  assert.equal(denied.allowed, false);
  assert.equal(denied.retryAfterMs, Math.ceil(1 / refillPerMs));
});

test(
  'the database limiter shares one bucket across replicas',
  { skip: !process.env.TEST_DATABASE_URL },
  async () => {
    const base = createPool(process.env.TEST_DATABASE_URL!);
    const schema = `rate_${randomUUID().replaceAll('-', '')}`;
    await base.query(`CREATE SCHEMA "${schema}"`);
    const url = new URL(process.env.TEST_DATABASE_URL!);
    url.searchParams.set('options', `-c search_path=${schema}`);
    const pool = createPool(url.href);
    try {
      await migrate(pool);
      // Two limiter instances stand in for two application replicas.
      const replicaA = createDatabaseRateLimiter(pool, 2, 0.001);
      const replicaB = createDatabaseRateLimiter(pool, 2, 0.001);
      const key = 'rl:shared-operator';
      assert.equal((await replicaA(key)).allowed, true);
      assert.equal((await replicaB(key)).allowed, true);
      const denied = await replicaA(key);
      assert.equal(denied.allowed, false, 'the second replica must see the exhausted bucket');
      assert.ok(denied.retryAfterMs > 0);
      // Simulate elapsed time without sleeping: refill is one token per second.
      await pool.query(
        "UPDATE rate_limit_buckets SET updated_at = updated_at - interval '2 seconds' WHERE bucket_key=$1",
        [key],
      );
      assert.equal((await replicaB(key)).allowed, true);
    } finally {
      await pool.end();
      await base.query(`DROP SCHEMA "${schema}" CASCADE`);
      await base.end();
    }
  },
);
