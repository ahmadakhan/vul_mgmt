import { test } from 'node:test';
import assert from 'node:assert/strict';
import { paceConcurrent } from '../server/concurrency';

const realSleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

test('paceConcurrent preserves input order regardless of completion order', async () => {
  const items = [30, 10, 20, 5, 25];
  const result = await paceConcurrent(items, 0, 4, realSleep, async (item) => {
    await realSleep(item); // later items resolve sooner, out of order
    return item * 2;
  });
  assert.deepEqual(result, items.map((item) => item * 2));
});

test('paceConcurrent overlaps latency: wall time is far less than serial sleep+latency', async () => {
  const items = Array.from({ length: 20 }, (_, i) => i);
  const interval = 10;
  const latency = 40;
  const started = Date.now();
  await paceConcurrent(items, interval, 8, realSleep, async (item) => {
    await realSleep(latency);
    return item;
  });
  const elapsed = Date.now() - started;
  // Fully serial (interval + latency per item) would take ~1000ms for 20 items.
  // Paced-concurrent dispatch is bound by the pacing interval once the pipeline
  // fills (~20*10=200ms) plus one latency tail, not by (interval+latency)*N.
  assert.ok(elapsed < 20 * (interval + latency) * 0.6, `expected well under serial time, got ${elapsed}ms`);
});

test('paceConcurrent never dispatches faster than the configured interval', async () => {
  const dispatchTimes: number[] = [];
  const interval = 50;
  await paceConcurrent(Array.from({ length: 10 }, (_, i) => i), interval, 5, realSleep, async () => {
    dispatchTimes.push(Date.now());
  });
  dispatchTimes.sort((a, b) => a - b);
  for (let i = 1; i < dispatchTimes.length; i++) {
    const gap = dispatchTimes[i] - dispatchTimes[i - 1];
    assert.ok(gap >= interval - 5, `dispatches ${gap}ms apart with ${interval}ms interval`);
  }
});

test('paceConcurrent fails closed: stops dispatching after the first error and rethrows it', async () => {
  let dispatched = 0;
  const items = Array.from({ length: 50 }, (_, i) => i);
  await assert.rejects(
    paceConcurrent(items, 0, 4, realSleep, async (item) => {
      dispatched++;
      if (item === 3) throw new Error('boom');
      await realSleep(5);
      return item;
    }),
    /boom/,
  );
  // A handful of items may already be in flight concurrently when the error
  // lands, but the full batch of 50 must never be dispatched.
  assert.ok(dispatched < items.length, `expected early abort, dispatched ${dispatched}/${items.length}`);
});

test('paceConcurrent drains workers and stops dispatching when pacing sleep fails', async () => {
  let dispatched = 0;
  const requestSleep = async () => {
    throw new Error('pipeline stopped');
  };
  await assert.rejects(
    paceConcurrent(Array.from({ length: 20 }, (_, i) => i), 100, 4, requestSleep, async () => {
      dispatched++;
      await realSleep(10);
    }),
    /pipeline stopped/,
  );
  assert.equal(dispatched, 1, 'sleep failure must prevent queued work from being dispatched');
});

test('paceConcurrent with concurrency 1 behaves like a serial paced loop', async () => {
  const seen: number[] = [];
  const result = await paceConcurrent([1, 2, 3], 0, 1, realSleep, async (item) => {
    seen.push(item);
    return item + 100;
  });
  assert.deepEqual(seen, [1, 2, 3]);
  assert.deepEqual(result, [101, 102, 103]);
});
