import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, before, describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { decideAction, parsePositiveInt, readState } from '../scripts/watchdog.mjs';

const RE_ALERT_MS = 30 * 60 * 1000;
const NOW = 1_700_000_000_000;

const healthyResult = { ok: true, status: 200, latencyMs: 12 };
const downResult = { ok: false, status: 0, latencyMs: 10_000, error: 'TimeoutError' };

const healthyState = () => ({ healthy: true, lastAlertAt: 0 });
const downState = (since = NOW - 60_000, lastAlertAt = NOW - 60_000) => ({
  healthy: false,
  lastAlertAt,
  since,
});

describe('decideAction', () => {
  describe('first down transition', () => {
    it('alerts and records the outage start when previously healthy', () => {
      const { alert, nextState, exitCode } = decideAction(healthyState(), downResult, NOW, RE_ALERT_MS);

      assert.equal(alert?.kind, 'down');
      assert.deepEqual(alert?.detail, { status: 0, latencyMs: 10_000, error: 'TimeoutError' });
      assert.deepEqual(nextState, { healthy: false, lastAlertAt: NOW, since: NOW });
      assert.equal(exitCode, 1);
    });

    it('treats a state with no health flag as the first down', () => {
      const { alert, nextState } = decideAction({ lastAlertAt: 0 }, downResult, NOW, RE_ALERT_MS);

      assert.equal(alert?.kind, 'down');
      assert.equal(nextState?.since, NOW);
    });
  });

  describe('repeated down', () => {
    it('stays quiet within the re-alert window but still exits non-zero', () => {
      const state = downState(NOW - 120_000, NOW - 60_000);
      const { alert, nextState, exitCode } = decideAction(state, downResult, NOW, RE_ALERT_MS);

      assert.equal(alert, null);
      assert.equal(nextState, null);
      assert.equal(exitCode, 1);
    });

    it('re-alerts after the window and keeps the original outage start', () => {
      const since = NOW - 2 * RE_ALERT_MS;
      const state = downState(since, NOW - RE_ALERT_MS);
      const { alert, nextState, exitCode } = decideAction(state, downResult, NOW, RE_ALERT_MS);

      assert.equal(alert?.kind, 'down');
      assert.equal(nextState?.since, since, 'outage start must not be reset on re-alert');
      assert.equal(nextState?.lastAlertAt, NOW);
      assert.equal(exitCode, 1);
    });

    it('re-alerts exactly at the window boundary', () => {
      const state = downState(NOW - 2 * RE_ALERT_MS, NOW - RE_ALERT_MS);
      const { alert } = decideAction(state, downResult, NOW, RE_ALERT_MS);

      assert.equal(alert?.kind, 'down');
    });
  });

  describe('recovery', () => {
    it('alerts recovery with the outage duration and clears the down flag', () => {
      const since = NOW - 5 * 60_000;
      const lastAlertAt = NOW - 4 * 60_000;
      const { alert, nextState, exitCode } = decideAction(downState(since, lastAlertAt), healthyResult, NOW, RE_ALERT_MS);

      assert.equal(alert?.kind, 'recovered');
      assert.deepEqual(alert?.detail, { latencyMs: 12, downForMs: 5 * 60_000 });
      assert.deepEqual(nextState, { healthy: true, lastAlertAt });
      assert.equal(exitCode, 0);
    });

    it('reports a null duration when the outage start is unknown', () => {
      const state = { healthy: false, lastAlertAt: NOW - 60_000 };
      const { alert, nextState } = decideAction(state, healthyResult, NOW, RE_ALERT_MS);

      assert.equal(alert?.detail.downForMs, null);
      assert.deepEqual(nextState, { healthy: true, lastAlertAt: NOW - 60_000 });
    });

    it('is silent when the service was already healthy', () => {
      const { alert, nextState, exitCode } = decideAction(healthyState(), healthyResult, NOW, RE_ALERT_MS);

      assert.equal(alert, null);
      assert.equal(nextState, null);
      assert.equal(exitCode, 0);
    });
  });
});

describe('parsePositiveInt', () => {
  it('returns the fallback when the variable is unset or empty', () => {
    assert.equal(parsePositiveInt(undefined, 10_000), 10_000);
    assert.equal(parsePositiveInt('', 10_000), 10_000);
  });

  it('parses a valid positive number', () => {
    assert.equal(parsePositiveInt('15000', 10_000), 15_000);
    assert.equal(parsePositiveInt('0.5', 10_000), 0.5);
  });

  it('rejects values that Number() would turn into NaN or a non-positive number', () => {
    for (const bad of ['10s', 'abc', ' ', 'NaN', 'Infinity', '0', '-1']) {
      assert.equal(parsePositiveInt(bad, 10_000), null, `expected ${JSON.stringify(bad)} to be rejected`);
    }
  });
});

describe('readState', () => {
  let dir: string;

  before(async () => {
    dir = await mkdtemp(join(tmpdir(), 'watchdog-state-'));
  });

  after(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  const path = (name: string) => join(dir, name);

  it('silently starts fresh when the state file does not exist', async () => {
    const state = await readState(path('missing.state'));

    assert.deepEqual(state, { healthy: true, lastAlertAt: 0 });
  });

  it('returns a well-formed state file unchanged', async () => {
    const file = path('good.state');
    const persisted = { healthy: false, lastAlertAt: NOW, since: NOW - 1000 };
    await writeFile(file, JSON.stringify(persisted));

    assert.deepEqual(await readState(file), persisted);
  });

  it('quarantines malformed JSON and starts fresh', async () => {
    const file = path('truncated.state');
    await writeFile(file, '{"healthy":false,"lastAlert');

    assert.deepEqual(await readState(file), { healthy: true, lastAlertAt: 0 });
    assert.equal(await readFile(`${file}.corrupt`, 'utf8'), '{"healthy":false,"lastAlert');
    await assert.rejects(readFile(file, 'utf8'), { code: 'ENOENT' });
  });

  it('quarantines structurally invalid state and starts fresh', async () => {
    for (const bad of ['null', '[]', '"ok"', '{"healthy":"no"}', '{"healthy":false,"lastAlertAt":"soon"}']) {
      const file = path(`invalid-${Buffer.from(bad).toString('hex')}.state`);
      await writeFile(file, bad);

      assert.deepEqual(await readState(file), { healthy: true, lastAlertAt: 0 }, `bad payload: ${bad}`);
      assert.equal(await readFile(`${file}.corrupt`, 'utf8'), bad);
    }
  });
});
