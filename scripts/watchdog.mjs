#!/usr/bin/env node
import { pathToFileURL } from 'node:url';
/**
 * External watchdog for "the system should always be on".
 *
 * Prometheus cannot detect a total outage: if the monitored system and the
 * collector are both down, no rule evaluates and nothing fires. This script is
 * the out-of-band check for exactly that case. Run it from cron or a systemd
 * timer on a host that is NOT the one running VulnStream, so it survives the
 * failure it is watching for:
 *
 *   WATCHDOG_URL=https://vulnstream.example.com/live \
 *   WATCHDOG_ALERT_WEBHOOK=https://hooks.example.com/... \
 *   node /opt/vulnstream/scripts/watchdog.mjs
 *
 * Schedule it every two minutes from cron (first field: star-slash-2), on a
 * host that is not the one running VulnStream.
 *
 * It alerts only on a state CHANGE or on a sustained outage, never once per
 * run, so a long outage does not produce an alert on every invocation. It exits
 * non-zero when unhealthy, so cron/mail-on-failure also reports it.
 *
 * No secrets are printed. The URL and webhook are treated as credentials.
 */

/**
 * Pure decision logic, exported so it can be unit-tested without network or disk.
 *
 * `state` is the persisted state ({ healthy, lastAlertAt, since }); `result` is
 * the output of check() ({ ok, status, latencyMs, error }).
 *
 * Returns { alert, nextState, exitCode }:
 *   - alert: null, or { kind: 'down' | 'recovered', detail } to deliver
 *   - nextState: the state to persist (null when nothing changed)
 *   - exitCode: process exit code implied by this result
 */
export function decideAction(state, result, now, reAlertAfterMs) {
  const previous = state || {};
  const lastAlertAt = previous.lastAlertAt || 0;

  if (!result.ok) {
    // Alert on the transition, then at most every reAlertAfterMs while it persists.
    const dueForRealert = now - lastAlertAt >= reAlertAfterMs;
    if (previous.healthy !== false || dueForRealert) {
      return {
        alert: {
          kind: 'down',
          detail: { status: result.status, latencyMs: result.latencyMs, error: result.error },
        },
        nextState: {
          healthy: false,
          lastAlertAt: now,
          since: previous.healthy === false ? previous.since : now,
        },
        exitCode: 1,
      };
    }
    return { alert: null, nextState: null, exitCode: 1 };
  }

  if (previous.healthy === false) {
    const downForMs = previous.since ? now - previous.since : null;
    return {
      alert: { kind: 'recovered', detail: { latencyMs: result.latencyMs, downForMs } },
      nextState: { healthy: true, lastAlertAt },
      exitCode: 0,
    };
  }

  return { alert: null, nextState: null, exitCode: 0 };
}

function isMain() {
  return Boolean(process.argv[1]) && import.meta.url === pathToFileURL(process.argv[1]).href;
}

/**
 * Parse a positive-integer env var, falling back to `fallback` when unset.
 * Returns null when set but not a finite positive number, so callers can fail fast.
 */
export function parsePositiveInt(raw, fallback) {
  if (raw === undefined || raw === '') return fallback;
  const value = Number(raw);
  return Number.isFinite(value) && value > 0 ? value : null;
}

async function check(url, timeoutMs) {
    const started = Date.now();
    try {
      const response = await fetch(url, {
        method: 'GET',
        redirect: 'manual',
        signal: AbortSignal.timeout(timeoutMs),
      });
      return { ok: response.ok, status: response.status, latencyMs: Date.now() - started };
    } catch (error) {
      // Distinguish "the process answered but is unhealthy" from "nothing answered".
      return { ok: false, status: 0, latencyMs: Date.now() - started, error: error?.name || 'FETCH_FAILED' };
    }
  }


function createStateStore(stateFile) {
  const DEFAULT_STATE = { healthy: true, lastAlertAt: 0 };

  /**
   * Read and validate the persisted state.
   *
   * - missing file (ENOENT): normal first run, silently start fresh
   * - unreadable file (EACCES, EISDIR, ...): warn, start fresh, keep the file
   * - malformed content: warn and move it aside to `<stateFile>.corrupt` so the
   *   next run starts from a clean slate instead of re-alerting forever
   */
  async function readState(file = stateFile) {
    let raw;
    try {
      const { readFile } = await import('node:fs/promises');
      raw = await readFile(file, 'utf8');
    } catch (error) {
      if (error?.code !== 'ENOENT') {
        console.error(JSON.stringify({ level: 'warning', event: 'watchdog.state_unreadable', code: error?.code || 'UNKNOWN' }));
      }
      return { ...DEFAULT_STATE };
    }

    let parsed;
    try {
      parsed = JSON.parse(raw);
    } catch {
      parsed = undefined;
    }

    if (!isValidState(parsed)) {
      console.error(JSON.stringify({ level: 'warning', event: 'watchdog.state_corrupt' }));
      await quarantineState(file);
      return { ...DEFAULT_STATE };
    }
    return parsed;
  }

  /** A state object is only trusted when its fields have the expected types. */
  function isValidState(value) {
    if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
    if (typeof value.healthy !== 'boolean') return false;
    if (value.lastAlertAt !== undefined && !Number.isFinite(value.lastAlertAt)) return false;
    if (value.since !== undefined && !Number.isFinite(value.since)) return false;
    return true;
  }

  async function quarantineState(file) {
    try {
      const { rename } = await import('node:fs/promises');
      await rename(file, `${file}.corrupt`);
    } catch {
      // Best effort: if we cannot move it, the next run simply warns again.
    }
  }

  async function writeState(state) {
    try {
      const { writeFile } = await import('node:fs/promises');
      await writeFile(stateFile, JSON.stringify(state), { mode: 0o600 });
    } catch {
      // A watchdog that cannot persist its state still alerts; it may repeat.
    }
  }

  return { readState, writeState };
}

/** Read the watchdog state file, quarantining corrupt content. */
export async function readState(file) {
  return createStateStore(file).readState(file);
}

async function alert(webhook, timeoutMs, kind, detail) {
    if (!webhook) {
      // Always emit to stdout so the cron mail / log collector carries it even
      // when no webhook is configured.
      console.log(JSON.stringify({ level: 'critical', event: `watchdog.${kind}`, ...detail }));
      return;
    }
    try {
      await fetch(webhook, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          // Generic shape; adapt to the provider (PagerDuty Events, Slack, etc.).
          source: 'vulnstream-watchdog',
          status: kind === 'recovered' ? 'resolved' : 'firing',
          summary:
            kind === 'recovered'
              ? 'VulnStream watchdog: service reachable again'
              : 'VulnStream watchdog: service is DOWN',
          detail,
          at: new Date().toISOString(),
        }),
        signal: AbortSignal.timeout(timeoutMs),
      });
    } catch {
      console.error(JSON.stringify({ level: 'critical', event: 'watchdog.delivery_failed' }));
    }
  }

async function main() {

  const url = process.env.WATCHDOG_URL || '';
  const webhook = process.env.WATCHDOG_ALERT_WEBHOOK || '';
  const timeoutMs = parsePositiveInt(process.env.WATCHDOG_TIMEOUT_MS, 10000);
  const stateFile = process.env.WATCHDOG_STATE_FILE || '/tmp/vulnstream-watchdog.state';
  const reAlertAfterMs = parsePositiveInt(process.env.WATCHDOG_REALERT_MS, 30 * 60 * 1000);

  const misconfigured = [];
  if (!url) misconfigured.push('WATCHDOG_URL is required');
  if (timeoutMs === null) misconfigured.push('WATCHDOG_TIMEOUT_MS must be a positive number of milliseconds');
  if (reAlertAfterMs === null) misconfigured.push('WATCHDOG_REALERT_MS must be a positive number of milliseconds');

  if (misconfigured.length > 0) {
    console.error(JSON.stringify({ level: 'error', event: 'watchdog.misconfigured', reason: misconfigured.join('; ') }));
    process.exit(2);
  }

  const { readState, writeState } = createStateStore(stateFile);

  const result = await check(url, timeoutMs);
  const state = await readState();
  const now = Date.now();

  const { alert: action, nextState, exitCode } = decideAction(state, result, now, reAlertAfterMs);

  if (action) {
    await alert(webhook, timeoutMs, action.kind, action.detail);
  }
  if (nextState) {
    await writeState(nextState);
  }
  process.exitCode = exitCode;
}

if (isMain()) {
  await main();
}
