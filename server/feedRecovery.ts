import type { ThreatFeed } from '../src/types/index.ts';

/** Persistent cooldowns survive restarts; only enabled, failed sources trigger recovery.
 * A DOWN feed with no circuit deadline (e.g. marked DOWN via a manual test or a
 * partial write) is immediately due so the automatic loop will probe it again
 * instead of leaving it stranded when the scheduler is disabled. */
export function isPermanentFeed(feed: ThreatFeed): boolean {
  const error = feed.errorLog || '';
  if (/^Configuration error \(not retryable\):/i.test(error)) return true;
  const statusMatch = /(?:^|\bHTTP\s+)(4[0-9]{2})\b/i.exec(error)
    ?? /(4[0-9]{2})\s+Client Error\b/i.exec(error);
  if (!statusMatch) return false;
  const status = Number(statusMatch[1]);
  return status >= 400 && status < 500 && ![401, 403, 408, 429].includes(status);
}

export function recoveryDue(feed: ThreatFeed, now = Date.now()): boolean {
  if (!feed.enabled || feed.healthStatus !== 'DOWN' || isPermanentFeed(feed)) return false;
  // Atomic recovery deduplication: prevent multiple concurrent recovery attempts
  // for the same feed by checking and updating the last recovery timestamp atomically.
  // A minimum interval with jitter prevents stampeding across workers when many
  // feeds simultaneously become available after an outage.
  if (feed.lastRecoveryAttemptAt) {
    const lastRecovery = Date.parse(feed.lastRecoveryAttemptAt);
    if (!Number.isNaN(lastRecovery)) {
      // Enforce minimum recovery interval (30 seconds) with jitter to prevent
      // synchronized recovery probes across workers. Jitter spreads probes
      // over a wider window, reducing the risk of thundering herd.
      const jitter = Math.random() * 10000; // 0-10s random offset
      const minInterval = 30000 + jitter;
      if (now - lastRecovery < minInterval) {
        return false;
      }
    }
  }
  if (!feed.circuitOpenUntil) return true;
  const deadline = Date.parse(feed.circuitOpenUntil);
  // An unparseable deadline must not strand a DOWN feed; treat it as due.
  return Number.isNaN(deadline) || deadline <= now;
}

export function recoveryAt(feed: ThreatFeed, failures: number, now = Date.now(), modelDelayMs?: number): string {
  const learned = typeof modelDelayMs === 'number' && Number.isFinite(modelDelayMs) && modelDelayMs > 0
    ? modelDelayMs
    : null;
  const fallback = (feed.recoveryDelayMinutes ?? 5) * 60000;
  // Exponential backoff capped at one hour, floored at the configured base delay
  // so the per-feed recoveryDelayMinutes is never undercut while backing off.
  const backoff = Math.min(3600000, fallback * Math.pow(2, Math.min(6, Math.max(0, failures - 1))));
  const delay = learned === null
    ? Math.max(fallback, backoff)
    : Math.max(fallback, Math.min(3600000, learned));
  return new Date(now + Math.max(60000, delay)).toISOString();
}

/**
 * Distinguishes a failure that retrying can fix from one it cannot.
 *
 * Audit H-5: every ingestion exception previously opened the circuit breaker,
 * so a feed rejected by SSRF policy or by an upstream 4xx/UI schema change kept
 * re-opening a cooldown and suppressing catch-up for a condition that would
 * never resolve on its own. Those are configuration faults and must surface as
 * an actionable error instead of being retried into the circuit breaker.
 *
 * Transient by design: network/transport errors, timeouts, 408, 429, the 5xx
 * family, and authentication expiries (401/403 may be a rotated credential the
 * operator is about to renew; these still count as recoverable so a token
 * refresh is picked up).
 */
export function isPermanentFeedFailure(error: unknown): boolean {
  const status = (error as { status?: unknown } | null)?.status;
  if (typeof status === 'number')
    return status >= 400 && status < 500 && status !== 408 && status !== 429 && status !== 401 && status !== 403;
  const message = error instanceof Error ? error.message : String(error ?? '');
  // Failures raised before any request is made are deterministic configuration
  // faults: the destination is rejected, the URL cannot be parsed, or a saved
  // checkpoint is unusable. Repeating them cannot change the outcome.
  if (/non-public destination|malformed url|https without url credentials|not permitted|not in |saved source checkpoint|invalid url|unsupported feed (type|url)/i.test(
    message,
  ))
    return true;
  // An upstream 4xx (from messages such as "Feed returned HTTP 406") means the
  // source rejects this request deterministically; retrying cannot fix it. Do
  // not open a cooldown that suppresses catch-up for a condition that will not
  // resolve on its own.
  const m = /(?:^|[^\d])(4[0-9]{2})(?:[^\d]|$)/.exec(message);
  if (m) {
    const code = Number(m[1]);
    return code !== 401 && code !== 403 && code !== 408 && code !== 429;
  }
  return false;
}

/** Recovery probes remain active when routine scheduled runs are disabled. */
export function shouldStartAutomaticRun(
  input: {
    schedulerEnabled: boolean;
    recoveryProbeDue: boolean;
    catchUpDue?: boolean;
    lastRun?: string | null;
    intervalMinutes: number;
  },
  now = Date.now(),
): boolean {
  if (!input.schedulerEnabled) return input.recoveryProbeDue;
  if (input.catchUpDue) return true;
  const lastRun = input.lastRun ? Date.parse(input.lastRun) : NaN;
  return !Number.isFinite(lastRun) || now - lastRun >= input.intervalMinutes * 60000;
}
