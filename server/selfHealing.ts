import { get, getForUpdate, list, put, transaction } from './db';
import { getHeapStatistics } from 'node:v8';
import { totalmem } from 'node:os';
import type { Db } from './db';
import { writeEvent } from './events';
import { enqueue } from './delivery';

import type { Pool } from 'pg';
import type { AppSettings, EmailRecipient, PipelineExecution, ThreatFeed } from '../src/types/index';

/**
 * Self-healing watchdog.
 *
 * Runs on every worker tick. It (1) recovers from known degraded states and
 * (2) tells the Security team, through the durable outbox, that something needed
 * recovery. Three invariants keep this safe to run every five seconds from every
 * replica:
 *
 *  - Every alert is *claimed* in a transaction before it is queued, so N
 *    replicas racing on the same fault enqueue exactly one round of messages.
 *  - Alerts go through the outbox (`enqueue` -> `deliverNext`), never straight to
 *    the transport. A direct send bypassed retry, at-least-once recovery, the
 *    delivery log and the dedupe key, and a single SMTP hiccup lost the alert
 *    permanently (it was swallowed by a bare `catch`).
 *  - The dedupe key is per (component, incident, recipient). A shared
 *    `selfHealing:<component>` key made every recipient after the first collide
 *    with the held row and lose the alert, and left no room for a *new*
 *    incident inside the same cooldown to notify anyone.
 *
 * This module previously queried `executions`, `feeds` and `settings` as if they
 * were tables. They are `records` rows (`kind='executions'` | `'feeds'` |
 * `'settings'`), so the first statement threw `relation does not exist` on every
 * tick: no alert was ever sent and no recovery ever ran.
 */

type Component = 'PIPELINE' | 'FEED' | 'SYSTEM' | 'SCHEDULER';

const DEFAULT_COOLDOWN_MINUTES = 30;
/** Node's default V8 ceiling is ~1.4 GB; 90% of `heapTotal` is a false alarm. */
const SYSTEM_HEAP_PCT_THRESHOLD = 95;
const SCHEDULER_STALE_MS = 3 * 60_000;
/** How far back a failed execution still counts as "the pipeline is failing now". */
const RECENT_FAILURE_MS = 30 * 60_000;
/** Recovery re-queues are rate limited so a crash loop cannot queue a run per tick. */
const RECOVERY_RETRY_MS = 10 * 60_000;

interface ComponentAlertState {
  lastAlertAt?: string;
  /** Incident identity; a change re-arms the alert even inside the cooldown. */
  incident?: string;
  lastRecoveryAt?: string;
}

interface AlertState {
  [component: string]: ComponentAlertState;
}

const cooldownMs = (minutes?: number): number =>
  Math.max(1, Number.isFinite(Number(minutes)) ? Number(minutes) : DEFAULT_COOLDOWN_MINUTES) * 60_000;

/** Strip CR/LF/control characters so a feed name cannot inject mail headers. */
const safeLine = (value: unknown): string =>
  String(value ?? '')
    .replace(/[\r\n\t]+/g, ' ')
    .replace(/[\u0000-\u001f\u007f\u2028\u2029]/g, '')
    .trim()
    .slice(0, 500);

/**
 * Atomically claims the alert slot for one component/incident.
 *
 * Returns `true` only when this caller is the one that should queue the alert.
 * The row is read `FOR UPDATE` inside the caller's transaction and the advisory
 * lock serializes the first claim before a row exists, so two replicas cannot
 * both win the race. A changed `incident` re-arms immediately (a new fault is
 * news even during the previous cooldown); a repeated fault is suppressed.
 */
async function claimAlertSlot(
  db: Db,
  component: Component,
  incident: string,
  cooldown: number,
): Promise<boolean> {
  const now = Date.now();
  const row = await db.query<{ data: AlertState | null }>(
    `SELECT data FROM records WHERE kind='systemState' AND id='selfHealing' FOR UPDATE`,
  );
  const state: AlertState = row.rows[0]?.data ?? {};
  const stored = state[component];
  if (stored?.lastAlertAt && stored.incident === incident) {
    const last = Date.parse(stored.lastAlertAt);
    if (Number.isFinite(last) && now - last < cooldown) return false;
  }
  const next: AlertState = {
    ...state,
    [component]: { ...stored, lastAlertAt: new Date(now).toISOString(), incident },
  };
  await db.query(
    `INSERT INTO records(kind,id,data) VALUES('systemState','selfHealing',$1::jsonb)
         ON CONFLICT(kind,id) DO UPDATE SET data=$1::jsonb, updated_at=now()`,
    [JSON.stringify(next)],
  );
  return true;
}

/**
 * Records the moment a component was recovered, and reports whether another
 * recovery attempt is allowed now. Separate from the alert cooldown: recovery
 * must be possible even when the alert is suppressed.
 */
async function claimRecoverySlot(pool: Pool, component: Component, retryMs: number): Promise<boolean> {
  return transaction(
    pool,
    async (db) => {
      const row = await db.query<{ data: AlertState | null }>(
        `SELECT data FROM records WHERE kind='systemState' AND id='selfHealing' FOR UPDATE`,
      );
      const state: AlertState = row.rows[0]?.data ?? {};
      const stored = state[component];
      const now = Date.now();
      const last = stored?.lastRecoveryAt ? Date.parse(stored.lastRecoveryAt) : NaN;
      if (Number.isFinite(last) && now - last < retryMs) return false;
      const next: AlertState = {
        ...state,
        [component]: { ...stored, lastRecoveryAt: new Date(now).toISOString() },
      };
      await db.query(
        `INSERT INTO records(kind,id,data) VALUES('systemState','selfHealing',$1::jsonb)
         ON CONFLICT(kind,id) DO UPDATE SET data=EXCLUDED.data,updated_at=now()`,
        [JSON.stringify(next)],
      );
      return true;
    },
    undefined,
    { locks: ['self-healing-alert'] },
  );
}

/** Security-team recipients (an unset group is the legacy security-team default). */
async function getSecurityRecipients(db: Db): Promise<EmailRecipient[]> {
  return (await list<EmailRecipient>(db, 'recipients')).filter(
    (r) => r.enabled && (r.deliveryGroup === 'SECURITY_TEAM' || r.deliveryGroup === undefined),
  );
}

/**
 * Queues one alert email per security-team recipient into the durable outbox.
 *
 * The dedupe key includes the incident and the recipient: the outbox unique
 * constraint is on `dedupe_key`, so a per-recipient key is what lets every
 * recipient receive the alert. Re-queueing the same incident is a no-op.
 */
async function queueSecurityAlert(
  pool: Pool,
  component: Component,
  incident: string,
  subject: string,
  text: string,
  cooldown: number,
  emailNotifications: boolean,
): Promise<number> {
  return transaction(
    pool,
    async (db) => {
      const settings = await get<AppSettings>(db, 'settings', 'main');
      const recipients = await getSecurityRecipients(db);
      if (!recipients.length) {
        if (!(await claimAlertSlot(db, component, `${incident}:no-recipients`, cooldown))) return 0;
        await writeEvent(db, {
          category: 'SYSTEM',
          level: 'WARNING',
          code: 'selfHealing.no_recipients',
          message: `Self-healing alert for ${component} suppressed: no enabled Security-team recipient`,
          context: { component, incident: safeLine(incident) },
        }).catch(() => undefined);
        return 0;
      }
      if (!emailNotifications || settings?.emailEnabled === false) {
        if (!(await claimAlertSlot(db, component, `${incident}:email-disabled`, cooldown))) return 0;
        await writeEvent(db, {
          category: 'SYSTEM',
          level: 'INFO',
          code: 'selfHealing.alert_suppressed',
          message: `Self-healing alert for ${component} suppressed: email disabled`,
          context: { component, incident: safeLine(incident), recipients: recipients.length },
        }).catch(() => undefined);
        return 0;
      }
      if (!(await claimAlertSlot(db, component, incident, cooldown))) return 0;

      const body =
        `${subject}\n\n${text}\n\nComponent: ${component}\n` +
        `Incident: ${safeLine(incident)}\nDetected at: ${new Date().toISOString()}\n` +
        'This alert was generated automatically by the VulnStream self-healing watchdog.';
      const escape = (value: string) =>
        value.replace(/[&<>]/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' })[ch]!);
      let queued = 0;
      for (const recipient of recipients) {
        const id = await enqueue(
          db,
          'email',
          recipient.id,
          `SELFHEAL:${component}:${incident}`,
          {
            subject: `[SECURITY ALERT] ${subject}`,
            text: body,
            // Plain markup on purpose: an infra alert must not depend on templating.
            html: `<pre style="font-family:ui-monospace,monospace;white-space:pre-wrap">${escape(body)}</pre>`,
            cveIds: [],
            recipientEmail: recipient.email,
          },
          `selfheal:${component}:${incident}:email:${recipient.id}`,
          'QUEUED',
          // Outage alerts must not sit behind a backlog of advisory deliveries.
          10,
        );
        if (id) queued++;
      }
      await writeEvent(db, {
        category: 'SYSTEM',
        level: 'ERROR',
        code: 'selfHealing.alert_queued',
        message: `Self-healing alert queued for ${queued} Security-team recipient(s)`,
        context: { component, incident: safeLine(incident), recipients: queued },
      });
      return queued;
    },
    undefined,
    { locks: ['self-healing-alert'] },
  );
}

export async function runSelfHealCheck(pool: Pool): Promise<void> {
  const settings = (await get<AppSettings>(pool, 'settings', 'main')) ?? null;
  const selfHealing = settings?.selfHealing;
  if (selfHealing?.enabled === false) return;
  const cooldown = cooldownMs(selfHealing?.cooldownMinutes);
  const emailNotifications = selfHealing?.emailNotifications ?? true;
  const now = Date.now();

  // PIPELINE: a recently failed run means the pipeline keeps crashing. Re-queue
  // at most once per recovery window (queueRun dedupes too, but this keeps the
  // audit trail honest), then alert.
  const { queueRun } = await import('./pipeline');
  const cutoff = new Date(now - RECENT_FAILURE_MS).toISOString();
  const executions = (
    await pool.query<{ data: PipelineExecution }>(
      `SELECT data FROM records WHERE kind='executions' AND data->>'status' IN ('QUEUED','RUNNING')
     UNION ALL
     SELECT data FROM records WHERE kind='executions' AND data->>'status'='FAILED'
       AND updated_at >= $1::timestamptz AND safe_timestamptz(data->>'endTime') >= $1::timestamptz`,
      [cutoff],
    )
  ).rows.map((row) => row.data);
  const alertState = await get<AlertState>(pool, 'systemState', 'selfHealing');
  const unresolvedFailures = executions.filter(
    (execution) =>
      execution.status === 'FAILED' &&
      execution.endTime &&
      Date.parse(execution.endTime) <= now &&
      now - Date.parse(execution.endTime) < RECENT_FAILURE_MS &&
      // A run queued after the failure means recovery already happened: only
      // alert when nothing newer is pending or in flight.
      (!executions.some(
        (other) =>
          ['QUEUED', 'RUNNING'].includes(other.status) &&
          Date.parse(other.startTime) > Date.parse(execution.endTime!),
      ) ||
        alertState?.PIPELINE?.incident !== `pipeline:${execution.id}`),
  );
  if (unresolvedFailures.length) {
    const latest = unresolvedFailures.reduce((a, b) =>
      Date.parse(a.endTime!) > Date.parse(b.endTime!) ? a : b,
    );
    const recoveryPending = executions.some(
      (other) =>
        ['QUEUED', 'RUNNING'].includes(other.status) &&
        Date.parse(other.startTime) > Date.parse(latest.endTime!),
    );
    if (!recoveryPending && (await claimRecoverySlot(pool, 'PIPELINE', RECOVERY_RETRY_MS))) {
      await queueRun(pool, undefined, 'auto-recovery');
      await writeEvent(pool, {
        category: 'PIPELINE',
        level: 'WARNING',
        code: 'pipeline.auto_recovered',
        message: 'Self-healing triggered automatic pipeline recovery',
        context: { executionId: latest.id, failureCount: unresolvedFailures.length },
      });
    }
    await queueSecurityAlert(
      pool,
      'PIPELINE',
      `pipeline:${latest.id}`,
      'Pipeline failure auto-recovery triggered',
      `Pipeline execution ${latest.id} failed at ${latest.endTime}` +
        `${latest.logs.length ? `: ${safeLine(latest.logs[latest.logs.length - 1])}` : ''}. ` +
        `${unresolvedFailures.length} recent failed run(s). Automatic recovery is monitored by the watchdog.`,
      cooldown,
      emailNotifications,
    );
  }

  // FEED: a feed whose circuit is absent or expired is recoverable. The probe
  // itself happens in the next pipeline run (`recoveryDue` gates it); the
  // watchdog clears the stale deadline and forces SSRF re-validation so a DOWN
  // feed is never stranded. An unexpired circuit keeps its own retry schedule:
  // clearing it every tick would defeat the breaker and hammer the provider.
  // Operator-disabled feeds are never touched.
  const feeds = await list<ThreatFeed>(pool, 'feeds');
  // Deliberately NOT `recoveryDue`: that predicate excludes permanent faults
  // (configuration errors), and re-arming exactly those — once, rate limited —
  // is this watchdog's job. An unexpired circuit is skipped: it has its own
  // retry schedule and clearing it every tick would defeat the breaker.
  const recoverableFeeds = feeds.filter(
    (feed) =>
      feed.enabled && feed.healthStatus === 'DOWN' && !(Date.parse(feed.circuitOpenUntil || '') > now),
  );
  if (recoverableFeeds.length) {
    if (await claimRecoverySlot(pool, 'FEED', RECOVERY_RETRY_MS)) {
      for (const feed of recoverableFeeds) {
        await transaction(pool, async (db) => {
          const current = await getForUpdate<ThreatFeed>(db, 'feeds', feed.id);
          if (
            !current?.enabled ||
            current.healthStatus !== 'DOWN' ||
            Date.parse(current.circuitOpenUntil || '') > Date.now()
          )
            return;
          await put(db, 'feeds', feed.id, {
            ...current,
            // Preserve the cumulative failure counter: the breaker must still
            // escalate if the recovery probe fails again.
            circuitOpenUntil: null,
            ssrfValidated: false,
          });
        });
      }
    }
    await queueSecurityAlert(
      pool,
      'FEED',
      // Bounded so a changing feed set cannot spawn a "new incident" per tick.
      `feeds:${recoverableFeeds
        .map((feed) => feed.id)
        .sort()
        .join(',')}`.slice(0, 200),
      'Feed auto-recovery triggered',
      `${recoverableFeeds.length} feed(s) are DOWN with an expired or absent circuit and will be probed on the next run: ` +
        recoverableFeeds.map((feed) => safeLine(feed.name || feed.id)).join(', '),
      cooldown,
      emailNotifications,
    );
    await writeEvent(pool, {
      category: 'FEED',
      level: 'WARNING',
      code: 'feed.self_recovered',
      message: `Self-healing re-armed ${recoverableFeeds.length} feed(s)`,
      context: {
        feedsReenabled: recoverableFeeds.length,
        feedIds: recoverableFeeds.map((feed) => feed.id).slice(0, 50),
      },
    }).catch(() => undefined);
  }

  // SYSTEM: database reachability and process memory.
  const issues: string[] = [];
  try {
    await pool.query('SELECT 1');
  } catch (error) {
    issues.push(`database unreachable (${(error as Error).message.slice(0, 200)})`);
  }
  const mem = process.memoryUsage();
  const heapLimit = getHeapStatistics().heap_size_limit;
  const memoryLimit = process.constrainedMemory?.() || totalmem();
  const heapPct =
    Math.max(heapLimit > 0 ? mem.heapUsed / heapLimit : 0, memoryLimit > 0 ? mem.rss / memoryLimit : 0) * 100;
  if (heapPct >= SYSTEM_HEAP_PCT_THRESHOLD) issues.push(`heap at ${heapPct.toFixed(0)}%`);
  if (issues.length) {
    await queueSecurityAlert(
      pool,
      'SYSTEM',
      // Coarse identity: heap pressure oscillating across the threshold is one
      // incident, not a new one per tick.
      issues.map((issue) => issue.split(' ')[0]).join(','),
      'BA Threat Intel: System health degraded',
      `${issues.join('; ')}. The connection pool reconnects on the next operation; ` +
        'no operator action is required unless this persists.',
      cooldown,
      emailNotifications,
    );
    await writeEvent(pool, {
      category: 'SYSTEM',
      level: 'WARNING',
      code: 'system.self_recovered',
      message: 'Self-healing detected unhealthy system state',
      context: { issues },
    }).catch(() => undefined);
  }

  // SCHEDULER: the heartbeat is refreshed by every worker tick; a stale value
  // means no worker has ticked for longer than the cutoff. Queue a catch-up so
  // a skipped schedule does not silently stop monitoring.
  const scheduler = (await pool.query('SELECT heartbeat FROM scheduler_state WHERE id=1')).rows[0] as
    { heartbeat: Date | string | null } | undefined;
  const heartbeat = scheduler?.heartbeat ? new Date(scheduler.heartbeat).getTime() : NaN;
  if (
    settings?.schedulerEnabled !== false &&
    Number.isFinite(heartbeat) &&
    now - heartbeat > SCHEDULER_STALE_MS
  ) {
    if (await claimRecoverySlot(pool, 'SCHEDULER', RECOVERY_RETRY_MS)) {
      await queueRun(pool, undefined, 'scheduler');
    }
    await queueSecurityAlert(
      pool,
      'SCHEDULER',
      'scheduler-stale',
      'Scheduler heartbeat is stale',
      `The scheduler heartbeat has not advanced for ${Math.round((now - heartbeat) / 60_000)} minute(s). ` +
        'A catch-up run was queued; if this repeats, check that a worker is running.',
      cooldown,
      emailNotifications,
    );
    await writeEvent(pool, {
      category: 'SYSTEM',
      level: 'WARNING',
      code: 'scheduler.catchup_triggered',
      message: 'Self-healing triggered scheduler catch-up run due to stale heartbeat',
      context: { staleMinutes: Math.round((now - heartbeat) / 60_000) },
    }).catch(() => undefined);
  }
}
