import type pg from 'pg';
import { get, getMany, list, put, transaction, schemaLockKey, type Db } from './db';
import { writeEvent } from './events';
import { advisoryRevision, enqueue, findingRevision, revision, recipientAllows } from './delivery';
import { advisoryEmail } from './advisoryEmail';
import { runVulnerabilityPipeline } from '../src/engine/pipelineEngine';
import { shouldSelectForDigest } from './ml/integration';
import { buildAliasMap } from '../src/utils/cpeMatcher';
import { resolveTimezone as resolveSettingsTimezone } from '../src/utils/dateTime';
import { DEFAULT_SETTINGS } from '../shared/state';
import {
  DEFAULT_DAILY_DIGEST_CUSTOMIZATION,
  renderDailyDigest,
  renderDailyFindingSummary,
  renderDailyHealthReport,
  renderHeldForReview,
  type DailyDigestParts,
  digestSeveritySummary,
  digestSeverityKpi,
  formatExecutiveSummary,
  formatExecutiveSummaryText,
  type DigestFinding,
} from '../src/utils/templateCompiler';
import type {
  Advisory,
  AliasEntry,
  NormalizedCVE,
  WatchListItem,
  AppSettings,
  EmailRecipient,
  Finding,
  TemplateCustomization,
} from '../src/types/index';

/** Advisory-lock class dedicated to the daily digest, distinct from the burst-digest lock (800003). */
const DAILY_LOCK_CLASS = 800004;
const DAILY_SCHEDULE_ID = 'dailyDigest-schedule';
const SEVERITY_RANK: Advisory['severity'][] = ['UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];

/**
 * Daily digest subscription.
 *
 * Unlike the burst digest (which coalesces a live ingestion burst into one email
 * per recipient), the daily digest is a calendar job: once per day, in the
 * operator-configured timezone, it sends each opted-in recipient a single email
 * containing a rolled-up summary of that day's findings plus an operational
 * health-check report.
 *
 * The job is serialized with a session-level advisory lock (mirroring the burst
 * digest and retention workers) and de-duplicated per calendar day via a
 * `systemState` claim row, so a multi-tick window or a multi-replica deployment
 * cannot produce a second 9 AM mail.
 */

// The daily digest runs on the same clock as the UI: the operator-configured
// Settings timezone, or the documented system default when none is stored or
// the stored value is not a zone this runtime knows.
const resolveTimezone = (value: string | undefined): string => resolveSettingsTimezone(value);

const calendarDateKey = (timezone: string, now: number): string =>
  new Intl.DateTimeFormat('en-CA', {
    timeZone: timezone,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
  }).format(now);

const DIGEST_MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

// The calendar date is captured in `en-CA` (YYYY-MM-DD) for use as the stable
// advisory-id / de-duplication key. The human-facing title and email subject
// instead render it as ddMMMyyyy (e.g. 31Oct2026) per the daily digest format.
const formatDigestDate = (dateKey: string): string => {
  const [year, month, day] = dateKey.split('-');
  if (!year || !month || !day) return dateKey;
  const monthName = DIGEST_MONTHS[Number(month) - 1];
  return `${day.padStart(2, '0')}${monthName ?? month}${year}`;
};

const wallClock = (timezone: string, now: number): { hour: number; minute: number } => {
  const parts = new Intl.DateTimeFormat('en-US', {
    timeZone: timezone,
    hourCycle: 'h23',
    hour: 'numeric',
    minute: '2-digit',
  }).formatToParts(now);
  let hour = 0;
  let minute = 0;
  for (const part of parts) {
    if (part.type === 'hour') hour = Number(part.value);
    else if (part.type === 'minute') minute = Number(part.value);
  }
  return { hour, minute };
};

const parseTime = (value: string | undefined): { hour: number; minute: number } => {
  const [h, m] = String(value ?? '09:00')
    .split(':')
    .map(Number);
  return { hour: Number.isFinite(h) ? h : 9, minute: Number.isFinite(m) ? m : 0 };
};

async function readDailyDigestConfig(db: Db): Promise<TemplateCustomization> {
  const row = await get<{ dailyDigestCustomization?: TemplateCustomization }>(db, 'template', 'main');
  return row?.dailyDigestCustomization || DEFAULT_DAILY_DIGEST_CUSTOMIZATION;
}

async function readDailyDigestTemplate(db: Db): Promise<string | null> {
  const row = await get<{ dailyDigestCustomTemplate?: string | null }>(db, 'template', 'main');
  return row?.dailyDigestCustomTemplate ?? null;
}

const severityRank = (s: Advisory['severity']) => SEVERITY_RANK.indexOf(s);

const buildRemediationInstructions = (findings: Finding[]): string => {
  const criticals = findings.filter((f) => f.cve.cvss.severity === 'CRITICAL');
  const weaponized = findings.filter(
    (f) => f.cve.exploitStatus === 'Active Weaponized' || f.cve.exploitStatus === 'POC Available',
  );
  const kev = findings.filter((f) => f.cve.cisaKev?.isKev);

  const steps: string[] = [];

  if (kev.length > 0) {
    steps.push(
      `Immediately patch the ${kev.length} CISA Known Exploited Vulnerability${kev.length > 1 ? 'ies' : ''} listed above per the vendor advisory and your CISA KEV remediation timeline.`,
    );
  }
  if (criticals.length > 0 && kev.length === 0) {
    steps.push(
      `Prioritize remediation of the ${criticals.length} Critical-severity finding${criticals.length > 1 ? 's' : ''} above all other items; confirm active exploitation status via your threat intelligence feeds.`,
    );
  }
  if (weaponized.length > 0) {
    steps.push(
      `${weaponized.length} finding${weaponized.length > 1 ? 's' : ''} has active exploit${weaponized.length > 1 ? 's' : ''} in the wild — treat as priority and implement compensating controls if patching is not immediately feasible.`,
    );
  }

  steps.push(`Review each finding's applicability against your inventory, apply vendor patches via your change management process, and validate backups before and after remediation.`);

  if (findings.some((f) => f.confidence !== undefined && f.confidence < 90)) {
    steps.push('Findings with confidence below 90% require manual verification — confirm asset applicability and version evidence before acting.');
  }

  return steps.join(' ');
};

const buildDailyDigestAdvisory = (findings: Finding[], settings: AppSettings, dateKey: string): Advisory => {
  const cveIds = Array.from(new Set(findings.map((finding) => finding.cveId))).sort();
  const severity = findings.reduce<Advisory['severity']>(
    (severity, finding) =>
      severityRank(finding.cve.cvss.severity) > severityRank(severity) ? finding.cve.cvss.severity : severity,
    'UNKNOWN',
  );
  const severityCounts = countSeverities(findings);
  return {
    id: `${settings.advisoryPrefix}DAILY_${dateKey.replace(/-/g, '')}`,
    title: `Daily Vulnerability Notification — ${formatDigestDate(dateKey)}`,
    severity,
    cveIds,
    findingIds: findings.map((finding) => finding.id),
    createdDate: new Date().toISOString(),
    deliveryStatus: 'PENDING',
    recipientCount: 0,
    executiveSummary: formatExecutiveSummaryText(findings.length, severityCounts),
    remediationInstructions: buildRemediationInstructions(findings),
    vendorLink:
      Array.from(
        new Set(
          findings
            .map((finding) => finding.cve.remediation?.vendorAdvisoryRef || finding.cve.remediation?.patchUrl)
            .filter(Boolean),
        ),
      ).sort()[0] || '',
    affectedSystems: Array.from(new Set(findings.map((finding) => finding.matchedAssetName))).sort(),
    isDigestBatch: true,
  };
};

const formatSeverityCounts = (counts: Record<string, number>) =>
  Object.entries(counts)
    .filter(([, n]) => n > 0)
    .map(([s, n]) => `${n} ${s.toLowerCase()}`)
    .join(', ');

const countSeverities = (findings: Finding[]): Record<string, number> => {
  const counts: Record<string, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0 };
  for (const finding of findings)
    counts[finding.cve.cvss.severity] = (counts[finding.cve.cvss.severity] ?? 0) + 1;
  return counts;
};

const formatReportGenerated = (date: Date, timezone: string): string => {
  const parts = new Intl.DateTimeFormat('en-GB', {
    timeZone: timezone,
    day: 'numeric',
    month: 'long',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    timeZoneName: 'shortOffset',
  }).formatToParts(date);
  const day = parts.find((p) => p.type === 'day')?.value || '';
  const month = parts.find((p) => p.type === 'month')?.value || '';
  const year = parts.find((p) => p.type === 'year')?.value || '';
  const hour = parts.find((p) => p.type === 'hour')?.value || '';
  const minute = parts.find((p) => p.type === 'minute')?.value || '';
  const tz = parts.find((p) => p.type === 'timeZoneName')?.value || '';
  return `${day} ${month} ${year} | ${hour}:${minute} ${tz}`;
};

interface HealthSnapshot {
  database: 'connected' | 'degraded';
  databaseLatencyMs: number;
  workerStatus: 'DISABLED' | 'NOT_OBSERVED' | 'STALE' | 'HEALTHY';
  workerHeartbeatAgeSeconds: number | null;
  nextScheduledAttempt: string | null;
  nextDailyDigestAt: string | null;
  backlog: { status: string; count: number }[];
  checkedAt: string;
  systemUptime: string;
  systemUptimePercentage: number | null;
}

async function computeHealth(
  db: Db,
  workerEnabled: boolean,
  workerHeartbeat: string | null,
  timezone: string,
  time: string,
  now: number,
): Promise<HealthSnapshot> {
  const start = performance.now();
  let database: HealthSnapshot['database'] = 'connected';
  try {
    await db.query('SELECT 1');
  } catch {
    database = 'degraded';
  }
  const databaseLatencyMs = Math.round(performance.now() - start);
  const heartbeatMs = workerHeartbeat ? Date.parse(workerHeartbeat) : NaN;
  const workerHeartbeatAgeSeconds = Number.isFinite(heartbeatMs)
    ? Math.max(0, Math.floor((Date.now() - heartbeatMs) / 1000))
    : null;
  const workerStatus: HealthSnapshot['workerStatus'] = !workerEnabled
    ? 'DISABLED'
    : workerHeartbeatAgeSeconds === null
      ? 'NOT_OBSERVED'
      : workerHeartbeatAgeSeconds > 90
        ? 'STALE'
        : 'HEALTHY';
  // The health report is secondary. A transient queue-table/query failure must
  // not abort the whole daily digest after the day has already been claimed, or
  // the findings would never be delivered.
  let deliveryQueue: { nextScheduledAttempt: string | null } | undefined;
  let backlog: { status: string; count: number }[] = [];
  try {
    deliveryQueue = (
      await db.query<{
        nextScheduledAttempt: string | null;
        expiredLeases: number;
      }>(
        `SELECT
           min(next_attempt) FILTER (WHERE status='QUEUED' AND next_attempt>now()) AS "nextScheduledAttempt",
           count(*) FILTER (WHERE status='SENDING' AND locked_at<now()-interval '2 minutes')::int AS "expiredLeases"
         FROM outbox WHERE status IN ('QUEUED','SENDING')`,
      )
    ).rows[0];
    backlog = (
      await db.query<{ status: string; count: number }>(
        // ACCEPTED is required: the health report derives "Processed" from it.
        // Without it every digest reported `0 processed` next to a non-zero
        // backlog, which reads as a stuck queue even on a healthy day.
        `SELECT status,count(*)::int AS count FROM outbox
          WHERE status IN ('QUEUED','SENDING','FAILED','REVIEW','ACCEPTED')
          GROUP BY status`,
      )
    ).rows;
  } catch {
    database = 'degraded';
  }
  const uptimeSeconds = process.uptime();
  const uptimeDays = Math.floor(uptimeSeconds / 86400);
  const uptimeHours = Math.floor((uptimeSeconds % 86400) / 3600);
  const dayWord = uptimeDays === 1 ? 'Day' : 'Days';
  const hourWord = uptimeHours === 1 ? 'Hour' : 'Hours';
  const systemUptime = `${uptimeDays} ${dayWord} ${uptimeHours} ${hourWord}`;
  // Today's digest is already claimed. Use the next local calendar day, not
  // 24 elapsed hours, so DST changes preserve the configured send time.
  const { hour, minute } = parseTime(time);
  const nextDailyDigestAt = (
    await db.query<{ nextDailyDigestAt: Date }>(
      `SELECT (($1::timestamptz AT TIME ZONE $2)::date + 1 + $3::time)
         AT TIME ZONE $2 AS "nextDailyDigestAt"`,
      [new Date(now).toISOString(), timezone, `${hour}:${String(minute).padStart(2, '0')}`],
    )
  ).rows[0].nextDailyDigestAt.toISOString();
  return {
    database,
    databaseLatencyMs,
    workerStatus,
    workerHeartbeatAgeSeconds,
    nextScheduledAttempt: deliveryQueue?.nextScheduledAttempt ?? null,
    nextDailyDigestAt,
    backlog,
    checkedAt: new Date().toISOString(),
    systemUptime, // worker-process uptime, kept for continuity
    systemUptimePercentage: null,
  };
}

/**
 * Runs the daily digest job. Returns the number of transport jobs queued (0 when
 * the job is not scheduled/claimed, disabled, already sent today, or no recipient
 * has opted in). Intended to be polled on a short interval by the worker; the
 * claim logic guarantees at-most-once execution per calendar day per timezone.
 */
export async function runDailyDigest(pool: pg.Pool): Promise<number> {
  const settings = (await get<AppSettings>(pool, 'settings', 'main')) || DEFAULT_SETTINGS;
  const daily = settings.dailyDigest || DEFAULT_SETTINGS.dailyDigest;
  if (!daily?.enabled) return 0;

  const timezone = resolveTimezone(settings.timezone);
  const now = Date.now();
  const todayKey = calendarDateKey(timezone, now);
  const nowClock = wallClock(timezone, now);
  const targetClock = parseTime(daily.time);
  const pastTarget = nowClock.hour * 60 + nowClock.minute >= targetClock.hour * 60 + targetClock.minute;

  if (!pastTarget) return 0;

  const client = await pool.connect();
  let locked = false;
  let failed = false;
  try {
    // Cheap pre-check without the advisory lock: every tick after the send time
    // (and after today's digest already ran) would otherwise take the session
    // lock and write two INFO events per replica per minute — thousands of
    // no-op events per day. The locked path re-checks the claim row, so a stale
    // pre-check can only cause one extra serialized read, never a duplicate
    // send.
    const precheck = (
      await pool.query<{ data: { lastKey?: string } | null }>(
        "SELECT data FROM records WHERE kind='systemState' AND id=$1",
        [DAILY_SCHEDULE_ID],
      )
    ).rows[0]?.data;
    if (precheck?.lastKey === todayKey) return 0;

    // ATOMIC: Use try_advisory_lock to prevent race conditions
    const lockResult = await client.query<{ locked: boolean }>(`
      SELECT pg_try_advisory_lock(${DAILY_LOCK_CLASS}, ${schemaLockKey}) AS locked
    `);

    locked = lockResult.rows[0]?.locked === true;
    if (!locked) {
      // A peer holding the lock is normal multi-replica behaviour, not an
      // operational event worth a log row per minute.
      return 0;
    }
    
  return await transaction(
        pool,
        async (db) => {
        const row = await db.query<{ data: Record<string, unknown> }>(
          `SELECT data FROM records WHERE kind='systemState' AND id=$1 FOR UPDATE`,
          [DAILY_SCHEDULE_ID],
        );
        const data = row.rows[0]?.data ?? {};

        const recipients = (await list<EmailRecipient>(db, 'recipients')).filter(
          (r) => r.enabled && r.dailyDigest,
        );
        // The day is claimed only when there is somebody to send to. Claiming it
        // first meant that a tick running before any recipient opted in (or with
        // every recipient temporarily disabled) burned the whole day: the claim
        // request repeated every minute, reported "queued for 0 recipient(s)",
        // and never delivered the findings that were right there in the window.
        // A recipient added later that same day now still receives the digest.
        if (!recipients.length) {
          await put(db, 'systemState', DAILY_SCHEDULE_ID, {
            ...data,
            lastCheckedAt: new Date(now).toISOString(),
          });
          await writeEvent(db, {
            category: 'EMAIL',
            level: 'INFO',
            code: 'digest.daily.no_recipients',
            message: 'Daily digest is enabled but no recipients have opted in',
            context: { date: todayKey, time: daily.time, timezone },
          });
          return 0;
        }
        if (data.lastKey === todayKey) {
          await put(db, 'systemState', DAILY_SCHEDULE_ID, {
            ...data,
            lastCheckedAt: new Date(now).toISOString(),
          });
          return 0;
        }
        // Commit the claim before queueing so a crash mid-send cannot re-fire
        // today's digest.
        await put(db, 'systemState', DAILY_SCHEDULE_ID, {
          ...data,
          lastKey: todayKey,
          lastRun: new Date(now).toISOString(),
          lastRecipients: recipients.length,
        });

        const findingRows = await db.query<{ data: Finding }>(
          `SELECT data FROM records WHERE kind='findings' AND created_at > now() - interval '24 hours'`,
        );
        // A daily digest is a summary of the last 24 hours of *deliverable*
        // findings. A `REVIEW_REQUIRED` finding is deliberately withheld by the
        // confidence policy or by unverifiable applicability evidence, and the
        // delivery worker refuses to carry it in an email bundle. Including it
        // made the whole digest fail as stale every day (and, because the
        // findings stay held, repeat on the next day too). Held findings remain
        // available for operator review; they are not summarised in the email.
        // A finding that is already queued, sent, or held for review is carried by
        // its own consolidated findings email. Repeating it here delivered every
        // alert twice a day, so the summary only covers findings no other email
        // includes.
        const candidates: Finding[] = findingRows.rows
          .map((r) => r.data)
          .filter(
            (f) =>
              f &&
              f.cveId &&
              !['RESOLVED', 'FALSE_POSITIVE', 'PATCH_APPLIED'].includes(f.status) &&
              !['NOT_APPLICABLE', 'SUPPRESSED_VEX_NOT_AFFECTED', 'DELIVERY_FAILED'].includes(
                f.notificationStatus,
              ) &&
              !['QUEUED_FOR_DISPATCH', 'AUTO_DISPATCHED', 'DELIVERED', 'REVIEW_REQUIRED'].includes(
                f.notificationStatus,
              ) &&
              !f.advisoryId,
          );

        // Reassess against today's inventory and policy, including findings
        // held under an older threshold. Never treat a stored hold as approval.
        const ids = [...new Set(candidates.map((f) => f.cveId))];
        // Serial, not Promise.all: `db` is one pooled client inside this
        // transaction, and pg serialises (and deprecates) concurrent queries on
        // a single connection. Issuing four at once races the protocol queue and
        // the results are only ordered by luck.
        const cached = await getMany<NormalizedCVE>(db, 'cveData', ids);
        const assets = await getMany<WatchListItem>(
          db,
          'watchlist',
          [...new Set(candidates.map((f) => f.matchedAssetId))],
        );
        const withdrawals = await getMany<{ modifiedDate: string }>(db, 'cveWithdrawals', ids);
        const aliases = await list<AliasEntry>(db, 'aliases');
        const cves = new Map(candidates.map((f) => [f.cveId, cached.get(f.cveId) || f.cve]));
        const current = runVulnerabilityPipeline(
          [],
          [...cves.values()],
          [...assets.values()],
          [],
          [],
          { ...DEFAULT_SETTINGS, ...settings, scopeHours: 0 },
          'Daily digest',
          false,
          buildAliasMap(aliases, 'VENDOR'),
          buildAliasMap(aliases, 'PRODUCT'),
          undefined,
          aliases,
        ).newFindings;
        const matches = new Map(current.map((f) => [`${f.cveId}:${f.matchedAssetId}`, f]));
        const findings = candidates.flatMap((f) => {
          const match = matches.get(`${f.cveId}:${f.matchedAssetId}`);
          const withdrawal = withdrawals.get(f.cveId);
          // A withdrawn CVE is never summarised: the advisory no longer applies.
          if (withdrawal && Date.parse(f.cve?.modifiedDate || '') <= Date.parse(withdrawal.modifiedDate))
            return [];
          // The rematch is authoritative when it produced a verdict. When it did
          // not, the finding must not silently vanish from the digest: that
          // happens when the CVE cache entry was pruned by retention or the
          // inventory item was disabled after the finding was created, neither
          // of which invalidates the delivery that was already queued. Such a
          // finding keeps its stored (already-delivered) applicability.
          if (match)
            return match.notificationStatus === 'QUEUED_FOR_DISPATCH'
              ? [{ ...f, ...match, id: f.id }]
              : [];
          const storedDeliverable =
            f.notificationStatus === 'QUEUED_FOR_DISPATCH' ||
            f.notificationStatus === 'AUTO_DISPATCHED' ||
            f.notificationStatus === 'DELIVERED';
          return storedDeliverable ? [f] : [];
        });

        // Attach the workspace timezone so the server-rendered timestamps match
        // every other view in the product instead of hard-coding UTC.
        const dailyConfig = { ...(await readDailyDigestConfig(db)), timezone };
        const dailyDigestTemplate = await readDailyDigestTemplate(db);
        const advisory = buildDailyDigestAdvisory(findings, settings, todayKey);
        // Count of findings dispatched today with a stated confidence limitation.
        // There is no review queue: the figure tells the team how many alerts need
        // a follow-up applicability check, and is the same on every recipient's
        // email because a limited-confidence finding is not tier-specific.
        const heldForReview = findingRows.rows.filter(
          (r) => r.data?.cveId && r.data.notificationStatus === 'REVIEW_REQUIRED',
        ).length;
        const worker = (await db.query('SELECT heartbeat FROM scheduler_state WHERE id=1')).rows[0];
        const health = daily.includeHealthReport
          ? await computeHealth(db, settings.schedulerEnabled, worker?.heartbeat ?? null, timezone, daily.time, now)
          : null;
        const healthReportHtml = health ? renderDailyHealthReport(health, dailyConfig) : '';
        // No findings and no health report means there is nothing to email. Skip
        // enqueueing to avoid deliverNext rejecting an empty advisory as stale
        // and triggering a futile pipeline rebuild every day.
        if (!findings.length && !health) {
          await writeEvent(db, {
            category: 'EMAIL',
            level: 'INFO',
            code: 'digest.daily.no_findings',
            message: 'Daily digest skipped: no findings in the last 24 hours and health report disabled',
            context: { date: todayKey },
          });
          return 0;
        }
        let jobs = 0;
        for (const recipient of recipients) {
          // Relevance ranks eligible findings; it must never override subscriptions or hide an alert.
          const included = findings.filter((finding) => recipientAllows(recipient, finding))
            .map((finding) => ({
              finding,
              relevance: shouldSelectForDigest({
                cvssScore: finding.cve.cvss.score, epssScore: finding.cve.epss?.score ?? 0,
                cisaKev: finding.cve.cisaKev?.isKev === true,
                exploitStatus: Math.max(0, ['None', 'POC Available', 'Reported In Wild', 'Active Weaponized'].indexOf(finding.cve.exploitStatus)),
                daysSincePublished: Math.max(0, (Date.now() - Date.parse(finding.cve.publishedDate)) / 86400000) || 0,
                sourceFeedWeight: 0, credibilityScore: finding.confidence ?? 0, assetCriticality: 0,
                recipientTier: 'SUBSCRIBED_ONLY', findingInDigest: true, timeInDigestMinutes: 0,
              }),
            }))
            .sort((a, b) => b.relevance - a.relevance)
            .map(({ finding }) => finding);
          if (!included.length && !health) continue;
          const view = buildDailyDigestAdvisory(included, settings, todayKey);
          const severityCounts = countSeverities(included);
          const criticalCount = severityCounts.CRITICAL ?? 0;
          const highCount = severityCounts.HIGH ?? 0;
          const mediumCount = severityCounts.MEDIUM ?? 0;
          const lowCount = severityCounts.LOW ?? 0;
          const uniqueAssets = new Set(included.map((finding) => finding.matchedAssetId));
          const reportGenerated = formatReportGenerated(new Date(), timezone);
          // Keep the narrative's scope and counts identical to the recipient's KPIs.
          const executiveSummary = formatExecutiveSummary(included.length, severityCounts);
          const parts: DailyDigestParts = {
             advisory_id: view.id,
             advisory_title: view.title,
             dispatch_date: new Date().toISOString(),
             severity: view.severity,
             finding_count: included.length,
             severity_counts: formatSeverityCounts(severityCounts),
              findings_summary: renderDailyFindingSummary(
                included.map((finding) => ({
                  cveId: finding.cveId,
                  severity: finding.cve.cvss.severity,
                  assetName: finding.matchedAssetName,
                  vendor: finding.matchedAssetVendor,
                  sourceUrl: `https://nvd.nist.gov/vuln/detail/${finding.cveId}`,
                  cvssScore: finding.cve.cvss.score,
                  exploitStatus: finding.cve.exploitStatus,
                  epssScore: finding.cve.epss?.score,
                  cisaKev: finding.cve.cisaKev?.isKev,
                })),
                dailyConfig,
              ),
             health_report: healthReportHtml,
             recipient_name: recipient.name || recipient.email,
             critical_count: criticalCount,
             high_count: highCount,
             medium_count: mediumCount,
             low_count: lowCount,
             asset_count: uniqueAssets.size,
             executive_summary: executiveSummary,
             report_generated: reportGenerated,
           held_for_review: renderHeldForReview(heldForReview, dailyConfig),
           critical_summary: digestSeveritySummary('CRITICAL', criticalCount, dailyConfig),
           high_summary: digestSeveritySummary('HIGH', highCount, dailyConfig),
           medium_summary: digestSeveritySummary('MEDIUM', mediumCount, dailyConfig),
           low_summary: digestSeveritySummary('LOW', lowCount, dailyConfig),
           critical_kpi: digestSeverityKpi('CRITICAL', criticalCount, dailyConfig),
           high_kpi: digestSeverityKpi('HIGH', highCount, dailyConfig),
           medium_kpi: digestSeverityKpi('MEDIUM', mediumCount, dailyConfig),
           low_kpi: digestSeverityKpi('LOW', lowCount, dailyConfig),
          };
          const html = renderDailyDigest(dailyConfig, parts, dailyDigestTemplate ?? undefined);
          // Recorded so approval can prove the stored body is unchanged. The
          // union `advisory` here is built from every recipient's findings, so a
          // recipient-specific view must not be re-hashed against it.
          const contentRevision = advisoryRevision(view, included);
          const payload = {
            ...advisoryEmail(view, html, undefined, { findings: included }),
            cveIds: view.cveIds,
            recipientEmail: recipient.email,
            includedFindingIds: included.map((finding) => finding.id),
            // Content-revision evidence, so the delivery worker can prove the
            // queued body still describes the current CVE cache instead of
            // rejecting it as a revision-less legacy payload.
            findingRevisions: Object.fromEntries(
              included.map((finding) => [finding.id, findingRevision(finding)]),
            ),
            cveRevisions: Object.fromEntries(
              included.map((finding) => [finding.cveId, revision(finding.cve)]),
            ),
            digestKey: `daily:${todayKey}`,
            contentRevision,
            dailyDigest: true,
          };
          if (
            await enqueue(
              db,
              'email',
              recipient.id,
              advisory.id,
              payload,
              `daily:${todayKey}:email:${recipient.id}`,
              // Every recipient receives the digest: there is no review queue.
              'QUEUED',
            )
          )
            jobs++;
        }

        advisory.recipientCount = jobs;
        advisory.deliveryStatus = 'PENDING';
        await put(db, 'advisories', advisory.id, advisory);
        await writeEvent(db, {
          category: 'EMAIL',
          level: 'INFO',
          code: 'digest.daily.sent',
          message: `Daily digest queued for ${jobs} recipient(s) with ${findings.length} finding(s)`,
          context: {
            advisoryId: advisory.id,
            recipients: jobs,
            findings: findings.length,
            heldForReview,
            date: todayKey,
            time: daily.time,
            timezone,
          },
        });
        return jobs;
      },
      client,
    );
  } catch (error) {
    // A transport-level failure can leave the connection unusable; release with
    // the failure flag so the pool destroys it instead of recycling it.
    failed = true;
    throw error;
  } finally {
    if (locked)
      await client
        .query(`SELECT pg_advisory_unlock(${DAILY_LOCK_CLASS}, ${schemaLockKey}) AS locked`)
        .catch(() => {});
    client.release(failed);
  }
}
