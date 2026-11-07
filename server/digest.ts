import type pg from 'pg';
import { DEFAULT_SETTINGS } from '../shared/state.ts';
import { DEFAULT_TEMPLATE_CUSTOMIZATION, compileCustomizedTemplate } from '../src/utils/templateCompiler.ts';
import { formatAdvisoryId } from '../src/utils/executionName.ts';
import type { Advisory, AppSettings, Finding, TemplateCustomization } from '../src/types/index.ts';
import {
  get,
  getForUpdate,
  put,
  remove,
  schemaLockKey,
  transaction,
  type Db,
} from './db.ts';
import { writeEvent } from './events.ts';
import { queueDigestAdvisory } from './delivery.ts';
import { renderAdvisory } from './advisoryRender.ts';

/**
 * Durable digest buffer.
 *
 * Findings are written into this record by the pipeline transaction and are
 * only turned into outbox jobs when the configured window elapses. That keeps
 * a burst of detections — whether from one run or several — in a single email
 * per recipient, without blocking the pipeline on transport latency.
 */
const DIGEST_KIND = 'digestBuffer';
const DIGEST_ID = 'pending';
const DIGEST_OVERFLOW_KIND = 'digestOverflow';
const DIGEST_OVERFLOW_ID = 'pending';
const MAX_BUFFERED_FINDINGS = 2000;
/** Bound one message. Larger bursts are sent as consecutive digest batches. */
const MAX_DIGEST_FINDINGS = 500;
const MIN_RETRY_MINUTES = 5;

interface DigestBufferItem {
  findingId: string;
  bufferedAt: string;
}

interface DigestBuffer {
  items: DigestBufferItem[];
  flushAt: string;
  attempts?: number;
  updatedAt: string;
}

const windowMinutes = (value: number | undefined) =>
  Math.max(1, Math.min(1440, Math.floor(Number.isFinite(value) ? value! : 5)));

/**
 * Adds findings to the current digest batch. Duplicate finding IDs are ignored,
 * so a repeated pipeline pass cannot make the eventual email larger or cause a
 * second delivery. The oldest entries are dropped only at the hard cap; those
 * findings stay unassigned and are picked up by the next pipeline run.
 */
export async function bufferFindingsForDigest(
  db: Db,
  findingIds: string[],
  digestWindowMinutes: number,
): Promise<number> {
  const unique = Array.from(new Set(findingIds.filter((id) => typeof id === 'string' && id.length)));
  if (!unique.length) return 0;

  const now = Date.now();
  const existing = await getForUpdate<DigestBuffer>(db, DIGEST_KIND, DIGEST_ID);
  const current = existing?.items ?? [];
  const known = new Set(current.map((item) => item.findingId));
  const added = unique
    .filter((id) => !known.has(id))
    .map((findingId) => ({ findingId, bufferedAt: new Date(now).toISOString() }));
  if (!added.length) return 0;

  let items = [...current, ...added];
  let overflowed = 0;
  if (items.length > MAX_BUFFERED_FINDINGS) {
    overflowed = items.length - MAX_BUFFERED_FINDINGS;
    const overflowItems = items.slice(0, overflowed);
    items = items.slice(overflowed);
    const existingOverflow = await getForUpdate<DigestBuffer>(db, DIGEST_OVERFLOW_KIND, DIGEST_OVERFLOW_ID);
    const existingIds = new Set((existingOverflow?.items ?? []).map((item) => item.findingId));
    const durable = [...(existingOverflow?.items ?? []), ...overflowItems.filter((item) => !existingIds.has(item.findingId))];
    await put(db, DIGEST_OVERFLOW_KIND, DIGEST_OVERFLOW_ID, {
      items: durable,
      flushAt: existingOverflow?.flushAt ?? new Date(now).toISOString(),
      attempts: existingOverflow?.attempts ?? 0,
      updatedAt: new Date(now).toISOString(),
    } satisfies DigestBuffer);
  }

  const existingDue = existing ? Date.parse(existing.flushAt) : NaN;
  const nextDue = now + windowMinutes(digestWindowMinutes) * 60_000;
  const flushAt = new Date(
    Number.isFinite(existingDue) ? Math.min(existingDue, nextDue) : nextDue,
  ).toISOString();

  await put(db, DIGEST_KIND, DIGEST_ID, {
    items,
    flushAt,
    attempts: existing?.attempts ?? 0,
    updatedAt: new Date(now).toISOString(),
  } satisfies DigestBuffer);

  if (overflowed)
    await writeEvent(db, {
      category: 'EMAIL',
      level: 'WARNING',
      code: 'digest.buffer_overflowed',
      message: 'Digest buffer reached capacity; overflow findings were persisted for later delivery',
      context: { overflowed, buffered: items.length, cap: MAX_BUFFERED_FINDINGS },
    });
  return added.length;
}

/**
 * A finding is deliverable when it still applies and has not been sent.
 *
 * `REVIEW_REQUIRED` is included deliberately: there is no operator review queue,
 * so a finding the confidence or applicability policy could not fully confirm is
 * delivered like any other and the email states the limitation on the finding.
 * Excluding it left those findings undelivered forever once they entered the
 * digest buffer.
 */
const DELIVERABLE_STATUSES: readonly Finding['notificationStatus'][] = [
  'QUEUED_FOR_DISPATCH',
  'REVIEW_REQUIRED',
];
const isDeliverable = (finding: Finding | undefined): finding is Finding =>
  !!finding &&
  !finding.advisoryId &&
  !finding.reviewNotifiedAt &&
  DELIVERABLE_STATUSES.includes(finding.notificationStatus) &&
  !['RESOLVED', 'FALSE_POSITIVE', 'PATCH_APPLIED'].includes(finding.status);

const buildDigestAdvisory = (findings: Finding[], settings: AppSettings): Advisory => {
  const cveIds = Array.from(new Set(findings.map((finding) => finding.cveId))).sort();
  const rank = ['UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
  return {
    id: formatAdvisoryId(settings.advisoryPrefix),
    title: `Vulnerability Notification: ${cveIds.slice(0, 3).join(', ')}${cveIds.length > 3 ? ` (+${cveIds.length - 3} more)` : ''}`,
    severity: findings.reduce(
      (severity, finding) =>
        rank.indexOf(finding.cve.cvss.severity) > rank.indexOf(severity)
          ? finding.cve.cvss.severity
          : severity,
      'UNKNOWN' as Advisory['severity'],
    ),
    cveIds,
    findingIds: findings.map((finding) => finding.id),
    createdDate: new Date().toISOString(),
    deliveryStatus: 'PENDING',
    recipientCount: 0,
    executiveSummary: `${findings.length} inventory correlations require investigation. Confirm applicability and consult the vendor before remediation.`,
    remediationInstructions:
      'Review vendor advisories and deploy tested remediation through your change process.',
    vendorLink:
      Array.from(
        new Set(
          findings
            .map((finding) => finding.cve.remediation.vendorAdvisoryRef || finding.cve.remediation.patchUrl)
            .filter(Boolean),
        ),
      ).sort()[0] || '',
    affectedSystems: Array.from(new Set(findings.map((finding) => finding.matchedAssetName))).sort(),
    isDigestBatch: true,
  };
};

async function readSettingsAndTemplate(db: Db): Promise<{ settings: AppSettings; template: string }> {
  const [settings, template] = await Promise.all([
    get<AppSettings>(db, 'settings', 'main'),
    get<{ templateCustomization?: TemplateCustomization }>(db, 'template', 'main'),
  ]);
  return {
    settings: settings ?? DEFAULT_SETTINGS,
    // Match pipelineState: regenerate from the saved layout so a digest uses
    // the same current template even when the denormalized HTML is outdated.
    template:
      (template?.templateCustomization &&
        compileCustomizedTemplate(template.templateCustomization)) ||
      compileCustomizedTemplate(DEFAULT_TEMPLATE_CUSTOMIZATION),
  };
}

/**
 * Flushes one due digest batch.
 *
 * Serialized with the pipeline using the same session advisory lock the worker
 * uses for a run, so a flush can never assign an advisory to findings while the
 * pipeline is still reconciling them. Returns the number of transport jobs
 * created (0 when the window is not due, another worker holds the lock, or no
 * recipient/webhook currently accepts the batch).
 */
export async function flushDueDigest(pool: pg.Pool): Promise<number> {
  const client = await pool.connect();
  let locked = false;
  let failed = false;
  try {
    locked =
      (
        await client.query<{ locked: boolean }>(
          `SELECT pg_try_advisory_lock(800003, ${schemaLockKey}) AS locked`,
        )
      ).rows[0]?.locked === true;
    if (!locked) return 0;

    return await transaction(
      pool,
      async (db) => {
        let buffer = await getForUpdate<DigestBuffer>(db, DIGEST_KIND, DIGEST_ID);
        if (!buffer?.items.length) {
          const overflow = await getForUpdate<DigestBuffer>(db, DIGEST_OVERFLOW_KIND, DIGEST_OVERFLOW_ID);
          if (!overflow?.items.length) return 0;
          buffer = {
            items: overflow.items.slice(0, MAX_DIGEST_FINDINGS),
            flushAt: new Date(Date.now()).toISOString(),
            attempts: overflow.attempts ?? 0,
            updatedAt: overflow.updatedAt,
          };
          const remaining = overflow.items.slice(MAX_DIGEST_FINDINGS);
          if (remaining.length)
            await put(db, DIGEST_OVERFLOW_KIND, DIGEST_OVERFLOW_ID, { ...overflow, items: remaining, updatedAt: new Date().toISOString() } satisfies DigestBuffer);
          else
            await remove(db, DIGEST_OVERFLOW_KIND, DIGEST_OVERFLOW_ID);
        }

        const { settings, template } = await readSettingsAndTemplate(db);
        const now = Date.now();
        const due = Date.parse(buffer.flushAt);
        // When the operator turns digest batching off, existing buffered
        // findings are still delivered as one combined batch rather than
        // silently abandoned.
        if (settings.digestBatchingEnabled && Number.isFinite(due) && due > now) return 0;

        const batchItems = buffer.items.slice(0, MAX_DIGEST_FINDINGS);
        // Items past the per-message cap are not queried in this pass, but they
        // must stay in the buffer. Treating them as stale here would silently
        // drop every finding after the first 500 in a large burst.
        const overflowItems = buffer.items.slice(batchItems.length);
        const ids = batchItems.map((item) => item.findingId);
        const rows = (
          await db.query<{ id: string; data: Finding }>(
            "SELECT id,data FROM records WHERE kind='findings' AND id=ANY($1::text[])",
            [ids],
          )
        ).rows;
        const byId = new Map(rows.map((row) => [row.id, row.data]));
        const usable = ids.map((id) => byId.get(id)).filter(isDeliverable);

        if (!usable.length) {
          const stale = batchItems.length;
          if (overflowItems.length)
            await put(db, DIGEST_KIND, DIGEST_ID, {
              items: overflowItems,
              // The next slice can be attempted immediately; it has not had a
              // delivery attempt yet just because the first slice was stale.
              flushAt: new Date(now).toISOString(),
              attempts: buffer.attempts ?? 0,
              updatedAt: new Date(now).toISOString(),
            } satisfies DigestBuffer);
          else await remove(db, DIGEST_KIND, DIGEST_ID);
          if (stale)
            await writeEvent(db, {
              category: 'EMAIL',
              level: 'INFO',
              code: 'digest.stale_entries_dropped',
              message: 'Digest buffer discarded findings that are no longer deliverable',
              context: { dropped: stale },
            });
          return 0;
        }

        const advisory = buildDigestAdvisory(usable, settings);
        // One pinned instant per flush: the body, the text alternative and the
        // PDF attachment of every recipient describe the same document.
        const generatedAt = new Date();
        const result = await queueDigestAdvisory(db, advisory, usable, (view, batchFindings) =>
          renderAdvisory(template, view, batchFindings, { generatedAt }),
        );
        const included = new Set(result.findingIds);
        if (result.jobs)
          for (const findingId of result.findingIds) {
            const finding = byId.get(findingId);
            if (finding)
              await put(db, 'findings', findingId, { ...finding, advisoryId: advisory.id });
          }

        // Items no longer deliverable are discarded; findings that are still
        // actionable but have no eligible subscriber stay buffered and are
        // retried later. The pipeline re-evaluates them on every run as well.
        const leftovers = batchItems.filter((item) => {
          const finding = byId.get(item.findingId);
          return isDeliverable(finding) && !included.has(item.findingId);
        });
        const retained = batchItems.filter((item) => included.has(item.findingId)).length;
        const stale = batchItems.length - retained - leftovers.length;
        const nextItems = [...leftovers, ...overflowItems];
        if (nextItems.length) {
          // A follow-up batch from the same burst goes out on the next worker
          // tick. Findings with no eligible subscriber wait for the retry
          // interval instead of spinning.
          const immediate = result.jobs > 0 && overflowItems.length > 0;
          const retryAt = immediate
            ? new Date(now).toISOString()
            : new Date(
                now +
                  Math.max(MIN_RETRY_MINUTES, windowMinutes(settings.digestWindowMinutes)) * 60_000,
              ).toISOString();
          await put(db, DIGEST_KIND, DIGEST_ID, {
            items: nextItems,
            flushAt: retryAt,
            attempts: immediate ? buffer.attempts ?? 0 : (buffer.attempts ?? 0) + 1,
            updatedAt: new Date(now).toISOString(),
          } satisfies DigestBuffer);
        } else {
          await remove(db, DIGEST_KIND, DIGEST_ID);
        }

        if (result.jobs)
          await writeEvent(db, {
            category: 'EMAIL',
            level: 'INFO',
            code: 'digest.flushed',
            message: 'Threat digest queued for delivery',
            context: {
              advisoryId: advisory.id,
              findings: result.findingIds.length,
              jobs: result.jobs,
              targets: result.eligible,
            },
          });
        else if (!result.eligible && !(buffer.attempts ?? 0))
          await writeEvent(db, {
            category: 'EMAIL',
            level: 'WARNING',
            code: 'digest.waiting_for_recipient',
            message: 'Digest is waiting because no enabled recipient or webhook accepts these findings',
            context: { findings: usable.length, attemptedFindings: buffer.items.length },
          });
        if (stale)
          await writeEvent(db, {
            category: 'EMAIL',
            level: 'INFO',
            code: 'digest.stale_entries_dropped',
            message: 'Digest buffer discarded findings that are no longer deliverable',
            context: { dropped: stale },
          });

        return result.jobs;
      },
      client,
    );
  } catch (error) {
    // A transport-level failure can leave the connection in an unusable state;
    // release with the failure flag so the pool destroys it instead of handing
    // a wedged socket to the next caller.
    failed = true;
    throw error;
  } finally {
    if (locked)
      await client.query(`SELECT pg_advisory_unlock(800003, ${schemaLockKey})`).catch(() => {});
    client.release(failed);
  }
}
