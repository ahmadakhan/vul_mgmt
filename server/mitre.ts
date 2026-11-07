import type { NormalizedCVE, ThreatFeed } from '../src/types/index.ts';
import type { Requester } from './network';
import { type IngestContext, type IngestResult } from './ingestion';
import { cveSchema } from './validation';
import { normalizeCveId, sourceCveContentHash, stableJson } from '../src/utils/deduplicator';
import { parseCPE23 } from '../src/utils/cpeMatcher.ts';
import { paceConcurrent } from './concurrency';
import { z } from 'zod';
import { cvssSeverity, normalizeCvssVersion, sanitizeCvssVector } from './cvss.ts';
/** In-flight per-CVE detail fetches; overlaps network latency without
 * exceeding the feed's configured request rate (see paceConcurrent). */
const DETAIL_FETCH_CONCURRENCY = 8;
import { ingestionWindow, recentRevisions, type IngestionState } from './ingestionState';

export const MITRE_DELTA_URL = 'https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/deltaLog.json';
const timestamp = (value: unknown): string => {
  if (typeof value !== 'string' || !Number.isFinite(Date.parse(value))) throw new Error('Invalid CVE record date');
  return new Date(value).toISOString();
};

/** CVE JSON version rules can include exclusions and custom version schemes.
 * Retain CNA product criteria as review candidates, never assert automatic applicability. */
export function normalizeMitre(record: any, feedId: string): NormalizedCVE | null {
  if (record?.dataType !== 'CVE_RECORD' || !/^5\./.test(record.dataVersion || '')) throw new Error('Expected a CVE JSON 5 record');
  const meta = record.cveMetadata;
  const id = normalizeCveId(meta?.cveId);
  if (!id) throw new Error('Invalid MITRE CVE identifier');
  if (meta.state === 'REJECTED') return null;
  if (meta.state !== 'PUBLISHED' || !record.containers?.cna) throw new Error('Expected a published CVE record');
  const cna = record.containers.cna;
  const containers = [cna, ...(record.containers.adp || [])];
  const metrics = containers.flatMap(c => c.metrics || []);
  const metric = metrics.map(m => m.cvssV4_0).find(Boolean) || metrics.map(m => m.cvssV3_1 || m.cvssV3_0).find(Boolean) || metrics.map(m => m.cvssV2_0).find(Boolean);
  const score = metric?.baseScore ?? 0;
  const descriptions = cna.descriptions || [];
  const description = descriptions.find((d: any) => /^en(?:-|$)/i.test(d.lang))?.value || descriptions[0]?.value || cna.title || id;
  const affected = containers.flatMap(c => c.affected || []);
  const cpes = [...new Set<string>(affected.flatMap(a => (a.cpes || []).filter((c: unknown) => typeof c === 'string' && parseCPE23(c).isValid)))];
  // Include explicit CNA product names for review-only text matching when CPEs are absent.
  const productNames = affected.map(a => [a.vendor, a.product].filter((v: unknown) => typeof v === 'string').join(' ')).filter(Boolean).join('; ');
  const references = containers.flatMap(c => c.references || []);
  const reference = references.find(r => typeof r.url === 'string' && /^https:\/\//.test(r.url));
  return cveSchema.parse({
    cveId: id, title: String(cna.title || description).slice(0, 500),
    description: `${description}${productNames ? `\nCNA affected products: ${productNames}` : ''}`.slice(0, 30000),
    publishedDate: timestamp(meta.datePublished), modifiedDate: timestamp(meta.dateUpdated || meta.datePublished),
    // A selected metric without its own version label is v3.1: `metric` prefers
    // cvssV4_0, then cvssV3_1/cvssV3_0, then cvssV2_0, each of which carries a
    // version in a valid CNA record.
    cvss: { version: !metric ? 'UNKNOWN' : normalizeCvssVersion(metric.version),
      score, vector: sanitizeCvssVector(metric?.vectorString),
      // See the matching comment in ingestion.ts: a metric present without its
      // own baseScore is the storage sentinel, not a genuine CVSS 0.0.
      severity: !metric || metric.baseScore == null ? 'UNKNOWN' : cvssSeverity(score) },
    cwe: [...new Set(containers.flatMap(c => (c.problemTypes || []).flatMap((p: any) => (p.descriptions || []).map((d: any) => d.cweId).filter((id: unknown) => typeof id === 'string'))))].slice(0, 100),
    cpeMatches: cpes, applicabilityRequiresReview: true, applicabilityPolicy: 'REVIEW_ONLY', sourceFeeds: [feedId],
    epss: { score: 0, percentile: 0 }, cisaKev: { isKev: false }, exploitStatus: 'None',
    remediation: { patchUrl: '', vendorAdvisoryRef: reference?.url || '', immediateActions: [], workarounds: [], rollbackPlan: '', stepByStep: [] },
  });
}

export async function ingestMitre(feed: ThreatFeed, scopeHours: number, request: Requester, sleep: (ms: number) => Promise<unknown>, state: IngestContext = {}): Promise<IngestResult> {
  if (feed.url !== MITRE_DELTA_URL || feed.authType !== 'NONE') throw new Error('MITRE CVE requires the official cvelistV5 deltaLog.json endpoint without authentication');
  const index = await requestJson(request, feed.url, { timeoutMs: 120000, socketTimeoutMs: 60000, maxResponseBytes: 64 * 1024 * 1024,
    headers: state.indexEtag ? { 'If-None-Match': state.indexEtag } : {} });
  if (index.status === 304 && state.indexEtag) return { cves: [], count: 0, notModified: true, syncState: state };
  if (index.status !== 200) throw new Error(`MITRE CVE returned HTTP ${index.status}`);
  const parse = (body: string) => { try { return JSON.parse(body); } catch { throw new Error('MITRE CVE returned invalid JSON'); } };
  const readJson = async (url: string, maxBytes: number): Promise<any> => {
    const { status, body } = await requestJson(request, url, { timeoutMs: 120000, socketTimeoutMs: 60000, maxResponseBytes: maxBytes });
    if (status !== 200) throw new Error(`MITRE CVE returned HTTP ${status}`);
    return parse(body);
  };
  const { start, end, hasMore } = ingestionWindow(scopeHours, state);
  const changes = z.array(z.object({
    fetchTime: z.string(),
    new: z.array(z.object({ cveId: z.string(), dateUpdated: z.string() })),
    updated: z.array(z.object({ cveId: z.string(), dateUpdated: z.string() })),
    error: z.array(z.unknown()).optional(),
  })).min(1).max(20000).parse(parse(index.body));
  const revisions = recentRevisions(state.revisions || {}, start);
  const ids = new Set<string>();
  const warnings: string[] = [];
  if (scopeHours > 720 && !state.cursor) warnings.push('MITRE incremental history is limited to 30 days; older CVEs require a historical import');
  const fetchTimes = changes.map(entry => Date.parse(timestamp(entry.fetchTime)));
  const newestFetch = Math.max(...fetchTimes), oldestFetch = Math.min(...fetchTimes);
  if (state.cursor && Date.parse(state.cursor) < oldestFetch - 3600000)
    throw new Error('MITRE checkpoint predates available delta history; historical recovery is required');
  for (const entry of changes) {
    const fetched = Date.parse(timestamp(entry.fetchTime));
    if (fetched >= start.getTime() && fetched <= end.getTime() && entry.error?.length) throw new Error('MITRE delta log reports upstream record errors; retry later');
    for (const row of [...entry.new, ...entry.updated]) {
      const updated = Date.parse(timestamp(row.dateUpdated));
      const id = normalizeCveId(row.cveId);
      if (!id) throw new Error('MITRE delta log contains an invalid CVE identifier');
      // Delta timestamps belong to MITRE's revision stream. NVD/OpenCVE dates
      // are independent provider clocks and must not suppress a valid MITRE
      // record merely because another source reports a later timestamp.
      const known = Date.parse(revisions[id] || '');
      if (updated >= start.getTime() && updated <= end.getTime() && (!Number.isFinite(known) || updated > known || (Number.isFinite(known) && updated === known && Boolean(state.knownCveContent?.has(id))))) ids.add(id);
    }
  }
  if (ids.size > 5000) throw new Error('MITRE window exceeds 5,000 unique CVEs; reduce ingestion scope');
  const sorted = [...ids].sort();
  type DetailResult = { cve: NormalizedCVE | null; withdrawnId: string; modifiedDate: string; unchanged: boolean };
  // One request per changed CVE is unavoidable (the delta log has no bulk detail
  // endpoint), but requests no longer need to be fully serialized: pace dispatch
  // at the configured rate while letting several responses be in flight at once,
  // so each fetch's network latency overlaps instead of stacking on every wait.
  const fetched = await paceConcurrent(
    sorted,
    60000 / feed.rateLimitPerMin,
    DETAIL_FETCH_CONCURRENCY,
    sleep,
    async (id): Promise<DetailResult> => {
      const [, year, sequence] = id.split('-');
      // Construct paths from validated IDs; never follow URLs supplied inside feed content.
      const bucket = `${sequence.slice(0, -3)}xxx`;
      const url = `https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/${year}/${bucket}/${id}.json`;
      const record = await readJson(url, 4 * 1024 * 1024);
      if (normalizeCveId(record?.cveMetadata?.cveId) !== id) throw new Error('MITRE response did not match requested CVE');
      const cve = normalizeMitre(record, feed.id);
      // A timestamp-equal revision may still carry a silent content correction
      // (severity, remediation, CPE set) without advancing dateUpdated. When a
      // cached copy exists, compare the normalised record and mark identical
      // ones unchanged so the finding is neither re-emitted nor treated as a
      // withdrawal.
      const cached = state.knownCveContent?.get(id);
      const sourceRevision = cached?.sourceApplicability?.[feed.id];
      const unchanged = Boolean(
        cached &&
          cve &&
          (sourceRevision
            ? sourceRevision.contentHash === sourceCveContentHash(cve)
            : stableJson(cve) === stableJson(cached)),
      );
      return { cve, withdrawnId: id, modifiedDate: timestamp(record.cveMetadata.dateUpdated || record.cveMetadata.datePublished), unchanged };
    },
  );
  const cves: NormalizedCVE[] = [], withdrawals: NonNullable<IngestResult['withdrawals']> = [];
  for (const result of fetched) {
    if (result.unchanged) {
      // Re-fetched only to confirm content stability; refresh its revision
      // marker without re-emitting or withdrawing the record.
      revisions[result.withdrawnId] = result.modifiedDate;
      continue;
    }
    if (result.cve) cves.push(result.cve);
    else withdrawals.push({ cveId: result.withdrawnId, modifiedDate: result.modifiedDate });
    revisions[result.withdrawnId] = result.modifiedDate;
  }
  // Only move the cursor through delta entries confirmed by this completed run.
  const cursor = new Date(Math.max(Date.parse(state.cursor || '') || 0, Math.min(end.getTime(), newestFetch))).toISOString();
  return { cves: cves.sort((a, b) => a.cveId.localeCompare(b.cveId)), withdrawals, count: sorted.length, warnings,
    syncState: { cursor, hasMore: end.getTime() < newestFetch, revisions, indexEtag: end.getTime() >= newestFetch && typeof index.headers.etag === 'string' ? index.headers.etag : undefined } };
}

/** Retry transient upstream stalls without advancing the source cursor. */
async function requestJson(request: Requester, url: string, options: Parameters<Requester>[1]) {
  for (let attempt = 0; ; attempt++) {
    try {
      const response = await request(url, options);
      if (![429, 502, 503, 504].includes(response.status) || attempt >= 2) return response;
      const raw = response.headers['retry-after'];
      const retryAfter = Array.isArray(raw) ? raw[0] : raw;
      const seconds = retryAfter ? Number(retryAfter) : NaN;
      const date = retryAfter ? Date.parse(retryAfter) : NaN;
      const requestedDelay = Number.isFinite(seconds) ? seconds * 1000 : Number.isFinite(date) ? date - Date.now() : 0;
      if (requestedDelay > 60000) throw new Error(`MITRE requested a ${Math.ceil(requestedDelay / 1000)} second retry delay; defer to a later run`);
      await new Promise((resolve) => setTimeout(resolve, Math.max(2000 * (attempt + 1), requestedDelay)));
    } catch (error) {
      const transient = error instanceof Error && (/timed out|timeout|^aborted$|socket hang up|premature close/i.test(error.message) || ['ECONNRESET', 'ETIMEDOUT', 'EPIPE', 'UND_ERR_SOCKET'].includes((error as NodeJS.ErrnoException).code || ''));
      if (!transient || attempt >= 2) throw error;
      await new Promise((resolve) => setTimeout(resolve, 2000 * (attempt + 1)));
    }
  }
}
