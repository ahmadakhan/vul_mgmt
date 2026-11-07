import type { Finding } from '../types';

const timestamp = (value: string): number => {
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : Number.NEGATIVE_INFINITY;
};

/**
 * Newest finding first. A finding's "latest activity" is the more recent of its
 * CVE's published and modified dates, so a vulnerability whose record was only
 * updated (no new publication) still surfaces above one published long ago.
 */
export function compareFindingsByRecency(a: Finding, b: Finding): number {
  const latestA = Math.max(timestamp(a.cve.publishedDate), timestamp(a.cve.modifiedDate));
  const latestB = Math.max(timestamp(b.cve.publishedDate), timestamp(b.cve.modifiedDate));
  if (latestA !== latestB) return latestA > latestB ? -1 : 1;
  return a.cveId.localeCompare(b.cveId) || a.id.localeCompare(b.id);
}
