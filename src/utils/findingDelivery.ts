import type { Finding } from '../types/index.ts';

/**
 * Identifies deliveries that represent a vulnerability advisory bundle.
 *
 * The Action Center's follow-up workflow re-renders an advisory and re-queues
 * it for an operator-selected audience. That is only meaningful for finding
 * advisories: daily digests, threat-intelligence news and zero-day digests are
 * generated summaries with no advisory row to re-render, so they must not appear
 * as pending follow-up actions.
 *
 * The advisory prefix is configurable, so this matches the fixed synthetic
 * prefixes and the `DAILY_<YYYYMMDD>` suffix rather than assuming `ADV-`.
 */
const NON_ADVISORY_PREFIXES = ['NEWS:', 'ZERODAY:', 'FINDINGS:', 'UNVERIFIABLE:'] as const;

export function isFindingDelivery(advisoryId: string | null | undefined): boolean {
  if (!advisoryId || advisoryId === 'TEST') return false;
  if (NON_ADVISORY_PREFIXES.some((prefix) => advisoryId.startsWith(prefix))) return false;
  return !/DAILY[_-]/i.test(advisoryId);
}

/**
 * True when a finding is still eligible to be announced.
 *
 * Every finding is dispatched — there is no operator review queue — so this
 * predicate answers only "has it already gone out, and is it still real?".
 * `REVIEW_REQUIRED` findings are eligible: the delivered email states their
 * confidence limitation on the finding itself.
 */
export function eligibleForDispatch(finding: Finding): boolean {
  const confidence = finding.confidence;
  return (
    !finding.reviewNotifiedAt &&
    !['RESOLVED', 'FALSE_POSITIVE', 'PATCH_APPLIED'].includes(finding.status) &&
    typeof confidence === 'number' &&
    Number.isFinite(confidence) &&
    confidence >= 0 &&
    confidence <= 100
  );
}


