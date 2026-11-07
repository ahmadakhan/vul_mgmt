import type { Finding } from '../types';
import { normalizeCveId } from '../utils/deduplicator';
/** Stable identity shared by reconciliation, matching and detection counts. */
export const findingIdentity = (f: Finding) =>
  `${normalizeCveId(f.cveId) ?? `raw:${f.cveId || f.id}`}:${f.matchedAssetId}`;
/**
 * Count candidates whose (CVE, asset) identity was not present in the previous
 * finding set. The pipeline re-derives every current match on each run so it
 * can refresh applicability; only identities absent from the previous set are
 * genuinely new detections. Repeated candidates within the run count once.
 */
export function countNewFindings(existing: readonly Finding[], candidates: readonly Finding[]): number {
  const known = new Set(existing.map(findingIdentity));
  const detected = new Set<string>();
  for (const candidate of candidates) {
    const id = findingIdentity(candidate);
    if (!known.has(id)) detected.add(id);
  }
  return detected.size;
}
/** Preserve finding identity, operator lifecycle decisions and delivery history while refreshing applicability. */
export function reconcileFindings(
  existing: Finding[],
  candidates: Finding[],
  now = new Date().toISOString(),
): Finding[] {
  const previous = new Map(existing.map((f) => [findingIdentity(f), f]));
  const uniqueCandidates: Finding[] = [];
  {
    const seen = new Set<string>();
    const dupes: Finding[] = [];
    for (const candidate of candidates) {
      const id = findingIdentity(candidate);
      if (seen.has(id)) {
        dupes.push(candidate);
        continue;
      }
      seen.add(id);
      uniqueCandidates.push(candidate);
    }
    if (dupes.length)
      console.warn(
        `[reconcileFindings] dropped ${dupes.length} duplicate candidate(s) with identities already present in the candidate set`,
      );
  }
  const current = new Set(uniqueCandidates.map(findingIdentity));
  const result = uniqueCandidates.map((candidate) => {
    const old = previous.get(findingIdentity(candidate));
    if (!old) return candidate;
    let notificationStatus = candidate.notificationStatus;
    if (notificationStatus !== 'REVIEW_REQUIRED' && old.advisoryId) {
      notificationStatus = old.autoDispatchedAt
        ? 'AUTO_DISPATCHED'
        : ['QUEUED_FOR_DISPATCH', 'DELIVERY_FAILED', 'SECURITY_REJECTED'].includes(old.notificationStatus)
          ? old.notificationStatus
          : 'DELIVERY_FAILED';
    } else if (old.reviewNotifiedAt) {
      // The finding has already been announced in a consolidated email. The
      // matcher rebuilds its candidate set on every run (a refreshed CVE record
      // re-derives the match), so without this the stored status was reset to the
      // freshly-built `QUEUED_FOR_DISPATCH` and the next run queued the same
      // finding again — a duplicate email for content the recipient already had.
      // `reviewNotifiedAt` is stamped on transport acceptance and is the only
      // durable record that this finding was delivered.
      notificationStatus = 'AUTO_DISPATCHED';
    } else if (notificationStatus !== 'REVIEW_REQUIRED' && old.notificationStatus === 'DELIVERY_FAILED') {
      // A delivery failure is a terminal, operator-visible outcome. The candidate
      // is freshly built and always starts as QUEUED_FOR_DISPATCH, so without this
      // every pipeline run silently turned a failed delivery back into an
      // automatic resend. Recovery from a failure is an explicit operator action;
      // only a rebuild that re-queued the finding (it sets `advisoryId`) or an
      // operator re-queue may clear it.
      //
      // `autoDispatchedAt` must NOT be part of the recovery test. It is stamped by
      // the *first* successful acceptance, so a later failed re-delivery of a
      // finding that still carries its advisory satisfied the old
      // `autoDispatchedAt || advisoryId === null` disjunct and was reset to
      // QUEUED_FOR_DISPATCH — the next run queued the same advisory again and the
      // security team received a duplicate email for unchanged content. Only a
      // cleared advisory (the pipeline clears it for a wholly rejected bundle so
      // a rebuild can re-queue the finding) is a recovery signal.
      notificationStatus = old.advisoryId === null ? candidate.notificationStatus : 'DELIVERY_FAILED';
    }
    const changed =
      old.matchingEvidence !== candidate.matchingEvidence ||
      old.matchedCpe !== candidate.matchedCpe ||
      old.matchedAssetVendor !== candidate.matchedAssetVendor ||
      old.matchedAssetProduct !== candidate.matchedAssetProduct ||
      JSON.stringify(old.matchedAssetPurls ?? []) !== JSON.stringify(candidate.matchedAssetPurls ?? []) ||
      old.notificationStatus !== notificationStatus;
    return {
      ...old,
      cve: candidate.cve,
      matchedAssetName: candidate.matchedAssetName,
      matchedAssetVendor: candidate.matchedAssetVendor,
      matchedAssetProduct: candidate.matchedAssetProduct,
      matchedAssetPurls: candidate.matchedAssetPurls,
      matchedCpe: candidate.matchedCpe,
      matchingMethod: candidate.matchingMethod,
       matchingEvidence: candidate.matchingEvidence,
       confidence: candidate.confidence,
       exposure: candidate.exposure,
       // Announcement state is never reset by a re-evaluation: it records
       // what was *sent*, not what currently applies.
       reviewNotifiedAt: old.reviewNotifiedAt ?? candidate.reviewNotifiedAt ?? null,
      exploitRisk: candidate.exploitRisk,
      mlAssessment: candidate.mlAssessment,
      notificationStatus,
      timeline: changed
        ? [
            ...(old.timeline ?? []),
            {
              timestamp: now,
              action: 'Applicability re-evaluated',
              system: 'Server correlation engine',
              details: candidate.matchingEvidence,
            },
          ]
        : old.timeline,
    };
  });
  for (const old of existing)
    if (!current.has(findingIdentity(old)))
      result.push(
        old.notificationStatus === 'NOT_APPLICABLE'
          ? old
          : {
              ...old,
              notificationStatus: 'NOT_APPLICABLE',
              matchingEvidence:
                'No current match: inventory is inactive, removed, or outside the cached vulnerability criteria.',
              timeline: [
                ...(old.timeline ?? []),
                {
                  timestamp: now,
                  action: 'Applicability re-evaluated',
                  system: 'Server correlation engine',
                  details: 'No current inventory match; excluded from notification.',
                },
              ],
            },
      );
  return result;
}
