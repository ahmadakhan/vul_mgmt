/**
 * CVE ID Normalization and Deduplication Engine
 * Enforces canonical CVE-YYYY-NNNN+ format and O(1) tracking.
 */

import type { NormalizedCVE } from '../types';
import type { SourceApplicabilityEvidence } from '../types';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils.js';

const CVE_REGEX = /^CVE-\d{4}-\d{4,}$/i;

export function stableJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`;
  if (value && typeof value === 'object')
    return `{${Object.entries(value)
      .filter(([, v]) => v !== undefined)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
      .map(([key, v]) => `${JSON.stringify(key)}:${stableJson(v)}`)
      .join(',')}}`;
  return JSON.stringify(value) ?? 'null';
}

/** Stable SHA-256 key for detecting an unchanged provider revision. */
export function sourceCveContentHash(cve: NormalizedCVE): string {
  const { sourceFeeds: _sourceFeeds, sourceApplicability: _sourceApplicability, ...content } = cve;
  return bytesToHex(sha256(utf8ToBytes(stableJson(content))));
}

/** Merge independent providers while replacing revisions within each provider. */
export function mergeCveRecords(records: NormalizedCVE[]): Map<string, NormalizedCVE> {
  const merged = new Map<string, NormalizedCVE>();
  const content = ({
    sourceFeeds: _sources,
    sourceApplicability: _applicability,
    cpeMatches: _cpeMatches,
    cpeMatchDetails: _cpeMatchDetails,
    purls: _purls,
    versionRange: _versionRange,
    applicabilityRequiresReview: _applicabilityRequiresReview,
    applicabilityPolicy: _applicabilityPolicy,
    ...cve
  }: NormalizedCVE) => stableJson(cve);
  const detailsFor = (cve: NormalizedCVE) =>
    cve.cpeMatchDetails?.length
      ? cve.cpeMatchDetails
      : cve.cpeMatches.map((criteria) => ({ criteria, range: cve.versionRange }));
  const evidenceFor = (cve: NormalizedCVE): SourceApplicabilityEvidence => ({
    modifiedDate: cve.modifiedDate,
    cpeMatches: [...cve.cpeMatches],
    cpeMatchDetails: detailsFor(cve),
    versionRange: cve.versionRange,
    purls: cve.purls ? [...cve.purls] : undefined,
    applicabilityRequiresReview: cve.applicabilityRequiresReview,
    applicabilityPolicy: cve.applicabilityPolicy,
    contentHash: sourceCveContentHash(cve),
  });
  const hasApplicabilityData = (evidence: SourceApplicabilityEvidence) =>
    evidence.cpeMatches.length > 0 ||
    evidence.cpeMatchDetails.length > 0 ||
    Boolean(evidence.purls?.length) ||
    Boolean(evidence.versionRange && Object.values(evidence.versionRange).some(Boolean));
  const sourceEvidence = (cve: NormalizedCVE): Map<string, SourceApplicabilityEvidence> => {
    if (cve.sourceApplicability) return new Map(Object.entries(cve.sourceApplicability));
    const sources = [...new Set(cve.sourceFeeds.filter(Boolean))];
    const keys = sources.length === 1 ? sources : ['__legacy_applicability__'];
    return new Map(keys.map((source) => [source, evidenceFor(cve)]));
  };
  const applicabilitySignature = (evidence: SourceApplicabilityEvidence) =>
    stableJson({
      cpes: [...new Set(evidence.cpeMatches)].sort(),
      details: evidence.cpeMatchDetails.map(stableJson).sort(),
      range: evidence.versionRange,
      purls: [...new Set(evidence.purls || [])].sort(),
    });
  const aggregateApplicability = (
    evidence: SourceApplicabilityEvidence[],
    equalRevisionConflict = false,
  ) => {
    const applicabilityEvidence = evidence.filter(hasApplicabilityData);
    const decisionEvidence = applicabilityEvidence.length ? applicabilityEvidence : evidence;
    const signatures = new Set(applicabilityEvidence.map(applicabilitySignature));
    const hasCrossSourceConflict = applicabilityEvidence.length > 1 && signatures.size > 1;
    const rangeValues = new Set(
      applicabilityEvidence.filter((entry) => entry.versionRange).map((entry) => stableJson(entry.versionRange)),
    );
    const hasConflictingRanges = rangeValues.size > 1;
    const details = [...new Map(
      evidence.flatMap((entry) => entry.cpeMatchDetails).map((detail) => [stableJson(detail), detail]),
    ).values()].sort((a, b) => stableJson(a).localeCompare(stableJson(b)));
    const cpeMatches = [...new Set([
      ...evidence.flatMap((entry) => entry.cpeMatches),
      ...details.map((detail) => detail.criteria),
    ])].sort();
    const purls = [...new Set(evidence.flatMap((entry) => entry.purls || []))].sort();
    return {
      cpeMatches,
      cpeMatchDetails: details,
      purls: purls.length ? purls : undefined,
      versionRange: hasConflictingRanges
        ? undefined
        : applicabilityEvidence.find((entry) => entry.versionRange)?.versionRange,
      applicabilityRequiresReview:
        decisionEvidence.some((entry) => entry.applicabilityRequiresReview) ||
        hasCrossSourceConflict ||
        equalRevisionConflict ||
        hasConflictingRanges,
      applicabilityPolicy: decisionEvidence.some((entry) => entry.applicabilityPolicy === 'REVIEW_ONLY')
        ? 'REVIEW_ONLY' as const
        : undefined,
    };
  };
  const mergeEqualSourceRevision = (
    old: SourceApplicabilityEvidence,
    candidate: SourceApplicabilityEvidence,
  ): SourceApplicabilityEvidence => ({
    ...candidate,
    cpeMatches: [...new Set([...old.cpeMatches, ...candidate.cpeMatches])].sort(),
    cpeMatchDetails: [...new Map(
      [...old.cpeMatchDetails, ...candidate.cpeMatchDetails].map((detail) => [stableJson(detail), detail]),
    ).values()].sort((a, b) => stableJson(a).localeCompare(stableJson(b))),
    versionRange:
      stableJson(old.versionRange) === stableJson(candidate.versionRange) ? candidate.versionRange : undefined,
    purls: [...new Set([...(old.purls || []), ...(candidate.purls || [])])].sort(),
    applicabilityRequiresReview: true,
    applicabilityPolicy:
      old.applicabilityPolicy === 'REVIEW_ONLY' || candidate.applicabilityPolicy === 'REVIEW_ONLY'
        ? 'REVIEW_ONLY'
        : undefined,
    contentHash: bytesToHex(sha256(utf8ToBytes([old.contentHash, candidate.contentHash].sort().join('\u0000')))),
  });
  for (const raw of records) {
    const cveId = normalizeCveId(raw.cveId);
    if (!cveId) continue;
    const candidate = { ...raw, cveId };
    const old = merged.get(cveId);
    if (!old) {
      const evidence = sourceEvidence(candidate);
      const sourceApplicability = Object.fromEntries([...evidence.entries()].sort(([a], [b]) => a.localeCompare(b)));
      merged.set(cveId, {
        ...candidate,
        ...aggregateApplicability([...evidence.values()]),
        sourceApplicability,
      });
      continue;
    }
    const candidateTime = Date.parse(candidate.modifiedDate);
    const oldTime = Date.parse(old.modifiedDate);
    const candidateValid = Number.isFinite(candidateTime);
    const oldValid = Number.isFinite(oldTime);
    const delta = candidateTime - oldTime;
    const contentWins = content(candidate) > content(old);
    // A missing or unparseable revision date must not silently make an older
    // record win. Prefer the record with a usable date; when both are unusable,
    // fall back to deterministic content ordering.
    const winner =
      candidateValid && !oldValid
        ? candidate
        : oldValid && !candidateValid
          ? old
          : candidateValid && oldValid
            ? delta > 0 || (delta === 0 && contentWins)
              ? candidate
              : old
            : contentWins
              ? candidate
              : old;
    const sources = sourceEvidence(old);
    const equalRevisionConflicts: string[] = [];
    for (const [source, incoming] of sourceEvidence(candidate)) {
      const current = sources.get(source);
      if (!current) {
        sources.set(source, incoming);
        continue;
      }
      const currentTime = Date.parse(current.modifiedDate);
      const incomingTime = Date.parse(incoming.modifiedDate);
      if (Number.isFinite(incomingTime) && (!Number.isFinite(currentTime) || incomingTime > currentTime)) {
        sources.set(source, incoming);
      } else if (
        (incomingTime === currentTime || (!Number.isFinite(incomingTime) && !Number.isFinite(currentTime))) &&
        applicabilitySignature(current) !== applicabilitySignature(incoming)
      ) {
        const currentHasApplicability = hasApplicabilityData(current);
        const incomingHasApplicability = hasApplicabilityData(incoming);
        if (currentHasApplicability !== incomingHasApplicability) {
          if (incomingHasApplicability) sources.set(source, incoming);
          continue;
        }
        sources.set(source, mergeEqualSourceRevision(current, incoming));
        if (currentHasApplicability) equalRevisionConflicts.push(source);
      } else if (incomingTime === currentTime && incoming.contentHash.localeCompare(current.contentHash) > 0) {
        sources.set(source, incoming);
      }
    }
    const evidence = [...sources.values()];
    const sourceApplicability = Object.fromEntries([...sources.entries()].sort(([a], [b]) => a.localeCompare(b)));
    merged.set(cveId, {
      ...winner,
      ...aggregateApplicability(evidence, equalRevisionConflicts.length > 0),
      sourceFeeds: [...new Set([...old.sourceFeeds, ...candidate.sourceFeeds])].sort(),
      sourceApplicability,
    });
  }
  return merged;
}

/**
 * Normalizes any CVE string into canonical uppercase, trimmed format.
 * Returns null if not a valid CVE ID.
 */
export function normalizeCveId(rawId: string): string | null {
  if (!rawId || typeof rawId !== 'string') return null;

  const trimmed = rawId.trim().toUpperCase();
  if (CVE_REGEX.test(trimmed)) {
    return trimmed;
  }
  return null;
}

/**
 * Checks if a CVE falls within the processing window based on scope_hours
 */
export function isWithinTimelineScope(
  publishedDate: string,
  modifiedDate: string,
  scopeHours: number,
  now: Date = new Date(),
): boolean {
  if (!scopeHours || scopeHours <= 0) return true; // If 0, no filter

  const windowMillis = scopeHours * 60 * 60 * 1000;
  const cutoffTime = now.getTime() - windowMillis;

  const pubTime = new Date(publishedDate).getTime();
  const modTime = new Date(modifiedDate).getTime();

  const latestActivity = Math.max(isNaN(pubTime) ? 0 : pubTime, isNaN(modTime) ? 0 : modTime);

  return latestActivity >= cutoffTime;
}

/**
 * Deduplicator class for in-run O(1) deduplication
 */
export class InRunDeduplicator {
  private seenInRun = new Set<string>();
  private previouslyAlerted = new Set<string>();

  constructor(previouslyAlertedIds: string[] = []) {
    for (const id of previouslyAlertedIds) {
      const norm = normalizeCveId(id);
      if (norm) {
        this.previouslyAlerted.add(norm);
      }
    }
  }

  /**
   * Evaluates if a CVE is new or duplicate
   */
  public evaluate(rawCveId: string): {
    canonicalId: string | null;
    isDuplicateInRun: boolean;
    isPreviouslyAlerted: boolean;
    isProcessable: boolean;
  } {
    const canonical = normalizeCveId(rawCveId);
    if (!canonical) {
      return {
        canonicalId: null,
        isDuplicateInRun: false,
        isPreviouslyAlerted: false,
        isProcessable: false,
      };
    }

    if (this.seenInRun.has(canonical)) {
      return {
        canonicalId: canonical,
        isDuplicateInRun: true,
        isPreviouslyAlerted: this.previouslyAlerted.has(canonical),
        isProcessable: false,
      };
    }

    this.seenInRun.add(canonical);

    const isPrevAlerted = this.previouslyAlerted.has(canonical);

    return {
      canonicalId: canonical,
      isDuplicateInRun: false,
      isPreviouslyAlerted: isPrevAlerted,
      isProcessable: true,
    };
  }

  public getSeenCount(): number {
    return this.seenInRun.size;
  }
}
