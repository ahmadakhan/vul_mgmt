import type { FeedType, Finding } from '../../src/types/index.ts';
import { parseCPE23 } from '../../src/utils/cpeMatcher.ts';
import type { FindingFeatures } from './models/reviewRanker.ts';

const APPLICABILITY_FEED_WEIGHTS: Partial<Record<FeedType, number>> = {
  NVD_API: 40,
  MITRE_CVE: 35,
  OPENCVE_API: 25,
  OSV_API: 40,
  GITHUB_ADVISORIES: 35,
};

const finite = (value: unknown) =>
  typeof value === 'number' && Number.isFinite(value) ? value : 0;

export function findingFeatures(
  finding: Finding,
  feedTypesById?: ReadonlyMap<string, FeedType>,
): FindingFeatures {
  const cve = finding.cve;
  const parsed = parseCPE23(finding.matchedCpe || '');
  const published = Date.parse(cve.publishedDate || '');
  const sourceFeedWeight = Math.max(
    10,
    ...(cve.sourceFeeds ?? []).map((sourceId) => {
      const type = feedTypesById?.get(sourceId);
      return type ? APPLICABILITY_FEED_WEIGHTS[type] ?? 10 : 10;
    }),
  );
  return {
    matchConfidence: finite(finding.confidence),
    cvssScore: finite(cve.cvss?.score),
    epssScore: finite(cve.epss?.score),
    cisaKev: cve.cisaKev?.isKev === true,
    exploitStatus: Math.max(0, ['None', 'Reported In Wild', 'POC Available', 'Active Weaponized'].indexOf(cve.exploitStatus)),
    cweRiskLevel: 0,
    signalDensity: 0,
    matchMethod: finding.matchingMethod,
    sourceFeedWeight,
    assetCriticality: 0,
    hasVersionEvidence: parsed.isValid && !['*', '-'].includes(parsed.version) && !/[?*]/.test(parsed.version),
    daysSincePublished: Number.isFinite(published) ? Math.max(0, (Date.now() - published) / 86400000) : 0,
    negated: false,
  };
}
