import type { FeedType, Finding } from '../../src/types/index.ts';
import { findingFeatures } from './findingFeatures.ts';
import {
  cpePreFilter, predictAliasConfidence, predictExploitRisk, predictMatchConfidence,
  predictRemediation, predictSeverityTier, rankReviewFindings,
} from './integration.ts';

export function assessFinding(
  finding: Finding,
  feedTypesById?: ReadonlyMap<string, FeedType>,
): Finding {
  const cve = finding.cve;
  const common = findingFeatures(finding, feedTypesById);
  // Recommendations never replace the parser's applicability, VEX, or operator dispatch policy.
  return {
    ...finding,
    mlAssessment: {
      assessedAt: new Date().toISOString(),
      cpeParseRecommended: cpePreFilter(finding.matchedCpe),
      matchConfidence: predictMatchConfidence({ ...common, matchMethod: finding.matchingMethod, negated: false }),
      aliasConfidence: predictAliasConfidence({
        ...common,
        matchMethod: finding.matchingMethod,
      }),
      exploitRisk: predictExploitRisk({
        ...common, exploitStatus: cve.exploitStatus, exploitationSourcesCount: cve.exploitationSources?.length ?? 0,
      }),
      severityTier: predictSeverityTier({ ...common, exploitStatus: cve.exploitStatus, cweRiskLevel: 0, cvssSeverity: cve.cvss.severity }),
      remediationCompleteness: predictRemediation({
        ...common,
      }, cve.remediation).recommendation,
    },
  };
}

export function assessFindings(
  findings: Finding[],
  feedTypesById?: ReadonlyMap<string, FeedType>,
): Finding[] {
  return rankReviewFindings(
    findings.map((finding) => assessFinding(finding, feedTypesById)),
    feedTypesById,
  );
}
