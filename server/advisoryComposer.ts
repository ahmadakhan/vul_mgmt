/**
 * Advisory email composition — ML-guided generation of subject lines,
 * executive summaries, remediation instructions, and severity summaries.
 *
 * Wraps AdvisoryComposerModel (server/ml/models/advisoryComposer.ts) and
 * falls back to the existing rule-based composer when the model is untrained.
 * All output is deterministic template text — never free-form generation from
 * untrusted input — so ML can only improve phrasing and ordering, never
 * introduce unsafe content.
 *
 * Usage:
 *   import { composeAdvisoryEmail } from './advisoryComposer.ts';
 *   const { subject, executiveSummary, remediationInstructions, severitySummary, findingOrder } =
 *     composeAdvisoryEmail(findings, advisory, getMlRuntime());
 */
import type { Advisory, Finding } from '../src/types/index.ts';
import { getMlRuntime } from './ml/integration.ts';
import {
  AdvisoryComposerModel,
  type EmailCompositionFeatures,
  type PerFindingFeatures,
  type EmailCompositionPrediction,
  type SummaryStyle,
  type PriorityEmphasis,
  type RemediationEmphasis,
  type SubjectTemplate,
  SUMMARY_STYLES,
  PRIORITY_EMPHASES,
  REMEDIATION_EMPHASES,
  SUBJECT_TEMPLATES,
} from './ml/models/advisoryComposer.ts';
import { predictSeverityTier } from './ml/integration.ts';

const composerModel = new AdvisoryComposerModel();

/** Extract aggregate features from findings for the composer model. */
function extractAggregateFeatures(findings: Finding[]): EmailCompositionFeatures {
  const severities: Record<string, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0 };
  let maxCvss = 0;
  let sumCvss = 0;
  let maxEpss = 0;
  let sumEpss = 0;
  let kevCount = 0;
  let weaponizedCount = 0;
  let reportedInWildCount = 0;
  let pocCount = 0;
  let sumConfidence = 0;
  let sumDaysSincePublished = 0;
  let sumFeedWeight = 0;
  const vendors = new Set<string>();
  const assets = new Set<string>();
  let n = 0;

  for (const f of findings) {
    const sev = f.cve.cvss.severity;
    severities[sev] = (severities[sev] ?? 0) + 1;
    const cvss = f.cve.cvss.score ?? 0;
    maxCvss = Math.max(maxCvss, cvss);
    sumCvss += cvss;
    const epss = f.cve.epss?.score ?? 0;
    maxEpss = Math.max(maxEpss, epss);
    sumEpss += epss;
    if (f.cve.cisaKev?.isKev) kevCount++;
    if (f.cve.exploitStatus === 'Active Weaponized') weaponizedCount++;
    if (f.cve.exploitStatus === 'Reported In Wild') reportedInWildCount++;
    if (f.cve.exploitStatus === 'POC Available') pocCount++;
    sumConfidence += f.confidence ?? 0;
    const published = f.cve.publishedDate ? new Date(f.cve.publishedDate).getTime() : 0;
    const days = published ? (Date.now() - published) / (1000 * 60 * 60 * 24) : 0;
    sumDaysSincePublished += days;
    sumFeedWeight += f.cve.epss?.percentile ?? 0;
    if (f.matchedAssetVendor) vendors.add(f.matchedAssetVendor);
    assets.add(f.matchedAssetName);
    n++;
  }

  const total = findings.length;
  return {
    criticalCount: severities.CRITICAL,
    highCount: severities.HIGH,
    mediumCount: severities.MEDIUM,
    lowCount: severities.LOW,
    unknownCount: severities.UNKNOWN,
    totalFindings: total,
    maxCvssScore: maxCvss,
    avgCvssScore: total ? sumCvss / total : 0,
    maxEpssScore: maxEpss,
    avgEpssScore: total ? sumEpss / total : 0,
    kevCount,
    weaponizedCount,
    reportedInWildCount,
    pocCount,
    affectedAssetCount: assets.size,
    uniqueVendorCount: vendors.size,
    avgMatchConfidence: total ? sumConfidence / total : 0,
    avgDaysSincePublished: total ? sumDaysSincePublished / total : 0,
    avgSourceFeedWeight: total ? sumFeedWeight / total : 0,
  };
}

/** Extract per-finding features for ranking. */
function extractPerFindingFeatures(findings: Finding[]): PerFindingFeatures[] {
  return findings.map((f) => ({
    cvssScore: f.cve.cvss.score ?? 0,
    epssScore: f.cve.epss?.score ?? 0,
    cisaKev: f.cve.cisaKev?.isKev ?? false,
    exploitStatus: f.cve.exploitStatus,
    matchConfidence: f.confidence ?? 0,
    daysSincePublished: f.cve.publishedDate
      ? (Date.now() - new Date(f.cve.publishedDate).getTime()) / (1000 * 60 * 60 * 24)
      : 0,
    sourceFeedWeight: f.cve.epss?.percentile ?? 0,
    assetCriticality: 0, // deprecated field; reserved for future use
  }));
}

/** Rule-based fallback composition (matches previous advisoryRebuild behavior). */
function ruleBasedComposition(
  findings: Finding[],
  aggregate: EmailCompositionFeatures,
): {
  subject: string;
  executiveSummary: string;
  remediationInstructions: string;
  severitySummary: string;
  findingOrder: number[];
} {
  const parts: string[] = [];
  for (const sev of ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const) {
    const count = aggregate[`${sev.toLowerCase()}Count` as keyof EmailCompositionFeatures] as number;
    if (count) parts.push(`${count} ${sev.charAt(0)}${sev.slice(1).toLowerCase()}`);
  }
  const severitySummary = parts.length ? parts.join(', ') : '0 vulnerabilities';
  const subject = `Vulnerability notice: ${severitySummary}`;

  const topSev = aggregate.criticalCount > 0 ? 'Critical' : aggregate.highCount > 0 ? 'High' : aggregate.mediumCount > 0 ? 'Medium' : 'Low';
  const executiveSummary = `${aggregate.totalFindings} current inventory correlation(s). Top severity: ${topSev}. Confirm applicability and consult the vendor before remediation.`;

  const remediationInstructions =
    'Review vendor advisories and deploy tested remediation through your change process.';

  // Order findings by severity rank, then CVE ID
  const rank: Record<string, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, UNKNOWN: 0 };
  const findingOrder = findings
    .map((f, i) => ({ idx: i, score: rank[f.cve.cvss.severity] ?? 0 }))
    .sort((a, b) => b.score - a.score || a.idx - b.idx)
    .map((e) => e.idx);

  return { subject, executiveSummary, remediationInstructions, severitySummary, findingOrder };
}

/** Compose advisory email text — ML-guided with rule-based fallback. */
export function composeAdvisoryEmail(
  findings: Finding[],
  advisory: Advisory,
): {
  subject: string;
  executiveSummary: string;
  remediationInstructions: string;
  severitySummary: string;
  findingOrder: number[];
  prediction: EmailCompositionPrediction | null;
  modelUsed: boolean;
} {
  const aggregate = extractAggregateFeatures(findings);
  const perFinding = extractPerFindingFeatures(findings);
  const runtime = getMlRuntime();
  const model = runtime?.advisoryComposer;

  if (model?.isTrained()) {
    try {
      const text = model.compose(aggregate, perFinding);
      const prediction = model.composePrediction(aggregate, perFinding);
      return {
        subject: text.subject,
        executiveSummary: text.executiveSummary,
        remediationInstructions: text.remediationInstructions,
        severitySummary: text.severitySummary,
        findingOrder: text.findingOrder,
        prediction,
        modelUsed: true,
      };
    } catch {
      /* fall through to rule-based on any composition error */
    }
  }

  const rule = ruleBasedComposition(findings, aggregate);
  return {
    ...rule,
    prediction: null,
    modelUsed: false,
  };
}

/** Predict composition parameters without generating text — useful for diagnostics. */
export function predictAdvisoryComposition(
  findings: Finding[],
): EmailCompositionPrediction | null {
  const runtime = getMlRuntime();
  const model = runtime?.advisoryComposer;
  if (!model?.isTrained()) return null;
  const aggregate = extractAggregateFeatures(findings);
  const perFinding = extractPerFindingFeatures(findings);
  try {
    return model.composePrediction(aggregate, perFinding);
  } catch {
    return null;
  }
}

/** Reorder findings according to ML-predicted importance scores. */
export function orderFindingsByMlImportance(findings: Finding[]): Finding[] {
  const aggregate = extractAggregateFeatures(findings);
  const perFinding = extractPerFindingFeatures(findings);
  const runtime = getMlRuntime();
  const model = runtime?.advisoryComposer;
  if (!model?.isTrained()) {
    // Fallback: severity rank
    const rank: Record<string, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, UNKNOWN: 0 };
    return [...findings].sort(
      (a, b) => (rank[b.cve.cvss.severity] ?? 0) - (rank[a.cve.cvss.severity] ?? 0),
    );
  }
  try {
    const { findingOrder } = model.compose(aggregate, perFinding);
    return findingOrder.map((i) => findings[i]).filter(Boolean);
  } catch {
    return findings;
  }
}

export { composerModel };
export type {
  EmailCompositionFeatures,
  PerFindingFeatures,
  EmailCompositionPrediction,
  SummaryStyle,
  PriorityEmphasis,
  RemediationEmphasis,
  SubjectTemplate,
};
