import type { MatchResult } from './cpeMatcher.ts';
import { matchesWatchlistItem } from './cpeMatcher.ts';
import type { NvdVersionRange } from './versionComparator.ts';

export type MatchMethod = MatchResult['method'];

export interface MatchingCaseInput {
  assetCpes?: string[];
  assetVendor: string;
  assetProduct: string;
  vulnCpes?: string[];
  vulnTitle?: string;
  vulnDescription?: string;
  versionRange?: NvdVersionRange;
  assetPurls?: string[];
  vulnPurls?: string[];
  assetTargetHw?: string;
  vulnTargetHw?: string;
  customVendorAliases?: Record<string, string[]>;
  customProductAliases?: Record<string, string[]>;
  assetVersion?: string;
}

/**
 * A labelled correlation. `expected` describes both the decision and the
 * evidence class, so the harness measures precision/recall *and* prevents the
 * matcher from reaching the right answer for the wrong reason.
 */
export interface MatchingCase {
  id: string;
  description: string;
  tags?: string[];
  input: MatchingCaseInput;
  expected: {
    matched: boolean;
    methods?: MatchMethod[];
    confidence?: number;
    maxConfidence?: number;
    requiresReview?: boolean;
  };
}

export interface MatchingCaseOutcome {
  id: string;
  description: string;
  tags: string[];
  expectedMatched: boolean;
  actual: MatchResult;
  passed: boolean;
  failures: string[];
}

export interface MethodMetrics {
  cases: number;
  truePositives: number;
  falsePositives: number;
  falseNegatives: number;
  trueNegatives: number;
  precision: number;
  recall: number;
  /** True-negative rate. Only meaningful for the NEGATIVE bucket. */
  specificity: number;
}

export interface MatchingReport {
  total: number;
  passed: number;
  failed: number;
  truePositives: number;
  falsePositives: number;
  falseNegatives: number;
  trueNegatives: number;
  precision: number;
  recall: number;
  accuracy: number;
  /** False positives at or above the auto-dispatch threshold. These are the
   * only matching errors that can notify a customer without review. */
  highConfidenceFalsePositives: MatchingCaseOutcome[];
  byExpectedMethod: Record<string, MethodMetrics>;
  outcomes: MatchingCaseOutcome[];
  failures: MatchingCaseOutcome[];
}

const AUTO_DISPATCH_CONFIDENCE = 90;

const ratio = (numerator: number, denominator: number) =>
  denominator === 0 ? 1 : numerator / denominator;

export function runMatchingCase(testCase: MatchingCase): MatchingCaseOutcome {
  const input = testCase.input;
  const actual = matchesWatchlistItem(
    input.assetCpes ?? [],
    input.assetVendor,
    input.assetProduct,
    input.vulnCpes ?? [],
    input.vulnTitle ?? '',
    input.vulnDescription ?? '',
    input.versionRange,
    input.assetPurls,
    input.vulnPurls,
    input.assetTargetHw,
    input.vulnTargetHw,
    true,
    input.customVendorAliases ?? {},
    input.customProductAliases ?? {},
    input.assetVersion,
  );

  const expected = testCase.expected;
  const failures: string[] = [];
  if (actual.matched !== expected.matched)
    failures.push(`expected matched=${expected.matched}, received ${actual.matched} (${actual.method})`);
  if (expected.matched && expected.methods && !expected.methods.includes(actual.method))
    failures.push(`expected method ${expected.methods.join('|')}, received ${actual.method}`);
  if (expected.confidence !== undefined && actual.confidence !== expected.confidence)
    failures.push(`expected confidence ${expected.confidence}, received ${actual.confidence}`);
  if (expected.maxConfidence !== undefined && actual.confidence > expected.maxConfidence)
    failures.push(`expected confidence <= ${expected.maxConfidence}, received ${actual.confidence}`);
  if (
    expected.requiresReview !== undefined &&
    Boolean(actual.applicabilityRequiresReview) !== expected.requiresReview
  )
    failures.push(
      `expected requiresReview=${expected.requiresReview}, received ${Boolean(
        actual.applicabilityRequiresReview,
      )}`,
    );

  return {
    id: testCase.id,
    description: testCase.description,
    tags: testCase.tags ?? [],
    expectedMatched: expected.matched,
    actual,
    passed: failures.length === 0,
    failures,
  };
}

export function evaluateMatchingCorpus(cases: readonly MatchingCase[]): MatchingReport {
  const outcomes = cases.map(runMatchingCase);
  const methods: Record<string, MethodMetrics> = {};
  const bucket = (key: string) => {
    methods[key] ||= {
      cases: 0,
      truePositives: 0,
      falsePositives: 0,
      falseNegatives: 0,
      trueNegatives: 0,
      precision: 1,
      recall: 1,
      specificity: 1,
    };
    return methods[key];
  };

  let truePositives = 0;
  let falsePositives = 0;
  let falseNegatives = 0;
  let trueNegatives = 0;

  for (let index = 0; index < outcomes.length; index += 1) {
    const outcome = outcomes[index];
    const testCase = cases[index];
    const group = testCase.expected.matched
      ? outcome.passed
        ? outcome.actual.method
        : (testCase.expected.methods?.[0] ?? 'ANY_MATCH')
      : 'NEGATIVE';
    const metrics = bucket(group);
    metrics.cases += 1;

    if (outcome.expectedMatched) {
      if (outcome.actual.matched && outcome.passed) {
        truePositives += 1;
        metrics.truePositives += 1;
      } else {
        falseNegatives += 1;
        metrics.falseNegatives += 1;
      }
    } else if (outcome.actual.matched) {
      falsePositives += 1;
      metrics.falsePositives += 1;
    } else {
      trueNegatives += 1;
      metrics.trueNegatives += 1;
    }
  }

  for (const metrics of Object.values(methods)) {
    metrics.precision = ratio(metrics.truePositives, metrics.truePositives + metrics.falsePositives);
    metrics.recall = ratio(metrics.truePositives, metrics.truePositives + metrics.falseNegatives);
    metrics.specificity = ratio(metrics.trueNegatives, metrics.trueNegatives + metrics.falsePositives);
  }

  const failed = outcomes.filter((outcome) => !outcome.passed);
  return {
    total: outcomes.length,
    passed: outcomes.length - failed.length,
    failed: failed.length,
    truePositives,
    falsePositives,
    falseNegatives,
    trueNegatives,
    precision: ratio(truePositives, truePositives + falsePositives),
    recall: ratio(truePositives, truePositives + falseNegatives),
    accuracy: ratio(truePositives + trueNegatives, outcomes.length),
    highConfidenceFalsePositives: outcomes.filter(
      (outcome) =>
        !outcome.expectedMatched && outcome.actual.matched && outcome.actual.confidence >= AUTO_DISPATCH_CONFIDENCE,
    ),
    byExpectedMethod: methods,
    outcomes,
    failures: failed,
  };
}

/** Minimum gates for the curated corpus. Accuracy is reported per method so a
 * regression in one evidence class cannot hide behind the overall average. */
export const MATCHING_QUALITY_GATES = {
  precision: 0.95,
  recall: 0.9,
  highConfidenceFalsePositives: 0,
} as const;

export function matchingQualityProblems(report: MatchingReport): string[] {
  const problems: string[] = [];
  if (report.failed > 0)
    problems.push(`${report.failed} labelled case(s) failed: ${report.failures.map((f) => f.id).join(', ')}`);
  if (report.precision < MATCHING_QUALITY_GATES.precision)
    problems.push(`precision ${report.precision.toFixed(3)} < ${MATCHING_QUALITY_GATES.precision}`);
  if (report.recall < MATCHING_QUALITY_GATES.recall)
    problems.push(`recall ${report.recall.toFixed(3)} < ${MATCHING_QUALITY_GATES.recall}`);
  if (report.highConfidenceFalsePositives.length > MATCHING_QUALITY_GATES.highConfidenceFalsePositives)
    problems.push(
      `high-confidence false positives: ${report.highConfidenceFalsePositives
        .map((f) => f.id)
        .join(', ')}`,
    );
  return problems;
}
