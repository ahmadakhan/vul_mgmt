/**
 * Matching quality gate.
 *
 * Runs the labelled corpus through the real matcher and reports precision and
 * recall per evidence class. This is deliberately separate from the unit
 * suite: it answers the procurement question ("what is the false-positive
 * rate on a labelled sample?") and fails CI when a matcher change degrades a
 * specific tier, rather than only when an individual assertion breaks.
 */
import { MATCHING_CORPUS } from '../tests/fixtures/matching-corpus.ts';
import {
  evaluateMatchingCorpus,
  matchingQualityProblems,
  MATCHING_QUALITY_GATES,
} from '../src/utils/matchingMetrics.ts';

const report = evaluateMatchingCorpus(MATCHING_CORPUS);
const percent = (value: number) => `${(value * 100).toFixed(1)}%`;

console.log('Matching quality evaluation');
console.log(`  cases:     ${report.total}`);
console.log(`  passed:    ${report.passed}`);
console.log(`  failed:    ${report.failed}`);
console.log(`  precision: ${percent(report.precision)}`);
console.log(`  recall:    ${percent(report.recall)}`);
console.log(`  accuracy:  ${percent(report.accuracy)}`);
console.log(
  `  confusion: TP=${report.truePositives} FP=${report.falsePositives} FN=${report.falseNegatives} TN=${report.trueNegatives}`,
);
console.log('');
console.log('By expected evidence class:');
for (const [method, metrics] of Object.entries(report.byExpectedMethod).sort(([a], [b]) =>
  a.localeCompare(b),
)) {
  console.log(
    `  ${method.padEnd(24)} cases=${String(metrics.cases).padStart(3)} ` +
      (method === 'NEGATIVE'
        ? `specificity=${percent(metrics.specificity).padStart(6)}`
        : `precision=${percent(metrics.precision).padStart(6)} recall=${percent(metrics.recall).padStart(6)}`),
  );
}

if (report.highConfidenceFalsePositives.length) {
  console.log('');
  console.log('High-confidence false positives (would auto-dispatch):');
  for (const outcome of report.highConfidenceFalsePositives)
    console.log(`  - ${outcome.id}: ${outcome.actual.confidence}% (${outcome.description})`);
}

if (report.failures.length) {
  console.log('');
  console.log('Failed labelled cases:');
  for (const failure of report.failures) {
    console.log(`  - ${failure.id}: ${failure.description}`);
    for (const reason of failure.failures) console.log(`      ${reason}`);
  }
}

const problems = matchingQualityProblems(report);
if (problems.length) {
  console.error('');
  console.error('Matching quality gate failed:');
  for (const problem of problems) console.error(`  - ${problem}`);
  process.exitCode = 1;
} else {
  console.log('');
  console.log(
    `Gate passed (precision >= ${percent(MATCHING_QUALITY_GATES.precision)}, ` +
      `recall >= ${percent(MATCHING_QUALITY_GATES.recall)}, ` +
      `high-confidence false positives = ${MATCHING_QUALITY_GATES.highConfidenceFalsePositives}).`,
  );
}
