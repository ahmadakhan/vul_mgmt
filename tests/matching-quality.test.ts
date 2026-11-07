import { test } from 'node:test';
import assert from 'node:assert/strict';
import { MATCHING_CORPUS } from './fixtures/matching-corpus.ts';
import {
  evaluateMatchingCorpus,
  matchingQualityProblems,
  runMatchingCase,
  type MatchingCase,
} from '../src/utils/matchingMetrics.ts';

const report = evaluateMatchingCorpus(MATCHING_CORPUS);

test('the labelled corpus is internally consistent and covers every evidence class', () => {
  const ids = MATCHING_CORPUS.map((entry) => entry.id);
  assert.equal(new Set(ids).size, ids.length, 'corpus case ids must be unique');
  assert.ok(MATCHING_CORPUS.length >= 25, 'the corpus must stay large enough to be meaningful');

  for (const entry of MATCHING_CORPUS) {
    assert.ok(entry.description.trim().length > 0, `${entry.id} needs a description`);
    if (entry.expected.matched) {
      assert.ok(entry.expected.methods?.length, `${entry.id} must name its expected evidence class`);
      assert.notEqual(
        entry.expected.methods?.[0],
        'NONE',
        `${entry.id} cannot expect a positive match with method NONE`,
      );
    } else {
      assert.equal(entry.expected.confidence, undefined, `${entry.id} is negative and has no confidence`);
    }
  }

  const positives = MATCHING_CORPUS.filter((entry) => entry.expected.matched).flatMap(
    (entry) => entry.expected.methods ?? [],
  );
  for (const method of [
    'STRICT_CPE',
    'STRICT_CPE_INTERVAL',
    'PURL_EXACT',
    'VENDOR_PRODUCT_ALIAS',
    'VENDOR_PRODUCT_FALLBACK',
  ] as const)
    assert.ok(positives.includes(method), `corpus must exercise ${method}`);
});

test('the matcher meets the precision and recall gates on the labelled corpus', () => {
  assert.deepEqual(
    matchingQualityProblems(report),
    [],
    `matching quality regressed: ${report.failures
      .map((failure) => `${failure.id} (${failure.failures.join('; ')})`)
      .join(', ')}`,
  );
  assert.equal(report.failed, 0);
  assert.ok(report.precision >= 0.95, `precision ${report.precision}`);
  assert.ok(report.recall >= 0.9, `recall ${report.recall}`);
});

test('no labelled negative reaches the auto-dispatch confidence threshold', () => {
  assert.deepEqual(
    report.highConfidenceFalsePositives.map((outcome) => outcome.id),
    [],
    'a false positive at >=90% would notify a customer without review',
  );
  assert.equal(report.byExpectedMethod.NEGATIVE.specificity, 1);
});

test('the harness fails when a labelled expectation regresses', () => {
  // A gate that cannot fail is not a gate. Feed it a deliberately wrong label
  // for a clean strict match and confirm both failure and dispatch detection.
  const strict = MATCHING_CORPUS.find((entry) => entry.id === 'strict-exact');
  assert.ok(strict);
  const broken: MatchingCase = {
    ...strict,
    id: 'deliberately-wrong-negative',
    expected: { matched: false },
  };
  const brokenReport = evaluateMatchingCorpus([broken]);
  assert.equal(brokenReport.failed, 1);
  assert.deepEqual(
    brokenReport.highConfidenceFalsePositives.map((outcome) => outcome.id),
    ['deliberately-wrong-negative'],
  );
  assert.ok(matchingQualityProblems(brokenReport).length > 0);

  const missing = MATCHING_CORPUS.find((entry) => entry.id === 'strict-exact');
  assert.ok(missing);
  const falseNegative: MatchingCase = {
    ...missing,
    id: 'deliberately-wrong-positive',
    expected: { matched: true, methods: ['VENDOR_PRODUCT_FALLBACK'] },
  };
  const falseNegativeReport = evaluateMatchingCorpus([falseNegative]);
  assert.equal(falseNegativeReport.failed, 1);
  assert.ok(matchingQualityProblems(falseNegativeReport).some((problem) => problem.includes('recall')));
});

test('prose fallback requires whole identity tokens, not substrings', () => {
  for (const id of [
    'negative-short-vendor-substring',
    'negative-short-token-identity',
    'negative-glued-words',
  ]) {
    const entry = MATCHING_CORPUS.find((candidate) => candidate.id === id);
    assert.ok(entry, `${id} must exist in the corpus`);
    const outcome = runMatchingCase(entry);
    assert.equal(outcome.actual.matched, false, `${id} must not match: ${outcome.actual.evidence}`);
  }
});

test('alias resolution cannot erase a platform or architecture exclusion', () => {
  for (const id of ['negative-platform-alias-names', 'negative-part', 'negative-architecture']) {
    const entry = MATCHING_CORPUS.find((candidate) => candidate.id === id);
    assert.ok(entry, `${id} must exist in the corpus`);
    const outcome = runMatchingCase(entry);
    assert.equal(outcome.actual.matched, false, `${id} must not match: ${outcome.actual.evidence}`);
    assert.equal(outcome.actual.method, 'NONE');
  }
});
