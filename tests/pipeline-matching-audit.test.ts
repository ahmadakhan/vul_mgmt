/**
 * Regression tests for the pipeline matching production-readiness audit.
 *
 * Each test corresponds to one finding (C-1, C-2, H-1, H-2, M-1, M-4, M-9, L-1)
 * and fails on the pre-fix implementation.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  MAX_ZERO_DAYS_PER_RUN,
  rankAndRateLimitZeroDays,
  runVulnerabilityPipeline,
} from '../src/engine/pipelineEngine.ts';
import { mergeArticles, matchIntelligence, computeCredibilityScore } from '../src/utils/intelligenceMatcher.ts';
import { purlIdentity } from '../src/utils/cpeMatcher.ts';
import { isPermanentFeedFailure } from '../server/feedRecovery.ts';
import { DEFAULT_SETTINGS } from '../shared/state.ts';
import type {
  Finding,
  IntelligenceArticle,
  IntelligenceMatch,
  NormalizedCVE,
  WatchListItem,
} from '../src/types/index.ts';

const NOW = new Date('2026-10-26T12:00:00Z');
const cpe = (version: string) => `cpe:2.3:a:acme:gateway:${version}:*:*:*:*:*:*:*`;

function cveRecord(overrides: Partial<NormalizedCVE> = {}): NormalizedCVE {
  return {
    cveId: 'CVE-2026-9999',
    title: 'Acme gateway flaw',
    description: 'A flaw in Acme Gateway allows remote code execution.',
    publishedDate: NOW.toISOString(),
    modifiedDate: NOW.toISOString(),
    cvss: { version: '3.1', score: 9.8, severity: 'CRITICAL', vector: '' },
    cwe: [],
    cpeMatches: [cpe('1.5')],
    cpeMatchDetails: [],
    versionRange: undefined,
    purls: undefined,
    sourceFeeds: ['NVD_API'],
    exploitStatus: 'None',
    remediation: { patchUrl: '', vendorAdvisoryRef: '', immediateActions: [] },
    cisaKev: { isKev: false },
    epss: { score: 0, percentile: 0 },
    references: [],
    timeline: [],
    ...overrides,
  } as NormalizedCVE;
}

function assetRecord(overrides: Partial<WatchListItem> = {}): WatchListItem {
  return {
    id: 'a1',
    assetTag: 'svc',
    vendor: 'acme',
    product: 'gateway',
    cpes: [cpe('1.5')],
    purls: ['pkg:npm/lodash@4.17.20'],
    ownerGroup: 'g',
    exposure: 'INTERNAL',
    active: true,
    version: '1.5',
    createdAt: NOW.toISOString(),
    ...overrides,
  } as WatchListItem;
}

const settings = { ...DEFAULT_SETTINGS, scopeHours: 0, autoDispatchEnabled: true };

/* ------------------------------------------------------------------ C-1 */

test('C-1: a contradicting package identifier cannot be outranked by a CPE match', () => {
  // The advisory names the product by CPE (asset is 1.5, advisory is 1.5) and
  // separately a package version the asset does not run (4.17.20 vs 4.17.99).
  // Before the fix the 90% STRICT_CPE result won and auto-dispatched, reporting
  // an unaffected dependency as affected.
  const asset = assetRecord();
  const cve = cveRecord({ purls: ['pkg:npm/lodash@4.17.99'] });
  const [finding] = runVulnerabilityPipeline([], [cve], [asset], [], [], settings).newFindings;
  assert.ok(finding, 'the product correlation is retained, not silently dropped');
  assert.notEqual(
    finding.notificationStatus,
    'QUEUED_FOR_DISPATCH',
    'contradicted evidence must never auto-dispatch',
  );
  assert.equal(finding.notificationStatus, 'REVIEW_REQUIRED');
  assert.match(finding.matchingEvidence, /package identifiers prove a different version/);
});

test('C-1: a provable package mismatch on its own yields no finding', () => {
  const asset = assetRecord({ cpes: [] });
  const cve = cveRecord({ cpeMatches: [], purls: ['pkg:npm/lodash@4.17.99'] });
  assert.equal(runVulnerabilityPipeline([], [cve], [asset], [], [], settings).newFindings.length, 0);
});

test('C-1: agreeing identifiers still auto-dispatch', () => {
  const asset = assetRecord();
  const cve = cveRecord({ purls: ['pkg:npm/lodash@4.17.29'] });
  // Version differs only outside the asset's installed range: still a mismatch.
  const [held] = runVulnerabilityPipeline([], [cve], [asset], [], [], settings).newFindings;
  assert.equal(held.notificationStatus, 'REVIEW_REQUIRED');
  // A CPE-only advisory is unaffected by the change.
  const plain = cveRecord();
  const [finding] = runVulnerabilityPipeline([], [plain], [asset], [], [], settings).newFindings;
  assert.equal(finding.notificationStatus, 'QUEUED_FOR_DISPATCH');
});

/* -------------------------------------------------------------- C-2 / M-* */

function match(i: number, over: Partial<IntelligenceMatch> = {}): IntelligenceMatch {
  return {
    id: `m${i}`,
    cveId: i % 2 ? null : `CVE-2026-${1000 + i}`,
    assetId: `asset${i % 3}`,
    assetName: `tag${i} (acme widget)`,
    articleIds: [`a${i}`],
    status: 'REVIEW_REQUIRED',
    evidence: '',
    zeroDay: i % 2 === 1,
    credibilityScore: 100 - i,
    ...over,
  };
}

test('learned zero-day caps are bounded and preserve every deferred match in a digest', () => {
  const matches = Array.from({ length: 10 }, (_, i) => match(i, { zeroDay: true }));
  const result = rankAndRateLimitZeroDays([], matches, 2);
  assert.equal(result.matches.length, 2);
  assert.equal(result.digests.reduce((sum, digest) => sum + digest.matchCount, 0), 8);
  assert.deepEqual(new Set([...result.matches.map((m) => m.id), ...result.digests.flatMap((d) => d.matchIds)]),
    new Set(matches.map((m) => m.id)));
  for (const cap of [0, -1, 1.5, NaN, Infinity, MAX_ZERO_DAYS_PER_RUN + 1])
    assert.throws(() => rankAndRateLimitZeroDays([], matches, cap), /Zero-day cap/);
});

test('C-2: digests report the group size, not the size of the whole match array', () => {
  const matches = Array.from({ length: 120 }, (_, i) => match(i));
  const { digests } = rankAndRateLimitZeroDays([], matches);
  const dropped = 60 - MAX_ZERO_DAYS_PER_RUN; // 60 zero-day matches, 50 kept
  assert.ok(digests.length > 0);
  assert.equal(
    digests.reduce((sum, d) => sum + d.matchCount, 0),
    dropped,
    'matchCount must sum to the suppressed group, never the whole array',
  );
  for (const digest of digests) assert.notEqual(digest.matchCount, matches.length);
});

test('C-2 / M-4: zero-day digests consolidate by vendor + product, not by asset', () => {
  const matches = Array.from({ length: 120 }, (_, i) => match(i));
  const { digests } = rankAndRateLimitZeroDays([], matches);
  assert.equal(digests.length, 1, 'one advisory per product, not one per asset');
  assert.equal(digests[0].vendor, 'acme');
  assert.equal(digests[0].product, 'widget');
});

test('C-2: a parenthesised asset tag does not corrupt the parsed identity', () => {
  const matches = Array.from({ length: 120 }, (_, i) =>
    match(i, { assetName: `prod (legacy) (acme widget)` }),
  );
  const { digests } = rankAndRateLimitZeroDays([], matches);
  assert.equal(digests[0].vendor, 'acme');
  assert.equal(digests[0].product, 'widget');
});

test('M-9: digest ids are not shaped like real advisory ids', () => {
  const matches = Array.from({ length: 120 }, (_, i) => match(i));
  const { digests } = rankAndRateLimitZeroDays([], matches);
  assert.ok(!digests[0].advisoryId.includes('ZDIGEST_'));
  assert.match(digests[0].advisoryId, /^DIGEST_/);
});

test('M-1: suppressed zero-day matches remove their counterpart findings', () => {
  const matches = Array.from({ length: 120 }, (_, i) => match(i, { findingId: `f${i}` }));
  // The findings array must be keyed by the same ids the matches reference;
  // deriving ids from the match id (m12 -> f12) silently targets findings that
  // are not in the array, so the assertion would hold even with the bug present.
  const supplied = matches.map((m) => ({ id: m.findingId })) as unknown as Finding[];
  const result = rankAndRateLimitZeroDays(supplied, matches);
  const droppedFindingIds = new Set(result.digests.flatMap((d) => d.findingIds));
  assert.ok(droppedFindingIds.size > 0, 'digests must carry actionable finding ids');
  assert.ok(
    [...droppedFindingIds].every((id) => supplied.some((finding) => finding.id === id)),
    'every suppressed finding id must exist in the supplied set',
  );
  assert.equal(result.findings.length, supplied.length - droppedFindingIds.size);
  for (const finding of result.findings) assert.ok(!droppedFindingIds.has(finding.id));
});

test('C-2: non-zero-day matches survive an exceeded cap untouched', () => {
  const matches = Array.from({ length: 120 }, (_, i) => match(i));
  const input = matches.filter((m) => !m.zeroDay);
  const result = rankAndRateLimitZeroDays([], matches);
  for (const kept of input) assert.ok(result.matches.some((m) => m.id === kept.id));
});

/* ------------------------------------------------------------------ H-1 */

test('H-1: credibility is monotone in corroborating sources', () => {
  const one = computeCredibilityScore(
    { id: 'x', cveId: null, assetId: 'a', assetName: '', articleIds: [], status: 'REVIEW_REQUIRED', evidence: '', zeroDay: true },
    ['RSS_NEWS'],
    false,
  );
  const three = computeCredibilityScore(
    { id: 'x', cveId: null, assetId: 'a', assetName: '', articleIds: [], status: 'REVIEW_REQUIRED', evidence: '', zeroDay: true },
    ['RSS_NEWS', 'THREAT_FEED', 'MITRE_CVE'],
    false,
  );
  assert.ok(three > one, `expected ${three} > ${one}`);
});

test('credibility scoring applies runtime-trained weights', () => {
  const match = { id: 'x', cveId: null, assetId: 'a', assetName: '', articleIds: [], status: 'REVIEW_REQUIRED' as const, evidence: '', zeroDay: true };
  const defaultScore = computeCredibilityScore(match, ['RSS_NEWS'], false);
  const feedHeavy = computeCredibilityScore(match, ['RSS_NEWS'], false, { feedWeight: 0.9, keywordWeight: 0.1 });
  assert.equal(feedHeavy, 21);
  assert.notEqual(feedHeavy, defaultScore);
});

test('H-1: zero-day ranking is deterministic for tied credibility', () => {
  const tied = Array.from({ length: 80 }, (_, i) =>
    match(i, { zeroDay: true, cveId: null, credibilityScore: 50 }),
  );
  const first = rankAndRateLimitZeroDays([], tied).digests.map((d) => d.matchIds).flat();
  const shuffled = [...tied].reverse();
  const second = rankAndRateLimitZeroDays([], shuffled).digests.map((d) => d.matchIds).flat();
  assert.deepEqual(first.sort(), second.sort(), 'suppression must not depend on input order');
});

test('H-1: a zero-day flagged article still produces a zero-day match', () => {
  // Vendor "acme" is mentioned; the product must be mentioned too for the prose
  // match. Publishing an article about a *different* product ("widget") matches
  // nothing, so the article must name the asset's actual product ("gateway").
  const article: IntelligenceArticle = {
    id: 'zd1',
    url: 'https://example.org/zd',
    title: 'Acme gateway zero-day exploited in the wild',
    summary: 'Acme gateway flaw is being actively exploited with no patch available.',
    publishedDate: NOW.toISOString(),
    modifiedDate: NOW.toISOString(),
    cveIds: [],
    sourceFeeds: ['RSS_NEWS'],
    zeroDay: true,
  };
  const asset = assetRecord({ cpes: [], purls: [] });
  const matches = matchIntelligence([article], [asset], [], [], {}, {}, 0, NOW);
  assert.equal(matches.length, 1, 'vendor + product prose must correlate');
  assert.equal(matches[0].zeroDay, true);
  assert.equal(matches[0].cveId, null);
  assert.match(matches[0].evidence, /Potential zero-day/);
});

test('H-1: merging a resolved article clears zero-day', () => {
  const base: IntelligenceArticle = {
    id: 'zd2',
    url: 'https://example.org/zd2',
    title: 'Acme widget zero-day exploited',
    summary: 'no patch',
    publishedDate: NOW.toISOString(),
    modifiedDate: NOW.toISOString(),
    cveIds: [],
    sourceFeeds: ['feed1'],
    zeroDay: true,
  };
  const [merged] = mergeArticles([
    base,
    { ...base, modifiedDate: '2026-10-27T00:00:00Z', cveIds: ['CVE-2026-12345'], zeroDay: false },
  ]);
  assert.equal(merged.zeroDay, false);
  assert.deepEqual(merged.cveIds, ['CVE-2026-12345']);
});

/* ------------------------------------------------------------------ H-2 */

test('H-2: purlIdentity is scope-aware and matches the matcher identity rule', () => {
  assert.equal(purlIdentity('pkg:npm/express@4.18.2'), 'npm/express');
  assert.equal(purlIdentity('pkg:npm/express'), 'npm/express');
  assert.equal(purlIdentity('pkg:npm/@scope/name@1.2.3'), 'npm/@scope/name');
  assert.equal(purlIdentity('pkg:npm/@scope/name'), 'npm/@scope/name');
  assert.equal(purlIdentity('pkg:pypi/django@4.0?arch=any'), 'pypi/django');
  assert.equal(purlIdentity('not-a-purl'), null);
});

test('H-2: a versionless scoped package is not truncated to its scope', () => {
  assert.notEqual(purlIdentity('pkg:npm/@acme/widget'), 'npm/@acme');
  assert.equal(purlIdentity('pkg:npm/@acme/widget'), 'npm/@acme/widget');
});

/* ------------------------------------------------------------------ L-1 */

test('L-1: a package-only advisory is still treated as having applicability data', () => {
  // applicabilityRequiresReview is set at ingestion, but there is no CPE data.
  // Before the fix the review override was disabled for package-only advisories.
  const asset = assetRecord({ cpes: [], version: '4.17.20' });
  const cve = cveRecord({
    cpeMatches: [],
    cpeMatchDetails: [],
    purls: ['pkg:npm/lodash@4.17.20'],
    applicabilityRequiresReview: true,
  });
  const [finding] = runVulnerabilityPipeline([], [cve], [asset], [], [], settings).newFindings;
  assert.ok(finding);
  assert.equal(finding.notificationStatus, 'REVIEW_REQUIRED');
  assert.equal(finding.confidence, 0);
});

/* ------------------------------------------------------------------ AND/negate vs product-wide wildcard */

test('a product-wide wildcard registration dispatches despite a CVE-level AND/negate hold', () => {
  // NVD configurations combining hardware-model criteria with software criteria
  // via an AND node set applicabilityRequiresReview on the whole CVE, because
  // flattening the tree into independent OR checks can't prove a concrete
  // asset satisfies every branch. A complete product-wide registration (every
  // component but vendor/product wildcarded) matches every branch by
  // construction, so that protection has nothing left to verify here.
  const cve = cveRecord({
    cpeMatches: ['cpe:2.3:o:sonicwall:sonicos:7.0.1:*:*:*:*:*:*:*'],
    cpeMatchDetails: [{ criteria: 'cpe:2.3:o:sonicwall:sonicos:7.0.1:*:*:*:*:*:*:*' }],
    applicabilityRequiresReview: true,
  });
  const asset = assetRecord({
    vendor: 'sonicwall',
    product: 'sonicos',
    version: '*',
    purls: [],
    cpes: ['cpe:2.3:o:sonicwall:sonicos:*:*:*:*:*:*:*:*'],
  });
  const [finding] = runVulnerabilityPipeline([], [cve], [asset], [], [], settings).newFindings;
  assert.ok(finding);
  assert.equal(finding.notificationStatus, 'QUEUED_FOR_DISPATCH');
});

test('a concrete device match still requires review under the same CVE-level AND/negate hold', () => {
  const cve = cveRecord({
    cveId: 'CVE-2026-9998',
    cpeMatches: ['cpe:2.3:o:sonicwall:sonicos:7.0.1:*:*:*:*:*:*:*'],
    cpeMatchDetails: [{ criteria: 'cpe:2.3:o:sonicwall:sonicos:7.0.1:*:*:*:*:*:*:*' }],
    applicabilityRequiresReview: true,
  });
  const asset = assetRecord({
    vendor: 'sonicwall',
    product: 'sonicos',
    version: '7.0.1',
    purls: [],
    cpes: ['cpe:2.3:o:sonicwall:sonicos:7.0.1:*:*:*:*:*:*:*'],
  });
  const [finding] = runVulnerabilityPipeline([], [cve], [asset], [], [], settings).newFindings;
  assert.ok(finding);
  assert.equal(finding.notificationStatus, 'REVIEW_REQUIRED');
});

test('a KEV naming the product dispatches for a wildcard registration when sources have no CPE data', () => {
  const cve = cveRecord({
    cveId: 'CVE-2026-19868',
    title: 'SonicOS SSLVPN authentication enforcement vulnerability',
    description: 'An authentication enforcement vulnerability affects the SonicOS SSLVPN service.',
    cpeMatches: [],
    cpeMatchDetails: [],
    purls: undefined,
    applicabilityRequiresReview: true,
    applicabilityPolicy: 'REVIEW_ONLY',
    cisaKev: { isKev: true, dateAdded: '2026-11-06' },
  });
  const asset = assetRecord({
    vendor: 'sonicwall',
    product: 'sonicos',
    version: '*',
    purls: [],
    cpes: ['cpe:2.3:o:sonicwall:sonicos:*:*:*:*:*:*:*:*'],
  });
  const [kevFinding] = runVulnerabilityPipeline([], [cve], [asset], [], [], settings).newFindings;
  assert.ok(kevFinding);
  assert.equal(kevFinding.notificationStatus, 'QUEUED_FOR_DISPATCH');

  const unconfirmedFindings = runVulnerabilityPipeline(
    [],
    [{ ...cve, cveId: 'CVE-2026-19869', cisaKev: { isKev: false } }],
    [asset],
    [],
    [],
    settings,
  ).newFindings;
  assert.equal(unconfirmedFindings.length, 0);
});

/* ------------------------------------------------------------------ H-5 */

test('H-5: deterministic configuration faults are classified as permanent', () => {
  assert.equal(isPermanentFeedFailure({ status: 404 }), true);
  assert.equal(isPermanentFeedFailure({ status: 400 }), true);
  assert.equal(isPermanentFeedFailure({ status: 422 }), true);
  assert.equal(isPermanentFeedFailure(new Error('Non-public destination')), true);
  assert.equal(isPermanentFeedFailure(new Error('Malformed URL')), true);
  assert.equal(isPermanentFeedFailure(new Error('Saved source checkpoint is invalid; clear it and re-run ingestion')), true);
});

test('H-5: transient failures keep their retry budget', () => {
  assert.equal(isPermanentFeedFailure({ status: 500 }), false);
  assert.equal(isPermanentFeedFailure({ status: 502 }), false);
  assert.equal(isPermanentFeedFailure({ status: 429 }), false);
  assert.equal(isPermanentFeedFailure({ status: 408 }), false);
  assert.equal(isPermanentFeedFailure({ status: 401 }), false);
  assert.equal(isPermanentFeedFailure(new Error('socket hang up')), false);
  assert.equal(isPermanentFeedFailure(new TypeError('fetch failed')), false);
});
