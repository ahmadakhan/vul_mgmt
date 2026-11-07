/**
 * Deep-audit integration regression: exercises product matching, VEX
 * suppression and email recipient eligibility together end-to-end, covering
 * properties individual unit tests do not assert in combination:
 *  - a fully verified match is always QUEUED_FOR_DISPATCH, never REVIEW_REQUIRED
 *    ("no valid finding goes to review");
 *  - a clearly inapplicable asset/version/product never produces a finding
 *    at all (no false positive);
 *  - a genuinely ambiguous version (equal-core distro revision against a
 *    plain-release bound) is held for review rather than silently excluded
 *    or silently dispatched;
 *  - exploit intelligence (CISA KEV) overrides a stale negative VEX claim
 *    (no false negative);
 *  - email recipient subscription tiers never receive severities outside
 *    their tier (no false-positive delivery);
 *  - a PURL/CPE contradiction (audit C-1) never auto-dispatches.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runVulnerabilityPipeline, applyVexSuppression } from '../src/engine/pipelineEngine.ts';
import { recipientAllows } from '../server/delivery.ts';
import { DEFAULT_SETTINGS } from '../shared/state.ts';
import type { AppSettings, EmailRecipient, Finding, NormalizedCVE, WatchListItem } from '../src/types/index.ts';

const settings: AppSettings = { ...DEFAULT_SETTINGS, scopeHours: 24 * 365 * 10 };

function baseCve(overrides: Partial<NormalizedCVE> = {}): NormalizedCVE {
  return {
    cveId: 'CVE-2026-00001',
    title: 'Example Widget vulnerability',
    description: 'A flaw was found in Example Widget.',
    publishedDate: new Date().toISOString(),
    modifiedDate: new Date().toISOString(),
    cvss: { version: '3.1', score: 9.8, vector: '', severity: 'CRITICAL' },
    cwe: [],
    cpeMatches: ['cpe:2.3:a:example:widget:*:*:*:*:*:*:*:*'],
    versionRange: { versionEndExcluding: '2.0' },
    sourceFeeds: ['NVD_API'],
    epss: { score: 0.5, percentile: 0.9 },
    cisaKev: { isKev: false },
    exploitStatus: 'None',
    remediation: {
      patchUrl: '', vendorAdvisoryRef: '', immediateActions: [], workarounds: [], rollbackPlan: '', stepByStep: [],
    },
    ...overrides,
  } as NormalizedCVE;
}

function baseAsset(overrides: Partial<WatchListItem> = {}): WatchListItem {
  return {
    id: 'asset-1',
    assetTag: 'server-01',
    vendor: 'example',
    product: 'widget',
    version: '1.5',
    cpes: ['cpe:2.3:a:example:widget:1.5:*:*:*:*:*:*:*'],
    purls: [],
    active: true,
    exposure: 'INTERNAL',
    targetHw: '*',
    ...overrides,
  } as WatchListItem;
}

test('a verified in-range strict CPE match dispatches automatically, never to review', () => {
  const result = runVulnerabilityPipeline([], [baseCve()], [baseAsset()], [], [], settings);
  const finding = result.newFindings[0];
  assert.equal(finding?.notificationStatus, 'QUEUED_FOR_DISPATCH');
  assert.equal(finding?.confidence, 100);
});

test('an out-of-range version produces no finding at all', () => {
  const asset = baseAsset({ version: '3.0', cpes: ['cpe:2.3:a:example:widget:3.0:*:*:*:*:*:*:*'] });
  const result = runVulnerabilityPipeline([], [baseCve()], [asset], [], [], settings);
  assert.equal(result.newFindings.length, 0);
});

test('an unrelated product never matches through alias or fallback over-reach', () => {
  const asset = baseAsset({ vendor: 'other', product: 'gadget', cpes: ['cpe:2.3:a:other:gadget:1.5:*:*:*:*:*:*:*'] });
  const result = runVulnerabilityPipeline([], [baseCve()], [asset], [], [], settings);
  assert.equal(result.newFindings.length, 0);
});

test('an equal-core distro revision against a plain-release bound is held for review, not excluded or dispatched', () => {
  const cve = baseCve({ versionRange: { versionEndExcluding: '1.9' } } as Partial<NormalizedCVE>);
  const asset = baseAsset({ version: '1.9-r1', cpes: ['cpe:2.3:a:example:widget:1.9-r1:*:*:*:*:*:*:*'] });
  const result = runVulnerabilityPipeline([], [cve], [asset], [], [], settings);
  const finding = result.newFindings[0];
  assert.ok(finding);
  assert.equal(finding.notificationStatus, 'REVIEW_REQUIRED');
});

test('a different-core distro revision is unambiguous and dispatches normally', () => {
  const asset = baseAsset({ version: '1.9-r1', cpes: ['cpe:2.3:a:example:widget:1.9-r1:*:*:*:*:*:*:*'] });
  const result = runVulnerabilityPipeline([], [baseCve()], [asset], [], [], settings);
  assert.equal(result.newFindings[0]?.notificationStatus, 'QUEUED_FOR_DISPATCH');
});

test('a signed VEX not_affected statement suppresses an otherwise dispatchable finding', () => {
  const cve = baseCve({
    vex: { status: 'not_affected', source: 'vendor', signed: true, scope: { vendor: 'example', product: 'widget' } },
  } as Partial<NormalizedCVE>);
  const result = runVulnerabilityPipeline([], [cve], [baseAsset()], [], [], settings);
  const [suppressed] = applyVexSuppression(result.newFindings);
  assert.equal(suppressed.notificationStatus, 'SUPPRESSED_VEX_NOT_AFFECTED');
});

test('CISA KEV exploit intelligence overrides a stale negative VEX claim', () => {
  const cve = baseCve({
    cisaKev: { isKev: true },
    vex: { status: 'not_affected', source: 'vendor', signed: true, scope: { vendor: 'example', product: 'widget' } },
  } as Partial<NormalizedCVE>);
  const result = runVulnerabilityPipeline([], [cve], [baseAsset()], [], [], settings);
  const [overridden] = applyVexSuppression(result.newFindings);
  assert.equal(overridden.notificationStatus, 'QUEUED_FOR_DISPATCH');
});

test('recipient subscription tiers never receive a severity outside their tier', () => {
  const criticalFinding = { cve: { cvss: { severity: 'CRITICAL' } } } as Finding;
  const lowFinding = { cve: { cvss: { severity: 'LOW' } } } as Finding;
  const highOnly = { subscriptionTier: 'CRITICAL_HIGH_ONLY' } as EmailRecipient;
  const all = { subscriptionTier: 'ALL_SEVERITIES' } as EmailRecipient;
  assert.equal(recipientAllows(highOnly, criticalFinding), true);
  assert.equal(recipientAllows(highOnly, lowFinding), false);
  assert.equal(recipientAllows(all, lowFinding), true);
});

test('a PURL mismatch contradicting a CPE match never auto-dispatches', () => {
  const cve = baseCve({
    cpeMatches: ['cpe:2.3:a:example:widget:1.5:*:*:*:*:*:*:*'],
    versionRange: undefined,
    purls: ['pkg:npm/widget@2.0.0'],
  } as Partial<NormalizedCVE>);
  const asset = baseAsset({ purls: ['pkg:npm/widget@1.5.0'] });
  const result = runVulnerabilityPipeline([], [cve], [asset], [], [], settings);
  assert.equal(result.newFindings[0]?.notificationStatus, 'REVIEW_REQUIRED');
});
