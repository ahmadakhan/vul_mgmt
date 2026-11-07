import { generateCPE23 } from '../src/utils/cpeMatcher.ts';
import { buildStrictCpe23 } from '../src/data/vendorCatalog.ts';
import type { AuditLog, NormalizedCVE, WatchListItem } from '../src/types/index.ts';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createHmac } from 'node:crypto';
import {
  matchCPE,
  matchPurl,
  matchesWatchlistItem,
  matchProductWithAliases,
  matchVendorWithAliases,
  buildAliasMap,
  parseCPE23,
} from '../src/utils/cpeMatcher.ts';
import { compareVersions } from '../src/utils/versionComparator.ts';
import { mergeCveRecords, isWithinTimelineScope, stableJson } from '../src/utils/deduplicator';
import { quickHash, generateHmacSignature, SortedMerkleAccumulator, merkleRoot, chainAuditLogs, verifyAuditChain } from '../src/utils/cryptoChain';
import { auditContext, auditText, commandAudit } from '../server/audit.ts';
import { runVulnerabilityPipeline, validateSsrfSafety } from '../src/engine/pipelineEngine';
import { reconcileFindings } from '../src/engine/reconcileFindings';
import { registrationAssetsFromCpes } from '../src/utils/watchlist.ts';
import {
  INITIAL_NORMALIZED_CVES,
  INITIAL_WATCHLIST,
  INITIAL_SETTINGS,
  INITIAL_FEEDS,
} from './fixtures/seedData';

const cpe = (version: string, product = 'widget') => `cpe:2.3:a:vendor:${product}:${version}:*:*:*:*:*:*:*`;
test('audit formatting redacts credentials, bounds data and describes commands without values', () => {
  const text = auditText('password=hunter2 token="private-token" smtpPassword=hidden-value {"authSecretKey":"json-secret"} Bearer abc.xyz https://user:pass@example.com/path?api_key=secret&view=logs\u0000\r\nforged', 4000);
  for (const secret of ['hunter2', 'private-token', 'hidden-value', 'json-secret', 'abc.xyz', 'user:pass', 'api_key=secret']) assert.ok(!text.includes(secret));
  assert.ok(text.includes('view=logs'));
  assert.ok(!/[\u0000-\u001f]/.test(text));
  assert.equal(auditText('x'.repeat(500), 100).length, 100);
  assert.equal(auditText('x\ud83d\ude00', 2), 'x\ufffd');
  assert.ok(!auditText('operator\u202eforged', 100).includes('\u202e'));
  const context = auditContext({ action: 'settings.save', fields: ['autoDispatchConfidenceThreshold', 'password', 'bad\nfield', 'password'] }, 'INFO');
  assert.deepEqual(context.fields, ['autoDispatchConfidenceThreshold', 'password']);
  assert.equal(context.outcome, 'RECORDED');
  const command = commandAudit('email.configure', 'main', { smtpPassword: 'do-not-log', fromEmail: 'private@example.com' });
  assert.equal(command.category, 'EMAIL');
  assert.equal(command.event, 'Email provider configuration updated');
  assert.equal(command.context.outcome, 'SUCCESS');
  assert.ok(!JSON.stringify(command).includes('do-not-log'));
  assert.ok(!JSON.stringify(command).includes('private@example.com'));
});
test('audit context is tamper-evident without changing historical hashes', () => {
  const legacy = chainAuditLogs([{
    id: 'legacy', timestamp: '2026-11-04T00:00:00Z', category: 'SECURITY', level: 'INFO',
    event: 'Settings updated', details: 'Workspace policy updated', actor: 'operator', ipAddress: '127.0.0.1',
    hash: '', prevHash: '',
  } satisfies AuditLog])[0];
  assert.equal(legacy.hash, quickHash(stableJson([
    legacy.prevHash, legacy.id, legacy.timestamp, legacy.category, legacy.level,
    legacy.event, legacy.details, legacy.actor, legacy.ipAddress,
  ])));
  assert.equal(verifyAuditChain([legacy]), true);
  const modern = chainAuditLogs([{ ...legacy, id: 'modern', context: {
    action: 'settings.save', resourceType: 'settings', resourceId: 'main', outcome: 'SUCCESS',
    fields: ['autoDispatchConfidenceThreshold'],
  } }], legacy.hash)[0];
  assert.equal(verifyAuditChain([modern, legacy]), true);
  assert.equal(verifyAuditChain([{ ...modern, context: { ...modern.context!, resourceId: 'other' } }, legacy]), false);
  const { context: removed, ...withoutContext } = modern;
  assert.equal(verifyAuditChain([withoutContext, legacy]), false);
});
test('incremental Merkle roots preserve the existing sorted odd-leaf convention', () => {
  for (const size of [0, 1, 2, 3, 5, 6, 7, 8, 17, 255, 256, 257, 513]) {
    const hashes = Array.from({ length: size }, (_, index) => quickHash(String(index % 113))).sort();
    const accumulator = new SortedMerkleAccumulator();
    for (const hash of hashes) accumulator.add(hash);
    assert.equal(accumulator.root(), merkleRoot(hashes), `size ${size}`);
    assert.equal(accumulator.root(), merkleRoot(hashes), 'root reads must not mutate the accumulator');
  }
});
test('CPE rejects malformed names and substring component matches', () => {
  assert.equal(parseCPE23('cpe:2.3:a:vendor').isValid, false);
  assert.equal(matchCPE(cpe('1.2'), cpe('1.20')).matched, false);
  assert.equal(matchCPE(cpe('1', 'widget'), cpe('1', 'widget_server')).matched, false);
});
test('CPE applies start-only ranges', () => {
  assert.equal(matchCPE(cpe('1'), cpe('*'), { versionStartIncluding: '2' }).matched, false);
});
test('CPE component wildcards match only the intended version pattern', () => {
  const pattern = (version: string) => `cpe:2.3:a:vendor:widget:${version}:*:*:*:*:*:*:*`;
  assert.equal(matchCPE(pattern('1.2.3'), pattern('1.*')).matched, true);
  assert.equal(matchCPE(pattern('2.0'), pattern('1.*')).matched, false);
  assert.equal(matchCPE(pattern('1.2'), pattern('1.\\*')).matched, false);
});
test('disjoint component wildcards never match each other', () => {
  const pattern = (version: string) => `cpe:2.3:a:vendor:widget:${version}:*:*:*:*:*:*:*`;
  // Both sides are globs, so the matcher must check whether their languages
  // overlap instead of accepting every wildcard-versus-wildcard comparison.
  assert.equal(matchCPE(pattern('2.*'), pattern('1.*')).matched, false);
  assert.equal(matchCPE(pattern('1.*'), pattern('2.*')).matched, false);
  assert.equal(matchCPE(pattern('1.*'), pattern('1.2*')).matched, true);
  assert.equal(matchCPE(pattern('1.2*'), pattern('1.*')).matched, true);
  assert.equal(matchCPE(pattern('1.?'), pattern('1.2')).matched, true);
});
test('pathological wildcard counts are matched without a regex backtracking crash', () => {
  const pattern = (version: string) => `cpe:2.3:a:vendor:widget:${version}:*:*:*:*:*:*:*`;
  const manyStars = '*'.repeat(64);
  assert.doesNotThrow(() => matchCPE(pattern('1.2.3'), pattern(manyStars)));
  assert.equal(matchCPE(pattern('1.2.3'), pattern(manyStars)).matched, true);
  assert.equal(matchCPE(pattern('1.2.3'), pattern('?'.repeat(64))).matched, false);
  assert.equal(matchCPE(pattern('1.2.3'), pattern('1.' + '?'.repeat(3))).matched, true);
});
test('one conflicting CPE does not suppress a compatible CPE of the same identity', () => {
  const pattern = (version: string) => `cpe:2.3:a:vendor:widget:${version}:*:*:*:*:*:*:*`;
  // A wildcard-version entry of the same identity remains compatible even when
  // another inventory CPE pins a version outside the advisory criterion.
  const result = matchesWatchlistItem(
    [pattern('1.0'), pattern('*')],
    'vendor',
    'widget',
    [pattern('2.0')],
    't',
    'd',
  );
  assert.equal(result.matched, true);
  assert.equal(result.applicabilityRequiresReview, false);
});
test('text fallback evaluates every known inventory version', () => {
  const pattern = (version: string, vendor = 'vendor', product = 'widget') =>
    `cpe:2.3:a:${vendor}:${product}:${version}:*:*:*:*:*:*:*`;
  // The first CPE is outside the advisory range, but the second instance of the
  // same inventory row is inside it. The fallback must not exclude the product
  // merely because it read only the first version.
  const result = matchesWatchlistItem(
    [pattern('2.0'), pattern('1.0')],
    'vendor',
    'widget',
    [pattern('1.0', 'other', 'unrelated')],
    'Vendor widget security notice',
    'A flaw affects the vendor widget product.',
    { versionEndExcluding: '1.5' },
  );
  assert.equal(result.matched, true);
  assert.equal(result.method, 'VENDOR_PRODUCT_FALLBACK');
});
test('non-intersecting wildcard asset version does not match a concrete vuln version', () => {
  // An asset wildcard like 2.* describes the 2.x release line; it must not
  // match a vulnerability whose CPE pins version 1.5. Before the strict CPE
  // fix the unverifiedVersion bypass short-circuited past globIntersects,
  // producing false-positive REVIEW_REQUIRED findings that surfaced as
  // duplicate CVEs on the Vulnerabilities page.
  const pattern = (version: string) => `cpe:2.3:a:vendor:widget:${version}:*:*:*:*:*:*:*`;
  assert.equal(matchCPE(pattern('2.*'), pattern('1.5')).matched, false);
  assert.equal(matchCPE(pattern('1.*'), pattern('2.0')).matched, false);
  // Overlapping wildcards still match at the token level.
  assert.equal(matchCPE(pattern('1.*'), pattern('1.5')).matched, true);
  // matchesWatchlistItem must not fabricate a finding for disjoint versions.
  assert.equal(
    matchesWatchlistItem([pattern('2.*')], 'vendor', 'widget', [pattern('1.5')], 't', 'd').matched,
    false,
  );
  // An all-version registration intentionally covers concrete vulnerable releases.
  const wildcardStar = matchesWatchlistItem([cpe('*')], 'vendor', 'widget', [cpe('1.5')], 't', 'd');
  assert.equal(wildcardStar.matched, true);
  assert.equal(wildcardStar.confidence, 90);
  assert.equal(wildcardStar.applicabilityRequiresReview, false);
});
test('non-intersecting wildcard assets do not produce duplicate CVE findings', () => {
  // Multiple assets whose wildcard CPE versions cannot overlap the vuln
  // version must not each yield a REVIEW_REQUIRED finding for the same CVE.
  const { cve, settings } = fixture();
  cve.cpeMatches = [cpe('1.5')];
  cve.cpeMatchDetails = [];
  cve.versionRange = undefined;
  const assets = [
    { ...fixture().asset, id: 'a1', assetTag: 'a1', cpes: [cpe('2.*')] },
    { ...fixture().asset, id: 'a2', assetTag: 'a2', cpes: [cpe('2.*')] },
    { ...fixture().asset, id: 'a3', assetTag: 'a3', cpes: [cpe('2.*')] },
  ];
  const result = runVulnerabilityPipeline([], [cve], assets as never, [], [], settings);
  assert.equal(result.newFindings.length, 0);
});
test('pipeline correctly distinguishes non-intersecting, intersecting, and exact version matches', () => {
  // Behavior matrix at the pipeline level:
  //   2.* vs 1.5  → no finding (non-intersecting wildcard)
  //   1.* vs 1.5  → REVIEW_REQUIRED (intersecting wildcard, version uncertain)
  //   *   vs 1.5  → CONFIRMED (registered all-version product)
  //   1.5 vs 1.5  → CONFIRMED (exact token match, auto-dispatch eligible)
  const { cve, settings } = fixture();
  cve.cpeMatches = [cpe('1.5')];
  cve.cpeMatchDetails = [];
  cve.versionRange = undefined;
  const baseAsset = fixture().asset;
  const makeAsset = (version: string) => ({
    ...baseAsset,
    id: `asset-${version}`,
    assetTag: `asset-${version}`,
    cpes: [cpe(version)],
  });
  for (const { version, expected, expectedStatus } of [
    { version: '2.*', expected: 0, expectedStatus: undefined },
    { version: '1.*', expected: 1, expectedStatus: 'REVIEW_REQUIRED' },
    { version: '*', expected: 1, expectedStatus: undefined },
    { version: '1.5', expected: 1, expectedStatus: undefined },
  ]) {
    const asset = makeAsset(version);
    const result = runVulnerabilityPipeline([], [cve], [asset], [], [], settings);
    assert.equal(result.newFindings.length, expected, `version ${version}: expected ${expected} findings`);
    if (expectedStatus)
      assert.equal(
        result.newFindings[0]?.notificationStatus,
        expectedStatus,
        `version ${version}: expected ${expectedStatus}`,
      );
    else if (expected === 1)
      assert.notEqual(
        result.newFindings[0]?.notificationStatus,
        'REVIEW_REQUIRED',
        `version ${version}: should not be REVIEW_REQUIRED`,
      );
  }
});
test('all-version product registration is dispatchable without the unverifiable override', () => {
  const { cve, asset, settings } = fixture();
  cve.cpeMatches = [cpe('1.5')];
  cve.cpeMatchDetails = [];
  cve.versionRange = { versionEndExcluding: '2.0' };
  const product = { ...asset, cpes: [cpe('*')] };
  const policy = { ...settings, autoDispatchConfidenceThreshold: 90, autoDispatchUnverifiableMatches: false };
  const findings = runVulnerabilityPipeline([], [cve], [product], [], [], policy).newFindings;
  assert.equal(findings.length, 1);
  assert.equal(findings[0].notificationStatus, 'QUEUED_FOR_DISPATCH');
  const held = runVulnerabilityPipeline([], [{ ...cve, applicabilityPolicy: 'REVIEW_ONLY' }], [product], [], [], policy).newFindings;
  assert.equal(held[0].notificationStatus, 'REVIEW_REQUIRED');
});

test('registered product-wide CPE dispatches a matching platform-specific advisory', () => {
  const { cve, settings } = fixture();
  cve.cveId = 'CVE-2026-12346';
  cve.cpeMatches = ['cpe:2.3:o:microsoft:windows_server_2022:20348:*:*:*:*:*:x64:*'];
  cve.cpeMatchDetails = [];
  cve.versionRange = { versionStartIncluding: '20348' };
  cve.applicabilityRequiresReview = false;
  const [registered] = registrationAssetsFromCpes(
    ['cpe:2.3:o:microsoft:windows_server_2022:*:*:*:*:*:*:*:*'],
    { assetTag: 'WIN-01', ownerGroup: 'SOC', notes: '', purls: [] },
  );
  const asset = { ...registered, id: 'asset-windows-server', createdAt: new Date().toISOString() };
  const finding = runVulnerabilityPipeline([], [cve], [asset], [], [], settings).newFindings[0];
  assert.ok(finding);
  assert.equal(finding.notificationStatus, 'QUEUED_FOR_DISPATCH');
});

test('autoDispatchUnverifiableMatches releases the version-uncertain hold at threshold 0', () => {
  const { cve, asset, settings } = fixture();
  cve.cpeMatches = [cpe('1.5')];
  cve.cpeMatchDetails = [];
  cve.versionRange = undefined;
  const wildcardAsset = { ...asset, id: 'asset-pattern', assetTag: 'asset-pattern', cpes: [cpe('1.*')] };
  const held = runVulnerabilityPipeline([], [cve], [wildcardAsset], [], [], settings);
  assert.equal(held.newFindings.length, 1);
  assert.equal(
    held.newFindings[0].notificationStatus,
    'REVIEW_REQUIRED',
    'unverifiable match stays in review at threshold 0 by default',
  );
  const released = runVulnerabilityPipeline([], [cve], [wildcardAsset], [], [], {
    ...settings,
    autoDispatchUnverifiableMatches: true,
  });
  assert.equal(released.newFindings.length, 1);
  assert.equal(
    released.newFindings[0].notificationStatus,
    'QUEUED_FOR_DISPATCH',
    'opt-in flag releases the unverifiable hold at threshold 0',
  );
});
test('autoDispatchUnverifiableMatches still respects the configured confidence threshold', () => {
  const { cve, asset, settings } = fixture();
  cve.cpeMatches = [cpe('1.5')];
  cve.cpeMatchDetails = [];
  cve.versionRange = undefined;
  const wildcardAsset = { ...asset, id: 'asset-pattern', assetTag: 'asset-pattern', cpes: [cpe('1.*')] };
  const held = runVulnerabilityPipeline([], [cve], [wildcardAsset], [], [], {
    ...settings,
    autoDispatchConfidenceThreshold: 80,
    autoDispatchUnverifiableMatches: true,
  });
  assert.equal(held.newFindings.length, 1);
  assert.equal(held.newFindings[0].confidence, 70);
  assert.equal(
    held.newFindings[0].notificationStatus,
    'REVIEW_REQUIRED',
    'a version-uncertain match below the configured minimum stays held even with the flag on',
  );
  const eligible = runVulnerabilityPipeline([], [cve], [wildcardAsset], [], [], {
    ...settings, autoDispatchConfidenceThreshold: 70, autoDispatchUnverifiableMatches: true,
  });
  assert.equal(eligible.newFindings[0].notificationStatus, 'QUEUED_FOR_DISPATCH');
});
test('fallback cannot override a known version exclusion', () => {
  assert.equal(
    matchesWatchlistItem([cpe('3')], 'vendor', 'widget', [cpe('*')], 'vendor widget', '', {
      versionEndExcluding: '2',
    }).matched,
    false,
  );
});
test('PURL matches exact identity and specified version', () => {
  assert.equal(matchPurl('pkg:npm/express-extra@1', 'pkg:npm/express'), false);
  assert.equal(matchPurl('pkg:npm/express@5', 'pkg:npm/express@4'), false);
  assert.equal(matchPurl('pkg:npm/express@5', 'pkg:npm/express'), true);
});
test('scoped PURLs keep the npm scope when no version is present', () => {
  assert.equal(matchPurl('pkg:npm/@scope/name', 'pkg:npm/@scope/name'), true);
  assert.equal(matchPurl('pkg:npm/@scope/name@1.0.0', 'pkg:npm/@scope/name'), true);
  assert.equal(matchPurl('pkg:npm/@scope/name@1.0.0', 'pkg:npm/@scope/name@2.0.0'), false);
  assert.equal(matchPurl('pkg:npm/@scope/name', 'pkg:npm/@other/name'), false);
});
test('SemVer build metadata does not change precedence', () => {
  assert.equal(compareVersions('1.2.3+build.1', '1.2.3+build.2'), 0);
});
test('hash and HMAC match independent crypto implementations', () => {
  assert.equal(quickHash('audit'), createHash('sha256').update('audit').digest('hex'));
  assert.equal(
    generateHmacSignature('payload', 'secret'),
    'sha256=' + createHmac('sha256', 'secret').update('payload').digest('hex'),
  );
});
for (const url of [
  'http://[::ffff:127.0.0.1]',
  'http://[fc00::1]',
  'http://localhost.',
  'http://100.64.0.1',
]) {
  test(`URL screening rejects ${url}`, () => assert.equal(validateSsrfSafety(url).safe, false));
}
function fixture() {
  const cve: NormalizedCVE = {
    ...structuredClone(INITIAL_NORMALIZED_CVES[0]),
    cveId: ' cve-2026-12345 ',
    cpeMatches: [cpe('*')],
    versionRange: undefined,
    purls: undefined,
    vex: undefined,
  };
  const asset: WatchListItem = {
    ...structuredClone(INITIAL_WATCHLIST[0]),
    id: 'asset-test',
    vendor: 'vendor',
    product: 'widget',
    cpes: [cpe('1')],
    purls: undefined,
    active: true,
  };
  const settings = { ...structuredClone(INITIAL_SETTINGS), scopeHours: 0, autoDispatchEnabled: true };
  return { cve, asset, settings };
}
test('unsigned VEX cannot silently suppress a verified product match', () => {
  const { cve, asset, settings } = fixture();
  cve.vex = { status: 'not_affected' };
  const result = runVulnerabilityPipeline(INITIAL_FEEDS, [cve], [asset], [], [], settings);
  assert.equal(result.newFindings.length, 1);
  assert.equal(result.newAdvisories.length, 0);
  assert.equal(result.newEmailLogs.length, 0);
  assert.equal(result.newFindings[0].notificationStatus, 'QUEUED_FOR_DISPATCH');
});
test('correlation canonicalizes output without fabricating delivery or mutating prior alerts', () => {
  const { cve, asset, settings } = fixture();
  const prior = [
    {
      cveId: 'CVE-2026-12345',
      firstAlertedAt: '',
      lastAlertedAt: '',
      advisoryId: 'old',
      recipientEmails: [],
      status: 'DISPATCHED' as const,
      dispatchCount: 1,
    },
  ];
  const before = structuredClone(prior);
  const result = runVulnerabilityPipeline(
    INITIAL_FEEDS,
    [cve],
    [asset, { ...asset, id: 'second' }],
    prior,
    [],
    settings,
  );
  assert.equal(result.newFindings[0].cveId, 'CVE-2026-12345');
  assert.deepEqual(prior, before);
  assert.equal(result.updatedAlertedCves.length, 1);
  assert.equal(result.updatedAlertedCves[0].dispatchCount, 1);
  assert.equal(result.newEmailLogs.length, 0);
});

import { INITIAL_AUDIT_LOGS } from './fixtures/seedData';
import { compileCustomizedTemplate, DEFAULT_TEMPLATE_CUSTOMIZATION } from '../src/utils/templateCompiler.ts';
test('audit verification detects changed content and reordered records', () => {
  const logs = chainAuditLogs(INITIAL_AUDIT_LOGS);
  assert.equal(verifyAuditChain(logs), true);
  const changed = structuredClone(logs);
  changed[0].details += 'tampered';
  assert.equal(verifyAuditChain(changed), false);
  assert.equal(verifyAuditChain([...logs].reverse()), false);
  const appended = chainAuditLogs([{ ...logs[0], id: 'new-log' }], logs[0].hash);
  assert.equal(verifyAuditChain([...appended, ...logs]), true);
});
test('customization escapes markup and rejects CSS breakout', () => {
  const html = compileCustomizedTemplate({
    ...DEFAULT_TEMPLATE_CUSTOMIZATION,
    badgeStampText: '<img src=x onerror=alert(1)>',
    canvasBg: '</style><script>evil()</script>',
    borderRadius: '0; background:url(https://evil.test)',
  });
  assert.ok(!html.includes('<img src=x'));
  assert.ok(html.includes('&lt;img'));
  assert.ok(!html.includes('<script>'));
  assert.ok(!html.includes('evil.test'));
});
test('valid public endpoints and matching CPE still work', () => {
  assert.equal(validateSsrfSafety('https://example.com/feed').safe, true);
  assert.equal(validateSsrfSafety('https://[2606:4700:4700::1111]/').safe, true);
  assert.equal(
    matchCPE(cpe('1.2.3'), cpe('*'), { versionStartIncluding: '1', versionEndExcluding: '2' }).matched,
    true,
  );
});
test('pipeline rerun is idempotent and emitted audit content verifies', () => {
  const { cve, asset, settings } = fixture();
  const first = runVulnerabilityPipeline(INITIAL_FEEDS, [cve, cve], [asset], [], [], settings);
  assert.equal(first.newFindings.length, 1);
  assert.equal(first.execution.stats.inRunDuplicatesDropped, 1);
  assert.equal(verifyAuditChain([...first.newAuditLogs].reverse()), true);
  const second = runVulnerabilityPipeline(
    INITIAL_FEEDS,
    [cve],
    [asset],
    first.updatedAlertedCves,
    first.newFindings,
    settings,
  );
  assert.equal(second.newFindings.length, 0);
  assert.equal(second.newAdvisories.length, 0);
});

import { csvCell } from '../src/utils/csv';
test('CSV escapes quotes, delimiters, and formula prefixes', () => {
  assert.equal(csvCell('=1+1'), '"\'=1+1"');
  assert.equal(csvCell('a,"b"'), '"a,""b"""');
  assert.equal(csvCell('\t=1+1'), '"\'\t=1+1"');
});
test('PURL cannot bypass an explicit version exclusion', () => {
  assert.equal(
    matchesWatchlistItem(
      [],
      'vendor',
      'widget',
      [],
      '',
      '',
      { versionEndExcluding: '2' },
      ['pkg:npm/widget@3'],
      ['pkg:npm/widget'],
    ).matched,
    false,
  );
});

test('unsupported package version ordering requires review before dispatch', () => {
  const { cve, asset, settings } = fixture();
  asset.cpes = [];
  asset.purls = ['pkg:npm/widget@1.0-custom'];
  cve.cpeMatches = [];
  cve.purls = ['pkg:npm/widget'];
  cve.versionRange = { versionEndExcluding: '2.0' };
  const result = runVulnerabilityPipeline([], [cve], [asset], [], [], settings);
  assert.equal(result.newFindings.length, 1);
  assert.equal(result.newFindings[0].notificationStatus, 'REVIEW_REQUIRED');
});

test('package-name-only PURL correlation requires review without a version constraint', () => {
  const { cve, asset, settings } = fixture();
  asset.cpes = [];
  asset.purls = ['pkg:npm/widget'];
  cve.cpeMatches = [];
  cve.purls = ['pkg:npm/widget'];
  cve.versionRange = undefined;
  const result = runVulnerabilityPipeline([], [cve], [asset], [], [], settings);
  assert.equal(result.newFindings.length, 1);
  assert.equal(result.newFindings[0].notificationStatus, 'REVIEW_REQUIRED');
  assert.equal(
    matchesWatchlistItem([], '', '', [], '', '', undefined, asset.purls, cve.purls).confidence,
    70,
  );
});

test('strict CPE does not equate different products through marketing aliases', () => {
  assert.equal(
    matchCPE(
      'cpe:2.3:a:paloaltonetworks:globalprotect:6.0:*:*:*:*:*:*:*',
      'cpe:2.3:a:paloaltonetworks:pan_os:*:*:*:*:*:*:*:*',
    ).matched,
    false,
  );
});
test('the alias thesaurus fallback does not equate GlobalProtect with PAN-OS either', () => {
  // GlobalProtect (VPN client) and PAN-OS (firewall OS) are separate Palo Alto
  // products with independent CVE histories. The free-text fallback is excluded
  // by giving no matching text, isolating this to the alias-thesaurus path.
  assert.equal(
    matchesWatchlistItem(
      [],
      'paloaltonetworks',
      'globalprotect',
      ['cpe:2.3:o:paloaltonetworks:pan_os:10.2.0:*:*:*:*:*:*:*'],
      'unrelated advisory title',
      'unrelated advisory body',
    ).matched,
    false,
  );
});
test('the alias thesaurus still resolves genuine formatting variants of the same product', () => {
  assert.equal(matchProductWithAliases('pan_os', 'panos'), true);
});
test('operator-managed custom aliases add to the built-in thesaurus without being required for defaults', () => {
  // Built-in resolution still works with no custom aliases supplied.
  assert.equal(matchProductWithAliases('pan_os', 'panos'), true);
  // A custom alias not present in the built-in table is honored once supplied.
  assert.equal(matchProductWithAliases('acme_widget', 'widget_pro'), false);
  assert.equal(matchProductWithAliases('acme_widget', 'widget_pro', { acme_widget: ['widget_pro'] }), true);
  assert.equal(matchVendorWithAliases('acme', 'acme_corp', { acme: ['acme_corp'] }), true);
});
test('custom aliases extend an existing canonical key rather than replacing its built-in aliases', () => {
  // 'panos' is a built-in alias of pan_os; adding a custom alias for the same
  // canonical must not drop the built-in one.
  assert.equal(matchProductWithAliases('pan_os', 'panos', { pan_os: ['pan-os-extra'] }), true);
  assert.equal(matchProductWithAliases('pan_os', 'pan-os-extra', { pan_os: ['pan-os-extra'] }), true);
});
test('buildAliasMap scopes rows to VENDOR or PRODUCT and merges repeated canonical keys', () => {
  const rows = [
    { scope: 'VENDOR' as const, canonical: 'acme', aliases: ['acme corp'] },
    { scope: 'PRODUCT' as const, canonical: 'widget', aliases: ['widget-pro'] },
    { scope: 'VENDOR' as const, canonical: 'acme', aliases: ['acme, inc.'] },
  ];
  // The map intentionally has a null prototype; compare its data content.
  assert.deepEqual({ ...buildAliasMap(rows, 'VENDOR') }, { acme: ['acme corp', 'acme, inc.'] });
  assert.deepEqual({ ...buildAliasMap(rows, 'PRODUCT') }, { widget: ['widget-pro'] });
});
test('the alias-thesaurus match step in matchesWatchlistItem honors custom aliases end to end', () => {
  const result = matchesWatchlistItem(
    [],
    'acme',
    'widgetpro',
    ['cpe:2.3:a:acme:widget:3.0:*:*:*:*:*:*:*'],
    'unrelated advisory title',
    'unrelated advisory body',
    undefined,
    undefined,
    undefined,
    undefined,
    undefined,
    true,
    {},
    { widget: ['widgetpro'] },
  );
  assert.equal(result.matched, true);
  assert.equal(result.method, 'VENDOR_PRODUCT_ALIAS');
});
test('empty per-CPE details fall back to supplied CPE matches', () => {
  const { cve, asset, settings } = fixture();
  cve.cpeMatchDetails = [];
  assert.equal(runVulnerabilityPipeline([], [cve], [asset], [], [], settings).newFindings.length, 1);
});
test('package without installed version produces a review finding for a ranged vulnerability', () => {
  const { cve, asset, settings } = fixture();
  asset.cpes = [];
  asset.purls = ['pkg:npm/widget'];
  cve.cpeMatches = [];
  cve.purls = ['pkg:npm/widget'];
  cve.versionRange = { versionEndExcluding: '2.0' };
  const result = runVulnerabilityPipeline([], [cve], [asset], [], [], settings);
  assert.equal(result.newFindings.length, 1);
  assert.equal(result.newFindings[0].notificationStatus, 'REVIEW_REQUIRED');
});
test('unknown architecture cannot confirm an architecture-specific vulnerability', () => {
  const { cve, asset, settings } = fixture();
  cve.cpeMatches = ['cpe:2.3:a:vendor:widget:*:*:*:*:*:*:arm64:*'];
  const result = runVulnerabilityPipeline([], [cve], [asset], [], [], settings);
  assert.equal(result.newFindings.length, 1);
  assert.equal(result.newFindings[0].notificationStatus, 'REVIEW_REQUIRED');
});

test('inventory CPE builders preserve hyphens in canonical product identifiers', () => {
  for (const build of [generateCPE23, buildStrictCpe23]) {
    assert.equal(parseCPE23(build('o', 'paloaltonetworks', 'pan-os', '10.2.3')).product, 'pan-os');
  }
});

test('inventory CPE builder escapes token delimiters instead of emitting invalid CPEs', () => {
  const built = buildStrictCpe23('a', 'acme', 'gateway:edge', '1.0');
  const parsed = parseCPE23(built);
  assert.equal(parsed.isValid, true);
  assert.equal(parsed.product, 'gateway\\:edge');
  assert.equal(matchCPE(built, 'cpe:2.3:a:acme:gateway\\:edge:1.0:*:*:*:*:*:*:*').matched, true);
});

test('buildStrictCpe23 escapes plus signs so generated CPEs align with NVD dictionary names', () => {
  const built = buildStrictCpe23('a', 'notepad_plus_plus', 'notepad++', '*', '*');
  const parsed = parseCPE23(built);
  assert.equal(parsed.isValid, true);
  assert.equal(parsed.vendor, 'notepad_plus_plus');
  assert.equal(parsed.product, 'notepad\\+\\+');
  // The escaped product must match the NVD dictionary entry format.
  assert.equal(matchCPE(built, 'cpe:2.3:a:notepad_plus_plus:notepad\\+\\+:*:*:*:*:*:*:*:*').matched, true);
});

test('a CPE range cannot override an explicit vulnerable version token', () => {
  assert.equal(matchCPE(cpe('2.0'), cpe('1.0'), { versionEndExcluding: '3.0' }).matched, false);
});
test('unsupported vendor version ordering creates a review candidate rather than a false exclusion', () => {
  const { cve, asset, settings } = fixture();
  asset.cpes = [cpe('2026release')];
  cve.versionRange = { versionEndExcluding: '2.0' };
  const findings = runVulnerabilityPipeline([], [cve], [asset], [], [], settings).newFindings;
  assert.equal(findings.length, 1);
  assert.equal(findings[0].notificationStatus, 'REVIEW_REQUIRED');
});
test('NVD per-CPE version bounds are applied independently during correlation', () => {
  const { cve, asset, settings } = fixture();
  cve.versionRange = undefined;
  cve.cpeMatches = [cpe('*')];
  cve.cpeMatchDetails = [{ criteria: cpe('*'), range: { versionEndExcluding: '2.0' } }];
  asset.cpes = [cpe('1.9')];
  assert.equal(runVulnerabilityPipeline([], [cve], [asset], [], [], settings).newFindings.length, 1);
  asset.cpes = [cpe('2.0')];
  assert.equal(runVulnerabilityPipeline([], [cve], [asset], [], [], settings).newFindings.length, 0);
});
test('in-run duplicates use the latest modified CVE rather than input order', () => {
  const { cve, asset, settings } = fixture();
  cve.modifiedDate = '2020-01-01T00:00:00Z';
  const newer = { ...cve, modifiedDate: '2026-01-01T00:00:00Z', cpeMatches: [cpe('2.0')] };
  for (const corpus of [
    [cve, newer],
    [newer, cve],
  ])
    assert.equal(runVulnerabilityPipeline([], corpus, [asset], [], [], settings).newFindings.length, 0);
});
test('equal-time conflicting CVE applicability keeps both candidate sets in review', () => {
  const { cve } = fixture();
  const firstCriteria = cpe('*', 'widget');
  const secondCriteria = cpe('*', 'other');
  const first = {
    ...cve,
    modifiedDate: '2026-01-01T00:00:00Z',
    cpeMatches: [firstCriteria],
    cpeMatchDetails: [{ criteria: firstCriteria, range: { versionEndExcluding: '2.0' } }],
    sourceFeeds: ['source-a'],
  };
  const second = {
    ...cve,
    modifiedDate: first.modifiedDate,
    cpeMatches: [secondCriteria],
    cpeMatchDetails: [{ criteria: secondCriteria, range: { versionStartIncluding: '3.0' } }],
    sourceFeeds: ['source-b'],
  };
  const merged = mergeCveRecords([first, second]).get('CVE-2026-12345')!;
  assert.deepEqual(new Set(merged.cpeMatches), new Set([firstCriteria, secondCriteria]));
  assert.equal(merged.cpeMatchDetails?.length, 2);
  assert.equal(merged.versionRange, undefined);
  assert.equal(merged.applicabilityRequiresReview, true);
});

/**
 * Timeline scope tests: prove the pipeline filters CVEs by the LATEST of
 * publishedDate and modifiedDate, and that 1 / 2 / 3 / 4-week windows
 * behave correctly.  Dates are relative to a fixed NOW so the assertions are
 * deterministic regardless of when the test suite runs.
 */
test('isWithinTimelineScope uses the latest of published and modified dates', () => {
  const NOW = new Date('2026-10-26T12:00:00Z');
  const ONE_WEEK = 168;

  // Published 2 days ago, modified 10 days ago → published is latest → in scope
  assert.equal(isWithinTimelineScope('2026-10-24T12:00:00Z', '2026-10-16T12:00:00Z', ONE_WEEK, NOW), true);

  // Published 10 days ago, modified 2 days ago → modified is latest → in scope
  assert.equal(isWithinTimelineScope('2026-10-16T12:00:00Z', '2026-10-24T12:00:00Z', ONE_WEEK, NOW), true);

  // Both 10 days ago → outside the 1-week window → out of scope
  assert.equal(isWithinTimelineScope('2026-10-16T12:00:00Z', '2026-10-16T12:00:00Z', ONE_WEEK, NOW), false);

  // Both 2 days ago → in scope
  assert.equal(isWithinTimelineScope('2026-10-24T12:00:00Z', '2026-10-24T12:00:00Z', ONE_WEEK, NOW), true);

  // Neither date is recent enough → out of scope for 4 weeks too
  assert.equal(
    isWithinTimelineScope('2026-09-20T00:00:00Z', '2026-09-20T00:00:00Z', 4 * ONE_WEEK, NOW),
    false,
  );
});

function makeCve(cveId: string, published: string, modified: string): NormalizedCVE {
  return {
    ...structuredClone(INITIAL_NORMALIZED_CVES[0]),
    cveId,
    publishedDate: published,
    modifiedDate: modified,
    cpeMatches: ['cpe:2.3:a:vendor:widget:*:*:*:*:*:*:*:*'],
    versionRange: { versionStartIncluding: '1.0', versionEndExcluding: '3.0' },
  };
}

const NOW_FOR_PIPELINE = new Date('2026-10-26T12:00:00Z');

const WEEK_SCOPED_CVES = [
  // 4 days ago — in scope at every window
  makeCve('CVE-2026-1001', '2026-10-22T12:00:00Z', '2026-10-22T12:00:00Z'),
  // 8 days published, 2 days modified — in scope via modified date at every window
  makeCve('CVE-2026-1002', '2026-10-18T12:00:00Z', '2026-10-24T12:00:00Z'),
  // 10 days ago (both) — in scope at 2/3/4 weeks, NOT 1 week
  makeCve('CVE-2026-1003', '2026-10-16T12:00:00Z', '2026-10-16T12:00:00Z'),
  // 18 days ago (both) — in scope at 3/4 weeks, NOT 1/2 weeks
  makeCve('CVE-2026-1004', '2026-10-08T12:00:00Z', '2026-10-08T12:00:00Z'),
  // 31 days ago (both) — out of scope at all standard windows
  makeCve('CVE-2026-1005', '2026-09-25T12:00:00Z', '2026-09-25T12:00:00Z'),
];

const WEEK_WINDOWS = [
  // NOW = Oct 26T12:00Z
  // 1-week cutoff  = Oct 19T12:00Z  — 1001 (Oct 22), 1002 (Oct 24)        → 2
  // 2-week cutoff  = Oct 12T12:00Z  — + 1003 (Oct 16)                      → 3
  // 3-week cutoff  = Oct  5T12:00Z  — + 1004 (Oct  8)                      → 4
  // 4-week cutoff  = Sep 28T12:00Z  — 1005 (Sep 25) still outside          → 4
  { label: '1 week', hours: 168, expected: 2 },
  { label: '2 weeks', hours: 336, expected: 3 },
  { label: '3 weeks', hours: 504, expected: 4 },
  { label: '4 weeks', hours: 672, expected: 4 },
];

test('pipeline scopeHours supports 1 / 2 / 3 / 4 week windows', () => {
  const { asset, settings } = (() => {
    const asset: WatchListItem = {
      ...structuredClone(INITIAL_WATCHLIST[0]),
      vendor: 'vendor',
      product: 'widget',
      version: '2.0', // within [1.0, 3.0)
      cpes: ['cpe:2.3:a:vendor:widget:2.0:*:*:*:*:*:*:*'],
      active: true,
    };
    const settings = { ...structuredClone(INITIAL_SETTINGS), scopeHours: 0, autoDispatchEnabled: false };
    return { asset, settings };
  })();

  const now = NOW_FOR_PIPELINE;

  for (const { label, hours, expected } of WEEK_WINDOWS) {
    const inScope = WEEK_SCOPED_CVES.filter((cve) =>
      isWithinTimelineScope(cve.publishedDate, cve.modifiedDate, hours, now),
    );
    assert.equal(
      inScope.length,
      expected,
      `${label}: expected ${expected} CVEs after timeline filter, got ${inScope.length}`,
    );

    const result = runVulnerabilityPipeline(
      INITIAL_FEEDS,
      WEEK_SCOPED_CVES,
      [asset],
      [],
      [],
      { ...settings, scopeHours: hours },
      'test',
      false,
      {},
      {},
      undefined,
      [],
      NOW_FOR_PIPELINE,
    );

    assert.equal(
      result.execution.stats.matchedWatchlist,
      expected,
      `${label}: expected ${expected} findings, got ${result.execution.stats.matchedWatchlist}`,
    );
  }
});

test('out-of-window CVEs refresh tracked findings without creating new matches', () => {
  const evaluatedAt = new Date();
  const oldDate = new Date(evaluatedAt.getTime() - 48 * 3600000).toISOString();
  const cve = makeCve('CVE-2026-1006', oldDate, oldDate);
  const trackedAsset: WatchListItem = {
    ...structuredClone(INITIAL_WATCHLIST[0]),
    id: 'tracked-asset',
    vendor: 'vendor',
    product: 'widget',
    version: '2.0',
    cpes: ['cpe:2.3:a:vendor:widget:2.0:*:*:*:*:*:*:*'],
    active: true,
  };
  const unrestricted = runVulnerabilityPipeline(
    INITIAL_FEEDS,
    [cve],
    [trackedAsset],
    [],
    [],
    { ...INITIAL_SETTINGS, scopeHours: 0 },
    'test',
    false,
    {},
    {},
    undefined,
    [],
    evaluatedAt,
  );
  const trackedFinding = unrestricted.newFindings[0];
  assert.ok(trackedFinding);
  const newlyMatchingAsset = { ...trackedAsset, id: 'new-asset' };
  const scoped = runVulnerabilityPipeline(
    INITIAL_FEEDS,
    [cve],
    [trackedAsset, newlyMatchingAsset],
    [],
    [trackedFinding],
    { ...INITIAL_SETTINGS, scopeHours: 1 },
    'test',
    true,
    {},
    {},
    undefined,
    [],
    evaluatedAt,
  );
  assert.deepEqual(scoped.newFindings.map((finding) => finding.matchedAssetId), ['tracked-asset']);
  assert.notEqual(reconcileFindings([trackedFinding], scoped.newFindings)[0].notificationStatus, 'NOT_APPLICABLE');
});
