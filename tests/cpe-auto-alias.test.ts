import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  autoAliasId,
  deriveCorrelationAliases,
  deriveInventoryAliases,
  reconcileAutoAliases,
} from '../src/utils/aliasLifecycle.ts';
import { matchesWatchlistItem } from '../src/utils/cpeMatcher.ts';
import { runVulnerabilityPipeline } from '../src/engine/pipelineEngine.ts';
import { DEFAULT_SETTINGS } from '../shared/state.ts';
import { INITIAL_FINDINGS, INITIAL_NORMALIZED_CVES } from './fixtures/seedData.ts';
import type { AliasEntry, NormalizedCVE, WatchListItem } from '../src/types/index.ts';

const cpe = (vendor: string, product: string, version = '*', part = 'a') =>
  `cpe:2.3:${part}:${vendor}:${product}:${version}:*:*:*:*:*:*:*`;

const asset = (overrides: Partial<WatchListItem> = {}): WatchListItem => ({
  id: 'asset-auto-alias',
  vendor: 'Acme Corp',
  product: 'Widget Pro',
  version: '1.5',
  cpes: [cpe('acme', 'widget_pro', '1.5')],
  assetTag: 'AUTO-ALIAS-1',
  ownerGroup: 'test',
  active: true,
  createdAt: '2026-10-25T00:00:00.000Z',
  ...overrides,
});

const manualAlias: AliasEntry = {
  id: 'manual-alias',
  scope: 'VENDOR',
  canonical: 'example',
  aliases: ['example_corp'],
  source: 'MANUAL',
  createdAt: '2026-10-20T00:00:00.000Z',
};

test('inventory aliases are added and stale automatic rows are removed without touching manual rows', () => {
  const initial = deriveInventoryAliases(
    [asset({ cpes: [cpe('acme_inc', 'widget_pro_x', '1.5')] })],
    [manualAlias],
    '2026-10-25T00:00:00.000Z',
  );
  const vendor = initial.find((entry) => entry.scope === 'VENDOR');
  const product = initial.find((entry) => entry.scope === 'PRODUCT');
  assert.equal(vendor?.id, autoAliasId('VENDOR', 'acme corp'));
  assert.equal(vendor?.canonical, 'acme corp');
  assert.deepEqual(vendor?.aliases, ['acme_inc']);
  assert.equal(vendor?.source, 'AUTO');
  assert.equal(product?.canonical, 'widget pro');
  assert.deepEqual(product?.aliases, ['widget_pro_x']);

  const first = reconcileAutoAliases([manualAlias], initial, '2026-10-25T00:00:00.000Z');
  assert.deepEqual(
    first.added.map((entry) => entry.id).sort(),
    initial.map((entry) => entry.id).sort(),
  );
  assert.deepEqual(first.removals, []);
  assert.deepEqual(
    first.upserts.map((entry) => entry.id).sort(),
    initial.map((entry) => entry.id).sort(),
  );
  assert.ok(first.aliases.some((entry) => entry.id === manualAlias.id));

  // Renaming the inventory vendor makes the old learned spelling stale while
  // the unchanged product relation survives.
  const renamed = asset({
    vendor: 'NewCo',
    cpes: [cpe('newco_inc', 'widget_pro_x', '1.5')],
  });
  const desired = deriveInventoryAliases([renamed], first.aliases);
  const second = reconcileAutoAliases(first.aliases, desired, undefined, { ttlDays: 0 });
  assert.deepEqual(second.removals, [autoAliasId('VENDOR', 'acme corp')]);
  assert.deepEqual(second.added.map((entry) => entry.id), [autoAliasId('VENDOR', 'newco')]);
  assert.ok(second.entries.some((entry) => entry.canonical === 'widget pro'));
  assert.ok(second.aliases.some((entry) => entry.id === manualAlias.id));

  // Empty inventory removes every automatic row and leaves the operator row.
  const empty = reconcileAutoAliases(second.aliases, [], undefined, { ttlDays: 0 });
  assert.deepEqual(empty.entries, []);
  assert.deepEqual(empty.removals.sort(), second.entries.map((entry) => entry.id).sort());
  assert.deepEqual(empty.aliases, [manualAlias]);
});

test('correlation aliases are learned only from current, non-rejected matches', () => {
  const watch = asset();
  const cve: NormalizedCVE = {
    ...structuredClone(INITIAL_NORMALIZED_CVES[0]),
    cveId: 'CVE-2026-81001',
    cpeMatches: [cpe('acme_holdings', 'widget_pro', '*')],
    cpeMatchDetails: [{ criteria: cpe('acme_holdings', 'widget_pro', '*') }],
    versionRange: undefined,
    purls: undefined,
  };
  const finding = {
    ...structuredClone(INITIAL_FINDINGS[0]),
    id: 'finding-auto-alias',
    cveId: cve.cveId,
    cve,
    matchedAssetId: watch.id,
    matchingMethod: 'VENDOR_PRODUCT_FALLBACK' as const,
    notificationStatus: 'AUTO_DISPATCHED' as const,
    status: 'MONITORED' as const,
    advisoryId: null,
    autoDispatchedAt: '2026-10-25T00:00:00.000Z',
    reviewNotifiedAt: null,
  };
  const byId = new Map([[cve.cveId, cve]]);
  const learned = deriveCorrelationAliases([finding], [watch], byId);
  const vendor = learned.find((entry) => entry.scope === 'VENDOR');
  assert.equal(vendor?.canonical, 'acme corp');
  assert.deepEqual(vendor?.aliases, ['acme_holdings']);
  assert.equal(vendor?.provenance, 'CONFIRMED_CORRELATION');

  // An unreviewed fallback is the weakest signal and must not teach aliases.
  const review = {
    ...finding,
    notificationStatus: 'REVIEW_REQUIRED' as const,
    autoDispatchedAt: null,
    reviewNotifiedAt: null,
  };
  assert.deepEqual(deriveCorrelationAliases([review], [watch], byId), []);

  // A finding that no longer applies (or that an operator rejected) cannot
  // keep an automatic alias alive on the next reconciliation.
  const stale = { ...finding, notificationStatus: 'NOT_APPLICABLE' as const };
  assert.deepEqual(deriveCorrelationAliases([stale], [watch], byId), []);
  const rejected = { ...finding, status: 'FALSE_POSITIVE' as const };
  assert.deepEqual(deriveCorrelationAliases([rejected], [watch], byId), []);
});

test('pipeline applies inventory auto aliases before candidate selection', () => {
  const record: NormalizedCVE = {
    ...structuredClone(INITIAL_NORMALIZED_CVES[0]),
    cveId: 'CVE-2026-81002',
    cpeMatches: [cpe('acme corp', 'widget_pro', '1.5')],
    cpeMatchDetails: [{ criteria: cpe('acme corp', 'widget_pro', '1.5') }],
    versionRange: undefined,
    purls: undefined,
    vex: undefined,
    vexStatements: [],
    sourceFeeds: [],
    exploitationSources: [],
    cisaKev: { isKev: false },
    exploitStatus: 'None' as const,
    applicabilityRequiresReview: false,
  };
  const finding = runVulnerabilityPipeline([], [record], [asset()], [], [], {
    ...DEFAULT_SETTINGS,
    scopeHours: 0,
  }).newFindings[0];

  assert.ok(finding, 'the alias-expanded candidate prefilter must reach the matcher');
  assert.equal(finding.matchingMethod, 'VENDOR_PRODUCT_ALIAS');
  assert.equal(finding.notificationStatus, 'REVIEW_REQUIRED');
});

test('a generic inventory CPE resolves to the inventory vendor/product', () => {
  const generic = cpe('*', '*', '1.5');
  const matched = matchesWatchlistItem(
    [generic],
    'acme',
    'widget',
    [cpe('acme', 'widget', '1.5')],
    '',
    '',
  );
  assert.equal(matched.matched, true);
  assert.equal(matched.method, 'STRICT_CPE');
  assert.equal(matched.confidence, 70);
  assert.equal(matched.applicabilityRequiresReview, true);

  // A generic CPE must not remain an unrestricted wildcard that matches an
  // unrelated advisory product. Before resolution both components were `*`.
  assert.equal(
    matchesWatchlistItem([generic], 'acme', 'widget', [cpe('other', 'thing', '1.5')], '', '')
      .matched,
    false,
  );
});
test('a CPE vendor/product mismatch falls through to the text fallback', () => {
  const result = matchesWatchlistItem(
    [cpe('asset_vendor', 'asset_widget', '1.5')],
    'asset_vendor',
    'asset_widget',
    [cpe('nvd_vendor', 'nvd_widget', '*')],
    'asset_vendor asset_widget security advisory',
    '',
  );
  assert.equal(result.matched, true);
  assert.equal(result.method, 'VENDOR_PRODUCT_FALLBACK');
  assert.equal(result.confidence, 70);

  // A PURL-vs-PURL mismatch remains authoritative even when the prose matches.
  assert.equal(
    matchesWatchlistItem(
      [cpe('asset_vendor', 'asset_widget', '1.5')],
      'asset_vendor',
      'asset_widget',
      [cpe('nvd_vendor', 'nvd_widget', '*')],
      'asset_vendor asset_widget security advisory',
      '',
      undefined,
      ['pkg:npm/widget@1.5'],
      ['pkg:npm/other@1.5'],
    ).matched,
    false,
  );
});
test('fallback cannot override a structured CPE version exclusion', () => {
  // Identical product identity with a different explicit version token: the
  // CPE side has already proved the release is not the vulnerable one.
  assert.equal(
    matchesWatchlistItem(
      [cpe('example', 'widget', '3.0')],
      'example',
      'widget',
      [cpe('example', 'widget', '1.0')],
      'example widget security advisory',
      '',
    ).matched,
    false,
  );
  // A range exclusion still wins over the text fallback when the vendor and
  // product names differ and the inventory version is comparable.
  assert.equal(
    matchesWatchlistItem(
      [cpe('asset_vendor', 'asset_widget', '3.0')],
      'asset_vendor',
      'asset_widget',
      [cpe('nvd_vendor', 'nvd_widget', '*')],
      'asset_vendor asset_widget security advisory',
      '',
       { versionEndExcluding: '2.0' },
     ).matched,
     false,
   );
});
test('a vuln-side partial wildcard version is review-gated even when it intersects the asset', () => {
  // The vulnerability CPE asserts a `1.*` family while the inventory proves a
  // concrete `1.5`; matchComponent accepts the intersection, but a partial
  // wildcard on the vuln side is an unverified release assertion and must not
  // auto-dispatch above the review threshold.
  const matched = matchesWatchlistItem(
    [cpe('acme', 'widget', '1.5')],
    'acme',
    'widget',
    [cpe('acme', 'widget', '1.*')],
    '',
    '',
  );
  assert.equal(matched.matched, true);
  assert.equal(matched.method, 'STRICT_CPE');
  assert.equal(matched.confidence, 70);
  assert.equal(matched.applicabilityRequiresReview, true);
});
