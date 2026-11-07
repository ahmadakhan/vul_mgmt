import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  buildAliasMap,
  matchCPE,
  matchesWatchlistItem,
  matchVendorWithAliases,
  matchProductWithAliases,
  aliasGroupKeys,
  DEFAULT_VENDOR_ALIASES,
  DEFAULT_PRODUCT_ALIASES,
} from '../src/utils/cpeMatcher.ts';
import { ENTERPRISE_VENDOR_CATALOG } from '../src/data/vendorCatalog.ts';

import { runVulnerabilityPipeline } from '../src/engine/pipelineEngine.ts';
import { DEFAULT_SETTINGS } from '../shared/state.ts';
import { INITIAL_NORMALIZED_CVES } from './fixtures/seedData';
import type { WatchListItem } from '../src/types/index.ts';

const cpe = (vendor: string, product: string, version = '*') =>
  `cpe:2.3:a:${vendor}:${product}:${version}:*:*:*:*:*:*:*`;

const aliases = {
  vendorAliases: { example: ['example_corp'] },
  productAliases: { widget: ['widget_pro'] },
};

test('structured CPE alias matching is symmetric in both operand orders', () => {
  const left = cpe('example', 'widget', '1.5');
  const right = cpe('example_corp', 'widget_pro', '1.5');

  const forward = matchCPE(left, right, undefined, aliases);
  const reverse = matchCPE(right, left, undefined, aliases);

  assert.equal(forward.matched, true);
  assert.equal(forward.viaAlias, true);
  assert.equal(reverse.matched, true);
  assert.equal(reverse.viaAlias, true);
});

test('strict CPE matching stays closed when alias maps are omitted', () => {
  const left = cpe('example', 'widget', '1.5');
  const right = cpe('example_corp', 'widget_pro', '1.5');

  assert.equal(matchCPE(left, right).matched, false);
  assert.equal(matchCPE(right, left).matched, false);
});

test('exact structured identifiers are authoritative and not flagged as alias matches', () => {
  const result = matchCPE(
    cpe('example', 'widget', '1.5'),
    cpe('example', 'widget', '1.5'),
    undefined,
    aliases,
  );
  assert.equal(result.matched, true);
  assert.equal(result.viaAlias, false);
});

test('an alias cannot bridge a genuinely different product', () => {
  assert.equal(
    matchCPE(
      cpe('example', 'widget', '1.5'),
      cpe('example_corp', 'gateway', '1.5'),
      undefined,
      aliases,
    ).matched,
    false,
  );
});

test('alias-resolved matches stay below auto-dispatch confidence and require review', () => {
  const result = matchesWatchlistItem(
    [cpe('example', 'widget', '1.5')],
    'example',
    'widget',
    [cpe('example_corp', 'widget_pro', '*')],
    'unrelated advisory title',
    'unrelated advisory body',
    undefined,
    undefined,
    undefined,
    undefined,
    undefined,
    true,
    aliases.vendorAliases,
    aliases.productAliases,
  );
  assert.equal(result.matched, true);
  assert.equal(result.method, 'VENDOR_PRODUCT_ALIAS');
  assert.equal(result.confidence, 85);
  assert.ok(result.confidence < 90, 'alias evidence must stay below auto-dispatch threshold');
});

test('operator alias keys cannot pollute object prototypes', () => {
  const custom = JSON.parse('{"__proto__":["polluted"]}') as Record<string, string[]>;
  assert.equal(matchVendorWithAliases('__proto__', 'polluted', custom), true);
  assert.equal(({} as Record<string, unknown>).polluted, undefined);

  const map = buildAliasMap(
    [{ scope: 'VENDOR', canonical: '__proto__', aliases: ['polluted'] }],
    'VENDOR',
  );
  assert.equal(Object.getPrototypeOf(map), null);
  assert.equal(Object.prototype.hasOwnProperty.call(map, '__proto__'), true);
  assert.deepEqual(map['__proto__'], ['polluted']);
  assert.equal(({} as Record<string, unknown>).polluted, undefined);
});

test('punctuation-only product variants reach the pipeline candidate prefilter', () => {
  // The matcher treats `widget_pro` and `widget-pro` as the same identity by
  // normalizing punctuation. The candidate index must index that normalized key
  // too, or the pair is dropped before the matcher can run.
  const record = {
    ...structuredClone(INITIAL_NORMALIZED_CVES[0]),
    cveId: 'CVE-2026-70003',
    cpeMatches: [cpe('example', 'widget-pro', '1.5')],
    cpeMatchDetails: [{ criteria: cpe('example', 'widget-pro', '1.5') }],
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
  const asset: WatchListItem = {
    id: 'asset-punctuation',
    vendor: 'example',
    product: 'widget_pro',
    version: '1.5',
    cpes: [cpe('example', 'widget_pro', '1.5')],
    assetTag: 'WIDGET-01',
    ownerGroup: 'test',
    active: true,
    createdAt: '2026-10-25T00:00:00.000Z',
  };

  const finding = runVulnerabilityPipeline([], [record], [asset], [], [], {
    ...DEFAULT_SETTINGS,
    scopeHours: 0,
  }).newFindings[0];

  assert.ok(finding, 'a punctuation-only product variant must reach the matcher');
  assert.equal(finding.matchingMethod, 'VENDOR_PRODUCT_ALIAS');
  assert.equal(finding.notificationStatus, 'REVIEW_REQUIRED');
});

test('built-in vendor aliases reach the pipeline candidate prefilter', () => {
  const vendorCpe = cpe('msft', 'windows_server_2022', '1.0');
  const record = {
    ...structuredClone(INITIAL_NORMALIZED_CVES[0]),
    cveId: 'CVE-2026-70002',
    cpeMatches: [vendorCpe],
    cpeMatchDetails: [{ criteria: vendorCpe }],
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
  const asset: WatchListItem = {
    id: 'asset-ms',
    vendor: 'microsoft',
    product: 'windows_server_2022',
    version: '1.0',
    cpes: [cpe('microsoft', 'windows_server_2022', '1.0')],
    assetTag: 'MS-01',
    ownerGroup: 'test',
    active: true,
    createdAt: '2026-10-25T00:00:00.000Z',
  };

  const finding = runVulnerabilityPipeline([], [record], [asset], [], [], {
    ...DEFAULT_SETTINGS,
    scopeHours: 0,
  }).newFindings[0];

  assert.ok(finding, 'a built-in alias pair must reach the matcher');
  assert.equal(finding.matchingMethod, 'VENDOR_PRODUCT_ALIAS');
  assert.equal(finding.notificationStatus, 'REVIEW_REQUIRED');
});

const DEFAULTS = { vendorAliases: DEFAULT_VENDOR_ALIASES, productAliases: DEFAULT_PRODUCT_ALIASES };
const osCpe = (vendor: string, product: string, version = '*') =>
  `cpe:2.3:o:${vendor}:${product}:${version}:*:*:*:*:*:*:*`;

test('fortios asset CPE matches the fortios product, not fortimanager', () => {
  const asset = osCpe('fortinet', 'fortios');
  const fortiOs = osCpe('fortinet', 'fortios');
  const fortiManager = 'cpe:2.3:a:fortinet:fortimanager:*:*:*:*:*:*:*:*';

  assert.equal(matchCPE(asset, fortiOs, undefined, DEFAULTS).matched, true);
  assert.equal(matchCPE(asset, fortiManager, undefined, DEFAULTS).matched, false);
  assert.equal(matchCPE(asset, osCpe('fortinet', 'fortimanager'), undefined, DEFAULTS).matched, false);
  assert.equal(matchProductWithAliases('fortios', 'fortimanager'), false);
});

test('product names do not leak into any vendor alias namespace', () => {
  assert.equal(matchVendorWithAliases('fortios', 'fortinet'), false);
  assert.equal(matchVendorWithAliases('fortinet', 'fortios'), false);
  assert.equal(matchVendorWithAliases('fortiguard', 'fortinet'), false);
  assert.equal(matchVendorWithAliases('fortinet', 'fortinet_technologies'), true);
  assert.equal(matchVendorWithAliases('windows', 'microsoft'), false);
  assert.equal(matchVendorWithAliases('microsoft', 'windows'), false);
  assert.equal(matchVendorWithAliases('microsoft', 'msft'), true);
  assert.equal(matchVendorWithAliases('esxi', 'vmware'), false);
  assert.equal(matchVendorWithAliases('vmware', 'esxi'), false);
  assert.equal(matchVendorWithAliases('httpd', 'apache'), false);
  assert.equal(matchVendorWithAliases('apache', 'apache_software_foundation'), true);
});

test('fortimanager watchlist item is never produced from a fortios asset CPE', () => {
  const result = matchesWatchlistItem(
    [osCpe('fortinet', 'fortios')],
    'fortinet',
    'fortios',
    ['cpe:2.3:a:fortinet:fortimanager:*:*:*:*:*:*:*:*'],
    'FortiManager advisory title',
    'A vulnerability in FortiManager',
    undefined,
    undefined,
    undefined,
    undefined,
    undefined,
    true,
    DEFAULT_VENDOR_ALIASES,
    DEFAULT_PRODUCT_ALIASES,
  );
  assert.equal(result.matched, false);
  assert.equal(result.method, 'NONE');
});

test('no catalog product name leaks into the vendor alias namespace', () => {
  const catalogProductIds = new Set(
    ENTERPRISE_VENDOR_CATALOG.flatMap((v) => v.products).map((p) => p.normalizedId.toLowerCase()),
  );
  const vendorAliasTokens = Object.values(DEFAULT_VENDOR_ALIASES)
    .flat()
    .map((a) => a.toLowerCase());
  const vendorAliasTokensThatAreAlsoCatalogProducts = vendorAliasTokens.filter((token) =>
    catalogProductIds.has(token),
  );
  const vendorAliasTokensLegitimatelySharedWithCatalogProducts = new Set(['linux_kernel']);
  const leakedProductNames = vendorAliasTokensThatAreAlsoCatalogProducts.filter(
    (token) => !vendorAliasTokensLegitimatelySharedWithCatalogProducts.has(token),
  );
  assert.equal(
    leakedProductNames.length,
    0,
    `product names must not appear as vendor aliases: ${leakedProductNames.join(', ')}`,
  );
});

test('solarwinds is a built-in vendor alias for the current n-able vendor', () => {
  assert.equal(matchVendorWithAliases('n-able', 'solarwinds'), true);
  assert.equal(matchVendorWithAliases('solarwinds', 'n-able'), true);
  // The two vendor spellings resolve to the same alias group keys.
  assert.deepEqual(
    aliasGroupKeys('solarwinds', DEFAULT_VENDOR_ALIASES),
    aliasGroupKeys('n-able', DEFAULT_VENDOR_ALIASES),
  );
});

test('a CVE with the legacy solarwinds:n-central CPE matches an n-able:n-central asset', () => {
  const record = {
    ...structuredClone(INITIAL_NORMALIZED_CVES[0]),
    cveId: 'CVE-2026-70004',
    cpeMatches: [cpe('solarwinds', 'n-central', '2020.1')],
    cpeMatchDetails: [{ criteria: cpe('solarwinds', 'n-central', '2020.1') }],
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
  const asset: WatchListItem = {
    id: 'asset-ncentral',
    vendor: 'n-able',
    product: 'n-central',
    version: '*',
    cpes: ['cpe:2.3:a:n-able:n-central:*:*:*:*:*:*:*:*'],
    assetTag: 'NC-01',
    ownerGroup: 'test',
    active: true,
    createdAt: '2026-10-25T00:00:00.000Z',
  };

  const finding = runVulnerabilityPipeline([], [record], [asset], [], [], {
    ...DEFAULT_SETTINGS,
    scopeHours: 0,
  }).newFindings[0];

  assert.ok(finding, 'a legacy solarwinds CPE must correlate with the current n-able vendor asset');
  assert.equal(finding.matchingMethod, 'VENDOR_PRODUCT_ALIAS');
  assert.equal(finding.notificationStatus, 'REVIEW_REQUIRED');
});
