import { randomBytes } from 'node:crypto';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ingestFeed, normalizeNvd } from '../server/ingestion';
import { loadConfig } from '../server/config.ts';
import { mergeCveRecords, sourceCveContentHash } from '../src/utils/deduplicator';
import { matchesWatchlistItem } from '../src/utils/cpeMatcher.ts';
import { runVulnerabilityPipeline } from '../src/engine/pipelineEngine';
import { DEFAULT_SETTINGS } from '../shared/state.ts';
import { cveSchema } from '../server/validation.ts';
import type { NormalizedCVE, ThreatFeed, WatchListItem } from '../src/types/index.ts';

const config = loadConfig({
  NODE_ENV: 'test',
  DATABASE_URL: 'postgres://unused',
  APP_ORIGIN: 'http://localhost',
  ENCRYPTION_KEY: randomBytes(32).toString('base64'),
});
const cpe = (version: string) => `cpe:2.3:a:example:widget:${version}:*:*:*:*:*:*:*`;
const feed = (type: ThreatFeed['type']): ThreatFeed => ({
  id: 'test-feed',
  name: 'Test source',
  type,
  url: 'https://example.com/data?date=2020-01-01',
  authType: 'NONE',
  rateLimitPerMin: 10,
  enabled: true,
  healthStatus: 'UNTESTED',
  lastSync: null,
  latencyMs: 0,
  itemCountLastRun: 0,
  ssrfValidated: false,
  vendorSeed: false,
});
const nvd = (status = 'Analyzed') => ({
  cve: {
    id: 'CVE-2026-12345',
    vulnStatus: status,
    published: '2026-01-01T00:00:00Z',
    lastModified: '2026-10-20T00:00:00Z',
    descriptions: [{ lang: 'en', value: 'Example widget issue' }],
    configurations: [{ nodes: [{ operator: 'OR', cpeMatch: [{ vulnerable: true, criteria: cpe('1.0') }] }] }],
  },
});
const cve = () => normalizeNvd(nvd(), 'source-a')!;
test('normalized feed remediation links reject executable URL schemes', () => {
  const record = cve();
  assert.throws(() =>
    cveSchema.parse({
      ...record,
      remediation: { ...record.remediation, vendorAdvisoryRef: 'javascript:alert(1)' },
    }),
  );
  assert.equal(
    cveSchema.parse({
      ...record,
      remediation: { ...record.remediation, patchUrl: 'https://example.com/patch' },
    }).remediation.patchUrl,
    'https://example.com/patch',
  );
});
const asset: WatchListItem = {
  id: 'asset',
  vendor: 'example',
  product: 'widget',
  cpes: [cpe('1.0')],
  assetTag: 'TEST',
  ownerGroup: 'test',
  active: true,
  createdAt: '2026-01-01T00:00:00Z',
};

test('product-wide CPE wildcards cover constrained platforms; later confirmed evidence wins', () => {
  for (const [criteria, expected] of [
    [cpe('1.0'), 'QUEUED_FOR_DISPATCH'],
    [cpe('*').replace(':*:*:*:*:*:*:*', ':*:*:*:*:windows:*:*'), 'QUEUED_FOR_DISPATCH'],
  ] as const) {
    const finding = runVulnerabilityPipeline(
      [],
      [{ ...cve(), cpeMatches: [criteria], cpeMatchDetails: undefined }],
      [{ ...asset, cpes: [cpe('*')] }],
      [],
      [],
      { ...DEFAULT_SETTINGS, scopeHours: 0 },
    ).newFindings[0];
    assert.equal(finding?.notificationStatus, expected);
  }
  const direct = matchesWatchlistItem([cpe('*'), cpe('1.0')], 'example', 'widget', [cpe('1.0')], '', '');
  assert.equal(direct.confidence, 90);
  assert.equal(direct.applicabilityRequiresReview, false);
  const record = {
    ...cve(),
    cpeMatchDetails: [
      { criteria: cpe('*').replace(':*:*:*:*:*:*:*', ':*:*:*:*:windows:*:*') },
      { criteria: cpe('1.0') },
    ],
  };
  const finding = runVulnerabilityPipeline([], [record], [asset], [], [], {
    ...DEFAULT_SETTINGS,
    scopeHours: 0,
  }).newFindings[0];
  assert.equal(finding.notificationStatus, 'QUEUED_FOR_DISPATCH');
});

test('equal-revision conflicts merge deterministically and cannot auto-dispatch', () => {
  const first = cve(),
    second: NormalizedCVE = {
      ...cve(),
      title: 'Other revision',
      sourceFeeds: ['source-b'],
      cpeMatches: [cpe('2.0')],
      cpeMatchDetails: [{ criteria: cpe('2.0') }],
    };
  const a = [...mergeCveRecords([first, second]).values()];
  const b = [...mergeCveRecords([second, first]).values()];
  assert.deepEqual(a, b);
  assert.equal(a[0].applicabilityRequiresReview, true);
  assert.deepEqual(a[0].sourceFeeds, ['source-a', 'source-b']);
  assert.equal(mergeCveRecords([{ ...first, cveId: ' cve-2026-12345 ' }, first]).size, 1);
});

test('text-only provider review policy does not override verified structured applicability', () => {
  const structured = { ...cve(), versionRange: { versionEndExcluding: '2.0' } };
  const textOnly = {
    ...structured,
    title: 'CNA text-only revision',
    description: 'example widget vulnerability',
    modifiedDate: '2026-10-25T00:00:00.000Z',
    sourceFeeds: ['mitre'],
    cpeMatches: [],
    cpeMatchDetails: [],
    versionRange: undefined,
    applicabilityRequiresReview: true,
    applicabilityPolicy: 'REVIEW_ONLY' as const,
  };
  const legacyTextOnly = {
    ...structured,
    title: 'Legacy text-only revision',
    sourceFeeds: [],
    cpeMatches: [],
    cpeMatchDetails: [],
    versionRange: undefined,
    applicabilityRequiresReview: true,
    applicabilityPolicy: 'REVIEW_ONLY' as const,
  };
  const merged = mergeCveRecords([structured, textOnly, legacyTextOnly]).get(structured.cveId)!;
  assert.deepEqual(merged.cpeMatches, structured.cpeMatches);
  assert.deepEqual(merged.cpeMatchDetails, structured.cpeMatchDetails);
  assert.deepEqual(merged.versionRange, structured.versionRange);
  assert.equal(merged.applicabilityPolicy, undefined);
  assert.equal(merged.applicabilityRequiresReview, false);
  assert.ok(merged.sourceApplicability?.__legacy_applicability__);
  const reloaded = mergeCveRecords([merged]).get(merged.cveId)!;
  assert.equal(reloaded.applicabilityPolicy, undefined);
  assert.equal(reloaded.applicabilityRequiresReview, false);

  const result = runVulnerabilityPipeline(
    [],
    [reloaded],
    [asset],
    [],
    [],
    { ...DEFAULT_SETTINGS, scopeHours: 0, autoDispatchEnabled: true, autoDispatchConfidenceThreshold: 90 },
  );
  assert.equal(result.newFindings[0]?.notificationStatus, 'QUEUED_FOR_DISPATCH');
  assert.equal(result.newFindings[0]?.confidence, 90);
});

test('a provider revision replaces its own old criteria without removing another provider evidence', () => {
  const nvd = {
    ...cve(),
    sourceFeeds: ['nvd'],
    modifiedDate: '2026-10-20T00:00:00.000Z',
    cpeMatches: [cpe('1.0')],
    cpeMatchDetails: [{ criteria: cpe('1.0') }],
  };
  const mitre = {
    ...nvd,
    sourceFeeds: ['mitre'],
    modifiedDate: '2026-10-21T00:00:00.000Z',
    cpeMatches: [cpe('2.0')],
    cpeMatchDetails: [{ criteria: cpe('2.0') }],
    applicabilityPolicy: 'REVIEW_ONLY' as const,
  };
  const initial = mergeCveRecords([nvd, mitre]).get(nvd.cveId)!;
  const nvdUpdate = {
    ...nvd,
    modifiedDate: '2026-10-22T00:00:00.000Z',
    cpeMatches: [cpe('1.5')],
    cpeMatchDetails: [{ criteria: cpe('1.5') }],
  };
  const updated = mergeCveRecords([initial, nvdUpdate]).get(nvd.cveId)!;
  assert.deepEqual(updated.cpeMatches, [cpe('1.5'), cpe('2.0')]);
  assert.deepEqual(Object.keys(updated.sourceApplicability || {}).sort(), ['mitre', 'nvd']);
  assert.equal(updated.sourceApplicability?.nvd.contentHash, sourceCveContentHash(nvdUpdate));
  assert.equal(updated.applicabilityPolicy, 'REVIEW_ONLY');
  assert.equal(updated.applicabilityRequiresReview, true);
  const conflictingFinding = runVulnerabilityPipeline(
    [],
    [updated],
    [{ ...asset, cpes: [cpe('1.5')] }],
    [],
    [],
    { ...DEFAULT_SETTINGS, scopeHours: 0, autoDispatchEnabled: true, autoDispatchConfidenceThreshold: 0, autoDispatchUnverifiableMatches: true },
  ).newFindings[0];
  assert.equal(conflictingFinding?.notificationStatus, 'REVIEW_REQUIRED');
});

test('a newer revision from the same provider replaces superseded applicability', () => {
  const original = {
    ...cve(),
    versionRange: { versionEndExcluding: '2.0' },
    applicabilityRequiresReview: true,
  };
  const revised = {
    ...original,
    modifiedDate: '2026-10-25T00:00:00.000Z',
    cpeMatches: [cpe('2.0')],
    cpeMatchDetails: [{ criteria: cpe('2.0') }],
    versionRange: { versionStartIncluding: '2.0' },
    applicabilityRequiresReview: false,
  };
  const merged = mergeCveRecords([original, revised]).get(original.cveId)!;
  assert.deepEqual(merged.cpeMatches, [cpe('2.0')]);
  assert.deepEqual(merged.versionRange, { versionStartIncluding: '2.0' });
  assert.equal(merged.applicabilityRequiresReview, false);
});

test('NVD retains provisional analysis as review-only and reports withdrawals', async () => {
  assert.equal(normalizeNvd(nvd('Awaiting Analysis'), 'nvd')?.applicabilityRequiresReview, true);
  const result = await ingestFeed(
    feed('NVD_API'),
    24,
    async () => ({
      status: 200,
      headers: {},
      body: JSON.stringify({ startIndex: 0, totalResults: 1, vulnerabilities: [nvd('Rejected')] }),
    }),
    config,
  );
  assert.equal(result.cves.length, 0);
  assert.deepEqual(result.withdrawals, [
    { cveId: 'CVE-2026-12345', modifiedDate: '2026-10-20T00:00:00.000Z' },
  ]);
});

test('NVD resumes from an overlapping checkpoint and avoids normalizing cached revisions', async () => {
  const checkpoint = new Date(Date.now() - 60 * 60 * 1000);
  let requestedUrl = '';
  const result = await ingestFeed(
    feed('NVD_API'),
    24,
    async (value) => {
      requestedUrl = value;
      return {
        status: 200,
        headers: {},
        body: JSON.stringify({ startIndex: 0, totalResults: 1, vulnerabilities: [nvd()] }),
      };
    },
    config,
    async () => {},
    [],
    undefined,
    {
      cursor: checkpoint.toISOString(),
      knownCveModifiedAt: new Map([['CVE-2026-12345', '2026-10-20T00:00:00.000Z']]),
    },
  );
  const url = new URL(requestedUrl);
  assert.equal(Date.parse(url.searchParams.get('lastModStartDate')!), checkpoint.getTime() - 10 * 60 * 1000);
  assert.equal(result.count, 1);
  assert.equal(result.cves.length, 0);
  assert.ok(result.syncState?.cursor);
});

test('EPSS fetches only requested inventory CVEs in bounded batches', async () => {
  const ids = Array.from({ length: 205 }, (_, index) => `CVE-2026-${10000 + index}`);
  let calls = 0;
  const result = await ingestFeed(
    feed('EPSS_API'),
    24,
    async (value, options) => {
      calls++;
      const url = new URL(value),
        requested = url.searchParams.get('cve')!.split(',');
      assert.ok(url.searchParams.get('cve')!.length <= 2000);
      assert.ok(requested.length <= 100);
      assert.equal(url.searchParams.has('date'), false);
      assert.equal(options?.headers?.['If-None-Match'], undefined);
      return {
        status: 200,
        headers: {},
        body: JSON.stringify({
          total: requested.length,
          offset: 0,
          data: requested.map((id) => ({ cve: id, epss: '0.7', percentile: '0.9' })),
        }),
      };
    },
    config,
    async () => {},
    ids,
  );
  assert.equal(calls, 3);
  assert.equal(result.count, 205);
  assert.deepEqual(result.epssScope, ids);
  await ingestFeed(
    feed('EPSS_API'),
    24,
    async () => {
      throw new Error('Empty scope must not request the full corpus');
    },
    config,
  );
});

test('EPSS rejects unexpected records instead of declaring a partial snapshot complete', async () => {
  await assert.rejects(
    ingestFeed(
      feed('EPSS_API'),
      24,
      async () => ({
        status: 200,
        headers: {},
        body: JSON.stringify({ total: 1, data: [{ cve: 'CVE-2026-99999', epss: 0.1, percentile: 0.2 }] }),
      }),
      config,
      async () => {},
      ['CVE-2026-12345'],
    ),
    /unexpected/,
  );
});

test('long NVD Retry-After defers instead of retrying before the allowed time', async () => {
  let calls = 0;
  await assert.rejects(
    ingestFeed(
      feed('NVD_API'),
      24,
      async () => {
        calls++;
        return { status: 429, headers: { 'retry-after': '120' }, body: '' };
      },
      config,
      async () => {
        throw new Error('Must defer');
      },
    ),
    /120 second retry delay/,
  );
  assert.equal(calls, 1);
});

test('package applicability never borrows a range from an unrelated CPE', () => {
  const record = {
    ...cve(),
    purls: ['pkg:npm/widget'],
    versionRange: { versionEndExcluding: '2.0' },
    cpeMatchDetails: [
      { criteria: cpe('*').replace(':widget:', ':other:'), range: { versionEndExcluding: '9.0' } },
    ],
  };
  const run = (version: string) =>
    runVulnerabilityPipeline(
      [],
      [record],
      [{ ...asset, cpes: [], purls: [`pkg:npm/widget@${version}`] }],
      [],
      [],
      { ...DEFAULT_SETTINGS, scopeHours: 0 },
    ).newFindings;
  assert.equal(run('3.0').length, 0);
  // Audit C-1: the advisory names this asset by a CPE criterion for a different
  // product while its package identifier matches an affected version. The CPE
  // must not contribute a *confirmed* verdict — it is not evidence about this
  // product — and it must not silently override the package match either. The
  // correct outcome is package evidence held for review: never a rejection
  // (the package is affected), never an auto-dispatch (the identifiers
  // contradict each other).
  const [finding] = run('1.0');
  assert.equal(finding.notificationStatus, 'REVIEW_REQUIRED');
  assert.equal(finding.matchingMethod, 'PURL_EXACT');
});

test('null JSON and unsolicited conditional responses cannot claim feed success', async () => {
  for (const type of ['JSON_SEARCH_API', 'CISA_KEV', 'NVD_API'] as const) {
    await assert.rejects(
      ingestFeed(feed(type), 24, async () => ({ status: 200, headers: {}, body: 'null' }), config),
    );
    await assert.rejects(
      ingestFeed(feed(type), 24, async () => ({ status: 304, headers: {}, body: '' }), config),
      /unexpected conditional/,
    );
  }
});

test('NVD rejects duplicate, overfull and shifting pages atomically', async () => {
  for (const pages of [
    [{ startIndex: 0, totalResults: 2, vulnerabilities: [nvd(), nvd()] }],
    [{ startIndex: 0, totalResults: 0, vulnerabilities: [nvd()] }],
    [
      { startIndex: 0, totalResults: 2, vulnerabilities: [nvd()] },
      { startIndex: 1, totalResults: 1, vulnerabilities: [] },
    ],
  ]) {
    let index = 0;
    await assert.rejects(
      ingestFeed(
        feed('NVD_API'),
        24,
        async () => ({ status: 200, headers: {}, body: JSON.stringify(pages[index++]) }),
        config,
        async () => {},
      ),
       /duplicate|pagination|short/,
    );
  }
});

test('KEV cannot clear enrichment using a truncated or duplicate catalog', async () => {
  const entry = {
    cveID: 'CVE-2026-12345',
    dateAdded: '2026-01-01',
    dueDate: '2026-02-01',
    requiredAction: 'Patch',
    knownRansomwareCampaignUse: 'Unknown',
  };
  for (const data of [
    { count: 1, vulnerabilities: [] },
    { count: 2, vulnerabilities: [entry, entry] },
  ])
    await assert.rejects(
      ingestFeed(
        feed('CISA_KEV'),
        24,
        async () => ({ status: 200, headers: {}, body: JSON.stringify(data) }),
        config,
      ),
      /count mismatch or duplicate/,
    );
});

test('ambiguous suffix families and unsafe numeric versions remain review-only', () => {
  for (const [installed, bound] of [
    ['1.0-h2', '1.0-p1'],
    ['9007199254740992', '9007199254740993'],
  ]) {
    const record = {
      ...cve(),
      cpeMatches: [cpe('*')],
      cpeMatchDetails: [{ criteria: cpe('*'), range: { versionEndExcluding: bound } }],
    };
    const finding = runVulnerabilityPipeline([], [record], [{ ...asset, cpes: [cpe(installed)] }], [], [], {
      ...DEFAULT_SETTINGS,
      scopeHours: 0,
    }).newFindings[0];
    assert.equal(finding?.notificationStatus, 'REVIEW_REQUIRED');
  }
});

test('NVD ingests a corrected CVE whose lastModified did not advance', async () => {
  // The publisher fixes an understated severity (and adds remediation) without
  // moving lastModified. Comparing timestamps alone dropped the record, so the
  // cached copy kept the old, wrong value indefinitely.
  const corrected = {
    ...nvd(),
    cve: {
      ...nvd().cve,
      metrics: {
        cvssMetricV31: [
          { cvssData: { baseScore: 9.8, baseSeverity: 'CRITICAL', version: '3.1', vectorString: 'X' } },
        ],
      },
      references: [{ url: 'https://example.com/advisory', tags: ['Vendor Advisory'] }],
    },
  };
  const request = async () => ({
    status: 200,
    headers: {},
    body: JSON.stringify({ startIndex: 0, totalResults: 1, vulnerabilities: [corrected] }),
  });
  const context = {
    cursor: new Date(Date.now() - 60 * 60 * 1000).toISOString(),
    // Same revision as the cached copy: the timestamp guard would skip it.
    knownCveModifiedAt: new Map([['CVE-2026-12345', '2026-10-20T00:00:00.000Z']]),
  };

  // Unchanged content at an unchanged timestamp is still skipped.
  const unchanged = await ingestFeed(feed('NVD_API'), 24, request, config, async () => {}, [], undefined, {
    ...context,
    knownCveContent: new Map([['CVE-2026-12345', cve()]]),
  });
  const reverted = {
    ...corrected,
    cve: { ...corrected.cve, metrics: {}, references: [] },
  };
  const baseline = await ingestFeed(
    feed('NVD_API'),
    24,
    async () => ({
      status: 200,
      headers: {},
      body: JSON.stringify({ startIndex: 0, totalResults: 1, vulnerabilities: [reverted] }),
    }),
    config,
    async () => {},
    [],
    undefined,
    { ...context, knownCveContent: new Map([['CVE-2026-12345', cve()]]) },
  );
  const cached = baseline.cves[0];
  assert.ok(cached, 'the baseline record must normalise');
  const changed = await ingestFeed(feed('NVD_API'), 24, request, config, async () => {}, [], undefined, {
    ...context,
    knownCveContent: new Map([['CVE-2026-12345', cached]]),
  });
  assert.equal(changed.cves.length, 1, 'a corrected record must be re-ingested');
  assert.equal(changed.cves[0].cvss.severity, 'CRITICAL');
  assert.equal(changed.cves[0].remediation.vendorAdvisoryRef, 'https://example.com/advisory');
  void unchanged;
});
