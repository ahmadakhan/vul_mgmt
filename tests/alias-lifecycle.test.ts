import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  autoAliasId,
  deriveCorrelationAliases,
  deriveInventoryAliases,
  reconcileAutoAliases,
} from '../src/utils/aliasLifecycle.ts';
import { matchesWatchlistItem } from '../src/utils/cpeMatcher.ts';
import type { AliasEntry, Finding, WatchListItem } from '../src/types/index.ts';

const cpe = (vendor: string, product: string, version = '*') =>
  `cpe:2.3:a:${vendor}:${product}:${version}:*:*:*:*:*:*:*`;

const asset = (overrides: Partial<WatchListItem> = {}): WatchListItem => ({
  id: 'asset-auto',
  vendor: 'Acme Corporation',
  product: 'Widget Pro',
  version: '1.0',
  cpes: [cpe('acme', 'widget_pro', '1.0')],
  purls: [],
  assetTag: 'AUTO-01',
  ownerGroup: 'Security',
  active: true,
  createdAt: '2026-10-26T00:00:00Z',
  ...overrides,
});

test('inventory/CPE spelling variants become automatic aliases', () => {
  const derived = deriveInventoryAliases([asset()]);
  assert.deepEqual(
    derived.map(({ scope, canonical, aliases }) => ({ scope, canonical, aliases })),
    [{ scope: 'VENDOR', canonical: 'acme corporation', aliases: ['acme'] }],
  );
  assert.equal(derived[0].id, autoAliasId('VENDOR', 'acme corporation'));
  assert.equal(derived[0].source, 'AUTO');
});

test('an unrelated CPE identity is never learned as an alias', () => {
  // A misconfigured asset must not teach the matcher that Microsoft and Linux
  // are alternate spellings of the same vendor.
  assert.deepEqual(
    deriveInventoryAliases([
      asset({ vendor: 'Microsoft', product: 'Windows', cpes: [cpe('linux', 'linux_kernel')] }),
    ]),
    [],
  );
});

test('automatic aliases are added and removed without touching operator rows', () => {
  const manual: AliasEntry = {
    id: 'manual-1',
    scope: 'VENDOR',
    canonical: 'acme',
    aliases: ['acme-inc'],
    createdAt: '2026-01-01T00:00:00Z',
    source: 'MANUAL',
  };
  const first = reconcileAutoAliases([manual], deriveInventoryAliases([asset()]));
  assert.equal(first.added.length, 1);
  assert.equal(first.updated.length, 0);
  assert.equal(first.removed.length, 0);
  assert.ok(first.aliases.some((entry) => entry.id === manual.id));
  assert.ok(first.aliases.some((entry) => entry.source === 'AUTO'));

  // The asset disappears/its CPE becomes generic: the derived relation is no
  // longer supported. With no TTL grace the next reconciliation removes only
  // the auto row (the TTL path is covered separately).
  const second = reconcileAutoAliases(
    first.aliases,
    deriveInventoryAliases([asset({ cpes: ['cpe:2.3:a:*:*:*:*:*:*:*:*:*:*'] })]),
    new Date().toISOString(),
    { ttlDays: 0 },
  );
  assert.equal(second.removed.length, 1);
  assert.deepEqual(
    second.aliases.map((entry) => entry.id),
    [manual.id],
  );
});

test('correlation evidence teaches an alias only after confirmation', () => {
  const review = {
    cveId: 'CVE-2026-90001',
    matchedAssetId: 'asset-auto',
    matchingMethod: 'VENDOR_PRODUCT_FALLBACK',
    notificationStatus: 'REVIEW_REQUIRED',
    status: 'MONITORED',
    autoDispatchedAt: null,
    reviewNotifiedAt: null,
    cve: {
      cveId: 'CVE-2026-90001',
      cpeMatches: [cpe('acme_corp', 'widget_pro', '1.0')],
    },
  } as unknown as Finding;

  // The fallback path is the weakest matcher. An unreviewed fallback must not
  // become permanent alias evidence, or one false positive would raise every
  // later correlation from 70% to the 85% structured tier.
  assert.deepEqual(deriveCorrelationAliases([review], [asset()]), []);

  const confirmed = {
    ...review,
    notificationStatus: 'AUTO_DISPATCHED' as const,
    autoDispatchedAt: '2026-10-26T00:00:00Z',
    reviewNotifiedAt: null,
  };
  const learned = deriveCorrelationAliases([confirmed], [asset()], undefined, [], '2026-10-26T00:00:00Z');
  assert.deepEqual(
    learned.map(({ scope, canonical, aliases, provenance, evidenceCount }) => ({
      scope,
      canonical,
      aliases,
      provenance,
      evidenceCount,
    })),
    [
      {
        scope: 'VENDOR',
        canonical: 'acme corporation',
        aliases: ['acme_corp'],
        provenance: 'CONFIRMED_CORRELATION',
        evidenceCount: 1,
      },
    ],
  );

  // Multiple criteria in one finding still count as one piece of evidence.
  const multiCriteria = {
    ...confirmed,
    cve: {
      cveId: 'CVE-2026-90001',
      cpeMatches: [cpe('acme_corp', 'widget_pro', '1.0'), cpe('acme_corp', 'widget_pro', '1.1')],
    },
  } as unknown as Finding;
  assert.equal(deriveCorrelationAliases([multiCriteria], [asset()])[0].evidenceCount, 1);

  // Delivery and operator closure are confirmation; a rejection is permanent.
  const delivered = { ...review, notificationStatus: 'DELIVERED' as const };
  assert.equal(deriveCorrelationAliases([delivered], [asset()]).length, 1);
  const resolved = { ...review, status: 'RESOLVED' as const };
  assert.equal(deriveCorrelationAliases([resolved], [asset()]).length, 1);
  const rejected = { ...confirmed, status: 'FALSE_POSITIVE' as const };
  assert.deepEqual(deriveCorrelationAliases([rejected], [asset()]), []);

  // A strict match means the names already agree, so there is nothing to learn.
  const strict = { ...confirmed, matchingMethod: 'STRICT_CPE' as const };
  assert.deepEqual(deriveCorrelationAliases([strict], [asset()]), []);
});

test('automatic aliases expire after their evidence TTL and can be promoted', () => {
  const derived = deriveInventoryAliases([asset()], [], '2026-10-01T00:00:00Z');
  const first = reconcileAutoAliases([], derived, '2026-10-01T00:00:00Z', { ttlDays: 30 });
  assert.equal(first.added.length, 1);
  assert.equal(first.added[0].expiresAt, '2026-10-31T00:00:00.000Z');
  assert.equal(first.added[0].firstSeenAt, '2026-10-01T00:00:00Z');

  // Inside the grace window the relation is still used even though current
  // inventory no longer supports it.
  const during = reconcileAutoAliases(first.aliases, [], '2026-10-20T00:00:00Z', { ttlDays: 30 });
  assert.equal(during.removed.length, 0);
  assert.equal(during.entries.length, 1);

  // Past the window it disappears.
  const after = reconcileAutoAliases(during.aliases, [], '2026-11-01T00:00:00Z', { ttlDays: 30 });
  assert.equal(after.removed.length, 1);
  assert.deepEqual(after.aliases, []);

  // A promoted row is operator-managed: the lifecycle neither expires nor
  // overwrites it, even when derivation proposes the same canonical name.
  const promoted: AliasEntry = {
    ...first.added[0],
    source: 'MANUAL',
    provenance: 'OPERATOR',
    expiresAt: undefined,
    revokedAliases: undefined,
    revokedAt: undefined,
  };
  const reconciled = reconcileAutoAliases([promoted], deriveInventoryAliases([asset()], [promoted]));
  assert.deepEqual(reconciled.upserts, []);
  assert.deepEqual(reconciled.removals, []);
  assert.equal(reconciled.aliases[0].source, 'MANUAL');
});

test('an operator revocation blocks re-learning until the tombstone is removed', () => {
  const now = '2026-10-26T00:00:00.000Z';
  const first = reconcileAutoAliases([], deriveInventoryAliases([asset()], [], now), now, {
    ttlDays: 0,
  });
  const row = first.added[0];
  const revoked: AliasEntry = {
    ...row,
    source: 'REVOKED',
    aliases: [],
    revokedAliases: [...row.aliases],
    revokedAt: now,
  };

  assert.deepEqual(deriveInventoryAliases([asset()], [revoked]), []);
  const reconciled = reconcileAutoAliases([revoked], [], now);
  assert.deepEqual(reconciled.upserts, []);
  assert.deepEqual(reconciled.removals, []);
  assert.ok(reconciled.aliases.some((entry) => entry.source === 'REVOKED'));

  // Removing the tombstone allows the relation to be learned again.
  assert.equal(deriveInventoryAliases([asset()], []).length, 1);
});

test('a generic inventory CPE is constrained by the inventory product', () => {
  const generic = 'cpe:2.3:a:*:*:*:*:*:*:*:*:*:*';
  const advisory = cpe('acme', 'widget', '1.0');
  const sameProduct = matchesWatchlistItem(
    [generic],
    'acme',
    'widget',
    [advisory],
    'unrelated title',
    'unrelated body',
  );
  assert.equal(sameProduct.matched, true);
  assert.equal(sameProduct.applicabilityRequiresReview, true);
  assert.ok(sameProduct.confidence < 90);

  const otherProduct = matchesWatchlistItem(
    [generic],
    'acme',
    'gadget',
    [advisory],
    'unrelated title',
    'unrelated body',
  );
  assert.equal(otherProduct.matched, false);
});

test('a CPE mismatch can still correlate on vendor and product', () => {
  const result = matchesWatchlistItem(
    [cpe('other', 'different', '*')],
    'acme',
    'widget',
    [cpe('acme', 'widget', '*')],
    'unrelated title',
    'unrelated body',
  );
  assert.equal(result.matched, true);
  assert.ok(['VENDOR_PRODUCT_ALIAS', 'VENDOR_PRODUCT_FALLBACK'].includes(result.method));
  assert.ok(result.confidence < 90, 'looser correlation must stay review-only');
});

test('the fallback still cannot override an explicit CPE version mismatch', () => {
  assert.equal(
    matchesWatchlistItem(
      [cpe('acme', 'widget', '3.0')],
      'acme',
      'widget',
      [cpe('acme', 'widget', '1.0')],
      'unrelated title',
      'unrelated body',
    ).matched,
    false,
  );
});

test('a PURL mismatch remains authoritative over a vendor/product text match', () => {
  assert.equal(
    matchesWatchlistItem(
      [],
      'acme',
      'widget',
      [],
      'Acme Widget vulnerability',
      'Acme Widget is affected',
      undefined,
      ['pkg:npm/acme-widget@1.0.0'],
      ['pkg:npm/other-package@1.0.0'],
    ).matched,
    false,
  );
});
