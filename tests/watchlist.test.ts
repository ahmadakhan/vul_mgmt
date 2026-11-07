import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { WatchListItem } from '../src/types/index.ts';
import {
  editedWatchlistCpe,
  orderWatchlist,
  registrationAssetsFromCpes,
  verifyRegistrationCpes,
  dictionaryCpesForCandidate,
} from '../src/utils/watchlist.ts';

const item = (id: string, createdAt: string, product = 'widget'): WatchListItem => ({
  id,
  vendor: 'example',
  product,
  cpes: [`cpe:2.3:a:example:${product}:1.0:*:*:*:*:*:*:*`],
  assetTag: id,
  ownerGroup: 'test',
  active: true,
  createdAt,
});

test('editing inventory data does not change its created-time order', () => {
  const older = item('older', '2026-01-01T00:00:00.000Z');
  const newer = item('newer', '2026-02-01T00:00:00.000Z');
  const edited = { ...older, product: 'renamed', createdAt: older.createdAt };

  assert.deepEqual(
    orderWatchlist([edited, newer]).map((asset) => asset.id),
    ['newer', 'older'],
  );
});

test('editing the product field generates and saves a matching CPE', () => {
  const asset = item('asset', '2026-01-01T00:00:00.000Z');
  const cpe = editedWatchlistCpe(asset, {
    cpeExpression: asset.cpes[0],
    vendor: 'example',
    product: 'widget-enterprise',
    part: 'a',
    version: '1.0',
    targetHw: '*',
  });

  assert.equal(cpe, 'cpe:2.3:a:example:widget-enterprise:1.0:*:*:*:*:*:*:*');
});

test('editing the CPE expression directly preserves that expression', () => {
  const asset = item('asset', '2026-01-01T00:00:00.000Z');
  const cpe = 'cpe:2.3:o:example:widget:2.0:*:*:*:*:*:*:*';

  assert.equal(
    editedWatchlistCpe(asset, {
      cpeExpression: cpe,
      vendor: 'example',
      product: 'widget',
      part: 'a',
      version: '1.0',
      targetHw: '*',
    }),
    cpe,
  );
});

test('dictionary registration uses the selected identity and version without a fallback CPE', () => {
  const cpe = 'cpe:2.3:o:microsoft:windows_server_2022:20348:*:*:*:*:*:x64:*';
  const rows = registrationAssetsFromCpes([cpe, cpe], {
    assetTag: 'WIN-01',
    ownerGroup: 'SOC',
    notes: '',
    purls: [],
  });
  assert.equal(rows.length, 1);
  assert.deepEqual(rows[0].cpes, [cpe]);
  assert.equal(rows[0].vendor, 'microsoft');
  assert.equal(rows[0].product, 'windows_server_2022');
  assert.equal(rows[0].version, '20348');
  assert.equal(rows[0].targetHw, 'x64');
  assert.equal(rows[0].assetTag, 'WIN-01');
});

test('registration separates different products and retains versions under the correct product', () => {
  const first = 'cpe:2.3:a:apache:http_server:2.4.61:*:*:*:*:*:*:*';
  const second = 'cpe:2.3:a:apache:http_server:2.4.62:*:*:*:*:*:*:*';
  const other = 'cpe:2.3:o:fortinet:fortios:7.2.1:*:*:*:*:*:*:*';
  const rows = registrationAssetsFromCpes([first, other, second], {
    assetTag: 'EDGE',
    ownerGroup: 'SOC',
    notes: '',
    purls: [],
  });
  assert.equal(rows.length, 2);
  assert.deepEqual(rows[0].cpes, [first, second]);
  assert.equal(rows[0].version, '*');
  assert.equal(rows[1].vendor, 'fortinet');
  assert.equal(rows[1].version, '7.2.1');
  assert.deepEqual(
    rows.map((row) => row.assetTag),
    ['EDGE-1', 'EDGE-2'],
  );
});

test('registration refuses empty identifiers and malformed CPEs instead of generating software assets', () => {
  const details = { assetTag: 'APP-01', ownerGroup: 'SOC', notes: '', purls: [] };
  assert.throws(() => registrationAssetsFromCpes([], details), /verified NVD/);
  assert.throws(() => registrationAssetsFromCpes(['invalid'], details), /valid product CPE/);
});

test('registration checks exact dictionary identity and rejects a related but different version', async () => {
  const cpe = 'cpe:2.3:a:example:widget:1.0:*:*:*:*:*:*:*';
  await assert.rejects(
    verifyRegistrationCpes([cpe], async () => ({ results: [{ cpeName: cpe.replace(':1.0:', ':2.0:') }] })),
    /not an active NVD dictionary entry/,
  );
  await assert.rejects(
    verifyRegistrationCpes([cpe], async () => ({ results: [] })),
    /not an active NVD/,
  );
  assert.deepEqual(
    await verifyRegistrationCpes([cpe, cpe], async (candidate) => ({ results: [{ cpeName: candidate }] })),
    [cpe],
  );
});

test('registration accepts vendor-agnostic match from NVD dictionary', async () => {
  const userCpe = 'cpe:2.3:a:notepad-plus-plus:notepadplus:*:*:*:*:*:*:*:*';
  const nvdCpe = 'cpe:2.3:a:don_ho:notepadplus:*:*:*:*:*:*:*:*';
  const verified = await verifyRegistrationCpes([userCpe], async () => ({
    results: [{ cpeName: nvdCpe }],
  }));
  assert.deepEqual(verified, [nvdCpe]);
});

test('registration propagates upstream failures and does not silently accept a CPE', async () => {
  const cpe = 'cpe:2.3:a:example:widget:1.0:*:*:*:*:*:*:*';
  await assert.rejects(
    verifyRegistrationCpes([cpe], async () => {
      throw new Error('NVD rate limit reached');
    }),
    /NVD rate limit/,
  );
  await assert.rejects(
    verifyRegistrationCpes([], async () => {
      throw new Error('must not query');
    }),
    /verified NVD/,
  );
});

test('a dictionary selection replaces generated suggestions only for the same product', () => {
  const generated = 'cpe:2.3:o:microsoft:windows_server_2022:*:*:*:*:*:*:*:*';
  const verified = 'cpe:2.3:o:microsoft:windows_server_2022:20348:*:*:*:*:*:x64:*';
  const unrelated = 'cpe:2.3:a:example:widget:1.0:*:*:*:*:*:*:*';
  assert.deepEqual(dictionaryCpesForCandidate(generated, [unrelated, verified]), [verified]);
  assert.deepEqual(dictionaryCpesForCandidate(generated, [unrelated]), [generated]);
});

test('strict vendor matching prevents substitution from unrelated vendors', () => {
  // Operator entered "notepad_plus_plus" as the vendor, but the NVD registry
  // uses the vendor "don_ho". Strict matching requires the vendor to match
  // exactly, so the generated CPE is NOT replaced by the NVD entry. The
  // operator must manually select the verified dictionary CPE from search
  // results rather than relying on an automatic substitution.
  const generated = 'cpe:2.3:a:notepad_plus_plus:notepad\\+\\+:*:*:*:*:*:*:*:*';
  const verified = 'cpe:2.3:a:don_ho:notepad\\+\\+:5.5:*:*:*:*:*:*:*';
  const unrelated = 'cpe:2.3:a:example:widget:1.0:*:*:*:*:*:*:*';
  assert.deepEqual(dictionaryCpesForCandidate(generated, [unrelated, verified]), [generated]);
  assert.deepEqual(dictionaryCpesForCandidate(generated, [unrelated]), [generated]);
});

test('registration allows operator-entered custom CPEs without an NVD dictionary match', async () => {
  const custom = 'cpe:2.3:a:internal:gateway:1.0.0:*:*:*:*:*:*:*';
  const verified = await verifyRegistrationCpes(
    [custom],
    async () => {
      throw new Error('must not query NVD for a custom CPE');
    },
    [custom],
  );
  assert.deepEqual(verified, [custom]);
});

test('registration still rejects a non-custom CPE missing from the NVD dictionary', async () => {
  const cpe = 'cpe:2.3:a:example:widget:1.0:*:*:*:*:*:*:*';
  await assert.rejects(
    verifyRegistrationCpes([cpe], async () => ({ results: [] })),
    /not an active NVD/,
  );
});
