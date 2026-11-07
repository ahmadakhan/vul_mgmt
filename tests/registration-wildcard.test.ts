import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { NvdCpeSearchResult } from '../src/types/index.ts';
import { parseCPE23 } from '../src/utils/cpeMatcher.ts';
import {
  productWildcardCpe,
  withProductWildcards,
  dictionaryEntryMatchesWildcard,
} from '../src/utils/registrationCpe.ts';
import { registrationAssetsFromCpes, verifyRegistrationCpes } from '../src/utils/watchlist.ts';
import { searchNvdCpes } from '../server/cpeSearch.ts';
import type { Requester } from '../server/network.ts';

const first = 'cpe:2.3:o:microsoft:windows_server_2022:20348:*:*:*:*:*:x64:*';
const second = first.replace(':20348:', ':20349:');
const other = 'cpe:2.3:a:apache:http_server:2.4.62:*:*:*:*:*:*:*';
const wildcard = 'cpe:2.3:o:microsoft:windows_server_2022:*:*:*:*:*:*:*:*';
const entry = (name: string, id = 'dictionary-id'): NvdCpeSearchResult => {
  const parsed = parseCPE23(name);
  return {
    cpeName: name,
    cpeNameId: id,
    part: parsed.part,
    vendor: parsed.vendor,
    product: parsed.product,
    version: parsed.version,
    update: parsed.update,
    targetSw: parsed.targetSw,
    targetHw: parsed.targetHw,
  };
};

test('wildcards retain a dictionary product identity and cover all versions and platforms', () => {
  assert.equal(productWildcardCpe(first), wildcard);
  assert.equal(parseCPE23(wildcard).isValid, true);
  assert.equal(productWildcardCpe('invalid'), null);
  assert.equal(productWildcardCpe('cpe:2.3:a:*:*:*:*:*:*:*:*:*:*'), null);
});

test('wildcard generation preserves escaped product components', () => {
  const name = String.raw`cpe:2.3:a:don_ho:notepad\+\+:8.0:*:*:*:*:*:*:*`;
  const result = productWildcardCpe(name)!;
  assert.equal(result, String.raw`cpe:2.3:a:don_ho:notepad\+\+:*:*:*:*:*:*:*:*`);
  assert.equal(parseCPE23(result).isValid, true);
});

test('one wildcard per product appears before the exact dictionary versions', () => {
  const results = withProductWildcards([entry(first), entry(second), entry(other)]);
  assert.equal(results.length, 5);
  assert.equal(results[0].cpeName, wildcard);
  assert.equal(results[0].generatedWildcard, true);
  assert.equal(results[0].cpeNameId, '', 'a generated pattern must not reuse an exact version UUID');
  assert.equal(results[1].version, '*');
  assert.deepEqual(
    results.slice(2).map((result) => result.cpeName),
    [first, second, other],
  );
  assert.deepEqual(withProductWildcards([]), []);
});

test('an official wildcard dictionary name stays first without a generated duplicate', () => {
  const results = withProductWildcards([entry(first), entry(wildcard, 'official-wildcard-id')]);
  assert.equal(results.length, 2);
  assert.equal(results[0].cpeName, wildcard);
  assert.equal(results[0].cpeNameId, 'official-wildcard-id');
  assert.equal(results[0].generatedWildcard, undefined);
});

test('registration retains the selected wildcard instead of narrowing it to one version', async () => {
  const verified = await verifyRegistrationCpes([wildcard], async () => ({
    results: [entry(first), entry(second)],
  }));
  assert.deepEqual(verified, [wildcard]);
  const assets = registrationAssetsFromCpes(verified, {
    assetTag: 'WIN-01',
    ownerGroup: 'SOC',
    notes: '',
    purls: [],
  });
  assert.deepEqual(assets[0].cpes, [wildcard]);
  assert.equal(assets[0].version, '*');
});

test('wildcards cannot be verified by a different vendor, part, or product', async () => {
  for (const mismatched of [
    first.replace(':microsoft:', ':other_vendor:'),
    first.replace(':o:', ':a:'),
    other,
  ]) {
    assert.equal(dictionaryEntryMatchesWildcard(wildcard, mismatched), false);
    await assert.rejects(
      verifyRegistrationCpes([wildcard], async () => ({ results: [entry(mismatched)] })),
      /not an active NVD/,
    );
  }
  await assert.rejects(
    verifyRegistrationCpes([wildcard], async () => ({ results: [] })),
    /not an active NVD/,
  );
});

test('wildcard verification fetches active structural matches in one request', async () => {
  let calls = 0;
  const request: Requester = async (url, options) => {
    calls++;
    assert.equal(new URL(url).searchParams.get('cpeMatchString'), wildcard);
    assert.equal(options?.headers?.apiKey, 'test-key');
    return {
      status: 200,
      headers: {},
      body: JSON.stringify({
        totalResults: 4,
        products: [
          { cpe: { cpeName: first, deprecated: false } },
          { cpe: { cpeName: second, deprecated: false } },
          { cpe: { cpeName: other, deprecated: false } },
          { cpe: { cpeName: first.replace(':20348:', ':20347:'), deprecated: true } },
        ],
      }),
    };
  };
  const response = await searchNvdCpes(request, 'test-key', '', '', 50, wildcard);
  assert.equal(calls, 1);
  assert.deepEqual(
    response.results.map((result) => result.cpeName),
    [first, second],
  );
});
