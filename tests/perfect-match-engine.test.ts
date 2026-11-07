import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  distributionSuffix,
  evaluateVersion,
  naturalLanguageRange,
} from '../server/correlation/version.ts';
import { identityTokens, TextCorrelationEngine } from '../server/correlation/engine.ts';

/**
 * Regression coverage for the "perfect-match engine" audit. Each case pins a
 * behaviour that was previously wrong and would silently produce a false
 * negative, a false positive, or a dead-lettered advisory.
 */

test('prose bounds with a second, unparsed clause are reviewed rather than inverted', () => {
  // The fix notice is followed by another temporal claim; taking only the
  // first bound would invert the verdict on every patched asset.
  assert.equal(naturalLanguageRange('patched in 9.0.86 after a month of testing'), null);
  // A semantic contradiction is detected even when the exact word "vulnerable"
  // is not used. These paraphrases previously translated to "<9.0.86".
  assert.equal(naturalLanguageRange('impacted models were patched in 9.0.86'), null);
  assert.equal(naturalLanguageRange('devices are prone to this and patched in 9.0.86'), null);
  assert.equal(naturalLanguageRange('hosts compromised before patched in 9.0.86'), null);
  // An unambiguous single fix notice still translates.
  assert.equal(naturalLanguageRange('patched in 9.0.86'), '<9.0.86');
});

test('a bound with less precision than the deployed version is REVIEW, not a guess', () => {
  // A coarser bound can still decide a deployment it lies entirely away from:
  // every 5.0.1 build is above the whole "5" line.
  assert.equal(evaluateVersion('5.0.1', '<5'), 'UNAFFECTED');
  // The undecidable case is a deployment that straddles the bound: a "1.2"
  // deployment has some builds below 1.2.5 and some above.
  assert.equal(evaluateVersion('1.2', '<1.2.5'), 'REVIEW');
  assert.equal(evaluateVersion('1.2', '<1.3'), 'AFFECTED');
  assert.equal(evaluateVersion('1.2', '>=1.2.5'), 'REVIEW');
  assert.equal(evaluateVersion('1.2', '>=1.2'), 'AFFECTED');
  // "<1.2.4" against a four-component 1.2.3.4 is decided by the fourth
  // component: every 1.2.3.x build is below 1.2.4, so padding the bound to
  // 1.2.4.0 happens to give the same answer and the result is not a guess.
  assert.equal(evaluateVersion('1.2.3.4', '<1.2.4'), 'AFFECTED');
  // The inverse is where padding lies: 1.2.4.0 is not below its own base.
  assert.equal(evaluateVersion('1.2.4.0', '<1.2.4'), 'UNAFFECTED');
  // Padding that carries no information stays comparable.
  assert.equal(evaluateVersion('1.9', '<2.0'), 'AFFECTED');
  // The same deployment is inside ">=1.2.4" (its own base release).
  assert.equal(evaluateVersion('1.2.4.0', '>=1.2.4'), 'AFFECTED');
  assert.equal(evaluateVersion('5.0.0', '<5.0.1'), 'AFFECTED');
});

test('equality against a truncated deployment version cannot be decided confidently', () => {
  // Regression: intervalIsOrderedBy short-circuited "=" to true without
  // checking whether the bound lands inside the deployment's precision
  // interval. A "9.0" deployment denotes every 9.0.x build, so "=9.0.3"
  // straddles it — some builds match and most don't. The old code reported
  // a confident UNAFFECTED here, a silent false negative.
  assert.equal(evaluateVersion('9.0', '=9.0.3'), 'REVIEW');
  // A bound that sits exactly on the interval's lower edge is also only
  // partially covered by the line and therefore undecidable.
  assert.equal(evaluateVersion('9.0', '=9.0.0'), 'REVIEW');
  // A bound strictly outside the widened interval is decidable and unaffected.
  assert.equal(evaluateVersion('9.0', '=8.0.3'), 'UNAFFECTED');
  // A full-precision deployment collapses to a single point, so equality is
  // decidable in both the matching and non-matching direction.
  assert.equal(evaluateVersion('9.0.0.0', '=9.0.0'), 'AFFECTED');
  assert.equal(evaluateVersion('9.0.0.0', '=9.0.3'), 'UNAFFECTED');
});

test('digit-leading distribution revisions are classified as backports', () => {
  // Leading-letter suffixes were the only accepted shape; "12ubuntu2" and
  // "1.el8" fell through to semver coercion and were decided on rebuild order.
  assert.equal(distributionSuffix('1.2.3-12ubuntu2'), '12ubuntu2');
  assert.equal(distributionSuffix('2.4.41-1.el8'), '1.el8');
  assert.equal(distributionSuffix('1.2.3-rc.1'), null, 'a named prerelease is upstream, not a backport');
  assert.equal(evaluateVersion('1.2.3-12ubuntu2', '<2.0'), 'REVIEW');
});

test('identity tokenization strips sentence punctuation from a product name', () => {
  // The extraction worker rewrites text as space-joined tokens, so a
  // sentence-final product name carries its full stop.
  assert.deepEqual(identityTokens('critical flaw patched in fortios.'), [
    'critical',
    'flaw',
    'patched',
    'in',
    'fortios',
  ]);
  assert.deepEqual(identityTokens('  Openssl,  then.nginx-1.2  '), ['openssl', 'then.nginx-1.2']);
});

const emptyExtraction = (overrides: Record<string, unknown> = {}) => ({
  text: '',
  cleanContent: '',
  ranges: [],
  cveIds: [],
  zeroDay: false,
  securitySignal: true,
  negated: false,
  zeroDayDensity: 0,
  ...overrides,
});

test('an alias finding is not dead-lettered when a product has many alias strings', async () => {
  const engine = new TextCorrelationEngine();
  // 120 distinct alias spellings of one product: the previous LIMIT 101 +
  // throw made this a MATCH_FANOUT/ENTITY_FANOUT dead letter.
  const rows = Array.from({ length: 120 }, (_, index) => ({
    alias: `alias${index}x`,
    vendor: 'vendor',
    product: 'product',
  }));
  const text = rows.map((row) => row.alias).join(' ');
  const matches = await engine.correlate(
    { title: 't', content: 'c', url: 'https://example.org/many', cpes: [], purls: [], entities: [] },
    emptyExtraction({ text }),
    async (sql: string) => {
      if (sql.includes('vendor_product_aliases')) return { rows } as never;
      // One canonical product, so the duplicate-alias collapse is what is
      // exercised: 120 rows in, one entity out, one asset evaluated.
      return {
        rows: [
          { id: '11111111-1111-4111-8111-111111111111', vendor: 'vendor', product: 'product', version: '1.0.0', revision: 'r' },
        ],
      } as never;
    },
  );
  // The fake inventory reports one asset per alias hit so the match path runs.
  // The point of the assertion is that no fanout exception was thrown and the
  // entity was resolved despite 120 alias spellings.
  assert.ok(matches.length >= 1);
  assert.ok(matches.every((match) => match.vendor === 'vendor' && match.product === 'product'));
});

test('a range is inferred from a bound adjacent to the alias it names', async () => {
  const engine = new TextCorrelationEngine();
  const asset = { id: '11111111-1111-4111-8111-111111111111', vendor: 'v', product: 'p', version: '1.0.0', revision: 'r' };
  const matches = await engine.correlate(
    { title: 't', content: 'c', url: 'https://example.org/adjacent', cpes: [], purls: [], entities: [] },
    emptyExtraction({
      text: 'the p release is affected patched in 9.0.0',
      ranges: [{ productPhrase: 'affected', range: '<9.0.0' }],
    }),
    async (sql: string) => {
      if (sql.includes('vendor_product_aliases')) return { rows: [{ alias: 'p', vendor: 'v', product: 'p' }] } as never;
      if (sql.includes('correlation_asset_inventory')) return { rows: [asset] } as never;
      return { rows: [] } as never;
    },
  );
  assert.equal(matches.length, 1);
  assert.equal(matches[0].confidence, 'HIGH');
  assert.match(matches[0].reason, /range satisfied/);
});

test('a negated advisory reaches review as an unassigned finding, never as an asset match', async () => {
  const engine = new TextCorrelationEngine();
  const matches = await engine.correlate(
    { title: 't', content: 'c', url: 'https://example.org/n', cpes: [], purls: [], entities: [] },
    emptyExtraction({ text: 'lorem ipsum', zeroDay: true, negated: true }),
    async () => ({ rows: [] }) as never,
  );
  assert.equal(matches.length, 1);
  assert.equal(matches[0].assetId, '');
  assert.match(matches[0].reason, /negation/);
});

test('the inventory walk is paginated and deterministic rather than truncated', async () => {
  const engine = new TextCorrelationEngine();
  const pages: string[][] = [];
  const assets = Array.from({ length: 1200 }, (_, index) => ({
    // UUID-shaped ids so the keyset cursor is realistic.
    id: `00000000-0000-4000-8000-${String(index).padStart(12, '0')}`,
    vendor: 'v',
    product: 'p',
    version: '2.0.0',
    revision: 'r',
  }));
  const matches = await engine
    .correlate(
      {
        title: 't',
        content: 'c',
        url: 'https://example.org/paged',
        cpes: [],
        purls: [],
        entities: [],
      },
      emptyExtraction({ text: 'v p', ranges: [{ productPhrase: 'v p', range: '>=1.0.0 <3.0.0' }] }),
      async (sql: string, values?: unknown[]) => {
        if (sql.includes('vendor_product_aliases')) return { rows: [{ alias: 'v p', vendor: 'v', product: 'p' }] } as never;
        const cursor = (values?.[2] ?? null) as string | null;
        pages.push([cursor ?? 'start']);
        const remaining = cursor ? assets.filter((asset) => asset.id > cursor) : assets;
        // 500 per page, exactly like INVENTORY_PAGE_SIZE.
        return { rows: remaining.slice(0, 500) } as never;
      },
    )
    .catch((error: Error) => error);
  assert.ok(matches instanceof Error, 'the fanout ceiling must refuse, not truncate silently');
  assert.match((matches as Error).message, /MATCH_FANOUT_LIMIT/);
  // The whole product was walked across keyset pages before the ceiling was
  // hit — the old code stopped at an arbitrary first 1001 rows and returned a
  // partial result as if it were complete.
  assert.ok(pages.length >= 3, `expected keyset pages, saw ${pages.length}`);
});
