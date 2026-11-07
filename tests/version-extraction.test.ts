import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { Writable } from 'node:stream';
import { naturalLanguageRange, evaluateVersion, evaluateVersionDetailed } from '../server/correlation/version.ts';
import { extractText } from '../server/correlation/extraction.ts';
import { CorrelationTelemetry } from '../server/correlation/telemetry.ts';

const silent = () =>
  new CorrelationTelemetry(
    new Writable({
      write(_chunk, _encoding, callback) {
        callback();
      },
    }),
  );

test('naturalLanguageRange translates "versions X through Y" as a band, not a single <= bound', () => {
  assert.equal(naturalLanguageRange('versions 5.0 through 5.7'), '>=5.0 <=5.7');
  assert.equal(naturalLanguageRange('5.0 through 5.7'), '>=5.0 <=5.7');
  assert.equal(naturalLanguageRange('version 2.1.0 to 2.3.4'), '>=2.1.0 <=2.3.4');
  assert.equal(naturalLanguageRange('between 1.0 and 3.0'), '>=1.0 <=3.0');
});

test('naturalLanguageRange does not misread "X through Y" as "product <= Y"', () => {
  assert.equal(naturalLanguageRange('k8s 2.0 through 3.0'), '>=2.0 <=3.0');
});

test('naturalLanguageRange handles "through" as a single inclusive upper bound when not a band', () => {
  assert.equal(naturalLanguageRange('elasticsearch through 8.0'), '<=8.0');
});

test('naturalLanguageRange handles "up to and including" as <=', () => {
  assert.equal(naturalLanguageRange('up to and including 4.2.1'), '<=4.2.1');
});

test('naturalLanguageRange handles "fixed/resolved/remediated/addressed in" as <', () => {
  assert.equal(naturalLanguageRange('fixed in 4.2.1'), '<4.2.1');
  assert.equal(naturalLanguageRange('patched in 5.0.0'), '<5.0.0');
  assert.equal(naturalLanguageRange('resolved in 6.1.3'), '<6.1.3');
  assert.equal(naturalLanguageRange('remediated in 7.2.0'), '<7.2.0');
  assert.equal(naturalLanguageRange('addressed in 8.3.1'), '<8.3.1');
});

test('naturalLanguageRange handles "patched before" as <', () => {
  assert.equal(naturalLanguageRange('patched before version 9.0.86'), '<9.0.86');
});

test('naturalLanguageRange handles "earlier than" and "at most" as <', () => {
  assert.equal(naturalLanguageRange('earlier than 2.0'), '<2.0');
  assert.equal(naturalLanguageRange('at most 1.5.0'), '<1.5.0');
});

test('evaluateVersion handles 4-component versions', () => {
  assert.equal(evaluateVersion('2.7.8.1', '>=2.7.8'), 'AFFECTED');
  assert.equal(evaluateVersion('2.7.7.9', '<2.7.8'), 'AFFECTED');
  assert.equal(evaluateVersion('2.7.8.1', '<2.7.8'), 'UNAFFECTED');
  assert.equal(evaluateVersion('2.7.8.0', '>=2.7.8'), 'AFFECTED');
});

test('evaluateVersion equality is undecidable when the bound falls inside a short version interval', () => {
  // A deployment version shorter than four components names a line, not a single
  // release, so an equality bound inside the precision interval could match some
  // builds and not others. The safe verdict is REVIEW, not a confident
  // UNAFFECTED (which would miss the vulnerability). Regression: the `=` branch
  // previously short-circuited to "decidable" and returned UNAFFECTED here.
  assert.equal(evaluateVersion('9.0', '=9.0.3'), 'REVIEW');
  assert.equal(evaluateVersion('9.0', '9.0.3'), 'REVIEW');
  // A bound strictly outside the interval is decidable: no build matches, so the
  // deployment is confidently UNAFFECTED before and after the fix.
  assert.equal(evaluateVersion('9.0', '=8.0'), 'UNAFFECTED');
  assert.equal(evaluateVersion('9.0', '=9.1'), 'UNAFFECTED');
  // A fully specified (single-point) deployment is decidable, and a matching
  // equality bound is AFFECTED.
  assert.equal(evaluateVersion('1.2.3.4', '=1.2.3.4'), 'AFFECTED');
});

test('evaluateVersionDetailed uses numeric provenance for 4-component fallback', () => {
  const result = evaluateVersionDetailed('2.7.8.1', '>=2.7.8');
  assert.equal(result.provenance, 'numeric');
  assert.equal(result.verdict, 'AFFECTED');
});

test('evaluateVersion handles case-insensitive prerelease tags', () => {
  assert.equal(evaluateVersion('1.0.0-RC.1', '<1.0.0'), 'AFFECTED');
  assert.equal(evaluateVersion('1.0.0-BETA', '<1.0.0'), 'AFFECTED');
  assert.equal(evaluateVersion('1.0.0-Alpha.1', '<1.0.0'), 'AFFECTED');
  assert.equal(evaluateVersion('1.0.0-PREVIEW', '<1.0.0'), 'AFFECTED');
  assert.equal(evaluateVersion('1.0.0-pre.2', '<1.0.0'), 'AFFECTED');
  assert.equal(evaluateVersion('1.0.0-alpha.3', '>=1.0.0-alpha.0 <1.0.0'), 'AFFECTED');
  assert.equal(evaluateVersion('1.0.0-beta.1', '>=1.0.0-alpha.0 <1.0.0'), 'AFFECTED');
});

test('naturalLanguageRange handles 4-component version bands', () => {
  assert.equal(naturalLanguageRange('between 1.2.3.0 and 1.2.3.5'), '>=1.2.3.0 <=1.2.3.5');
  assert.equal(naturalLanguageRange('from 1.2.3.0 to 1.2.3.5'), '>=1.2.3.0 <=1.2.3.5');
  assert.equal(naturalLanguageRange('versions 1.2.3.0 through 1.2.3.5'), '>=1.2.3.0 <=1.2.3.5');
});

test('evaluateVersionDetailed returns semver provenance for case-insensitive prereleases', () => {
  const result = evaluateVersionDetailed('1.0.0-RC.1', '<1.0.0');
  assert.equal(result.provenance, 'semver');
  assert.equal(result.verdict, 'AFFECTED');
});

test('extraction parses "through" band without misreading as single bound', async () => {
  const telemetry = silent();
  const result = await extractText('k8s 2.0 through 3.0 vulnerability affects clusters', telemetry, randomUUID());
  assert.deepEqual(
    result.ranges.find((r: { productPhrase: string; range: string }) => r.range.includes('>=2.0')),
    { productPhrase: 'k8s', range: '>=2.0 <=3.0' },
  );
  assert.equal(result.ranges.find((r: { productPhrase: string; range: string }) => r.range === '<3.0'), undefined);
});

test('extraction parses "versions X through Y" band', async () => {
  const telemetry = silent();
  const result = await extractText('versions 5.0 through 5.7 are vulnerable', telemetry, randomUUID());
  assert.ok(result.ranges.some((r: { range: string }) => r.range === '>=5.0 <=5.7'));
});

test('extraction parses "fixed in", "patched in", "resolved in" phrases', async () => {
  const telemetry = silent();
  const fixed = await extractText('fixed in 4.2.1 resolves the issue', telemetry, randomUUID());
  assert.ok(fixed.ranges.some((r: { range: string }) => r.range === '<4.2.1'));

  const patched = await extractText('patched in 5.0.0 is available', telemetry, randomUUID());
  assert.ok(patched.ranges.some((r: { range: string }) => r.range === '<5.0.0'));

  const resolved = await extractText('resolved in 6.1.3 addresses the CVE', telemetry, randomUUID());
  assert.ok(resolved.ranges.some((r: { range: string }) => r.range === '<6.1.3'));
});

test('extraction parses "remediated in" and "addressed in" phrases', async () => {
  const telemetry = silent();
  const remediated = await extractText('remediated in 7.2.0 is deployed', telemetry, randomUUID());
  assert.ok(remediated.ranges.some((r: { range: string }) => r.range === '<7.2.0'));

  const addressed = await extractText('addressed in 8.3.1 fixes it', telemetry, randomUUID());
  assert.ok(addressed.ranges.some((r: { range: string }) => r.range === '<8.3.1'));
});

test('extraction parses product-bound "openssl fixed in 2.5.0" with product phrase', async () => {
  const telemetry = silent();
  const result = await extractText('openssl fixed in 2.5.0 resolves the issue', telemetry, randomUUID());
  assert.ok(result.ranges.some((r: { range: string }) => r.range === '<2.5.0'));
  assert.ok(result.ranges.some((r: { productPhrase: string }) => r.productPhrase === 'openssl'));
});

test('extraction parses "up to and including" as <= bound', async () => {
  const telemetry = silent();
  const result = await extractText('affected up to and including 4.2.1', telemetry, randomUUID());
  assert.deepEqual(result.ranges, [{ productPhrase: 'affected', range: '<=4.2.1' }]);
});

test('extraction parses "earlier than" and "at most" as < bound', async () => {
  const telemetry = silent();
  const earlier = await extractText('elasticsearch earlier than 8.0 is vulnerable', telemetry, randomUUID());
  assert.deepEqual(earlier.ranges, [{ productPhrase: 'elasticsearch', range: '<8.0' }]);

  const atMost = await extractText('elasticsearch at most 8.0 is vulnerable', telemetry, randomUUID());
  assert.deepEqual(atMost.ranges, [{ productPhrase: 'elasticsearch', range: '<8.0' }]);
});

test('extraction handles 4-component versions in range phrases', async () => {
  const telemetry = silent();
  const result = await extractText('affected before 1.2.3.4 in production', telemetry, randomUUID());
  assert.deepEqual(result.ranges, [{ productPhrase: 'affected', range: '<1.2.3.4' }]);
});

test('extraction "through" as single inclusive upper bound preserves "<=" semantics', async () => {
  const telemetry = silent();
  const result = await extractText('elasticsearch through 8.0 is affected', telemetry, randomUUID());
  assert.deepEqual(result.ranges, [{ productPhrase: 'elasticsearch', range: '<=8.0' }]);
});

test('extraction strips pathological HTML with unclosed script tags without CPU exhaustion', async () => {
  const telemetry = silent();
  const pathological = '<script>'.repeat(5000) + 'vulnerability data';
  const start = Date.now();
  const result = await extractText(pathological, telemetry, randomUUID());
  const elapsed = Date.now() - start;
  assert.ok(elapsed < 500, `stripping took ${elapsed}ms, expected <500ms`);
  assert.equal(result.cleanContent, 'vulnerability data');
});

test('extraction handles "between X and Y" band alongside single-bound phrases', async () => {
  const telemetry = silent();
  const result = await extractText(
    'vulnerable between 2.1.0 and 2.3.4, fix available before 2.5.0',
    telemetry,
    randomUUID(),
  );
  assert.ok(result.ranges.some((r: { range: string }) => r.range === '>=2.1.0 <=2.3.4'));
  assert.ok(result.ranges.some((r: { range: string }) => r.range === '<2.5.0'));
});

test('extraction handles "from X to Y" band', async () => {
  const telemetry = silent();
  const result = await extractText('vulnerable from 1.0 to 3.0 in the wild', telemetry, randomUUID());
  assert.deepEqual(result.ranges, [{ productPhrase: 'vulnerable', range: '>=1.0 <=3.0' }]);
});
