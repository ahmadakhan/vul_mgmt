import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runCpeSimulation, buildCpeParseResult, generateCpePrefixes } from '../src/utils/cpeSimulation';
import { parseCPE23, matchCPE, DEFAULT_VENDOR_ALIASES } from '../src/utils/cpeMatcher';

// CPE 2.3 format: cpe:2.3:part:vendor:product:version:update:edition:language:swEdition:targetSw:targetHw:other
// That's 11 fields after the prefix, with exactly 10 colons in the remainder.

test('runCpeSimulation returns matched=true for exact CPE match', () => {
  const result = runCpeSimulation(
    'cpe:2.3:a:microsoft:windows_10:10.0.19041:*:*:*:*:*:*:*',
    'cpe:2.3:a:microsoft:windows_10:*:*:*:*:*:*:*:*',
    'microsoft',
    'windows_10',
  );

  assert.equal(result.match.matched, true);
  assert.equal(result.match.method, 'STRICT_CPE');
  assert.equal(result.match.viaAlias, false);
  assert.ok(result.match.confidence >= 90, `Expected confidence >= 90, got ${result.match.confidence}`);
  assert.ok(result.assetCpe.parsed?.isValid, 'Asset CPE should be valid');
  assert.ok(result.vulnerabilityCpe.parsed?.isValid, 'Vulnerability CPE should be valid');
  // 'microsoft' has built-in aliases (msft, windows)
  assert.ok(result.assetVendorAlias);
  assert.equal(result.versionRangeCheck, null);
});

test('runCpeSimulation returns matched=false for vendor mismatch', () => {
  const result = runCpeSimulation(
    'cpe:2.3:a:microsoft:windows_10:10.0.19041:*:*:*:*:*:*:*',
    'cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*',
    'microsoft',
    'windows_10',
  );

  assert.equal(result.match.matched, false);
  assert.equal(result.match.method, 'NONE');
  assert.equal(result.match.confidence, 0);
  assert.ok(result.match.reason && result.match.reason.length > 0);
});

test('runCpeSimulation resolves vendor alias for microsoft/msft', () => {
  const result = runCpeSimulation(
    'cpe:2.3:a:msft:windows_10:10.0.19041:*:*:*:*:*:*:*',
    'cpe:2.3:a:microsoft:windows_10:*:*:*:*:*:*:*:*',
    'msft',
    'windows_10',
  );

  assert.equal(result.match.matched, true);
  assert.equal(result.match.viaAlias, true);
  assert.ok(result.match.evidence.includes('alias thesaurus'), 'Evidence should mention alias thesaurus');
});

test('runCpeSimulation resolves alias from custom vendor thesaurus', () => {
  const customVendorAliases = { apache: ['apache_software_foundation', 'httpd'] };

  const result = runCpeSimulation(
    'cpe:2.3:a:apache:http_server:2.4.58:*:*:*:*:*:*:*',
    'cpe:2.3:a:apache_software_foundation:http_server:*:*:*:*:*:*:*:*',
    'apache',
    'http_server',
    customVendorAliases,
  );

  assert.equal(result.match.matched, true);
  assert.equal(result.match.viaAlias, true);
});

test('runCpeSimulation evaluates version range when out of range', () => {
  const result = runCpeSimulation(
    'cpe:2.3:a:microsoft:windows_10:9.0:*:*:*:*:*:*:*',
    'cpe:2.3:a:microsoft:windows_10:*:*:*:*:*:*:*:*',
    'microsoft',
    'windows_10',
    {},
    {},
    { versionEndExcluding: '10.0', versionStartIncluding: '10.0.19041' },
    '9.0',
  );

  assert.equal(result.match.matched, false, 'Match should fail when version is out of range');
  assert.ok(result.versionRangeCheck, 'Should have a version range check result');
  assert.equal(result.versionRangeCheck!.inRange, false);
});

test('runCpeSimulation evaluates version range when in range', () => {
  const result = runCpeSimulation(
    'cpe:2.3:a:microsoft:windows_10:10.0.19041:*:*:*:*:*:*:*',
    'cpe:2.3:a:microsoft:windows_10:*:*:*:*:*:*:*:*',
    'microsoft',
    'windows_10',
    {},
    {},
    { versionStartIncluding: '10.0', versionEndExcluding: '11.0' },
    '10.0.19041',
  );

  assert.equal(result.match.matched, true);
  assert.ok(result.versionRangeCheck, 'Should have a version range check result');
  assert.equal(result.versionRangeCheck!.inRange, true);
});

test('runCpeSimulation returns matched=false for architecture conflict', () => {
  const result = runCpeSimulation(
    'cpe:2.3:a:microsoft:windows_10:*:*:*:*:*:*:x86_64:*',
    'cpe:2.3:a:microsoft:windows_10:*:*:*:*:*:*:aarch64:*',
    'microsoft',
    'windows_10',
  );

  const fpChecks = result.falsePositiveChecks;
  const archCheck = fpChecks.find((c) => c.name === 'Target Architecture');
  assert.ok(archCheck, 'Should have a Target Architecture check');
  assert.equal(archCheck.passed, false);
  assert.equal(archCheck.severity, 'BLOCK');
});

test('runCpeSimulation classifies severity for matched result', () => {
  const result = runCpeSimulation(
    'cpe:2.3:a:microsoft:windows_10:10.0.19041:*:*:*:*:*:*:*',
    'cpe:2.3:a:microsoft:windows_10:*:*:*:*:*:*:*:*',
    'microsoft',
    'windows_10',
  );

  assert.ok(result.severity, 'Should have a severity classification');
  assert.equal(result.severity!.source, 'CPE_SIMULATION');
  assert.ok(result.severity!.rationale.length > 0, 'Should have rationale');
  assert.ok(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL'].includes(result.severity!.tier));
});

test('runCpeSimulation classifies severity as INFORMATIONAL for no match', () => {
  const result = runCpeSimulation(
    'cpe:2.3:a:microsoft:windows_10:10.0.19041:*:*:*:*:*:*:*',
    'cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*',
    'microsoft',
    'windows_10',
  );

  assert.equal(result.match.matched, false);
  assert.ok(result.severity, 'Should have a severity classification');
  assert.equal(result.severity!.tier, 'INFORMATIONAL');
});

test('runCpeSimulation flags generic vendor/product CPEs', () => {
  const result = runCpeSimulation(
    'cpe:2.3:a:*:*:10.0.19041:*:*:*:*:*:*:*',
    'cpe:2.3:a:*:*:*:*:*:*:*:*:*:*',
    'microsoft',
    'windows_10',
  );

  const fpChecks = result.falsePositiveChecks;
  const genericCheck = fpChecks.find((c) => c.name === 'Generic Identity');
  assert.ok(genericCheck, 'Should have a Generic Identity check');
  assert.equal(genericCheck.passed, false);
  assert.equal(genericCheck.severity, 'WARN');
});

test('buildCpeParseResult parses valid CPE with all components', () => {
  const result = buildCpeParseResult('cpe:2.3:a:microsoft:windows_10:10.0.19041:*:*:*:*:*:*:*');

  assert.equal(result.errors.length, 0);
  assert.ok(result.parsed, 'Parsed result should not be null');
  assert.equal(result.parsed!.vendor, 'microsoft');
  assert.equal(result.parsed!.product, 'windows_10');
  assert.equal(result.parsed!.version, '10.0.19041');
  assert.equal(result.components.length, 11);
});

test('buildCpeParseResult reports errors for invalid CPE', () => {
  const result = buildCpeParseResult('cpe:2.3:a:invalid');

  assert.ok(result.errors.length > 0);
  assert.equal(result.parsed, null);
  assert.ok(result.errors[0].includes('Invalid'));
});

test('generateCpePrefixes generates prefixes for all parts', () => {
  const prefixes = generateCpePrefixes('microsoft', 'windows_10');

  assert.equal(prefixes.length, 3);
  for (const prefix of prefixes) {
    assert.ok(prefix.startsWith('cpe:2.3:'), `Should start with cpe:2.3: but got ${prefix}`);
    assert.ok(prefix.includes(':microsoft:windows_10:'), `Should include vendor/product in ${prefix}`);
  }
  assert.ok(prefixes.some((p) => p.startsWith('cpe:2.3:a:')));
  assert.ok(prefixes.some((p) => p.startsWith('cpe:2.3:o:')));
  assert.ok(prefixes.some((p) => p.startsWith('cpe:2.3:h:')));
});

test('buildCpeParseResult handles wildcard components', () => {
  const result = buildCpeParseResult('cpe:2.3:a:microsoft:windows_10:*:*:*:*:*:*:*:*');

  assert.equal(result.errors.length, 0);
  const versionComponent = result.components.find((c) => c.field === 'Version');
  assert.ok(versionComponent, 'Should have a Version component');
  assert.equal(versionComponent!.isWildcard, true);
  assert.equal(versionComponent!.isAmbiguous, false);
});

test('buildCpeParseResult handles ambiguous (-) components', () => {
  const result = buildCpeParseResult('cpe:2.3:a:microsoft:windows_10:10.0.19041:-:*:*:*:*:*:*');

  assert.equal(result.errors.length, 0);
  const updateComponent = result.components.find((c) => c.field === 'Update');
  assert.ok(updateComponent, 'Should have an Update component');
  assert.equal(updateComponent!.isWildcard, false);
  assert.equal(updateComponent!.isAmbiguous, true);
});

test('runCpeSimulation includes parse results for both CPEs', () => {
  const result = runCpeSimulation(
    'cpe:2.3:a:microsoft:windows_10:10.0.19041:*:*:*:*:*:*:*',
    'cpe:2.3:a:microsoft:windows_10:*:*:*:*:*:*:*:*',
    'microsoft',
    'windows_10',
  );

  assert.ok(result.assetCpe);
  assert.ok(result.vulnerabilityCpe);
  assert.equal(result.assetCpe.cpe, 'cpe:2.3:a:microsoft:windows_10:10.0.19041:*:*:*:*:*:*:*');
  assert.equal(result.vulnerabilityCpe.cpe, 'cpe:2.3:a:microsoft:windows_10:*:*:*:*:*:*:*:*');
});

test('runCpeSimulation handles invalid CPE on either side', () => {
  const result = runCpeSimulation(
    'cpe:2.3:a:invalid',
    'cpe:2.3:a:microsoft:windows_10:10.0.19041:*:*:*:*:*:*:*',
    'microsoft',
    'windows_10',
  );

  assert.equal(result.match.matched, false);
  assert.ok(result.assetCpe.errors.length > 0);
  assert.equal(result.vulnerabilityCpe.errors.length, 0);
});

test('runCpeSimulation with invalid CPEs produces FP validity check', () => {
  const result = runCpeSimulation(
    'not-a-cpe',
    'also-not-a-cpe',
    'vendor',
    'product',
  );

  assert.equal(result.match.matched, false);
  assert.ok(result.falsePositiveChecks.length >= 1, 'Should have at least one FP check for invalid CPEs');
  assert.equal(result.falsePositiveChecks[0].name, 'CPE Validity');
  assert.equal(result.falsePositiveChecks[0].passed, false);
  assert.equal(result.falsePositiveChecks[0].severity, 'BLOCK');
});

test('runCpeSimulation blocks match when version range excludes asset', () => {
  const result = runCpeSimulation(
    'cpe:2.3:a:microsoft:windows_10:12.0:*:*:*:*:*:*:*',
    'cpe:2.3:a:microsoft:windows_10:*:*:*:*:*:*:*:*',
    'microsoft',
    'windows_10',
    {},
    {},
    { versionEndExcluding: '11.0' },
    '12.0',
  );

  const fpChecks = result.falsePositiveChecks;
  const rangeCheck = fpChecks.find((c) => c.name === 'Version Range');
  assert.ok(rangeCheck, 'Should have a Version Range check');
  assert.equal(rangeCheck.passed, false);
  assert.equal(rangeCheck.severity, 'BLOCK');
});

test('matchCPE returns matched=false for different vendors without alias option', () => {
  const result = matchCPE(
    'cpe:2.3:a:msft:windows_10:10.0.19041:*:*:*:*:*:*:*',
    'cpe:2.3:a:microsoft:windows_10:10.0.19041:*:*:*:*:*:*:*',
  );

  assert.equal(result.matched, false);
  assert.ok(result.reason && result.reason.includes('Vendor mismatch'));
});

test('matchCPE returns viaAlias=true for microsoft/msft alias pair with aliases option', () => {
  const result = matchCPE(
    'cpe:2.3:a:msft:windows_10:10.0.19041:*:*:*:*:*:*:*',
    'cpe:2.3:a:microsoft:windows_10:10.0.19041:*:*:*:*:*:*:*',
    undefined,
    { vendorAliases: {}, productAliases: {} },
  );

  assert.equal(result.matched, true);
  assert.equal(result.viaAlias, true);
});

test('DEFAULT_VENDOR_ALIASES includes microsoft/msft pair', () => {
  assert.ok(DEFAULT_VENDOR_ALIASES.microsoft);
  assert.ok(DEFAULT_VENDOR_ALIASES.microsoft.includes('msft'));
});

test('DEFAULT_VENDOR_ALIASES includes n-able/solarwinds pair for the N-central product', () => {
  assert.ok(DEFAULT_VENDOR_ALIASES['n-able']);
  assert.ok(DEFAULT_VENDOR_ALIASES['n-able'].includes('solarwinds'));
});
