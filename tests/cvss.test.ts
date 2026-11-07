import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  normalizeCvssVersion,
  cvssSeverity,
  isCvssVersion,
  maxCvssVersion,
  parseCvssVector,
  cvssVectorIsValid,
} from '../server/cvss.ts';

test('normalizeCvssVersion passes through known versions', () => {
  assert.equal(normalizeCvssVersion('4.0'), '4.0');
  assert.equal(normalizeCvssVersion('3.1'), '3.1');
  assert.equal(normalizeCvssVersion('3.0'), '3.0');
  assert.equal(normalizeCvssVersion('2.0'), '2.0');
});

test('normalizeCvssVersion trims whitespace', () => {
  assert.equal(normalizeCvssVersion(' 3.1 '), '3.1');
});

test('normalizeCvssVersion falls back for unknown versions', () => {
  assert.equal(normalizeCvssVersion('3.2'), '3.1');
  assert.equal(normalizeCvssVersion('unknown'), '3.1');
assert.equal(normalizeCvssVersion('unknown', 'UNKNOWN'), 'UNKNOWN');
  assert.equal(normalizeCvssVersion('', 'UNKNOWN'), 'UNKNOWN');
  assert.equal(normalizeCvssVersion('1.0', '3.1'), '3.1');
});

test('normalizeCvssVersion handles non-string input', () => {
  assert.equal(normalizeCvssVersion(undefined, 'UNKNOWN'), 'UNKNOWN');
  assert.equal(normalizeCvssVersion(null, 'UNKNOWN'), 'UNKNOWN');
  assert.equal(normalizeCvssVersion(3.1, 'UNKNOWN'), 'UNKNOWN');
  assert.equal(normalizeCvssVersion({ version: '3.1' }, 'UNKNOWN'), 'UNKNOWN');
});

test('cvssSeverity maps score ranges to correct bands', () => {
  assert.equal(cvssSeverity(10.0), 'CRITICAL');
  assert.equal(cvssSeverity(9.0), 'CRITICAL');
  assert.equal(cvssSeverity(8.9), 'HIGH');
  assert.equal(cvssSeverity(7.0), 'HIGH');
  assert.equal(cvssSeverity(6.9), 'MEDIUM');
  assert.equal(cvssSeverity(4.0), 'MEDIUM');
  assert.equal(cvssSeverity(3.9), 'LOW');
  assert.equal(cvssSeverity(0.1), 'LOW');
  assert.equal(cvssSeverity(0.0), 'LOW');
});

test('isCvssVersion is a type guard', () => {
  assert.equal(isCvssVersion('3.1'), true);
  assert.equal(isCvssVersion('4.0'), true);
  assert.equal(isCvssVersion('3.0'), true);
  assert.equal(isCvssVersion('2.0'), true);
  assert.equal(isCvssVersion('UNKNOWN'), false);
  assert.equal(isCvssVersion('3.2'), false);
  assert.equal(isCvssVersion(''), false);
});

test('maxCvssVersion prefers the higher version', () => {
  assert.equal(maxCvssVersion('3.0', '3.1'), '3.1');
  assert.equal(maxCvssVersion('3.1', '3.0'), '3.1');
  assert.equal(maxCvssVersion('3.0', '4.0'), '4.0');
  assert.equal(maxCvssVersion('2.0', '3.1'), '3.1');
});

test('maxCvssVersion returns non-UNKNOWN when one side is UNKNOWN', () => {
  assert.equal(maxCvssVersion('UNKNOWN', '3.1'), '3.1');
  assert.equal(maxCvssVersion('3.1', 'UNKNOWN'), '3.1');
  assert.equal(maxCvssVersion('UNKNOWN', 'UNKNOWN'), 'UNKNOWN');
});

test('parseCvssVector parses v3.1 vectors', () => {
  const parsed = parseCvssVector('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
  assert.equal(parsed.AV, 'N');
  assert.equal(parsed.AC, 'L');
  assert.equal(parsed.PR, 'N');
  assert.equal(parsed.UI, 'N');
  assert.equal(parsed.S, 'U');
  assert.equal(parsed.C, 'H');
  assert.equal(parsed.I, 'H');
  assert.equal(parsed.A, 'H');
});

test('parseCvssVector parses v4.0 vectors', () => {
  const parsed = parseCvssVector('CVSS:4.0/AV:N/AC:L/AT:N/PR:N');
  assert.equal(parsed.AV, 'N');
  assert.equal(parsed.AC, 'L');
  assert.equal(parsed.AT, 'N');
  assert.equal(parsed.PR, 'N');
});

test('parseCvssVector parses v2 vectors without prefix', () => {
  const parsed = parseCvssVector('AV:N/AC:L/Au:N/C:COMPLETE');
  assert.equal(parsed.AV, 'N');
  assert.equal(parsed.AC, 'L');
  assert.equal(parsed.Au, 'N');
  assert.equal(parsed.C, 'COMPLETE');
});

test('parseCvssVector returns empty object for empty string', () => {
  assert.deepEqual(parseCvssVector(''), {});
});

test('parseCvssVector handles malformed segments gracefully', () => {
  const parsed = parseCvssVector('CVSS:3.1/AV:N/AC:L/malformed');
  assert.equal(parsed.AV, 'N');
  assert.equal(parsed.AC, 'L');
  assert.equal(parsed.malformed, undefined);
});

test('cvssVectorIsValid accepts valid v3.1 vectors', () => {
  assert.equal(cvssVectorIsValid('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'), true);
});

test('cvssVectorIsValid accepts valid v4.0 vectors', () => {
  assert.equal(cvssVectorIsValid('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N'), true);
});

test('cvssVectorIsValid accepts valid v2 vectors', () => {
  assert.equal(cvssVectorIsValid('AV:N/AC:L/Au:N/C:COMPLETE/I:COMPLETE'), true);
});

test('cvssVectorIsValid rejects malformed vectors', () => {
  assert.equal(cvssVectorIsValid('garbage'), false);
  assert.equal(cvssVectorIsValid('CVSS:3.1'), false);
});

test('cvssVectorIsValid accepts empty string', () => {
  assert.equal(cvssVectorIsValid(''), true);
});

test('cvssVectorIsValid rejects vectors with an unknown CVSS prefix', () => {
  // Regression: the v2 detector used to accept any vector starting with "AV"/"N",
  // so an unsupported prefix like CVSS:9.9/ slipped through as "valid".
  assert.equal(cvssVectorIsValid('CVSS:9.9/AV:N/AC:L'), false);
  assert.equal(cvssVectorIsValid('CVSS:3.2/AV:N/AC:L'), false);
  assert.equal(cvssVectorIsValid('CVSS:2.0/AV:N/AC:L'), false);
});

test('cvssVectorIsValid rejects a prefix with an empty body', () => {
  assert.equal(cvssVectorIsValid('CVSS:3.1/'), false);
  assert.equal(cvssVectorIsValid('CVSS:4.0/'), false);
});

test('cvssVectorIsValid rejects segments without a value', () => {
  assert.equal(cvssVectorIsValid('CVSS:3.1/AV:N/AC:'), false);
  assert.equal(cvssVectorIsValid('CVSS:3.1/AV:N/:L'), false);
});

test('cvssVectorIsValid tolerates surrounding whitespace', () => {
  assert.equal(cvssVectorIsValid(' CVSS:3.1/AV:N/AC:L/PR:N '), true);
  assert.equal(cvssVectorIsValid('  '), false);
});
