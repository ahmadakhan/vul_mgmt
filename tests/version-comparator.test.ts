import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  canCompareRange,
  compareVersions,
  isVersionInNvdRange,
} from '../src/utils/versionComparator.ts';

test('post-release vendor revisions order above the upstream release', () => {
  assert.equal(compareVersions('1.2.3-r1', '1.2.3'), 1);
  assert.equal(compareVersions('1.2.3-r2', '1.2.3-r1'), 1);
  assert.equal(compareVersions('1.2.3-sec1', '1.2.3'), 1);
  assert.equal(compareVersions('1.2.3-final', '1.2.3'), 0);
  assert.equal(compareVersions('1.2.3-ga1', '1.2.3'), 0);
  assert.equal(compareVersions('1.2.3-release', '1.2.3'), 0);
});

test('Alpine revision is not silently excluded by an equal-core start bound', () => {
  // Regression: the previous comparator classified `r` as a prerelease, so a
  // package at 1.2.3-r1 was treated as older than 1.2.3 and excluded.
  assert.deepEqual(
    isVersionInNvdRange('1.2.3-r1', { versionStartIncluding: '1.2.3' }).inRange,
    true,
  );
  assert.equal(
    isVersionInNvdRange('1.2.3-r1', { versionStartExcluding: '1.2.3' }).inRange,
    true,
  );
});

test('an equal-core plain upper bound cannot prove a distribution revision fixed', () => {
  const range = { versionEndExcluding: '1.2.3' };
  assert.equal(canCompareRange('1.2.3-r1', range), false);
  const result = isVersionInNvdRange('1.2.3-r1', range);
  assert.equal(result.inRange, true);
  assert.match(result.reason, /requires review/);
});

test('a clearly later plain upper bound still permits automatic exclusion', () => {
  const range = { versionEndExcluding: '1.2.4' };
  assert.equal(canCompareRange('1.2.3-r1', range), true);
  assert.equal(isVersionInNvdRange('1.2.3-r1', range).inRange, true);
  assert.equal(isVersionInNvdRange('1.2.5-r1', range).inRange, false);
});

test('prereleases order below the release and use conventional family ranks', () => {
  assert.equal(compareVersions('1.0.0-rc1', '1.0.0'), -1);
  assert.equal(compareVersions('1.0.0-beta2', '1.0.0-rc1'), -1);
  assert.equal(compareVersions('1.0.0-alpha', '1.0.0-beta'), -1);
  assert.equal(isVersionInNvdRange('1.0.0-rc1', { versionStartIncluding: '1.0.0' }).inRange, false);
  assert.equal(isVersionInNvdRange('1.0.0-rc1', { versionEndExcluding: '1.0.0' }).inRange, true);
});

test('different post-release families require review instead of guessing', () => {
  const range = { versionStartExcluding: '1.2.3-p2' };
  assert.equal(canCompareRange('1.2.3-h1', range), false);
  assert.equal(isVersionInNvdRange('1.2.3-h1', range).inRange, true);
  assert.match(isVersionInNvdRange('1.2.3-h1', range).reason, /requires review/);
});

test('distribution revisions with no portable ordering are review-only', () => {
  for (const [version, range] of [
    ['1.2.3-0ubuntu0.22.04.1', { versionEndExcluding: '1.2.3-0ubuntu0.22.04.2' }],
    ['1.2.3-8.el8_6', { versionEndExcluding: '1.2.3-9.el8_7' }],
    ['1:2.3.4', { versionEndExcluding: '1:2.3.5' }],
    ['1.2.3~rc1', { versionEndExcluding: '1.2.3' }],
    ['1.2.3a', { versionEndExcluding: '1.2.3b' }],
    ['1.2.3-1', { versionEndExcluding: '1.2.4' }],
  ] as const) {
    assert.equal(canCompareRange(version, range), false, version);
    const result = isVersionInNvdRange(version, range);
    assert.equal(result.inRange, true, version);
    assert.match(result.reason, /requires review/, version);
  }
});

test('legacy fallback never equates distinct alphanumeric releases', () => {
  assert.notEqual(compareVersions('1.2.3a', '1.2.3'), 0);
  assert.equal(compareVersions('1.2.3+build.1', '1.2.3+build.2'), 0);
});

test('numeric core comparison pads missing segments', () => {
  assert.equal(compareVersions('1.2', '1.2.0'), 0);
  assert.equal(compareVersions('1.2.0.1', '1.2.0'), 1);
  assert.equal(compareVersions('2.0', '10.0'), -1);
});
