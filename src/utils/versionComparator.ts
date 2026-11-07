/**
 * Vendor-aware version and patch-range comparison.
 *
 * NVD ranges are written against upstream releases, while inventories commonly
 * report distribution revisions (Alpine `-r1`, Red Hat `.el8_6`, Ubuntu
 * `-0ubuntu…`) and vendor post-release tags. Only orderings that are portable
 * across those families may justify an automatic exclusion; everything else is
 * retained as a review candidate.
 */

export interface NvdVersionRange {
  versionStartIncluding?: string;
  versionStartExcluding?: string;
  versionEndIncluding?: string;
  versionEndExcluding?: string;
}

type SuffixRank = 0 | 1 | 2; // prerelease < release < post-release

interface ComparableVersion {
  core: number[];
  rank: SuffixRank;
  family: string;
  number: number;
  preRank: number;
}

/** Conventional prerelease ordering. Unknown families are not comparable. */
const PRERELEASE_RANK: Readonly<Record<string, number>> = {
  dev: 0,
  snapshot: 0,
  alpha: 1,
  beta: 2,
  pre: 3,
  preview: 3,
  rc: 4,
};

/** Tags that name the final upstream release rather than a later revision. */
const RELEASE_EQUIVALENT = new Set(['final', 'ga', 'release']);

/**
 * Post-release vendor revisions. Within one family the numeric suffix is
 * ordered; different families have no portable relative order and force a
 * review instead of an automatic exclusion.
 */
const POST_RELEASE = new Set([
  'h',
  'p',
  'patch',
  'hotfix',
  'sp',
  'u',
  'update',
  'build',
  'fix',
  'rel',
  'rev',
  'maint',
  'maintenance',
  'r',
  's',
  'sec',
]);

function parseComparable(value: string): ComparableVersion | undefined {
  if (!value) return undefined;
  const trimmed = value.trim().toLowerCase().replace(/^v(?=\d)/, '');
  if (!trimmed || trimmed === '*' || trimmed === '-') return undefined;
  // SemVer build metadata does not affect precedence. Epochs and Debian tildes
  // do affect ordering and are not modelled, so they must not be auto-compared.
  const withoutMetadata = trimmed.split('+')[0];
  if (/[~:\s]/.test(withoutMetadata)) return undefined;

  // A single optional tag only. Distribution revisions such as `-8.el8_6` or
  // `-0ubuntu0.22.04.1` intentionally do not parse and therefore require review.
  const match = /^(\d+(?:\.\d+)*)(?:[-_.]([a-z]+)(?:[-_.]?(\d+))?)?$/.exec(withoutMetadata);
  if (!match) return undefined;

  const core = match[1].split('.').map(Number);
  if (!core.length || core.some((token) => !Number.isSafeInteger(token))) return undefined;

  const family = match[2] || '';
  const number = match[3] ? Number(match[3]) : 0;
  if (!Number.isSafeInteger(number)) return undefined;

  if (!family || RELEASE_EQUIVALENT.has(family)) {
    return { core, rank: 1, family, number: 0, preRank: 0 };
  }
  if (Object.hasOwn(PRERELEASE_RANK, family)) {
    return { core, rank: 0, family, number, preRank: PRERELEASE_RANK[family] };
  }
  if (POST_RELEASE.has(family)) {
    return { core, rank: 2, family, number, preRank: 0 };
  }
  return undefined;
}

function sameCore(left: number[], right: number[]): boolean {
  return left.length === right.length && left.every((token, index) => token === right[index]);
}

/** Two suffixed versions are comparable only when their order is portable. */
function suffixesComparable(left: ComparableVersion, right: ComparableVersion): boolean {
  // `1.0.0-p1` versus `1.0.0-h1`: both post-release, but no portable order.
  if (left.rank === 2 && right.rank === 2) return left.family === right.family;
  return true;
}

/**
 * A distribution revision (`1.2.3-r1`) against an equal-core plain release
 * upper bound (`1.2.3`) is ambiguous: the revision may or may not contain the
 * upstream fix. Do not let that comparison exclude the asset.
 */
function ambiguousDistributionUpperBound(
  deployed: ComparableVersion,
  range: NvdVersionRange,
): boolean {
  const upper = range.versionEndIncluding || range.versionEndExcluding;
  if (!upper || deployed.rank !== 2) return false;
  const parsedUpper = parseComparable(upper);
  return Boolean(
    parsedUpper &&
      parsedUpper.rank === 1 &&
      sameCore(deployed.core, parsedUpper.core),
  );
}

/** Only values with a defined, portable ordering may be compared automatically. */
export function canCompareRange(version: string, range: NvdVersionRange): boolean {
  const values = [version, ...Object.values(range).filter((bound): bound is string => !!bound)];
  const parsed = values.map(parseComparable);
  if (parsed.some((entry) => !entry)) return false;
  const entries = parsed as ComparableVersion[];
  const deployed = entries[0];
  if (ambiguousDistributionUpperBound(deployed, range)) return false;
  for (let i = 0; i < entries.length; i++)
    for (let j = i + 1; j < entries.length; j++)
      if (!suffixesComparable(entries[i], entries[j])) return false;
  return true;
}

interface ParsedVersion {
  numbers: number[];
  prerelease: string[];
  raw: string;
}

/**
 * Lenient parser retained for diagnostics and unknown-value fallback. Range
 * decisions must use `canCompareRange` first; this parser intentionally cannot
 * prove ordering for unrecognised vendor tags.
 */
export function parseVersion(verStr: string): ParsedVersion {
  if (!verStr || verStr === '*' || verStr === '-') {
    return { numbers: [], prerelease: [], raw: verStr || '*' };
  }

  const clean = verStr.trim().toLowerCase().replace(/^v(?=\d)/, '');
  const [core, ...preParts] = clean.split('+')[0].split(/[-_]/);
  const numMatches = core.match(/\d+/g);
  const numbers = numMatches ? numMatches.map(Number) : [0];
  // Preserve a trailing literal such as `a` in `1.2.3a` instead of silently
  // discarding it, which previously made distinct releases compare equal.
  const literal = core.replace(/[\d.\s]+/g, '');
  if (literal) preParts.push(literal);

  return { numbers, prerelease: preParts, raw: verStr };
}

function compareLegacy(left: string, right: string): number {
  const a = parseVersion(left);
  const b = parseVersion(right);
  const maxLen = Math.max(a.numbers.length, b.numbers.length);
  for (let i = 0; i < maxLen; i++) {
    const x = a.numbers[i] || 0;
    const y = b.numbers[i] || 0;
    if (x !== y) return x > y ? 1 : -1;
  }
  const pa = a.prerelease.join('-');
  const pb = b.prerelease.join('-');
  if (pa === pb) return 0;
  return pa.localeCompare(pb, undefined, { numeric: true, sensitivity: 'base' }) > 0 ? 1 : -1;
}

/**
 * Returns -1 when v1 < v2, 0 when equal, and 1 when v1 > v2.
 *
 * A wildcard (`'*'`) is semantically "any version" and has no defined ordering,
 * so this function returns 0 when either argument is a wildcard. This is only a
 * safe terminal value: callers evaluating NVD intervals MUST first check
 * `canCompareRange`, which returns false for wildcards so the range evaluator
 * falls through to the "requires review" path instead of relying on a
 * comparison result. Direct callers that bypass `canCompareRange` should treat
 * a 0 return as "indeterminate" rather than "equal".
 */
export function compareVersions(v1Str: string, v2Str: string): number {
  if (v1Str === v2Str) return 0;
  if (v1Str === '*' || v2Str === '*') return 0;

  const left = parseComparable(v1Str);
  const right = parseComparable(v2Str);
  if (!left || !right) return compareLegacy(v1Str, v2Str);

  const maxLen = Math.max(left.core.length, right.core.length);
  for (let i = 0; i < maxLen; i++) {
    const a = left.core[i] || 0;
    const b = right.core[i] || 0;
    if (a !== b) return a > b ? 1 : -1;
  }

  if (left.rank !== right.rank) return left.rank < right.rank ? -1 : 1;

  if (left.rank === 0) {
    if (left.preRank !== right.preRank) return left.preRank < right.preRank ? -1 : 1;
    if (left.number !== right.number) return left.number < right.number ? -1 : 1;
    return 0;
  }

  if (left.rank === 2) {
    if (left.family !== right.family)
      return left.family < right.family ? -1 : 1;
    if (left.number !== right.number) return left.number < right.number ? -1 : 1;
    return 0;
  }

  return 0;
}

/**
 * Tri-state verdict for one version against an NVD interval.
 *
 * `INCONCLUSIVE` covers wildcard/incomparable versions — cases that must be
 * reviewed, never auto-excluded and never auto-confirmed. The legacy boolean
 * `isVersionInNvdRange` below collapses INCONCLUSIVE into `inRange: true`,
 * which every caller in this codebase must (and does) pair with a prior
 * `canCompareRange` check; new callers should use this function instead so the
 * "cannot decide" answer cannot be mistaken for "affected".
 */
export type RangeVerdict = 'IN_RANGE' | 'OUT_OF_RANGE' | 'INCONCLUSIVE';

/**
 * Tri-state evaluation of a deployed version against an NVD version interval.
 *
 * Never throws; unparseable or wildcard versions return INCONCLUSIVE, not an
 * optimistic IN_RANGE. Callers that need a boolean must decide explicitly what
 * to do with INCONCLUSIVE (the correct production behaviour is review).
 */
export function evaluateVersionInRange(
  deployedVersion: string,
  range: NvdVersionRange,
): { verdict: RangeVerdict; reason: string } {
  if (!deployedVersion || deployedVersion === '*' || deployedVersion === '-')
    return { verdict: 'INCONCLUSIVE', reason: 'Asset version is a wildcard — range check inconclusive, requires review' };

  if (!canCompareRange(deployedVersion, range))
    return { verdict: 'INCONCLUSIVE', reason: 'Version ordering is unsupported or vendor-ambiguous; applicability requires review' };

  if (range.versionStartIncluding && compareVersions(deployedVersion, range.versionStartIncluding) < 0)
    return {
      verdict: 'OUT_OF_RANGE',
      reason: `Deployed version ${deployedVersion} < start limit ${range.versionStartIncluding}`,
    };

  if (range.versionStartExcluding && compareVersions(deployedVersion, range.versionStartExcluding) <= 0)
    return {
      verdict: 'OUT_OF_RANGE',
      reason: `Deployed version ${deployedVersion} <= start exclusion limit ${range.versionStartExcluding}`,
    };

  if (range.versionEndIncluding && compareVersions(deployedVersion, range.versionEndIncluding) > 0)
    return {
      verdict: 'OUT_OF_RANGE',
      reason: `Deployed version ${deployedVersion} > patched limit ${range.versionEndIncluding} (Already Patched)`,
    };

  if (range.versionEndExcluding && compareVersions(deployedVersion, range.versionEndExcluding) >= 0)
    return {
      verdict: 'OUT_OF_RANGE',
      reason: `Deployed version ${deployedVersion} >= fixed limit ${range.versionEndExcluding} (Already Patched)`,
    };

  return {
    verdict: 'IN_RANGE',
    reason: `Deployed version ${deployedVersion} is strictly within vulnerable interval [${range.versionStartIncluding || '*'}, ${range.versionEndExcluding || range.versionEndIncluding || '*'})`,
  };
}

/** Checks whether a deployed version satisfies an NVD version interval.
 *
 * @deprecated Prefer the tri-state `evaluateVersionInRange`. This boolean
 * signature keeps historical behaviour: an INCONCLUSIVE verdict (wildcard or
 * vendor-ambiguous ordering) is reported as `inRange: true` because callers in
 * this codebase pair it with a `canCompareRange` guard that routes the
 * inconclusive case to review instead of exclusion. New call sites must not
 * rely on that convention — use `evaluateVersionInRange` directly. */
export function isVersionInNvdRange(
  deployedVersion: string,
  range: NvdVersionRange,
): { inRange: boolean; reason: string } {
  if (!deployedVersion || deployedVersion === '*') {
    return { inRange: true, reason: 'Wildcard version on asset matches all ranges' };
  }

  if (!canCompareRange(deployedVersion, range)) {
    return {
      inRange: true,
      reason: 'Version ordering is unsupported or vendor-ambiguous; applicability requires review',
    };
  }

  if (range.versionStartIncluding) {
    if (compareVersions(deployedVersion, range.versionStartIncluding) < 0) {
      return {
        inRange: false,
        reason: `Deployed version ${deployedVersion} < start limit ${range.versionStartIncluding}`,
      };
    }
  }

  if (range.versionStartExcluding) {
    if (compareVersions(deployedVersion, range.versionStartExcluding) <= 0) {
      return {
        inRange: false,
        reason: `Deployed version ${deployedVersion} <= start exclusion limit ${range.versionStartExcluding}`,
      };
    }
  }

  if (range.versionEndIncluding) {
    if (compareVersions(deployedVersion, range.versionEndIncluding) > 0) {
      return {
        inRange: false,
        reason: `Deployed version ${deployedVersion} > patched limit ${range.versionEndIncluding} (Already Patched)`,
      };
    }
  }

  if (range.versionEndExcluding) {
    if (compareVersions(deployedVersion, range.versionEndExcluding) >= 0) {
      return {
        inRange: false,
        reason: `Deployed version ${deployedVersion} >= fixed limit ${range.versionEndExcluding} (Already Patched)`,
      };
    }
  }

  return {
    inRange: true,
    reason: `Deployed version ${deployedVersion} is strictly within vulnerable interval [${range.versionStartIncluding || '*'}, ${range.versionEndExcluding || range.versionEndIncluding || '*'})`,
  };
}
