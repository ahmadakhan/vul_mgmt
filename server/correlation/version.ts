import semver from 'semver';

const PRERELEASE_TAG = /-(alpha|beta|rc|pre|preview)([.-][0-9]+)?$/i;

const isNamedPrerelease = (clean: string): boolean => PRERELEASE_TAG.test(clean);

/** Coerce only plain numeric releases. Never discard distribution/backport suffixes.
 * Only unambiguous, named prerelease tags (alpha, beta, rc, pre, preview, optionally
 * with a numeric ordinal) are accepted. A bare digit-only suffix (e.g., "2.4.41-2")
 * falls through to REVIEW, consistent with NVD-side comparator behavior. */
export function portableVersion(value: string): string | null {
  if (value.length > 100) return null;
  const clean = value.trim().replace(/^v/i, '');
  const valid = semver.valid(clean);
  if (valid) {
    if (clean.includes('+')) return null;
    if (clean.includes('-') && !isNamedPrerelease(clean)) return null;
    return valid;
  }
  if (!/^[0-9]{1,9}(\.[0-9]{1,9}){0,3}$/.test(clean)) return null;
  return clean;
}

/** Detect a distribution/backport suffix on an enterprise package version.
 *  Examples: "1.2.3-ubuntu1~20.04.1", "2.4.41-el8", "10.3.2-MariaDB",
 *  "1.2.3-12ubuntu2", "2.4.41-1.el8", "1.8.0_392" (Java update ordinal).
 *  These versions carry vendor rebuild numbering that no upstream range can
 *  resolve; comparing them against an upstream bound silently produces wrong
 *  verdicts. Named prereleases (rc/beta/…) are upstream tags, not rebuilds. */
export function distributionSuffix(value: string): string | null {
  const clean = value.trim().replace(/^v/i, '');
  if (isNamedPrerelease(clean)) return null;
  // A leading-letter build tag: "1.2.3-ubuntu1~20.04.1", "10.3.2-MariaDB".
  const debian = /^[0-9]{1,9}(?:\.[0-9]{1,9}){1,3}-([A-Za-z][A-Za-z0-9.+~]*)$/.exec(clean);
  if (debian) return debian[1];
  // A digit-leading package revision followed by a distro token:
  // "1.2.3-12ubuntu2", "2.4.41-1.el8". The whole revision segment is returned
  // because the build number is what differs between two rebuilds.
  const revision = /^[0-9]{1,9}(?:\.[0-9]{1,9}){1,3}-([0-9]+(?:\.[a-z][a-z0-9.+~]*|[a-z][a-z0-9.+~]*))$/i.exec(clean);
  if (revision && !isNamedPrerelease(clean)) return revision[1];
  if (/^[0-9]{1,9}(\.[0-9]{1,9}){0,3}_[0-9]+$/.test(clean)) return clean.split('_')[1];
  return null;
}

/**
 * Numeric components, always four wide with a zero tail, so two versions can be
 * compared component-wise. Returns null when the text is not numeric.
 */
function numericParts(version: string): number[] | null {
  const match = /^(\d{1,9})(?:\.(\d{1,9}))?(?:\.(\d{1,9}))?(?:\.(\d{1,9}))?$/.exec(
    version.trim().replace(/^v/i, ''),
  );
  if (!match) return null;
  return [1, 2, 3, 4].map((index) => (match[index] === undefined ? 0 : Number(match[index])));
}

/** How many components were actually written: "5" is 1, "5.0.1" is 3. */
function numericWidth(version: string): number {
  const text = version.trim().replace(/^v/i, '').match(/^\d+(?:\.\d+)*/)?.[0];
  return text ? text.split('.').length : 0;
}

/** Component-wise comparison of two equal-width arrays. */
function compareParts(a: readonly number[], b: readonly number[]): number {
  for (let index = 0; index < 4; index++) {
    const left = a[index] ?? 0;
    const right = b[index] ?? 0;
    if (left !== right) return left > right ? 1 : -1;
  }
  return 0;
}

/**
 * True when every build in the deployment's precision interval answers the
 * bound the same way. A deployment version shorter than four components does
 * not name one release, it names a line ("1.2" is every 1.2.x), so a bound that
 * falls inside that line is undecidable: "<1.2.5" is neither satisfied nor
 * excluded by "1.2". This is the only place precision is decided, and it
 * applies to the numeric comparator only — SemVer ranges address releases, and
 * `semver.satisfies` has already handled them.
 */
function intervalIsOrderedBy(
  lower: readonly number[],
  upper: readonly number[],
  bound: readonly number[],
  operator: string,
): boolean {
  if (operator === '=') {
    // Equality is undecidable against an interval that spans the bound: when the
    // deployment version is short ("1.2" = every 1.2.x), the bound can land
    // inside the precision interval, so some builds match and others don't. It
    // is decidable only when the bound is strictly outside the interval, or the
    // interval is a single point (a fully specified version).
    return (
      compareParts(bound, lower) < 0 ||
      compareParts(bound, upper) > 0 ||
      compareParts(lower, upper) === 0
    );
  }
  const satisfies = (point: readonly number[]) => {
    const cmp = compareParts(point, bound);
    switch (operator) {
      case '>': return cmp > 0;
      case '>=': return cmp >= 0;
      case '<': return cmp < 0;
      case '<=': return cmp <= 0;
      default: return cmp === 0;
    }
  };
  // The deployment denotes an interval [lower, upper]. The term is decidable
  // exactly when every build agrees, which for a comparison is the same as both
  // ends agreeing. When only one end agrees the deployment straddles the bound
  // — for example a "1.2" deployment against "<1.2.5" — and the answer is not
  // knowable from the advisory.
  return satisfies(lower) === satisfies(upper);
}

const VERSION_TOKEN = 'v?([0-9]{1,9}(?:\\.[0-9]{1,9}){0,3})';
const RANGE_VERSION_TOKEN = 'v?([0-9]{1,9}(?:\\.[0-9]{1,9}){0,3})';

function stripLeadingV(raw: string): string {
  return raw.replace(/^v?/i, '');
}

/** Bounds that assert live exposure. Semantically, not lexically exhaustive. */
const EXPOSURE = /\b(?:vulnerable|affected|susceptible|exposed|impacted|prone|compromised|exploitable)\b/;
/** Bounds that assert a remediation exists. */
const REMEDIATION =
  /\b(?:patched|fixed|resolved|remediated|addressed|corrected|hardened)\s+(?:in|by|with)\b/;

/**
 * Translate an advisory's natural-language range into the comparator grammar.
 *
 * Returns null when the prose cannot be reduced to exactly one interval. Null
 * is not a failure: `evaluateVersion` translates it into REVIEW, which is the
 * only safe answer when a claim is ambiguous. What must never happen is a
 * silent fallback to equality (the pre-fix behaviour), because `=X` against an
 * unrelated asset version yields a confident UNAFFECTED for patched and
 * unpatched estates alike.
 */
export function naturalLanguageRange(prose: string): string | null {
  const text = prose
    .toLowerCase()
    .replace(/\bversions?\b/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
  if (!text) return null;

  // A single phrase must not silently pick one of several claims. "Fixed in
  // 9.0.86; versions before 8.1 are vulnerable" contains a fix bound and an
  // affected bound; translating only one inverts the verdict. Separators inside
  // an inclusive band (`between X and Y`) are not extra clauses.
  const band = /\b(?:between|from)\s+\S+\s+(?:and|to|through|thru)\s+\S+/g;
  const bands = text.match(band) ?? [];
  const withoutBands = text.replace(band, ' ');
  const clauseCount =
    (
      withoutBands.match(
        /\b(?:before|prior to|below|earlier than|at most|up to|through|and earlier|or older|and later|or newer)\b/g,
      ) ?? []
    ).length + bands.length;
  const verbCount = (
    text.match(/\b(?:patched|fixed|resolved|remediated|addressed|corrected|hardened)\s+(?:in|by|with)\b/g) ?? []
  ).length;
  if (clauseCount + verbCount > 1 && !/\bbetween\b/.test(text)) return null;

  // A fix claim and a live-exposure claim in one sentence cannot both be the
  // interval: the writer is describing two different states of the estate.
  if (REMEDIATION.test(text) && EXPOSURE.test(text)) return null;

  // "patched in X after …" puts a second, unparsed claim right after the bound.
  if (
    /\b(?:patched|fixed|resolved|remediated|addressed)\s+(?:in|by|with)\s+v?[0-9][0-9.]*\s+(?:after|following|along with|once|when)\b/.test(
      text,
    )
  )
    return null;

  let match: RegExpExecArray | null;

  // Inclusive band. Checked first so "between 2.1.0 and 2.3.4" is not read as
  // the single bound "2.3.4 and …".
  match = new RegExp(`(?:between|from) ${RANGE_VERSION_TOKEN} (?:and|to|through|thru) ${RANGE_VERSION_TOKEN}`).exec(
    text,
  );
  if (match) {
    const low = stripLeadingV(match[1]);
    const high = stripLeadingV(match[2]);
    const lowParts = numericParts(low);
    const highParts = numericParts(high);
    // An inverted band is a typo or two different claims; never normalise it.
    if (lowParts && highParts && compareParts(lowParts, highParts) > 0) return null;
    return `>=${low} <=${high}`;
  }

  match = new RegExp(`${RANGE_VERSION_TOKEN}\\s+(?:through|to|thru)\\s+${RANGE_VERSION_TOKEN}`).exec(text);
  if (match) {
    const low = stripLeadingV(match[1]);
    const high = stripLeadingV(match[2]);
    const lowParts = numericParts(low);
    const highParts = numericParts(high);
    if (lowParts && highParts && compareParts(lowParts, highParts) > 0) return null;
    return `>=${low} <=${high}`;
  }

  match = new RegExp(`(?:before|prior to|below|earlier than|at most)\\s+${VERSION_TOKEN}`).exec(text);
  if (match) return `<${stripLeadingV(match[1])}`;

  match = new RegExp(
    `(?:patched|fixed|resolved|remediated|addressed|corrected|hardened)\\s+(?:in|by|with)\\s+${VERSION_TOKEN}`,
  ).exec(text);
  if (match) return `<${stripLeadingV(match[1])}`;

  match = new RegExp(`(?:up to and including|up to|through)\\s+${VERSION_TOKEN}`).exec(text);
  if (match) return `<=${stripLeadingV(match[1])}`;

  match = new RegExp(`^${VERSION_TOKEN}\\s+(?:and earlier|or older|or earlier|or below)$`).exec(text);
  if (match) return `<=${stripLeadingV(match[1])}`;

  match = new RegExp(`^${VERSION_TOKEN}\\s+(?:and later|or later|or newer|or above)$`).exec(text);
  if (match) return `>=${stripLeadingV(match[1])}`;

  return null;
}

export interface VersionVerdict {
  verdict: 'AFFECTED' | 'UNAFFECTED' | 'REVIEW';
  provenance: 'semver' | 'numeric' | 'distro-backport' | 'unparseable' | 'empty';
  comparator: string;
}

/**
 * Evaluate whether a deployed version is affected by a range.
 *
 * Returns the verdict string directly for backward compatibility. Use
 * `evaluateVersionDetailed` when provenance metadata is required.
 *
 * includePrerelease: true is an explicit policy decision: a prerelease of the
 * next release (e.g., 1.0.0-rc.1 satisfies <1.0.0) is treated as vulnerable
 * because it is older than the stable release. This is recorded as policy, not
 * an incidental semver flag.
 */
export function evaluateVersion(
  version: string | null,
  range: string,
): 'AFFECTED' | 'UNAFFECTED' | 'REVIEW' {
  return evaluateVersionDetailed(version, range).verdict;
}

export function evaluateVersionDetailed(version: string | null, range: string): VersionVerdict {
  if (!version || !version.trim()) return { verdict: 'REVIEW', provenance: 'empty', comparator: range };
  if (range.length > 200) return { verdict: 'REVIEW', provenance: 'unparseable', comparator: range };

  // A distro rebuild has no portable ordering against an upstream bound.
  if (distributionSuffix(version))
    return {
      verdict: 'REVIEW',
      provenance: 'distro-backport',
      comparator: `distribution-suffix:${version}`,
    };

  const parsed = portableVersion(version);
  if (!parsed) return { verdict: 'REVIEW', provenance: 'unparseable', comparator: range };

  // A prerelease tag is upstream, but without a comparison operator the range
  // says nothing about ordering: letting semver decide a bare tag made every
  // release candidate AFFECTED.
  if (/-\w/.test(parsed) && !/^\s*(?:>=|<=|>|<|=)\S/.test(range))
    return { verdict: 'REVIEW', provenance: 'unparseable', comparator: range };

  const effective = naturalLanguageRange(range) ?? range;
  const terms = effective.trim().split(/\s+/);
  if (terms.length > 8) return { verdict: 'REVIEW', provenance: 'unparseable', comparator: range };

  const normalized: string[] = [];
  for (const term of terms) {
    const match = /^(>=|<=|>|<|=)?([vV]?.*)$/.exec(term);
    if (!match || !match[2]) return { verdict: 'REVIEW', provenance: 'unparseable', comparator: range };
    const bound = portableVersion(match[2]);
    if (!bound) return { verdict: 'REVIEW', provenance: 'unparseable', comparator: range };
    // The bound may itself be a distro rebuild; it has no upstream ordering.
    if (distributionSuffix(bound))
      return { verdict: 'REVIEW', provenance: 'distro-backport', comparator: effective };
    normalized.push(`${match[1] || '='}${bound}`);
  }

  const versionParts = numericParts(parsed);
  const boundsAreNumeric = normalized.every((term) => numericParts(term.replace(/^(>=|<=|>|<|=)?/, '')));

  // SemVer is the right engine only when the deployment and every bound are
  // full, three-component, numeric versions. `semver.validRange` widens a bare
  // "1.9" into a partial range and reads "1.2.3.4" as 1.2.3 with prerelease
  // "4"; both are silent reinterpretations of the enterprise version. Anything
  // else is decided by the numeric comparator below, which models precision.
  const semverEligible =
    /^[0-9]{1,9}\.[0-9]{1,9}\.[0-9]{1,9}(-[a-zA-Z0-9.-]{1,40})?$/.test(parsed) &&
    terms.every(
      (term) => /^(>=|<=|>|<|=)?[vV]?[0-9]{1,9}\.[0-9]{1,9}\.[0-9]{1,9}(-[a-zA-Z0-9.-]{1,40})?$/.test(term),
    );
  const semverComparator = semverEligible ? semver.validRange(normalized.join(' ')) : null;
  if (semverComparator && semver.valid(parsed)) {
    return {
      verdict: semver.satisfies(parsed, semverComparator, { includePrerelease: true })
        ? 'AFFECTED'
        : 'UNAFFECTED',
      provenance: 'semver',
      comparator: semverComparator,
    };
  }

  if (!versionParts || !boundsAreNumeric)
    return { verdict: 'REVIEW', provenance: 'unparseable', comparator: range };

  const width = numericWidth(parsed);
  const lower = [...versionParts];
  // The high end of the deployment's own precision interval. A four-component
  // version is fully specified; a shorter one ("1.2") denotes every build under
  // it, so its upper end is widened rather than zero-padded.
  const upper = [...lower];
  if (width < 4)
    for (let index = width; index < 4; index++) upper[index] = index === 3 ? 9_999_999_999 : 999_999_999;

  let affected = true;
  for (const term of normalized) {
    const match = /^(>=|<=|>|<|=)?(.*)$/.exec(term)!;
    const operator = match[1] || '=';
    const bound = numericParts(match[2])!;
    if (!intervalIsOrderedBy(lower, upper, bound, operator))
      return { verdict: 'REVIEW', provenance: 'unparseable', comparator: normalized.join(' ') };
    const cmpHigh = compareParts(upper, bound);
    const cmpLow = compareParts(lower, bound);
    const satisfies =
      operator === '>' ? cmpLow > 0 :
        operator === '>=' ? cmpLow >= 0 :
          operator === '<' ? cmpHigh < 0 :
            operator === '<=' ? cmpLow <= 0 :
              cmpLow === 0 && cmpHigh === 0;
    if (!satisfies) {
      affected = false;
      break;
    }
  }
  return {
    verdict: affected ? 'AFFECTED' : 'UNAFFECTED',
    provenance: 'numeric',
    comparator: normalized.join(' '),
  };
}
