/**
 * Enterprise CPE 2.3 Strict Component Matcher, SemVer Range Evaluator & PURL Matcher
 * Spec: NIST IR 7695 & Package URL (purl-spec)
 */

import { NvdVersionRange, canCompareRange, evaluateVersionInRange } from './versionComparator.ts';

export interface ParsedCPE {
  prefix: string; // cpe:2.3
  part: string; // a, o, h
  vendor: string;
  product: string;
  version: string;
  update: string;
  edition: string;
  language: string;
  swEdition: string;
  targetSw: string;
  targetHw: string;
  other: string;
  raw: string;
  isValid: boolean;
}

const cpeCache = new Map<string, { value: ParsedCPE; expiresAt: number }>();
const MAX_CPE_CACHE_SIZE = 10000;
const CPE_CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes
const MAX_INVALID_CPE_CACHE = 1000; // Limit invalid CPE cache to prevent pollution

/**
 * Unescapes CPE 2.3 special characters and lowercases for semantic comparison.
 * The NVD CPE dictionary API may return cpeName with different escape
  * representations (e.g. unescaped "+" vs. "\+"), so both sides must be
  * normalized before an exact-match comparison.
  *
  * Three normalizers exist in this codebase and are deliberately different,
  * not drift: this one only unescapes CPE-reserved characters for literal CPE
  * string comparison; `normalizeAliasToken` (below) strips separator
  * characters but preserves symbols like `+` so `c++` and `c` stay distinct
  * products; `normalizeName` (aliasLifecycle.ts) strips everything
  * non-alphanumeric and is used only for auto-alias *derivation*, never for
  * live matching — using it on the matching path would collapse `c++` to `c`.
  * Do not consolidate these without re-running the full test suite; the
  * difference is load-bearing for distinguishing products like C vs C++.
  */
export function normalizeCpeForComparison(cpe: string): string {
  return cpe
    .toLowerCase()
    .replace(/\\([+:\\*?()])/g, '$1');
}

function evictLRU(): void {
  const now = Date.now();
  let evicted = false;
  // First pass: remove expired entries
  for (const [key, entry] of cpeCache) {
    if (entry.expiresAt < now) {
      cpeCache.delete(key);
      evicted = true;
    }
  }
  // Second pass: evict in batches if still over limit
  if (!evicted && cpeCache.size > MAX_CPE_CACHE_SIZE) {
    const toEvict = Math.max(1, Math.floor(cpeCache.size * 0.1));
    const keys = [...cpeCache.keys()].slice(0, toEvict);
    for (const key of keys) cpeCache.delete(key);
  }
}

export function parseCPE23(cpeString: string): ParsedCPE {
  if (!cpeString || typeof cpeString !== 'string') {
    return createEmptyCPE(cpeString, false);
  }

  const cached = cpeCache.get(cpeString);
  if (cached && cached.expiresAt > Date.now()) {
    // Refresh TTL on access
    cpeCache.set(cpeString, { value: cached.value, expiresAt: Date.now() + CPE_CACHE_TTL_MS });
    return cached.value;
  }

  const trimmed = cpeString.trim();
  if (!trimmed.startsWith('cpe:2.3:')) {
    const empty = createEmptyCPE(trimmed, false);
    const invalidCount = cpeCache.size; // Count before adding
    if (invalidCount >= MAX_CPE_CACHE_SIZE) evictLRU();
    // Limit invalid CPE entries to prevent cache pollution
    if (cpeCache.size < MAX_INVALID_CPE_CACHE || cpeCache.has(cpeString)) {
      cpeCache.set(cpeString, { value: empty, expiresAt: Date.now() + CPE_CACHE_TTL_MS });
    }
    return empty;
  }

  const tokens = splitCpeTokens(trimmed.slice(8));

  if (
    tokens.length !== 11 ||
    !['a', 'o', 'h', '*', '-'].includes(tokens[0]) ||
    tokens.some((token) => !token || /(?<!\\)(?:\\\\)*\\$/.test(token))
  ) {
    const empty = createEmptyCPE(trimmed, false);
    if (cpeCache.size >= MAX_CPE_CACHE_SIZE) evictLRU();
    // Limit invalid CPE entries to prevent cache pollution
    if (cpeCache.size < MAX_INVALID_CPE_CACHE || cpeCache.has(cpeString)) {
      cpeCache.set(cpeString, { value: empty, expiresAt: Date.now() + CPE_CACHE_TTL_MS });
    }
    return empty;
  }

  const result: ParsedCPE = {
    prefix: 'cpe:2.3',
    part: tokens[0]?.toLowerCase() || '*',
    vendor: tokens[1]?.toLowerCase() || '*',
    product: tokens[2]?.toLowerCase() || '*',
    version: tokens[3]?.toLowerCase() || '*',
    update: tokens[4]?.toLowerCase() || '*',
    edition: tokens[5]?.toLowerCase() || '*',
    language: tokens[6]?.toLowerCase() || '*',
    swEdition: tokens[7]?.toLowerCase() || '*',
    targetSw: tokens[8]?.toLowerCase() || '*',
    targetHw: tokens[9]?.toLowerCase() || '*',
    other: tokens[10]?.toLowerCase() || '*',
    raw: trimmed,
    isValid: true,
  };

  if (cpeCache.size >= MAX_CPE_CACHE_SIZE) evictLRU();
  cpeCache.set(cpeString, { value: result, expiresAt: Date.now() + CPE_CACHE_TTL_MS });
  return result;
}

function splitCpeTokens(str: string): string[] {
  const result: string[] = [];
  let current = '';
  let escaped = false;

  for (let i = 0; i < str.length; i++) {
    const char = str[i];
    if (escaped) {
      current += char;
      escaped = false;
    } else if (char === '\\') {
      escaped = true;
      current += char;
    } else if (char === ':') {
      result.push(current);
      current = '';
    } else {
      current += char;
    }
  }
  result.push(current);
  return result;
}

function createEmptyCPE(raw: string, isValid: boolean): ParsedCPE {
  return {
    prefix: 'cpe:2.3',
    part: '*',
    vendor: '*',
    product: '*',
    version: '*',
    update: '*',
    edition: '*',
    language: '*',
    swEdition: '*',
    targetSw: '*',
    targetHw: '*',
    other: '*',
    raw: raw || '',
    isValid,
  };
}

type GlobToken = { type: 'star' } | { type: 'any' } | { type: 'literal'; value: string };

function globTokens(value: string): GlobToken[] {
  const tokens: GlobToken[] = [];
  let escaped = false;
  for (const char of value.toLowerCase()) {
    if (escaped) {
      tokens.push({ type: 'literal', value: char });
      escaped = false;
    } else if (char === '\\') {
      escaped = true;
    } else if (char === '*') {
      tokens.push({ type: 'star' });
    } else if (char === '?') {
      tokens.push({ type: 'any' });
    } else {
      tokens.push({ type: 'literal', value: char });
    }
  }
  return tokens;
}

/**
 * Decides whether two CPE component globs can describe the same concrete
 * value. A wildcard-versus-wildcard comparison cannot simply be accepted:
 * `2.*` and `1.*` are disjoint, while `1.*` and `1.2*` overlap. This is the
 * standard non-emptiness check for the intersection of two glob languages.
 */
function globIntersects(leftValue: string, rightValue: string): boolean {
  const left = globTokens(leftValue);
  const right = globTokens(rightValue);
  const memo = new Map<string, boolean>();
  const onlyStars = (tokens: GlobToken[], from: number) =>
    tokens.slice(from).every((token) => token.type === 'star');
  const visit = (i: number, j: number): boolean => {
    if (i === left.length && j === right.length) return true;
    if (i === left.length) return onlyStars(right, j);
    if (j === right.length) return onlyStars(left, i);
    const key = `${i}:${j}`;
    const cached = memo.get(key);
    if (cached !== undefined) return cached;
    const a = left[i],
      b = right[j];
    let result: boolean;
    if (a.type === 'star') {
      // The star can match the empty string, or consume whatever b[j] matches.
      result = visit(i + 1, j) || visit(i, j + 1);
    } else if (a.type === 'any') {
      result = b.type === 'star' ? visit(i, j + 1) || visit(i + 1, j) : visit(i + 1, j + 1);
    } else {
      result =
        b.type === 'star'
          ? visit(i, j + 1) || visit(i + 1, j)
          : b.type === 'any'
            ? visit(i + 1, j + 1)
            : a.value === b.value && visit(i + 1, j + 1);
    }
    memo.set(key, result);
    return result;
  };
  return visit(0, 0);
}

function hasUnescapedCpeWildcard(value: string): boolean {
  if (value === '*') return false;
  let escaped = false;
  for (const char of value) {
    if (escaped) {
      escaped = false;
      continue;
    }
    if (char === '\\') {
      escaped = true;
      continue;
    }
    if (char === '*' || char === '?') return true;
  }
  return false;
}

/** Unescapes CPE 2.3 component escapes for a plain literal comparison. */
function cpeLiteral(value: string): string {
  let result = '';
  let escaped = false;
  for (const char of value.toLowerCase()) {
    if (escaped) {
      result += char;
      escaped = false;
    } else if (char === '\\') {
      escaped = true;
    } else {
      result += char;
    }
  }
  return result;
}

function matchComponent(assetAttr: string, vulnAttr: string): boolean {
  if (assetAttr === '*' || vulnAttr === '*') return true;
  if (assetAttr === '-' && vulnAttr === '-') return true;
  if (assetAttr === '-' || vulnAttr === '-') return false;

  // Wildcard components are compared as glob languages. Building a RegExp with
  // one `.*` per wildcard allows catastrophic backtracking on hostile values,
  // so the memoized intersection check handles every wildcard pair instead.
  if (hasUnescapedCpeWildcard(assetAttr) || hasUnescapedCpeWildcard(vulnAttr)) {
    return globIntersects(assetAttr, vulnAttr);
  }
  return cpeLiteral(assetAttr) === cpeLiteral(vulnAttr);
}

function escapeCpeToken(value: string): string {
  return value.replace(/\\/g, '\\\\').replace(/:/g, '\\:');
}

/** Inventory fields are operator-facing, so map them to the same component
 * conventions used by NVD CPEs before substituting them for a wildcard. */
function inventoryCpeToken(value: string): string {
  return escapeCpeToken(
    value
      .toLowerCase()
      .trim()
      .replace(/[^a-z0-9_.-]/g, '_'),
  );
}

function isGenericCpeComponent(value: string): boolean {
  return value === '*' || hasUnescapedCpeWildcard(value);
}

/**
 * Free text is the weakest matching path, so a substring test is not enough:
 * a two-letter vendor such as `os` or `ai` occurs inside `most`, `cost` and
 * `maintain`. Require each identity word to appear as a whole token, and treat
 * identities made only of very short words as too ambiguous for prose. Those
 * still match through strict CPE, alias or PURL evidence.
 */
const TEXT_IDENTITY_MIN_WORD = 3;
const textWordPatterns = new Map<string, RegExp>();
const MAX_TEXT_WORD_PATTERNS = 2000;

function textWordPattern(word: string): RegExp {
  const cached = textWordPatterns.get(word);
  if (cached) return cached;
  const escaped = word.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const pattern = new RegExp(`(?<![a-z0-9])${escaped}(?![a-z0-9])`);
  if (textWordPatterns.size >= MAX_TEXT_WORD_PATTERNS) {
    // Evict oldest 10% instead of clearing all
    const toEvict = Math.max(1, Math.floor(textWordPatterns.size * 0.1));
    const keys = [...textWordPatterns.keys()].slice(0, toEvict);
    for (const key of keys) textWordPatterns.delete(key);
  }
  textWordPatterns.set(word, pattern);
  return pattern;
}

function containsIdentityWords(text: string, value: string): boolean {
  const words = value
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter(Boolean);
  const significant = words.filter((word) => word.length >= TEXT_IDENTITY_MIN_WORD);
  // `os`, `ai`, `go` and `3m` are real names but not usable as prose evidence.
  if (!significant.length) return false;
  // Prefer the long words; for a multi-word identity that also contains short
  // tokens (for example `f5 big_ip`) keep the short ones so `f5` cannot be
  // dropped from its own name.
  const required = significant.length >= 2 || words.length === 1 ? significant : words;
  return required.every((word) => textWordPattern(word).test(text));
}

/**
 * Fixed CPE criteria that describe the platform rather than the product name.
 * Once two CPEs describe the same identity (directly or through the alias
 * thesaurus), a conflict here is an authoritative exclusion, not a spelling
 * difference.
 */
const CPE_PLATFORM_FIELDS = [
  'part',
  'update',
  'edition',
  'language',
  'swEdition',
  'targetSw',
  'targetHw',
  'other',
] as const;

function cpeCriterionConflict(asset: ParsedCPE, vuln: ParsedCPE): boolean {
  if (CPE_PLATFORM_FIELDS.some((field) => !matchComponent(asset[field], vuln[field]))) return true;
  return (
    asset.version !== '*' &&
    asset.version !== '-' &&
    vuln.version !== '*' &&
    vuln.version !== '-' &&
    !matchComponent(asset.version, vuln.version)
  );
}

export interface AliasIdentityVerification {
  verified: boolean;
  conflicts: string[];
}

/** Verifies namespace and edition fields before an alias may widen identity. */
export function verifyAliasNamespaceEdition(asset: ParsedCPE, vuln: ParsedCPE): AliasIdentityVerification {
  const conflicts: string[] = [];
  if (asset.part !== '*' && vuln.part !== '*' && asset.part !== vuln.part) conflicts.push('namespace.part');
  for (const field of ['edition', 'swEdition', 'targetSw', 'targetHw'] as const) {
    const assetValue = asset[field];
    const vulnValue = vuln[field];
    if (assetValue !== '*' && assetValue !== '-' && vulnValue !== '*' && vulnValue !== '-' && assetValue !== vulnValue)
      conflicts.push(`edition.${field}`);
  }
  return { verified: conflicts.length === 0, conflicts };
}

/**
 * A CPE whose vendor or product is a wildcard is not evidence of either
 * identity: without help it intersects every advisory for the same part.
 * Resolve the wildcard side from the inventory's own vendor/product fields so
 * a generic inventory CPE matches the product it actually describes.
 */
function resolveGenericCpeIdentity(
  assetCpeStr: string,
  assetVendor: string,
  assetProduct: string,
): { cpe: string; inferred: boolean } {
  const parsed = parseCPE23(assetCpeStr);
  if (!parsed.isValid) return { cpe: assetCpeStr, inferred: false };

  const genericVendor = isGenericCpeComponent(parsed.vendor);
  const genericProduct = isGenericCpeComponent(parsed.product);
  if (!genericVendor && !genericProduct) return { cpe: assetCpeStr, inferred: false };

  let vendor = parsed.vendor;
  let product = parsed.product;
  let inferred = false;
  if (genericVendor && assetVendor.trim()) {
    vendor = inventoryCpeToken(assetVendor);
    inferred = true;
  }
  if (genericProduct && assetProduct.trim()) {
    product = inventoryCpeToken(assetProduct);
    inferred = true;
  }
  if (!inferred) return { cpe: assetCpeStr, inferred: false };

  const tokens = splitCpeTokens(parsed.raw.slice(8));
  tokens[1] = vendor;
  tokens[2] = product;
  return { cpe: `cpe:2.3:${tokens.join(':')}`, inferred: true };
}

export interface CpeAliasOptions {
  /** Passing either map enables symmetric alias resolution for structured CPEs. */
  vendorAliases?: Record<string, string[]>;
  productAliases?: Record<string, string[]>;
}

/**
 * Strict CPE 2.3 Component matching between watch-list asset CPE and vulnerability target CPE.
 *
 * Exact component equality is always evaluated first and remains authoritative.
 * When alias maps are supplied, a structured CPE pair whose vendor/product differ
 * only by a thesaurus entry is matched symmetrically and flagged `viaAlias` so
 * the caller can apply the lower alias confidence and review gate.
 */
export function matchCPE(
  assetCpeStr: string,
  vulnCpeStr: string,
  versionRange?: NvdVersionRange,
  aliases?: CpeAliasOptions,
  /**
   * The inventory entry does not assert a version (wildcard or missing). The
   * product identity still matches, but a version-constrained advisory criterion
   * cannot be proven, so the caller must treat the result as review evidence.
   */
  unverifiedVersion = false,
): {
  matched: boolean;
  viaAlias?: boolean;
  reason?: string;
  unverifiedVersion?: boolean;
  /** True when the unasserted inventory version must go through review. */
  applicabilityRequiresReview?: boolean;
} {
  const asset = parseCPE23(assetCpeStr);
  const vuln = parseCPE23(vulnCpeStr);

  if (!asset.isValid || !vuln.isValid) {
    return { matched: false, reason: 'Invalid CPE syntax' };
  }

  // Part match (application, os, hardware)
  if (!matchComponent(asset.part, vuln.part)) return { matched: false, reason: 'Part mismatch' };

  let viaAlias = false;

  // Exact structured identifiers win. Only an explicit alias map may broaden a
  // vendor/product comparison, and only in the symmetric thesaurus sense.
  if (!matchComponent(asset.vendor, vuln.vendor)) {
    if (!aliases || !matchVendorWithAliases(asset.vendor, vuln.vendor, aliases.vendorAliases))
      return { matched: false, reason: `Vendor mismatch (${asset.vendor} vs ${vuln.vendor})` };
    viaAlias = true;
  }

  // Do not equate separate products through marketing aliases unless the
  // operator/built-in thesaurus explicitly groups them.
  if (!matchComponent(asset.product, vuln.product)) {
    if (!aliases || !matchProductWithAliases(asset.product, vuln.product, aliases.productAliases))
      return { matched: false, reason: `Product mismatch (${asset.product} vs ${vuln.product})` };
    viaAlias = true;
  }

  // Architecture check if specified (e.g. x86_64 vs aarch64)
  if (asset.targetHw !== '*' && vuln.targetHw !== '*' && !matchComponent(asset.targetHw, vuln.targetHw)) {
    return { matched: false, reason: `Target architecture mismatch (${asset.targetHw} vs ${vuln.targetHw})` };
  }

  // Target SW check if specified (e.g. linux vs windows)
  if (asset.targetSw !== '*' && vuln.targetSw !== '*' && !matchComponent(asset.targetSw, vuln.targetSw)) {
    return { matched: false, reason: `Target OS/SW mismatch (${asset.targetSw} vs ${vuln.targetSw})` };
  }

  for (const field of ['update', 'edition', 'language', 'swEdition', 'other'] as const) {
    if (!matchComponent(asset[field], vuln[field])) return { matched: false, reason: `${field} mismatch` };
  }

  if (!matchComponent(asset.version, vuln.version) && !unverifiedVersion)
    return { matched: false, reason: 'Version token mismatch' };

  // An unasserted inventory version is reported as unverified, never as
  // agreement. `applicabilityRequiresReview` is set explicitly rather than
  // omitted: a consumer reading only that field (rather than the separate
  // `unverifiedVersion` flag) must see the same verdict — the previous
  // omission made the two signals disagree on this path.
  if (unverifiedVersion)
    return { matched: true, viaAlias, unverifiedVersion: true, applicabilityRequiresReview: true };

  // Version matching: If explicit NVD version interval provided, evaluate interval
  if (
    versionRange &&
    (versionRange.versionStartIncluding ||
      versionRange.versionStartExcluding ||
      versionRange.versionEndExcluding ||
      versionRange.versionEndIncluding)
  ) {
    // Audit M-1: use the tri-state verdict. An incomparable or wildcard version
    // is INCONCLUSIVE, which surfaces as a review-gated match rather than the
    // boolean sentinel `inRange: true` that reads as "affected".
    const rangeCheck = evaluateVersionInRange(asset.version, versionRange);
    if (rangeCheck.verdict === 'OUT_OF_RANGE') {
      return { matched: false, reason: rangeCheck.reason };
    }
  } else {
    // Standard component matching
    if (!matchComponent(asset.version, vuln.version))
      return { matched: false, reason: 'Version token mismatch' };
  }

  return { matched: true, viaAlias };
}

/**
 * Enterprise Alias & Synonym Thesaurus.
 * These built-in tables are the code-reviewed baseline and are never mutated
 * at runtime. Operator-managed custom aliases (the "Alias Thesaurus" admin
 * page) are stored separately and merged on top at match time by
 * matchVendorWithAliases/matchProductWithAliases — see their `customAliases`
 * parameter. Exported so the admin UI can display the built-in baseline
 * alongside what operators have added.
 */
export const DEFAULT_VENDOR_ALIASES: Record<string, string[]> = {
  microsoft: ['msft'],
  paloaltonetworks: ['palo_alto', 'panw', 'paloalto', 'unit42'],
  fortinet: ['fortinet_technologies'],
  cisco: ['cisco_systems', 'cisco-systems'],
  vmware: ['broadcom', 'vmware_inc'],
  apache: ['apache_software_foundation'],
  f5: ['f5_networks', 'f5-networks', 'f5_inc'],
  kubernetes: ['k8s'],
  openssl: ['openssl_project', 'openssl-org'],
  nginx: ['f5_nginx', 'nginx_inc'],
  docker: ['moby', 'docker_inc'],
  linux: ['linux_kernel', 'kernel'],
  postgresql: ['postgres', 'postgresql_global_development_group'],
  hashicorp: ['hashicorp_inc'],
  sentinelone: ['sentinelone_inc', 'sentinel_one'],
  adobe: ['adobe_systems'],
  canonical: ['ubuntu'],
  // N-able spun out of SolarWinds in 2021. The NVD CPE dictionary still carries
  // the legacy `solarwinds` vendor entries for N-central (not flagged as
  // deprecated), so the alias bridges the old and current vendor spellings and
  // keeps CVE CPE criteria on either vendor correlated with a registered asset.
  'n-able': ['solarwinds'],
};

export const DEFAULT_PRODUCT_ALIASES: Record<string, string[]> = {
  http_server: ['httpd', 'apache2', 'apache_http_server'],
  // GlobalProtect is Palo Alto's separate VPN client product, not a spelling
  // variant of PAN-OS (the firewall OS) — the two have independent CVE
  // histories, so they must not be aliased together. 'panos' is kept: it is
  // only a formatting variant of the same pan_os product string.
  pan_os: ['panos'],
  fortios: ['forti_os', 'fortigate'],
  ios_xe: ['ios-xe', 'cisco_ios_xe'],
  windows_server_2022: ['windows_server', 'win_server_2022'],
  esxi: ['esx', 'vsphere_esxi'],
  big_ip: ['bigip', 'big-ip_access_policy_manager'],
  log4j_core: ['log4j', 'log4j-core'],
  express: ['expressjs'],
};

/**
 * Normalizes an alias token without erasing meaningful identity characters.
 *
 * CPE vendors/products commonly use `_`, `-`, `.` and whitespace as formatting
 * separators, so those are removed. Other symbols are significant: `c++` and
 * `c` are different products, and distinct non-Latin names must not collapse to
 * an empty token (which previously made every CJK-only identity compare equal).
 */
export const normalizeAliasToken = (value: string) =>
  value
    .normalize('NFKC')
    .toLowerCase()
    .replace(/\\(.)/g, '$1')
    .replace(/[\s._-]+/g, '');

/**
 * Returns every spelling in the alias group that contains `value`.
 *
 * Candidate prefilters (the in-process inventory index and the PostgreSQL
 * version index) must expand exactly like the matcher. Expanding only
 * operator-managed aliases would exclude built-in pairs such as
 * `microsoft`/`msft` before `matchVendorWithAliases` ever sees them, silently
 * dropping a finding that the matcher considers valid.
 */
export function aliasGroupKeys(
  value: string,
  base: Record<string, string[]>,
  custom: Record<string, string[]> = {},
): string[] {
  const target = normalizeAliasToken(value);
  if (!target) return [];
  const keys = new Set<string>();
  for (const [canonical, aliases] of Object.entries(mergeAliasTables(base, custom))) {
    const group = [canonical, ...aliases];
    if (!group.some((entry) => normalizeAliasToken(entry) === target)) continue;
    for (const entry of group) keys.add(entry.toLowerCase());
  }
  return [...keys];
}

/** Merges operator-managed additions onto the built-in baseline. Custom
 * entries only ever ADD aliases to a canonical key (or introduce a new
 * canonical key); they cannot remove a built-in alias, so the reviewed
 * baseline can't be silently broken from the admin page.
 *
 * Audit M-2: on the hot matching path this merge used to re-run for every
 * candidate pair (once per component per asset×criterion). The merged result
 * is a pure function of the two tables, so it is memoised by identity — the
 * returned object is frozen to keep the cache coherent. Bounded so a long
 * process with many distinct custom tables cannot grow without limit. */
const mergedAliasCache = new Map<Record<string, string[]>, { base: Record<string, string[]>; merged: Record<string, string[]> }>();
const MERGED_ALIAS_CACHE_LIMIT = 32;

function mergeAliasTables(
  base: Record<string, string[]>,
  custom: Record<string, string[]>,
): Record<string, string[]> {
  if (!Object.keys(custom).length) return base;
  const cached = mergedAliasCache.get(custom);
  // Memoise by table identity: the merged result is a pure function of the two
  // inputs, and both tables are treated as immutable once built.
  if (cached && cached.base === base) return cached.merged;
  // A null prototype keeps operator-controlled keys such as `__proto__` as
  // ordinary data instead of invoking the prototype setter.
  const merged: Record<string, string[]> = Object.assign(Object.create(null), base);
  for (const [canonical, extra] of Object.entries(custom))
    merged[canonical] = [...new Set([...(merged[canonical] || []), ...extra])];
  if (mergedAliasCache.size >= MERGED_ALIAS_CACHE_LIMIT) {
    const first = mergedAliasCache.keys().next().value;
    if (first !== undefined) mergedAliasCache.delete(first);
  }
  mergedAliasCache.set(custom, { base, merged });
  return merged;
}

/** Converts persisted operator-managed alias rows into the canonical -> aliases[]
 * shape matchVendorWithAliases/matchProductWithAliases expect, scoped to one of
 * VENDOR/PRODUCT and merging any rows that repeat the same canonical key. */
export function buildAliasMap(
  entries: { scope: 'VENDOR' | 'PRODUCT'; canonical: string; aliases: string[] }[],
  scope: 'VENDOR' | 'PRODUCT',
): Record<string, string[]> {
  const map: Record<string, string[]> = Object.create(null);
  for (const entry of entries) {
    if (entry.scope !== scope) continue;
    const key = entry.canonical.toLowerCase().trim();
    map[key] = [...new Set([...(map[key] || []), ...entry.aliases.map((a) => a.toLowerCase().trim())])];
  }
  return map;
}

export function matchVendorWithAliases(
  assetVendor: string,
  vulnVendor: string,
  customAliases: Record<string, string[]> = {},
): boolean {
  if (matchComponent(assetVendor, vulnVendor)) return true;

  const a = normalizeAliasToken(assetVendor);
  const v = normalizeAliasToken(vulnVendor);

  // Punctuation-only identities carry no comparable name. Treating two empty
  // normalizations as equal would make unrelated symbols (or scripts) match.
  if (!a || !v) return false;
  if (a === v) return true;

  // Check aliases (built-in baseline + any operator-managed custom aliases)
  for (const [canonical, aliases] of Object.entries(
    mergeAliasTables(DEFAULT_VENDOR_ALIASES, customAliases),
  )) {
    const group = [canonical, ...aliases].map(normalizeAliasToken);
    if (group.includes(a) && group.includes(v)) return true;
  }

  return false;
}

export function matchProductWithAliases(
  assetProduct: string,
  vulnProduct: string,
  customAliases: Record<string, string[]> = {},
): boolean {
  if (matchComponent(assetProduct, vulnProduct)) return true;

  const a = normalizeAliasToken(assetProduct);
  const v = normalizeAliasToken(vulnProduct);

  if (!a || !v) return false;
  if (a === v) return true;

  for (const [canonical, aliases] of Object.entries(
    mergeAliasTables(DEFAULT_PRODUCT_ALIASES, customAliases),
  )) {
    const group = [canonical, ...aliases].map(normalizeAliasToken);
    if (group.includes(a) && group.includes(v)) return true;
  }

  return false;
}

/**
 * Package identity (`npm/express`, `npm/@scope/name`) used to index PURL inventory.
 *
 * Single canonical implementation (audit H-2): the engine and the PostgreSQL
 * version index previously carried divergent copies, and the engine's copy did
 * not respect the npm scope boundary, so scoped packages were indexed
 * differently by the in-process prefilter and the database pushdown. Mirrors
 * `matchPurl`'s identity rule exactly.
 */
export function purlIdentity(purl: string): string | null {
  if (!purl) return null;
  const match = /^pkg:([a-z][a-z0-9.+-]*)\/([^?#]+)/.exec(purl.trim());
  if (!match) return null;
  const path = match[2];
  // A leading `@` is the npm scope, not a version delimiter.
  const at = path.lastIndexOf('@');
  const versionAt = at > path.indexOf('/') + 1 ? at : -1;
  return `${match[1]}/${versionAt > 0 ? path.slice(0, versionAt) : path}`;
}

/**
 * Package URL (PURL) matcher e.g. pkg:npm/express@4.18.2
 */
export function matchPurl(assetPurl: string, vulnPurl: string): boolean {
  if (!assetPurl || !vulnPurl) return false;
  // Keep package names case-sensitive. Ignore neither version nor qualifiers.
  const parse = (value: string) => {
    const match = /^pkg:([a-z][a-z0-9.+-]*)\/([^?#]+)(\?[^#]*)?(#.*)?$/.exec(value.trim());
    if (!match) return null;
    const path = match[2];
    // A leading `@` is the npm scope, not a version delimiter. Only an `@`
    // after the package path is a version separator, so `pkg:npm/@scope/name`
    // keeps its full identity instead of becoming `npm/@scope/`.
    const at = path.lastIndexOf('@');
    const versionAt = at > path.indexOf('/') + 1 ? at : -1;
    return {
      identity: `${match[1]}/${versionAt > 0 ? path.slice(0, versionAt) : path}`,
      version: versionAt > 0 ? path.slice(versionAt + 1) : '',
      qualifiers: match[3] || '',
      subpath: match[4] || '',
    };
  };
  const a = parse(assetPurl),
    v = parse(vulnPurl);
  return (
    !!a &&
    !!v &&
    a.identity === v.identity &&
    (!v.version || a.version === v.version) &&
    a.qualifiers === v.qualifiers &&
    a.subpath === v.subpath
  );
}

export interface MatchResult {
  matched: boolean;
  method:
    | 'STRICT_CPE_INTERVAL'
    | 'STRICT_CPE'
    | 'PURL_EXACT'
    | 'VENDOR_PRODUCT_ALIAS'
    | 'VENDOR_PRODUCT_FALLBACK'
    | 'NONE';
  matchedCpe?: string;
  confidence: number; // 0 to 100
  evidence: string;
  suppressedByVex?: boolean;
  suppressedReason?: string;
  applicabilityRequiresReview?: boolean;
  /** Matched a complete product-wide registration (every component but vendor/product wildcarded). */
  productWideAllVersions?: boolean;
}

/**
 * Enterprise evaluation combining CPE 2.3 intervals, PURL, alias thesaurus, and de-noising
 */
export function matchesWatchlistItem(
  assetCpes: string[],
  assetVendor: string,
  assetProduct: string,
  vulnCpeMatches: string[],
  vulnTitle: string,
  vulnDescription: string,
  versionRange?: NvdVersionRange,
  assetPurls?: string[],
  vulnPurls?: string[],
  assetTargetHw?: string,
  vulnTargetHw?: string,
  evaluatePackages = true,
  customVendorAliases: Record<string, string[]> = {},
  customProductAliases: Record<string, string[]> = {},
  assetVersionInput?: string,
  allowProductOnlyFallback = false,
): MatchResult {
  let bestMatch: MatchResult | undefined;
  const retain = (candidate: MatchResult) => {
    if (!bestMatch || candidate.confidence > bestMatch.confidence) bestMatch = candidate;
  };
  // 1. Architecture De-noising check
  if (assetTargetHw && vulnTargetHw && assetTargetHw !== '*' && vulnTargetHw !== '*') {
    const hwA = assetTargetHw.toLowerCase();
    const hwV = vulnTargetHw.toLowerCase();
    if (hwA !== hwV) {
      return {
        matched: false,
        method: 'NONE',
        confidence: 0,
        evidence: `De-noised: Target architecture mismatch (${assetTargetHw} vs ${vulnTargetHw})`,
      };
    }
  }

  // 2. PURL Matching if present
  if (evaluatePackages && assetPurls && vulnPurls) {
    for (const ap of assetPurls) {
      for (const vp of vulnPurls) {
        const assetMain = ap.split(/[?#]/)[0];
        const atIdx = assetMain.lastIndexOf('@');
        const packageVersion = atIdx > assetMain.indexOf('/') + 1 ? assetMain.slice(atIdx + 1) : '';
        const hasVersion = atIdx > assetMain.indexOf('/') + 1;
        const vulnMain = vp.split(/[?#]/)[0];
        const vulnAtIdx = vulnMain.lastIndexOf('@');
        const vulnHasVersion = vulnAtIdx > vulnMain.indexOf('/') + 1;
        if (!matchPurl(ap, vp)) continue;
        // Audit M-1: exclude a PURL candidate only on a provable OUT_OF_RANGE.
        // An INCONCLUSIVE (incomparable) package version must stay in play for
        // review; the old boolean sentinel folded both into `inRange`.
        if (
          versionRange &&
          hasVersion &&
          evaluateVersionInRange(packageVersion, versionRange).verdict === 'OUT_OF_RANGE'
        )
          continue;
        if (versionRange) {
          const verified = hasVersion && canCompareRange(packageVersion, versionRange);
          retain({
            matched: true,
            method: 'PURL_EXACT',
            confidence: verified ? 95 : 70,
            matchedCpe: ap,
            evidence: verified
              ? `Matched package dependency via PURL with verified version range: ${vp} (95% confidence)`
              : `Matched package name via PURL; installed version or range requires review: ${vp} (70% confidence)`,
            applicabilityRequiresReview: !verified,
          });
          continue;
        }
        // Without a range, a version-less advisory PURL only proves the package
        // identity. Treat it as review evidence rather than an exact correlation.
        const verified = hasVersion && vulnHasVersion;
        retain({
          matched: true,
          method: 'PURL_EXACT',
          confidence: verified ? 95 : 70,
          matchedCpe: ap,
          evidence: verified
            ? `Matched package dependency via PURL: ${vp} (95% confidence)`
            : `Matched package name via PURL without a version constraint; applicability requires review: ${vp} (70% confidence)`,
          applicabilityRequiresReview: !verified,
        });
      }
    }
  }

  // 3. Strict CPE 2.3 comparison with NVD version interval evaluation
  //
  // Audit M-7: each asset CPE is resolved and parsed once, not once per advisory
  // criterion. On a large run the parse cache thrashes, so the repeated parses
  // were uncached work on the hottest loop in the engine.
  const preparedAssetCpes = assetCpes.map((rawAssetCpe) => {
    const { cpe: assetCpe, inferred: genericIdentity } = resolveGenericCpeIdentity(
      rawAssetCpe,
      assetVendor,
      assetProduct,
    );
    const parsed = parseCPE23(assetCpe);
    return {
      assetCpe,
      genericIdentity,
      parsed,
      // Product-level registrations cover all versions. Partial patterns still
      // require intersection checks; unknown concrete versions stay review-gated.
      versionUnasserted: parsed.isValid && (!parsed.version || parsed.version === '*'),
    };
  });
  const isProductWideRegistration = (asset: ParsedCPE, versionUnasserted: boolean, genericIdentity: boolean) =>
    versionUnasserted &&
    !genericIdentity &&
    asset.part !== '*' &&
    asset.vendor !== '*' &&
    asset.product !== '*' &&
    !hasUnescapedCpeWildcard(asset.vendor) &&
    !hasUnescapedCpeWildcard(asset.product) &&
    (['update', 'edition', 'language', 'swEdition', 'targetSw', 'targetHw', 'other'] as const).every(
      (field) => asset[field] === '*' || asset[field] === '-',
    );
  const hasProductWideRegistration = preparedAssetCpes.some(({ genericIdentity, parsed, versionUnasserted }) =>
    isProductWideRegistration(parsed, versionUnasserted, genericIdentity),
  );
  for (const { assetCpe, genericIdentity, parsed: assetParsed, versionUnasserted } of preparedAssetCpes) {
    for (const vulnCpe of vulnCpeMatches) {
      const vulnParsed = parseCPE23(vulnCpe);
      const vulnConstrainsVersion =
        vulnParsed.isValid &&
        vulnParsed.version !== '*' &&
        vulnParsed.version !== '-' &&
        !hasUnescapedCpeWildcard(vulnParsed.version);
      const matchRes = matchCPE(
        assetCpe,
        vulnCpe,
        versionRange,
        {
          vendorAliases: customVendorAliases,
          productAliases: customProductAliases,
        },
        versionUnasserted && vulnConstrainsVersion,
      );
      if (matchRes.matched) {
        const asset = assetParsed;
        const vuln = vulnParsed;
        const rangeHasBounds = Boolean(versionRange && Object.values(versionRange).some(Boolean));
        const rangeNeedsReview = Boolean(
          rangeHasBounds &&
          !versionUnasserted && !canCompareRange(asset.version, versionRange!),
        );
        if (matchRes.viaAlias) {
          // A structured CPE pair resolved only through the thesaurus is a
          // product correlation, not a verified exact token match. Keep it
          // below the auto-dispatch threshold and require review when the
          // advisory constrains a version the inventory cannot prove.
          retain({
            matched: true,
            method: 'VENDOR_PRODUCT_ALIAS',
            confidence: 85,
            matchedCpe: vulnCpe,
            evidence: `Matched structured CPE through the symmetric alias thesaurus (${asset.vendor}/${asset.product} -> ${vuln.vendor}/${vuln.product}) (85% confidence)`,
            applicabilityRequiresReview: rangeNeedsReview || genericIdentity,
          });
          continue;
        }
        // A complete product-wide registration declares every version and
        // remaining CPE component in scope. Partial patterns and inferred
        // identities still require review when criteria are unknown.
        const contextFields = [
          'part',
          'vendor',
          'product',
          ...(versionUnasserted ? [] : ['version'] as const),
          'update',
          'edition',
          'language',
          'swEdition',
          'targetSw',
          'targetHw',
          'other',
        ] as const;
        const productWideAllVersions = isProductWideRegistration(asset, versionUnasserted, genericIdentity);
        const contextNeedsReview = !productWideAllVersions && (
          contextFields.some(
            (field) =>
              (asset[field as keyof ParsedCPE] as string) === '*' &&
              (vuln[field as keyof ParsedCPE] as string) !== '*',
          ) ||
          contextFields.some(
            (field) =>
              hasUnescapedCpeWildcard(asset[field as keyof ParsedCPE] as string) ||
              hasUnescapedCpeWildcard(vuln[field as keyof ParsedCPE] as string),
          ));
        const requiresReview = rangeNeedsReview || contextNeedsReview || genericIdentity ||
          (Boolean(matchRes.unverifiedVersion) && !versionUnasserted);
        retain({
          matched: true,
          method: versionRange ? 'STRICT_CPE_INTERVAL' : 'STRICT_CPE',
          confidence: requiresReview ? 70 : versionRange ? 100 : 90,
          matchedCpe: vulnCpe,
          evidence: genericIdentity
            ? 'Matched CPE product identity inferred from the inventory record; confirm the generic CPE is intended (70% confidence)'
            : versionRange
              ? requiresReview
                ? 'Matched strict CPE 2.3 product identifiers; version or architecture applicability requires review'
                : `Matched strict CPE 2.3 component tokens + verified in version interval [< ${versionRange.versionEndExcluding || versionRange.versionEndIncluding}] (100% confidence)`
              : requiresReview
                ? 'Matched strict CPE 2.3 component tokens; review required (wildcard version or context) (70% confidence)'
                : 'Matched strict CPE 2.3 component tokens (90% confidence)',
          applicabilityRequiresReview: requiresReview,
          productWideAllVersions,
        });
      }
    }
  }

  if (bestMatch) return bestMatch;

  // Package identity is exact: a PURL-vs-PURL mismatch remains authoritative.
  // A CPE mismatch, by contrast, may only mean the two sides spell the same
  // vendor/product differently, which the alias and fallback steps below can
  // still resolve.
  if (assetPurls?.length && vulnPurls?.length) {
    return {
      matched: false,
      method: 'NONE',
      confidence: 0,
      evidence: 'Package identifiers did not match',
    };
  }

  // 4. Vendor / Product Alias Resolution
  const normVendor = assetVendor.toLowerCase().trim();
  const normProduct = assetProduct.toLowerCase().trim();
  // The alias path is the last structured option before free text. Evaluate the
  // advisory's version interval against every inventory version when known so an
  // alias cannot create a finding for explicitly unaffected releases, while one
  // affected instance of a multi-CPE inventory row is still enough to match.
  const versionCandidates = new Set<string>();
  const declaredVersion = (assetVersionInput || '').trim();
  if (declaredVersion) versionCandidates.add(declaredVersion);
  for (const cpe of assetCpes) {
    const parsed = parseCPE23(cpe);
    if (parsed.isValid && parsed.version && parsed.version !== '*' && parsed.version !== '-')
      versionCandidates.add(parsed.version);
  }
  const assetVersions = [...versionCandidates];
  const rangeHasBounds = Boolean(versionRange && Object.values(versionRange).some(Boolean));
  const comparableVersions =
    rangeHasBounds && versionRange
      ? assetVersions.filter((version) => canCompareRange(version, versionRange))
      : [];
  const inRangeVersions =
    rangeHasBounds && versionRange
      ? comparableVersions.filter(
          // Audit M-1: only a provable IN_RANGE counts. An incomparable version
          // is INCONCLUSIVE and must not claim "inside the advisory range".
          (version) => evaluateVersionInRange(version, versionRange).verdict === 'IN_RANGE',
        )
      : [];
  // Exclude only when every known version is comparable and provably outside.
  // One unparseable identifier means applicability still needs review.
  const allVersionsProvablyOutside = Boolean(
    rangeHasBounds &&
    versionRange &&
    assetVersions.length > 0 &&
    comparableVersions.length === assetVersions.length &&
    inRangeVersions.length === 0,
  );

  // A CPE mismatch is only allowed to fall through when it concerns the
  // vendor/product names. If the structured identity is the same and a CPE
  // criterion explicitly excludes the inventory (version token, part,
  // architecture, target OS or another fixed field), that exclusion remains
  // authoritative. Otherwise a text fallback could re-admit a release the CPE
  // evidence already proved inapplicable.
  const sameStructuredIdentity = (asset: ParsedCPE, vuln: ParsedCPE) =>
    (matchComponent(asset.vendor, vuln.vendor) ||
      matchVendorWithAliases(asset.vendor, vuln.vendor, customVendorAliases)) &&
    (matchComponent(asset.product, vuln.product) ||
      matchProductWithAliases(asset.product, vuln.product, customProductAliases));
  // Resolve generic inventory CPEs with the same inventory fields used by the
  // strict comparison so their version/platform cannot be attributed to an
  // unrelated advisory product.
  const resolvedAssetCpes = assetCpes
    .map((cpe) => parseCPE23(resolveGenericCpeIdentity(cpe, assetVendor, assetProduct).cpe))
    .filter((parsed) => parsed.isValid);
  // The exclusion is authoritative only when *every* same-identity pair
  // conflicts. One inventory CPE with a different (or wildcard) version must not
  // suppress the fallback when another CPE of the same identity is compatible.
  let sawSameIdentity = false;
  let compatibleSameIdentity = false;
  for (const asset of resolvedAssetCpes) {
    for (const vulnCpe of vulnCpeMatches) {
      const vuln = parseCPE23(vulnCpe);
      if (!vuln.isValid || !sameStructuredIdentity(asset, vuln)) continue;
      sawSameIdentity = true;
      if (!cpeCriterionConflict(asset, vuln)) {
        compatibleSameIdentity = true;
        break;
      }
    }
    if (compatibleSameIdentity) break;
  }
  if (resolvedAssetCpes.length > 0 && sawSameIdentity && !compatibleSameIdentity) {
    return {
      matched: false,
      method: 'NONE',
      confidence: 0,
      evidence: 'Structured CPE criteria explicitly excluded the inventory version or platform',
    };
  }

  for (const vulnCpe of vulnCpeMatches) {
    const parsedVuln = parseCPE23(vulnCpe);
    if (parsedVuln.isValid) {
      if (
        matchVendorWithAliases(normVendor, parsedVuln.vendor, customVendorAliases) &&
        matchProductWithAliases(normProduct, parsedVuln.product, customProductAliases)
      ) {
        // An alias only broadens the vendor/product names. The remaining CPE
        // criteria (part, architecture, target OS, edition, language, update
        // and concrete version) stay authoritative on this path too, so a
        // Windows-only advisory cannot correlate a Linux asset merely because
        // the vendor spellings differ.
        if (
          resolvedAssetCpes.length > 0 &&
          !resolvedAssetCpes.some((asset) => !cpeCriterionConflict(asset, parsedVuln))
        )
          continue;
        let applicabilityRequiresReview = rangeHasBounds;
        if (
          [parsedVuln.edition, parsedVuln.swEdition, parsedVuln.targetSw, parsedVuln.targetHw].some(
            (value) => value !== '*' && value !== '-',
          ) && resolvedAssetCpes.length === 0
        ) applicabilityRequiresReview = true;
        let versionVerified = false;
        let matchedVersion: string | undefined;
        if (rangeHasBounds && versionRange) {
          if (allVersionsProvablyOutside) continue;
          if (inRangeVersions.length) {
            versionVerified = true;
            matchedVersion = inRangeVersions[0];
            applicabilityRequiresReview = false;
          }
        }
        return {
          matched: true,
          method: 'VENDOR_PRODUCT_ALIAS',
          confidence: 85,
          matchedCpe: vulnCpe,
          evidence: versionVerified
            ? `Resolved via Enterprise Alias Thesaurus (${normVendor}/${normProduct} -> ${parsedVuln.vendor}/${parsedVuln.product}); inventory version ${matchedVersion} is inside the advisory range (85% confidence)`
            : `Resolved via Enterprise Alias Thesaurus (${normVendor}/${normProduct} -> ${parsedVuln.vendor}/${parsedVuln.product}) (85% confidence)`,
          applicabilityRequiresReview,
        };
      }
    }
  }

  // 5. Fallback Heuristic
  const fullText = `${vulnTitle} ${vulnDescription}`.toLowerCase();
  const productOnlyKevFallback =
    allowProductOnlyFallback &&
    hasProductWideRegistration &&
    normProduct &&
    containsIdentityWords(fullText, normProduct);
  if (
    normVendor &&
    normProduct &&
    ((containsIdentityWords(fullText, normVendor) && containsIdentityWords(fullText, normProduct)) ||
      productOnlyKevFallback)
  ) {
    // Do not let the text fallback re-admit a release that the advisory range
    // explicitly excludes when every inventory version is comparable.
    if (rangeHasBounds && allVersionsProvablyOutside)
      return { matched: false, method: 'NONE', confidence: 0, evidence: 'Version outside advisory range' };
    return {
      matched: true,
      method: 'VENDOR_PRODUCT_FALLBACK',
      confidence: 70,
      matchedCpe: assetCpes[0] || `cpe:2.3:a:${normVendor}:${normProduct}:*:*:*:*:*:*:*:*`,
      evidence: `Matched vendor "${normVendor}" and product "${normProduct}" in advisory text (70% confidence)`,
      productWideAllVersions: productOnlyKevFallback || undefined,
    };
  }

  return { matched: false, method: 'NONE', confidence: 0, evidence: 'No component or keyword correlation' };
}

export function generateCPE23(
  part: 'a' | 'o' | 'h',
  vendor: string,
  product: string,
  version: string = '*',
  targetHw: string = '*',
): string {
  const escape = (value: string) => value.replace(/\\/g, '\\\\').replace(/:/g, '\\:');
  const cleanPart = part || 'a';
  const cleanVendor = escape(
    (vendor || 'any')
      .toLowerCase()
      .trim()
      .replace(/[^a-z0-9_.-]/g, '_'),
  );
  const cleanProduct = escape(
    (product || 'any')
      .toLowerCase()
      .trim()
      .replace(/[^a-z0-9_.-]/g, '_'),
  );
  const cleanVersion = version && version !== '*' ? escape(version.trim()) : '*';
  const cleanHw = targetHw && targetHw !== '*' ? escape(targetHw.trim()) : '*';

  return `cpe:2.3:${cleanPart}:${cleanVendor}:${cleanProduct}:${cleanVersion}:*:*:*:*:*:${cleanHw}:*`;
}
