import type { Db } from './db.ts';
import type { NormalizedCVE, WatchListItem } from '../src/types/index.ts';
import type { NvdVersionRange } from '../src/utils/versionComparator.ts';
import {
  DEFAULT_PRODUCT_ALIASES,
  DEFAULT_VENDOR_ALIASES,
  aliasGroupKeys,
  normalizeAliasToken,
  parseCPE23,
  purlIdentity,
} from '../src/utils/cpeMatcher.ts';

/**
 * Typed version ordinal used by the PostgreSQL candidate index.
 *
 * Only plain dotted numeric versions are encoded. Anything else (prereleases,
 * distribution revisions, wildcards, non-numeric vendor tags) returns `null`,
 * which the index treats as "cannot exclude" so the authoritative JS matcher
 * still evaluates the pair. This keeps the index a conservative superset.
 *
 * Four components of at most four digits each are packed base-10000 into an
 * int8, preserving numeric ordering for the overwhelmingly common version
 * shapes without ever overflowing.
 */
const ORDINAL_BASE = 10_000n;
const ORDINAL_COMPONENTS = 4;
const ORDINAL_LIMIT = ORDINAL_BASE ** BigInt(ORDINAL_COMPONENTS);

export function versionOrdinal(version: string | undefined): bigint | null {
  if (!version) return null;
  const trimmed = version.trim().toLowerCase();
  if (!trimmed || trimmed === '*' || trimmed === '-') return null;
  const match = /^(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:\.(\d+))?$/.exec(trimmed);
  if (!match) return null;
  const parts: bigint[] = [];
  for (let index = 1; index <= ORDINAL_COMPONENTS; index++)
    parts.push(match[index] === undefined ? 0n : BigInt(match[index]));
  if (parts.some((part) => part >= ORDINAL_BASE)) return null;
  const ordinal = parts.reduce((acc, part) => acc * ORDINAL_BASE + part, 0n);
  return ordinal < ORDINAL_LIMIT ? ordinal : null;
}

const identityKey = (vendor: string, product: string) =>
  `cpe:${vendor.toLowerCase()}\u001f${product.toLowerCase()}`;

/** Package identity (`npm/express`) used to index PURL inventory. */
const purlKey = (purl: string): string | null => {
  // Canonical parser shared with the matcher and the JS engine (audit H-2):
  // the three copies could drift on scoped npm packages, which silently
  // excluded pairs from this pushdown that the matcher would have accepted.
  const identity = purlIdentity(purl);
  return identity ? `purl:${identity}` : null;
};

export interface MatchIndexOptions {
  vendorAliases?: Record<string, string[]>;
  productAliases?: Record<string, string[]>;
}

/**
 * Mirrors the pipeline's alias-expanded inventory index. Both built-in and
 * operator-managed aliases must participate; otherwise the index would exclude
 * a pair that the authoritative matcher accepts (for example
 * `microsoft`/`msft`).
 */
const aliasKeys = (
  value: string,
  base: Record<string, string[]>,
  aliases: Record<string, string[]> = {},
): string[] => [
  ...new Set([
    value.toLowerCase(),
    // The matcher's alias path ignores punctuation, so `widget_pro` joins
    // `widget-pro`. Index the normalized token or the pushdown drops the pair.
    normalizeAliasToken(value),
    ...aliasGroupKeys(value, base, aliases),
  ]),
];

function cpeIdentities(cpe: string, options: MatchIndexOptions): string[] {
  const parsed = parseCPE23(cpe);
  if (!parsed.isValid) return [];
  if (/[?*]/.test(parsed.vendor) || /[?*]/.test(parsed.product)) return [];
  const vendors = aliasKeys(parsed.vendor, DEFAULT_VENDOR_ALIASES, options.vendorAliases);
  const products = aliasKeys(parsed.product, DEFAULT_PRODUCT_ALIASES, options.productAliases);
  const identities = new Set<string>();
  for (const vendor of vendors)
    for (const product of products) identities.add(identityKey(vendor, product));
  return [...identities];
}

function assetIdentities(asset: WatchListItem, options: MatchIndexOptions): string[] {
  const identities = new Set<string>();
  for (const cpe of asset.cpes) for (const identity of cpeIdentities(cpe, options)) identities.add(identity);
  for (const purl of asset.purls ?? []) {
    const identity = purlKey(purl);
    if (identity) identities.add(identity);
  }
  return [...identities];
}

interface VersionBounds {
  unbounded: boolean;
  start: bigint | null;
  startInclusive: boolean;
  end: bigint | null;
  endInclusive: boolean;
}

const UNBOUNDED: VersionBounds = {
  unbounded: true,
  start: null,
  startInclusive: true,
  end: null,
  endInclusive: true,
};

/**
 * Derives the numeric bounds PostgreSQL can enforce. A declared bound that
 * cannot be encoded makes the whole criterion unbounded: dropping a pair is
 * only safe when every bound in play is provably ordered.
 */
function boundsFor(range: NvdVersionRange | undefined, criterionVersion?: string): VersionBounds {
  const hasRange = Boolean(
    range &&
      (range.versionStartIncluding ||
        range.versionStartExcluding ||
        range.versionEndIncluding ||
        range.versionEndExcluding),
  );
  if (hasRange && range) {
    const startText = range.versionStartIncluding ?? range.versionStartExcluding;
    const endText = range.versionEndIncluding ?? range.versionEndExcluding;
    const start = versionOrdinal(startText);
    const end = versionOrdinal(endText);
    if ((startText && start === null) || (endText && end === null)) return UNBOUNDED;
    return {
      unbounded: false,
      start,
      startInclusive: Boolean(range.versionStartIncluding),
      end,
      endInclusive: Boolean(range.versionEndIncluding),
    };
  }
  // No interval: the criterion's version token must match exactly. Wildcards
  // and unparseable tokens stay unbounded so the matcher decides.
  const exact = versionOrdinal(criterionVersion);
  if (exact === null) return UNBOUNDED;
  return { unbounded: false, start: exact, startInclusive: true, end: exact, endInclusive: true };
}

interface CveIndexRow {
  criterionId: string;
  identities: string[];
  bounds: VersionBounds;
}

function cveIndexRows(cve: NormalizedCVE, options: MatchIndexOptions): CveIndexRow[] | null {
  const rows: CveIndexRow[] = [];
  const details = cve.cpeMatchDetails?.length
    ? cve.cpeMatchDetails.map((detail, index) => ({
        id: `cpe-${index}`,
        criteria: detail.criteria,
        // A per-detail criterion without bounds means "any version of this
        // product"; the product-level range must not leak onto it. This mirrors
        // the pipeline's applicabilitySets, so the index cannot exclude a pair
        // the matcher would accept.
        range:
          detail.range && Object.values(detail.range).some(Boolean) ? detail.range : undefined,
      }))
    : cve.cpeMatches.map((criteria, index) => ({
        id: `cpe-${index}`,
        criteria,
        range: cve.versionRange,
      }));
  for (const detail of details) {
    const identities = cpeIdentities(detail.criteria, options);
    // A wildcard or invalid criterion can match any inventory item; the worker
    // must fall back to its full candidate set for this CVE.
    if (!identities.length) return null;
    const parsed = parseCPE23(detail.criteria);
    rows.push({
      criterionId: detail.id,
      identities,
      bounds: boundsFor(detail.range, parsed.isValid ? parsed.version : undefined),
    });
  }
  if (cve.purls?.length) {
    const identities = cve.purls.map(purlKey).filter((identity): identity is string => !!identity);
    if (identities.length)
      rows.push({
        criterionId: 'purl',
        identities,
        bounds: boundsFor(cve.versionRange),
      });
  }
  return rows.length ? rows : null;
}

interface AssetIndexRow {
  assetId: string;
  identities: string[];
  version: bigint | null;
}

function purlVersion(purl: string): string | null {
  const match = /^pkg:([a-z][a-z0-9.+-]*)\/([^?#]+)/.exec(purl.trim());
  if (!match) return null;
  const path = match[2];
  const at = path.lastIndexOf('@');
  const versionAt = at > path.indexOf('/') + 1 ? at : -1;
  return versionAt > 0 ? path.slice(versionAt + 1) : null;
}

/**
 * Derives one conservative version ordinal for an asset row.
 *
 * The asset index has a single ordinal, but an inventory entry can carry
 * several CPEs and PURLs with different versions. Using the declared
 * `asset.version` blindly would let the SQL pushdown drop a pair whose matching
 * CPE or package is inside the advisory range but whose declared version
 * differs. Only a version every concrete identifier agrees on is safe to use
 * for exclusion; anything ambiguous becomes NULL, which the query treats as
 * "cannot exclude".
 */
function assetVersionOrdinal(asset: WatchListItem): bigint | null {
  const declared = versionOrdinal(asset.version);
  const ordinals: bigint[] = [];
  for (const cpe of asset.cpes) {
    const parsed = parseCPE23(cpe);
    if (!parsed.isValid) continue;
    if (/[?*]/.test(parsed.vendor) || /[?*]/.test(parsed.product)) return null;
    if (!parsed.version || parsed.version === '*' || parsed.version === '-') return null;
    const ordinal = versionOrdinal(parsed.version);
    if (ordinal === null) return null;
    ordinals.push(ordinal);
  }
  for (const purl of asset.purls ?? []) {
    const version = purlVersion(purl);
    if (!version) return null;
    const ordinal = versionOrdinal(version);
    if (ordinal === null) return null;
    ordinals.push(ordinal);
  }
  if (!ordinals.length) return declared;
  const first = ordinals[0];
  if (ordinals.some((ordinal) => ordinal !== first)) return null;
  if (declared !== null && declared !== first) return null;
  return first;
}

function assetIndexRows(assets: WatchListItem[], options: MatchIndexOptions): AssetIndexRow[] {
  return assets
    .filter((asset) => asset.active)
    .map((asset) => ({
      assetId: asset.id,
      identities: assetIdentities(asset, options),
      version: assetVersionOrdinal(asset),
    }));
}

const CHUNK = 500;

/**
 * Refreshes the candidate index from the current corpus and inventory. The
 * pipeline already loads both in full, so a scoped refresh is cheaper and more
 * predictable than wiring index maintenance into every generic record write.
 */
export async function syncMatchIndex(
  db: Db,
  cves: NormalizedCVE[],
  assets: WatchListItem[],
  options: MatchIndexOptions = {},
): Promise<void> {
  const assetRows = assetIndexRows(assets, options);
  const cveRows: {
    cveId: string;
    criterionId: string;
    identities: string[];
    bounds: VersionBounds;
  }[] = [];
  for (const cve of cves) {
    const rows = cveIndexRows(cve, options);
    if (!rows) continue;
    for (const row of rows)
      cveRows.push({
        cveId: cve.cveId,
        criterionId: row.criterionId,
        identities: row.identities,
        bounds: row.bounds,
      });
  }

  for (let offset = 0; offset < assetRows.length; offset += CHUNK) {
    const chunk = assetRows.slice(offset, offset + CHUNK);
    const values: unknown[] = [];
    const params = chunk.map((row, index) => {
      const first = index * 3 + 1;
      values.push(row.assetId, row.identities, row.version === null ? null : row.version.toString());
      return `($${first},$${first + 1}::text[],$${first + 2}::bigint)`;
    });
    await db.query(
      `INSERT INTO match_asset_index(asset_id,identities,version_ordinal) VALUES${params.join(',')}
       ON CONFLICT(asset_id) DO UPDATE SET identities=EXCLUDED.identities,
         version_ordinal=EXCLUDED.version_ordinal,updated_at=now()`,
      values,
    );
  }
  await db.query('DELETE FROM match_asset_index WHERE NOT (asset_id = ANY($1::text[]))', [
    assetRows.map((row) => row.assetId),
  ]);

  for (let offset = 0; offset < cveRows.length; offset += CHUNK) {
    const chunk = cveRows.slice(offset, offset + CHUNK);
    const values: unknown[] = [];
    const params = chunk.map((row, index) => {
      const first = index * 8 + 1;
      values.push(
        row.cveId,
        row.criterionId,
        row.identities,
        row.bounds.start === null ? null : row.bounds.start.toString(),
        row.bounds.startInclusive,
        row.bounds.end === null ? null : row.bounds.end.toString(),
        row.bounds.endInclusive,
        row.bounds.unbounded,
      );
      return `($${first},$${first + 1},$${first + 2}::text[],$${first + 3}::bigint,$${first + 4},$${first + 5}::bigint,$${first + 6},$${first + 7})`;
    });
    await db.query(
      `INSERT INTO match_cve_index(cve_id,criterion_id,identities,start_ordinal,start_inclusive,end_ordinal,end_inclusive,unbounded)
       VALUES${params.join(',')}
       ON CONFLICT(cve_id,criterion_id) DO UPDATE SET identities=EXCLUDED.identities,
         start_ordinal=EXCLUDED.start_ordinal,start_inclusive=EXCLUDED.start_inclusive,
         end_ordinal=EXCLUDED.end_ordinal,end_inclusive=EXCLUDED.end_inclusive,
         unbounded=EXCLUDED.unbounded,updated_at=now()`,
      values,
    );
  }
  await db.query(
    `DELETE FROM match_cve_index
      WHERE NOT (cve_id = ANY($1::text[]))
         OR NOT ((cve_id, criterion_id) IN (
              SELECT cve_id, criterion_id
                FROM unnest($1::text[], $2::text[]) AS t(cve_id, criterion_id)
            ))`,
    // Both arrays must be positionally aligned. De-duplicating the CVE ids here
    // would zip them against a longer criterion array and delete every criterion
    // after the first one for a multi-criterion CVE.
    [cveRows.map((row) => row.cveId), cveRows.map((row) => row.criterionId)],
  );
}

/**
 * Returns the plausible `(cveId, assetId)` pairs for the current index. The
 * query is the pushdown: identity arrays are joined with GIN, and the typed
 * ordinals exclude only pairs whose version is provably outside the interval.
 */
export async function buildCandidatePairs(
  db: Db,
): Promise<Map<string, Set<string>>> {
  const result = await db.query(
    `SELECT DISTINCT c.cve_id, a.asset_id
       FROM match_cve_index c
       JOIN match_asset_index a ON a.identities && c.identities
      WHERE c.unbounded
         OR a.version_ordinal IS NULL
         OR (
              (c.start_ordinal IS NULL
                OR a.version_ordinal > c.start_ordinal
                OR (c.start_inclusive AND a.version_ordinal = c.start_ordinal))
              AND
              (c.end_ordinal IS NULL
                OR a.version_ordinal < c.end_ordinal
                OR (c.end_inclusive AND a.version_ordinal = c.end_ordinal))
            )`,
  );
  const pairs = new Map<string, Set<string>>();
  for (const row of result.rows as { cve_id: string; asset_id: string }[]) {
    const bucket = pairs.get(row.cve_id) || new Set<string>();
    bucket.add(row.asset_id);
    pairs.set(row.cve_id, bucket);
  }
  return pairs;
}

/** Refresh the index and return the candidate pairs in one call. */
export async function refreshCandidatePairs(
  db: Db,
  cves: NormalizedCVE[],
  assets: WatchListItem[],
  options: MatchIndexOptions = {},
): Promise<Map<string, Set<string>>> {
  await syncMatchIndex(db, cves, assets, options);
  return buildCandidatePairs(db);
}
