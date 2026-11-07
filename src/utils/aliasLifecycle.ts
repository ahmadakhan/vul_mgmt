import type { AliasEntry, Finding, NormalizedCVE, WatchListItem } from '../types/index.ts';
import {
  buildAliasMap,
  matchProductWithAliases,
  matchVendorWithAliases,
  parseCPE23,
} from './cpeMatcher.ts';

const AUTO_ALIAS_PREFIX = 'auto:';

/** Automatic relations are retained for this long after their last supporting
 * evidence, then removed. Operators can promote a relation to a manual row to
 * keep it indefinitely, or revoke it to block re-learning. */
export const DEFAULT_AUTO_ALIAS_TTL_DAYS = 30;

/** Stable identity for an automatic alias row. The id only depends on the
 * scope and canonical name, so recomputing the same relation on a later run
 * updates the existing row instead of creating a duplicate. */
export function autoAliasId(scope: 'VENDOR' | 'PRODUCT', canonical: string): string {
  return `${AUTO_ALIAS_PREFIX}${scope.toLowerCase()}:${canonical.trim().toLowerCase()}`;
}

/** Manual rows and operator tombstones are never modified by reconciliation. */
const isProtected = (entry: AliasEntry) =>
  entry.source === 'MANUAL' ||
  entry.source === 'REVOKED' ||
  (entry.source === undefined && !entry.id.startsWith(AUTO_ALIAS_PREFIX));

const relationKey = (scope: string, canonical: string, alias: string) =>
  `${scope.toLowerCase()}\u0000${canonical.trim().toLowerCase()}\u0000${alias.trim().toLowerCase()}`;

/** Pairs an operator explicitly rejected. Automatic learning must never
 * recreate them; only a new operator decision can. */
function revokedPairs(existing: readonly AliasEntry[]): Set<string> {
  const revoked = new Set<string>();
  for (const entry of existing) {
    if (entry.source !== 'REVOKED') continue;
    for (const alias of entry.revokedAliases ?? [])
      revoked.add(relationKey(entry.scope, entry.canonical, alias));
  }
  return revoked;
}

function expiryFor(now: string, ttlDays: number): string | undefined {
  if (ttlDays <= 0) return undefined;
  const start = Date.parse(now);
  if (!Number.isFinite(start)) return undefined;
  return new Date(start + ttlDays * 86_400_000).toISOString();
}

// Deliberately looser than cpeMatcher.ts's normalizeAliasToken: this one is
// for suggesting candidate aliases, not for live matching, and stripping all
// non-alphanumeric characters (including `+`) is intentional here. Do not
// reuse it on the matching path — it would collapse `c++` into `c`.
const normalizeName = (value: string) => value.toLowerCase().replace(/[^a-z0-9]/g, '');

/**
 * Corporate/edition suffixes recognized when two names normalize differently
 * but share the same family name (for example `acme corp` and `acme_inc`).
 * Wholly different vendors/products are rejected by the base-name and prefix
 * checks below, so a misconfigured CPE cannot teach the engine that
 * `Microsoft` and `linux` are the same vendor. Arbitrary abbreviations still
 * require an operator alias or the reviewed built-in table.
 */
const SAFE_NAME_SUFFIXES = new Set(
  [
    'inc',
    'incorporated',
    'corp',
    'corporation',
    'co',
    'company',
    'ltd',
    'limited',
    'llc',
    'plc',
    'gmbh',
    'ag',
    'bv',
    'nv',
    'sa',
    'group',
    'holdings',
    'international',
    'global',
    'technologies',
    'technology',
    'software',
    'systems',
    'system',
    'networks',
    'network',
    'labs',
    'lab',
    'foundation',
    'project',
    'pro',
    'professional',
    'enterprise',
    'standard',
    'edition',
    'cloud',
    'suite',
    'platform',
    'appliance',
    'virtual',
    'client',
    'server',
    'app',
    'application',
  ].map(normalizeName),
);

/** True when the names share a family name after stripping common corporate or
 * edition suffixes, or one normalized name is a prefix of the other. */
function isSafeNameVariant(left: string, right: string): boolean {
  const a = normalizeName(left || '');
  const b = normalizeName(right || '');
  if (!a || !b || a === b) return false;

  const stripSuffix = (value: string) => {
    const suffixes = [...SAFE_NAME_SUFFIXES].sort((x, y) => y.length - x.length);
    for (const suffix of suffixes) {
      if (value.length > suffix.length && value.endsWith(suffix))
        return value.slice(0, -suffix.length);
    }
    return value;
  };
  const base = (value: string) => {
    let current = value;
    let changed = false;
    for (;;) {
      const next = stripSuffix(current);
      if (next === current) return { value: current, changed };
      current = next;
      changed = true;
    }
  };
  const leftBase = base(a);
  const rightBase = base(b);
  if ((leftBase.changed || rightBase.changed) && leftBase.value === rightBase.value)
    return leftBase.value.length >= 3;

  const [short, long] = a.length <= b.length ? [a, b] : [b, a];
  // A family name followed by an arbitrary edition/marketing token (for
  // example `widgetpro` -> `widgetprox`) is a reasonable automatic relation.
  // The prefix requirement still rejects wholly different vendors/products.
  return short.length >= 3 && long.startsWith(short);
}

/**
 * Merges one derived relation into the pending map.
 *
 * `suppressed` contains operator revocations. Filtering here (rather than only
 * at persistence time) keeps the in-memory maps used by the current pipeline
 * run consistent with what will survive reconciliation.
 */
const mergeEntry = (
  target: Map<string, AliasEntry>,
  entry: AliasEntry,
  suppressed: ReadonlySet<string> = new Set(),
) => {
  const key = autoAliasId(entry.scope, entry.canonical);
  const aliases = entry.aliases
    .map((alias) => alias.trim().toLowerCase())
    .filter((alias) => isSafeNameVariant(entry.canonical, alias))
    .filter((alias) => !suppressed.has(relationKey(entry.scope, entry.canonical, alias)));
  if (!aliases.length) return;
  const previous = target.get(key);
  if (!previous) {
    target.set(key, {
      ...entry,
      id: key,
      canonical: entry.canonical.trim().toLowerCase(),
      aliases: [...new Set(aliases)].sort(),
      source: 'AUTO',
    });
    return;
  }
  target.set(key, {
    ...previous,
    aliases: [...new Set([...previous.aliases, ...aliases])].sort(),
    evidenceCount: (previous.evidenceCount ?? 0) + (entry.evidenceCount ?? 0) || undefined,
  });
};

/**
 * Derives the vendor/product aliases implied by an inventory record and its
 * own CPEs.
 *
 * The operator declares `vendor`/`product` and one or more CPEs for the same
 * asset, so when the CPE uses a different spelling (for example
 * `Acme Corp`/`Widget Pro` versus `acme`/`widget_pro`) that spelling is an
 * authoritative alias, not a guess from advisory prose. Keeping auto aliases
 * tied to inventory declarations is what makes the lifecycle safe: they can
 * be recomputed and removed deterministically when the inventory changes.
 *
 * Built-in and operator-managed aliases are consulted first so an auto row is
 * only created when the pair is not already resolvable.
 */
export function deriveInventoryAliases(
  assets: readonly Pick<WatchListItem, 'vendor' | 'product' | 'cpes' | 'active'>[],
  existing: readonly AliasEntry[] = [],
  now = new Date().toISOString(),
): AliasEntry[] {
  const manual = existing.filter((entry) => isProtected(entry) && entry.source !== 'REVOKED');
  const vendorAliases = buildAliasMap(manual, 'VENDOR');
  const productAliases = buildAliasMap(manual, 'PRODUCT');
  const suppressed = revokedPairs(existing);
  const groups = new Map<string, AliasEntry>();

  for (const asset of assets) {
    if (asset.active === false) continue;
    const vendor = asset.vendor.trim().toLowerCase();
    const product = asset.product.trim().toLowerCase();
    for (const cpe of asset.cpes ?? []) {
      const parsed = parseCPE23(cpe);
      if (!parsed.isValid) continue;
      const cpeVendor = parsed.vendor;
      const cpeProduct = parsed.product;
      if (
        vendor &&
        !/[*?]/.test(cpeVendor) &&
        cpeVendor !== '-' &&
        !matchVendorWithAliases(vendor, cpeVendor, vendorAliases)
      )
        mergeEntry(
          groups,
          {
            id: autoAliasId('VENDOR', vendor),
            scope: 'VENDOR',
            canonical: vendor,
            aliases: [cpeVendor],
            provenance: 'INVENTORY',
            firstSeenAt: now,
            lastSeenAt: now,
            createdAt: now,
          },
          suppressed,
        );
      if (
        product &&
        !/[*?]/.test(cpeProduct) &&
        cpeProduct !== '-' &&
        !matchProductWithAliases(product, cpeProduct, productAliases)
      )
        mergeEntry(
          groups,
          {
            id: autoAliasId('PRODUCT', product),
            scope: 'PRODUCT',
            canonical: product,
            aliases: [cpeProduct],
            provenance: 'INVENTORY',
            firstSeenAt: now,
            lastSeenAt: now,
            createdAt: now,
          },
          suppressed,
        );
    }
  }

  return [...groups.values()].sort((a, b) => a.id.localeCompare(b.id));
}

/**
 * A correlation may teach a naming relation only after it has been confirmed.
 *
 * Review-only evidence is deliberately excluded: the text fallback is the
 * weakest matcher (70%), so learning from an unreviewed fallback would let a
 * single false positive become persistent alias evidence and raise every
 * later correlation to the 85% structured path. Confirmation means the finding
 * was auto-dispatched, delivered, or an operator closed it as resolved or
 * patched. A rejection disqualifies it permanently.
 */
export function isConfirmedFinding(finding: Finding): boolean {
  if (finding.status === 'FALSE_POSITIVE') return false;
  if (
    finding.notificationStatus === 'NOT_APPLICABLE' ||
    finding.notificationStatus === 'SUPPRESSED_VEX_NOT_AFFECTED'
  )
    return false;
  if (finding.status === 'RESOLVED' || finding.status === 'PATCH_APPLIED') return true;
  if (finding.autoDispatchedAt) return true;
  return (
    finding.notificationStatus === 'AUTO_DISPATCHED' || finding.notificationStatus === 'DELIVERED'
  );
}

/**
 * Derives aliases from correlations that are confirmed *and* still current.
 *
 * Only the looser methods can teach a spelling: a strict match means the names
 * already agree, so there is nothing to learn. Each qualifying finding counts
 * once per relation, which makes `evidenceCount` a usable promotion signal for
 * operators without letting repeated CPE criteria inflate it.
 */
export function deriveCorrelationAliases(
  findings: readonly Finding[],
  watchlist: readonly WatchListItem[],
  cveById?: ReadonlyMap<string, NormalizedCVE>,
  existing: readonly AliasEntry[] = [],
  now = new Date().toISOString(),
): AliasEntry[] {
  const assets = new Map(watchlist.map((asset) => [asset.id, asset]));
  const suppressed = revokedPairs(existing);
  const groups = new Map<string, AliasEntry>();

  for (const finding of findings) {
    if (!['VENDOR_PRODUCT_ALIAS', 'VENDOR_PRODUCT_FALLBACK'].includes(finding.matchingMethod)) continue;
    if (!isConfirmedFinding(finding)) continue;
    const asset = assets.get(finding.matchedAssetId);
    if (!asset || asset.active === false) continue;
    const cve =
      cveById?.get(finding.cveId.toUpperCase()) || cveById?.get(finding.cveId) || finding.cve;
    if (!cve) continue;
    const criteria = cve.cpeMatchDetails?.length
      ? cve.cpeMatchDetails.map((detail) => detail.criteria)
      : cve.cpeMatches;

    // Collect per finding first so multiple criteria for the same relation do
    // not inflate the evidence count.
    const perFinding = new Map<string, AliasEntry>();
    const vendor = asset.vendor.trim().toLowerCase();
    const product = asset.product.trim().toLowerCase();
    for (const criterion of criteria ?? []) {
      const parsed = parseCPE23(criterion);
      if (!parsed.isValid) continue;
      if (
        vendor &&
        !/[*?]/.test(parsed.vendor) &&
        parsed.vendor !== '-' &&
        !matchVendorWithAliases(vendor, parsed.vendor)
      )
        mergeEntry(
          perFinding,
          {
            id: autoAliasId('VENDOR', vendor),
            scope: 'VENDOR',
            canonical: vendor,
            aliases: [parsed.vendor],
            provenance: 'CONFIRMED_CORRELATION',
            evidenceCount: 1,
            firstSeenAt: now,
            lastSeenAt: now,
            createdAt: now,
          },
          suppressed,
        );
      if (
        product &&
        !/[*?]/.test(parsed.product) &&
        parsed.product !== '-' &&
        !matchProductWithAliases(product, parsed.product)
      )
        mergeEntry(
          perFinding,
          {
            id: autoAliasId('PRODUCT', product),
            scope: 'PRODUCT',
            canonical: product,
            aliases: [parsed.product],
            provenance: 'CONFIRMED_CORRELATION',
            evidenceCount: 1,
            firstSeenAt: now,
            lastSeenAt: now,
            createdAt: now,
          },
          suppressed,
        );
    }
    for (const entry of perFinding.values())
      mergeEntry(groups, { ...entry, evidenceCount: 1 }, suppressed);
  }

  return [...groups.values()].sort((a, b) => a.id.localeCompare(b.id));
}

export interface AutoAliasReconciliation {
  /** Automatic rows that remain after reconciliation (including rows resting
   * in their TTL grace period). */
  entries: AliasEntry[];
  /** Rows to insert or update. */
  upserts: AliasEntry[];
  /** Ids of automatic rows that are no longer supported. */
  removals: string[];
  /** Complete alias list after reconciliation (protected rows + automatic). */
  aliases: AliasEntry[];
  added: AliasEntry[];
  updated: AliasEntry[];
  removed: AliasEntry[];
}

export interface ReconcileOptions {
  /** Days an automatic row survives after its last supporting evidence.
   * `0` removes unsupported rows immediately. */
  ttlDays?: number;
}

/**
 * Reconciles persisted auto aliases against the relations implied by the
 * current inventory and confirmed correlations.
 *
 * - Manual rows and revocations are never changed or removed.
 * - A row re-observed now refreshes `lastSeenAt` and `expiresAt`.
 * - A row that lost its evidence stays usable until `expiresAt`, so a feed or
 *   retention lapse does not silently widen the gap in matching coverage.
 * - Revoked pairs are filtered even if a derivation still proposes them.
 */
export function reconcileAutoAliases(
  existing: readonly AliasEntry[],
  desired: readonly AliasEntry[],
  now = new Date().toISOString(),
  options: ReconcileOptions = {},
): AutoAliasReconciliation {
  const ttlDays = options.ttlDays ?? DEFAULT_AUTO_ALIAS_TTL_DAYS;
  const expiresAt = expiryFor(now, ttlDays);
  const protectedRows = existing.filter(isProtected);
  const suppressed = revokedPairs(existing);
  const remainingAuto = new Map(
    existing
      .filter((entry) => !isProtected(entry))
      .map((entry) => [autoAliasId(entry.scope, entry.canonical), entry]),
  );
  const desiredById = new Map<string, AliasEntry>();
  for (const entry of desired) mergeEntry(desiredById, entry, suppressed);

  const added: AliasEntry[] = [];
  const updated: AliasEntry[] = [];
  const entries: AliasEntry[] = [];
  const protectedIds = new Set(protectedRows.map((row) => row.id));

  for (const entry of desiredById.values()) {
    // A promoted (manual) row keeps the deterministic auto id. Never let a
    // later derivation overwrite the operator's decision under that id.
    if (protectedIds.has(entry.id)) continue;
    const previous = remainingAuto.get(entry.id);
    if (!previous) {
      const created: AliasEntry = {
        ...entry,
        createdAt: entry.createdAt || now,
        firstSeenAt: entry.firstSeenAt || now,
        lastSeenAt: now,
        expiresAt,
      };
      added.push(created);
      entries.push(created);
      continue;
    }
    remainingAuto.delete(entry.id);
    const merged: AliasEntry = {
      ...previous,
      ...entry,
      createdAt: previous.createdAt || entry.createdAt || now,
      firstSeenAt: previous.firstSeenAt || entry.firstSeenAt || now,
      lastSeenAt: now,
      expiresAt,
    };
    const changed =
      previous.scope !== merged.scope ||
      previous.canonical !== merged.canonical ||
      previous.source !== merged.source ||
      previous.provenance !== merged.provenance ||
      previous.notes !== merged.notes ||
      previous.evidenceCount !== merged.evidenceCount ||
      previous.expiresAt !== merged.expiresAt ||
      previous.aliases.length !== merged.aliases.length ||
      previous.aliases.some((alias, index) => alias !== merged.aliases[index]);
    if (changed) {
      updated.push(merged);
      entries.push(merged);
    } else entries.push(previous);
  }

  const removed: AliasEntry[] = [];
  const nowMs = Date.parse(now);
  for (const entry of remainingAuto.values()) {
    const keepUntil = entry.expiresAt ? Date.parse(entry.expiresAt) : Number.NaN;
    if (ttlDays > 0 && Number.isFinite(keepUntil) && keepUntil > nowMs) {
      // Still inside the grace window: keep matching with it, but do not
      // refresh the row (it is not supported by current evidence).
      entries.push(entry);
      continue;
    }
    removed.push(entry);
  }

  return {
    entries,
    upserts: [...added, ...updated],
    removals: removed.map((entry) => entry.id),
    aliases: [...protectedRows, ...entries],
    added,
    updated,
    removed,
  };
}
