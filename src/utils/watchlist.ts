import type { WatchListItem } from '../types/index.ts';
import { isProductWildcard, dictionaryEntryMatchesWildcard, productWildcardCpe } from './registrationCpe.ts';
import { buildStrictCpe23 } from '../data/vendorCatalog.ts';
import { parseCPE23, normalizeCpeForComparison } from './cpeMatcher.ts';

export function orderWatchlist(items: WatchListItem[]): WatchListItem[] {
  return [...items].sort((a, b) => {
    const createdOrder = Date.parse(b.createdAt) - Date.parse(a.createdAt);
    return Number.isFinite(createdOrder) && createdOrder !== 0 ? createdOrder : a.id.localeCompare(b.id);
  });
}

export function editedWatchlistCpe(
  item: WatchListItem,
  fields: {
    cpeExpression: string;
    vendor: string;
    product: string;
    part: 'a' | 'o' | 'h';
    version: string;
    targetHw: string;
  },
): string {
  const original = parseCPE23(item.cpes[0] || '');
  const formChanged =
    fields.vendor.trim() !== (original.isValid ? original.vendor : item.vendor) ||
    fields.product.trim() !== (original.isValid ? original.product : item.product) ||
    fields.part !== (original.part === 'o' || original.part === 'h' ? original.part : 'a') ||
    fields.version !== (original.version || '*') ||
    fields.targetHw !== (original.isValid ? original.targetHw : item.targetHw || '*');

  return formChanged
    ? buildStrictCpe23(fields.part, fields.vendor, fields.product, fields.version, fields.targetHw)
    : fields.cpeExpression.trim();
}

/** Turn verified names or product patterns into inventory rows without adding fallback identifiers. */
export function registrationAssetsFromCpes(
  cpes: string[],
  details: { assetTag: string; ownerGroup: string; notes: string; purls: string[] },
): Array<Omit<WatchListItem, 'id' | 'createdAt'>> {
  const groups = new Map<string, { parsed: ReturnType<typeof parseCPE23>; cpes: string[] }>();
  for (const raw of cpes) {
    const cpe = raw.trim();
    const parsed = parseCPE23(cpe);
    if (!productWildcardCpe(cpe)) {
      throw new Error('Select a valid product CPE from the NVD dictionary.');
    }
    const key = JSON.stringify([parsed.part, parsed.vendor.toLowerCase(), parsed.product.toLowerCase()]);
    const group = groups.get(key) ?? { parsed, cpes: [] };
    if (!group.cpes.some((entry) => entry.toLowerCase() === cpe.toLowerCase())) group.cpes.push(cpe);
    groups.set(key, group);
  }
  if (!groups.size) throw new Error('Select at least one verified NVD CPE before registering a product.');
  return [...groups.values()].map(({ parsed, cpes }, index) => {
    const versions = new Set(cpes.map((cpe) => parseCPE23(cpe).version));
    const architectures = new Set(cpes.map((cpe) => parseCPE23(cpe).targetHw));
    return {
      vendor: parsed.vendor,
      product: parsed.product,
      version: versions.size === 1 ? parsed.version : '*',
      cpes,
      targetHw: architectures.size === 1 && parsed.targetHw !== '*' ? parsed.targetHw : undefined,
      assetTag: `${details.assetTag.trim()}${groups.size > 1 ? `-${index + 1}` : ''}`,
      ownerGroup: details.ownerGroup.trim() || 'Cyber',
      notes: details.notes.trim(),
      purls: details.purls.length ? details.purls : undefined,
      active: true,
    };
  });
}

/** Verify exact dictionary names or product-scoped wildcard patterns before any write.
 *
 * CPEs listed in `custom` are operator-entered custom expressions: they are
 * validated as well-formed CPE 2.3 and saved as-is without an NVD dictionary
 * match, so monitored inventory can register unverified custom CPEs.
 */
export async function verifyRegistrationCpes(
  cpes: string[],
  lookup: (cpe: string) => Promise<{ results: Array<{ cpeName: string }> }>,
  custom: string[] = [],
): Promise<string[]> {
  if (!cpes.length) throw new Error('Select at least one verified NVD CPE before saving.');
  const verified: string[] = [];
  const seen = new Set<string>();
  const customSet = new Set(custom.map((entry) => entry.trim().toLowerCase()));
  for (const cpe of cpes.map((entry) => entry.trim())) {
    if (seen.has(cpe.toLowerCase())) continue;
    seen.add(cpe.toLowerCase());
    if (customSet.has(cpe.toLowerCase())) {
      if (!parseCPE23(cpe).isValid) throw new Error(`Invalid CPE 2.3 expression: ${cpe}`);
      verified.push(cpe);
      continue;
    }
    if (!parseCPE23(cpe).isValid) throw new Error(`Invalid CPE 2.3 expression: ${cpe}`);
    const response = await lookup(cpe);
    if (
      isProductWildcard(cpe) &&
      response.results.some((entry) => dictionaryEntryMatchesWildcard(cpe, entry.cpeName))
    ) {
      verified.push(cpe);
      continue;
    }
    let match = response.results.find(
      (entry) => normalizeCpeForComparison(entry.cpeName) === normalizeCpeForComparison(cpe),
    );
    if (!match) {
      const parsed = parseCPE23(cpe);
      if (parsed.isValid) {
        const fields = [
          'part',
          'product',
          'version',
          'update',
          'edition',
          'language',
          'swEdition',
          'targetSw',
          'targetHw',
          'other',
        ] as const;
        const compatible = response.results.filter((entry) => {
          const published = parseCPE23(entry.cpeName);
          return (
            published.isValid &&
            fields.every(
              (field) =>
                normalizeCpeForComparison(published[field]) === normalizeCpeForComparison(parsed[field]),
            )
          );
        });
        const unique = new Map(compatible.map((entry) => [normalizeCpeForComparison(entry.cpeName), entry]));
        // A canonical vendor spelling can be resolved only when the rest of the CPE
        // is identical and NVD returns a single unambiguous identity.
        if (unique.size === 1) match = [...unique.values()][0];
      }
    }
    if (!match)
      throw new Error(
        `CPE is not an active NVD dictionary entry: ${cpe}. Search NVD and select a published identifier.`,
      );
    if (!verified.some((entry) => entry.toLowerCase() === match.cpeName.toLowerCase()))
      verified.push(match.cpeName);
  }
  return verified;
}

/** Replace a generated suggestion only with dictionary names for the same
 * vendor/product identity. Strict matching ensures that CPEs from unrelated
 * vendors — even ones that share a product name — are never silently
 * substituted. */
export function dictionaryCpesForCandidate(candidate: string, dictionaryCpes: string[]): string[] {
  const parsed = parseCPE23(candidate);
  if (!parsed.isValid) return [candidate];
  const matches = dictionaryCpes.filter((cpe) => {
    const entry = parseCPE23(cpe);
    return (
      entry.isValid &&
      entry.part === parsed.part &&
      entry.vendor.toLowerCase() === parsed.vendor.toLowerCase() &&
      entry.product.toLowerCase() === parsed.product.toLowerCase()
    );
  });
  return matches.length ? matches : [candidate];
}

/** Preserve every row's ownership and IDs while saving the identifiers NVD actually verified. */
export async function verifyRegistrationAssets<T extends Omit<WatchListItem, 'id' | 'createdAt'>>(
  items: T[],
  lookup: (cpe: string) => Promise<{ results: Array<{ cpeName: string }> }>,
  customCpes: string[] = [],
): Promise<T[]> {
  const cache = new Map<string, Promise<{ results: Array<{ cpeName: string }> }>>();
  const cachedLookup = (cpe: string) => {
    const key = normalizeCpeForComparison(cpe);
    if (!cache.has(key)) cache.set(key, lookup(cpe));
    return cache.get(key)!;
  };
  const verifiedItems: T[] = [];
  for (const item of items) {
    const cpes = await verifyRegistrationCpes(item.cpes, cachedLookup, customCpes);
    const primary = parseCPE23(cpes[0]);
    const versions = new Set(cpes.map((cpe) => parseCPE23(cpe).version));
    const architectures = new Set(cpes.map((cpe) => parseCPE23(cpe).targetHw));
    verifiedItems.push({
      ...item,
      cpes,
      vendor: primary.vendor,
      product: primary.product,
      version: versions.size === 1 ? primary.version : '*',
      targetHw: architectures.size === 1 ? primary.targetHw : '*',
    });
  }
  return verifiedItems;
}
