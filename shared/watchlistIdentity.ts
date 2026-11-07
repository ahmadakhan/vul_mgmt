export interface WatchlistIdentityItem {
  id?: string;
  vendor: string;
  product: string;
  cpes: string[];
  purls?: string[];
  assetTag?: string;
}

/** Tags identify registrations; product identifiers determine duplicate monitored products. */
export function watchlistIdentity(item: WatchlistIdentityItem): string {
  return JSON.stringify([
    item.vendor.trim().toLowerCase(),
    item.product.trim().toLowerCase(),
    [...new Set(item.cpes.map((cpe) => cpe.trim().toLowerCase()))].sort(),
    [...new Set((item.purls || []).map((purl) => purl.trim()))].sort(),
  ]);
}

/** Compare the proposed final inventory, including duplicate rows in this batch. */
export function watchlistDuplicateErrors(
  incoming: WatchlistIdentityItem[],
  existing: WatchlistIdentityItem[],
): string[] {
  const replacing = new Set(incoming.map((item) => item.id).filter(Boolean));
  const identities = new Map<string, WatchlistIdentityItem>();
  for (const item of existing)
    if (!item.id || !replacing.has(item.id)) identities.set(watchlistIdentity(item), item);
  const ids = new Set<string>();
  const errors: string[] = [];
  for (const item of incoming) {
    if (item.id && ids.has(item.id)) {
      errors.push(`Duplicate record ID in batch: ${item.id}.`);
      continue;
    }
    if (item.id) ids.add(item.id);
    const key = watchlistIdentity(item);
    const duplicate = identities.get(key);
    if (duplicate)
      errors.push(
        `Duplicate: "${item.vendor} / ${item.product}" is already monitored as "${duplicate.assetTag || duplicate.id || 'another row in this batch'}".`,
      );
    else identities.set(key, item);
  }
  return errors;
}
