import type { NvdCpeSearchResult } from '../types/index.ts';
import { normalizeCpeForComparison, parseCPE23 } from './cpeMatcher.ts';

export type RegistrationCpeSearchResult = NvdCpeSearchResult & { generatedWildcard?: boolean };

function hasUnescapedWildcard(value: string): boolean {
  let escaped = false;
  for (const character of value) {
    if (escaped) {
      escaped = false;
      continue;
    }
    if (character === '\\') {
      escaped = true;
      continue;
    }
    if (character === '*' || character === '?') return true;
  }
  return false;
}

/** A product-scoped pattern keeps the dictionary identity and covers every version/platform. */
export function productWildcardCpe(name: string): string | null {
  const parsed = parseCPE23(name);
  if (
    !parsed.isValid ||
    !['a', 'o', 'h'].includes(parsed.part) ||
    ['*', '?', '-'].includes(parsed.vendor) ||
    ['*', '?', '-'].includes(parsed.product) ||
    hasUnescapedWildcard(parsed.vendor) ||
    hasUnescapedWildcard(parsed.product)
  )
    return null;
  return `cpe:2.3:${[parsed.part, parsed.vendor, parsed.product, ...Array(8).fill('*')].join(':')}`;
}

export function isProductWildcard(name: string): boolean {
  if (!productWildcardCpe(name)) return false;
  const parsed = parseCPE23(name);
  return [
    parsed.version,
    parsed.update,
    parsed.edition,
    parsed.language,
    parsed.swEdition,
    parsed.targetSw,
    parsed.targetHw,
    parsed.other,
  ].every((component) => component === '*');
}

export function dictionaryEntryMatchesWildcard(pattern: string, dictionaryName: string): boolean {
  if (!isProductWildcard(pattern)) return false;
  const candidate = productWildcardCpe(dictionaryName);
  return candidate !== null && normalizeCpeForComparison(candidate) === normalizeCpeForComparison(pattern);
}

/** Keep one wildcard per dictionary product at the front, followed by exact entries. */
export function withProductWildcards(entries: NvdCpeSearchResult[]): RegistrationCpeSearchResult[] {
  const wildcards = new Map<string, RegistrationCpeSearchResult>();
  const exact = new Map(entries.map((entry) => [normalizeCpeForComparison(entry.cpeName), entry]));
  for (const entry of entries) {
    const cpeName = productWildcardCpe(entry.cpeName);
    if (!cpeName) continue;
    const key = normalizeCpeForComparison(cpeName);
    if (wildcards.has(key)) continue;
    const published = exact.get(key);
    wildcards.set(
      key,
      published ?? {
        ...entry,
        cpeName,
        cpeNameId: '',
        version: '*',
        update: '*',
        targetSw: '*',
        targetHw: '*',
        title: `${entry.vendor} / ${entry.product} · all versions`,
        generatedWildcard: true,
      },
    );
  }
  return [
    ...wildcards.values(),
    ...entries.filter((entry) => !wildcards.has(normalizeCpeForComparison(entry.cpeName))),
  ];
}
