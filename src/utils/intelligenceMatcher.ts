import type { Finding, IntelligenceArticle, IntelligenceMatch, WatchListItem, NormalizedCVE, ThreatFeed } from '../types';
import { quickHash } from './cryptoChain';
import { isWithinTimelineScope } from './deduplicator';
import { normalizeAliasToken } from './cpeMatcher';

const text = (value: string) =>
  value
    .normalize('NFKC')
    .toLowerCase()
    .replace(/[^\p{L}\p{N}]+/gu, ' ')
    .trim();

/** Source feed weight: higher for authoritative threat intel feeds (0–40).
 *
 * Single source of truth (audit C-3): the ML trainer's sample collector carried
 * a duplicate table. Editing one copy changed the score without changing the
 * training features, or the reverse, and the mismatch was invisible.
 */
export const FEED_WEIGHTS: Record<string, number> = {
  NVD_API: 40,
  CISA_KEV: 40,
  MITRE_CVE: 35,
  VULNCHECK_KEV: 30,
  OPENCVE_API: 25,
  RSS_NEWS: 15,
  THREAT_FEED: 20,
};

/** Compute a credibility score (0–100) for an intelligence match.
 *
 * Combines the source feed weight with the confidence of the vendor/product
 * keyword match. Corroborated structural matches score higher than
 * heuristic text matches.
 */
export function computeCredibilityScore(
  match: IntelligenceMatch,
  sourceFeeds: string[] = [],
  hasStructuredFinding: boolean,
  weights: { feedWeight: number; keywordWeight: number } = { feedWeight: 0.6, keywordWeight: 0.4 },
): number {
  let feedScore = 10; // baseline for unknown feeds
  if (sourceFeeds.length) {
    const maxWeight = Math.max(...sourceFeeds.map((f) => FEED_WEIGHTS[f] ?? 10));
    feedScore = maxWeight;
  }
  // Keyword confidence: corroborated by a structured finding = 100,
  // zero-day without CVE = 70, review-only text match = 50.
  let keywordScore: number;
  if (hasStructuredFinding && match.status === 'CORROBORATED') keywordScore = 100;
  else if (match.zeroDay) keywordScore = 70;
  else keywordScore = 50;
  // Audit H-1: corroboration must be monotone in the score. A zero-day match
  // that cites more independent articles is stronger evidence, but it capped at
  // 52 because a null CVE id can never resolve a structured finding. Credibility
  // is also the zero-day rate-limit ranking key, so ties were broken by
  // database return order and two identical runs could suppress different
  // findings.
  const corroboration = Math.min(Math.max(sourceFeeds.length - 1, 0), 4) * 3;
  // Average feed weight and keyword confidence, normalized to 0–100.
  return Math.min(100, Math.round(feedScore * weights.feedWeight + keywordScore * weights.keywordWeight + corroboration));
}

/**
 * Built-in vendor display-name aliases for the news text matcher.
 * These handle cases where a vendor's CPE identifier differs from how their
 * name appears in article prose (e.g. "paloaltonetworks" in CPE vs.
 * "palo alto networks" in a headline).
 *
 * Operator-managed aliases from the Alias Thesaurus are merged on top of
 * this table at call time via the `customVendorAliases` parameter of
 * matchIntelligence, so the Thesaurus page controls both CVE matching
 * and news evidence matching from a single place.
 */
const BUILTIN_VENDOR_ALIASES: Record<string, string[]> = {
  paloaltonetworks: ['palo alto networks'],
  checkpoint: ['check point'],
  f5networks: ['f5'],
  juniper: ['juniper networks'],
  microsoft: ['microsoft'],
  redhat: ['red hat'],
};
/**
 * Whole-token mention test with a bounded plural tolerance.
 *
 * Audit F-5: an article that inflects the identity ("Acme Widgets affected",
 * "Fortinet VPN zero-days" -> two tokens) never matched, so evidence was
 * silently lost even when decomposition had already proposed the right stem.
 * Only a single trailing `s` is tolerated — no stemming, no prefixes — because
 * anything broader reintroduces the generic-word false positives this matcher
 * exists to avoid: `status` must not match `statu`, and `alias` must not match
 * `alia`. The plural form is still a full token, so `as` cannot match `ass`.
 */
function mentions(document: string, value: string): boolean {
  const normalized = text(value);
  if (!normalized || normalized.length < 2 || normalized === 'unknown') return false;
  const haystack = ` ${document} `;
  if (haystack.includes(` ${normalized} `)) return true;
  // Article pluralized the identity (`widgets` for inventory `widget`), or the
  // identity itself is the plural and the article used the singular (`cpus` vs
  // `cpu`). Only one trailing `s` is tolerated — no stemming, no prefixes — so
  // `status` cannot match `statu` and `alias` cannot match `alia`, and each
  // candidate form must stay a meaningful token (>=3 chars).
  if (normalized.endsWith('s')) {
    if (normalized.length < 4) return false;
    const singular = normalized.slice(0, -1);
    if (singular.length >= 3 && singular !== 'unknown' && haystack.includes(` ${singular} `)) return true;
  } else if (normalized.length >= 3) {
    if (haystack.includes(` ${normalized}s `)) return true;
  }
  return false;
}

/** Identity stems so generic they must never be proposed on their own.
 *
 * Audit F-5: stripping a corporate suffix from e.g. `progresssoftware` yields
 * `progress`, and from `securitymetrics` yields `security`. Matching a generic
 * English word as a vendor multiplies false positives exactly where the
 * credibility score has the most influence (the zero-day rate-limit ranking).
 * A suffix strip whose result lands in this list is discarded; the full
 * identity still matches, so nothing is lost — only the invented generic stem
 * is suppressed.
 */
const GENERIC_STEMS = new Set([
  'progress', 'advance', 'security', 'systems', 'software', 'network', 'data',
  'tech', 'service', 'solution', 'group', 'holding', 'partners', 'global',
  'content', 'open', 'next', 'new', 'modern', 'core', 'base', 'point',
  'control', 'access', 'trust', 'cloud', 'smart', 'one', 'top', 'pro',
]);

/** Splits a compound vendor/product token into the words an article would use.
 *
 * Audit N-1: the news matcher compared the raw inventory identity against the
 * article, so a CPE-style vendor (`paloaltonetworks`, `fortinettech`) could only
 * match prose through the six-entry built-in table. Every other vendor was
 * silently unreachable. Decomposition (`paloaltonetworks` -> `palo alto
 * networks`) is the same rule the CVE matcher already applies on the structured
 * path, so news evidence now sees the spellings inventory declares.
 */
const COMPOUND_SUFFIXES = ['networks', 'network', 'technologies', 'technology', 'systems', 'software', 'security', 'labs', 'inc', 'corp', 'gmbh'];
/** Interior word fragments that survive compression in vendor names. */
const INTERFIXES = ['alto', 'soft', 'ware', 'data', 'tech'];

/** Splits a compressed head at the last known interfix boundary.
 *
 * `paloalto` -> [`palo`, `alto`]. Only a boundary that leaves at least two
 * characters on both sides is accepted; everything else stays whole, so a
 * generic concatenation never turns into invented words.
 */
function splitAtInterfix(head: string): string[] {
  for (const interfix of INTERFIXES) {
    const at = head.lastIndexOf(interfix);
    if (at >= 2 && head.length - at === interfix.length) {
      return [head.slice(0, at), head.slice(at)];
    }
  }
  return [head];
}
function segmentCompressedToken(token: string): string[] {
  const suffix = COMPOUND_SUFFIXES.find(
    (candidate) => token.endsWith(candidate) && token.length >= candidate.length + 2,
  );
  const head = suffix ? token.slice(0, -suffix.length) : token;
  const parts = splitAtInterfix(head);
  if (suffix) parts.push(suffix);
  return parts;
}
function decomposedVariants(value: string): string[] {
  const normalized = normalizeAliasToken(value);
  if (!normalized) return [];
  const variants = new Set<string>();
  // Whole token compressed and spaced (`paloaltonetworks` / `palo alto networks`).
  variants.add(normalized);
  variants.add(normalized.replace(/[^a-z0-9]+/g, ' ').trim());
  // Trailing corporate/plural forms an article normally elides. A strip whose
  // stem is a generic English word is discarded (see GENERIC_STEMS): matching
  // `progress` because inventory says `progresssoftware` would correlate any
  // article using the ordinary word with this vendor.
  for (const suffix of COMPOUND_SUFFIXES)
    if (normalized.endsWith(suffix) && normalized.length > suffix.length + 2) {
      const stem = normalized.slice(0, -suffix.length);
      if (stem.length >= 3 && !GENERIC_STEMS.has(stem)) {
        variants.add(stem);
        variants.add(stem.replace(/[^a-z0-9]+/g, ' ').trim());
      }
    }
  const segmented = segmentCompressedToken(normalized).filter(Boolean);
  if (segmented.length > 1) {
    const spaced = segmented.join(' ');
    variants.add(spaced);
    // A strip whose only result would be a generic word is still allowed to
    // contribute the spaced compound (`progress software`) — the generic stem
    // itself (`progress`) is what stays suppressed.
    if (segmented.length === 2 && GENERIC_STEMS.has(segmented[0]))
      variants.add(`${segmented[0]} ${segmented[1]}`);
  }
  return [...variants].filter((variant) => variant.length >= 3);
}

/** Every spelling an article may use for an inventory identity.
 *
 * Combines, in one place and in a stable order:
 *  - the declared value and its compound decomposition,
 *  - the built-in display-name table (only for vendors),
 *  - operator aliases from the Alias Thesaurus.
 *
 * Operator aliases are looked up through the same alias-group expansion the
 * CVE matcher uses (`aliasGroupKeys`), not by an exact normalized key, so an
 * operator entry keyed `PaloAltoNetworks` still resolves for an asset declared
 * `paloaltonetworks`. Keys are normalized before the lookup, which the previous
 * implementation did for built-ins but not for `customVendorAliases`.
 */
export function newsIdentityVariants(
  value: string,
  customAliases: Record<string, string[]> = {},
  builtin: Record<string, string[]> = {},
): string[] {
  const declared = value.trim();
  if (!declared) return [];
  const variants = new Set<string>([declared, text(declared)]);
  for (const variant of decomposedVariants(declared)) variants.add(variant);
  // One membership test covers built-in and operator tables alike. Matching on a
  // single normalized key was wrong twice over:
  //  - the built-in lookup used the article normalizer while operator rows are
  //    keyed by the operator's spelling;
  //  - an operator row keyed by a *different* canonical (the normal Thesaurus
  //    shape: `acme -> acmecorp, acme corp`, or `xgateway -> xenon gateway`)
  //    never resolved, because only the asset's own spelling was compared.
  // Every spelling in a matching group contributes, and each contribution is
  // decomposed too so an alias like `xenongateway` still reaches `xenon gateway`.
  // Two directions must both resolve:
  //  - the asset's own spelling appears in a group's canonical OR alias list
  //    (`acmecorp` -> `acme corp`), and
  //  - a group is keyed by the asset's spelling but carries marketing aliases
  //    (`xgateway -> xenon gateway`).
  // The previous lookup only handled the first, so a Thesaurus row keyed on the
  // inventory identifier contributed nothing.
  const ownKey = normalizeAliasToken(declared);
  const ownGroup = customAliases[declared.toLowerCase()] ?? customAliases[ownKey];
  if (ownGroup) for (const entry of [declared, ...ownGroup]) variants.add(entry);
  // Operator-declared aliases are always honoured, including generic-looking
  // stems: an operator who declares `progress -> progresssoftware` asserted the
  // correlation deliberately. GENERIC_STEMS only suppresses stems the matcher
  // invents on its own from suffix stripping.
  const declaredGenericStems: string[] = [];
  for (const entry of ownGroup ?? [])
    for (const derived of decomposedVariants(entry))
      if (GENERIC_STEMS.has(derived)) declaredGenericStems.push(derived);
  for (const [canonical, aliases] of Object.entries({ ...builtin, ...customAliases })) {
    const group = [canonical, ...aliases];
    const groupTokens = group.map((entry) => normalizeAliasToken(entry)).filter(Boolean);
    if (!groupTokens.length) continue;
    const related =
      groupTokens.includes(ownKey) ||
      groupTokens.some((token) => token === ownKey || decomposedVariants(token).includes(ownKey));
    if (!related) continue;
    for (const entry of group) {
      variants.add(entry);
      for (const derived of decomposedVariants(entry)) variants.add(derived);
    }
  }
  // Reinstate generic stems the operator declared explicitly. decomposedVariants
  // filtered them out above because the builtin/custom group loop reuses it.
  for (const stem of declaredGenericStems) variants.add(stem);
  return [...variants].filter((variant) => text(variant).length >= 2);
}
export function mergeArticles(records: IntelligenceArticle[]): IntelligenceArticle[] {
  const byId = new Map<string, IntelligenceArticle>();
  for (const article of records) {
    const old = byId.get(article.id);
    const winner =
      !old ||
      Date.parse(article.modifiedDate) > Date.parse(old.modifiedDate) ||
      (article.modifiedDate === old.modifiedDate && JSON.stringify(article) > JSON.stringify(old))
        ? article
        : old;
    const mergedCveIds = [...new Set(winner.cveIds || [])].sort();
    byId.set(article.id, {
      ...winner,
      sourceFeeds: [...new Set([...(old?.sourceFeeds || []), ...article.sourceFeeds])].sort(),
      zeroDay: (winner.zeroDay || old?.zeroDay || article.zeroDay) && mergedCveIds.length === 0,
      // Cluster identity and resolution travel with the merged article: a
      // zero-day report and its later CVE announcement may arrive from
      // different feeds, but they describe one incident.
      clusterId: article.clusterId || old?.clusterId,
      resolvedCveId: article.resolvedCveId || old?.resolvedCveId,
      cveIds: mergedCveIds,
    });
  }
  return [...byId.values()];
}

/** News mentions are review evidence. Only the structured matcher can confirm installed-version applicability.
 *
 * @param customVendorAliases - Operator-managed vendor aliases from the Alias Thesaurus
 *   (buildAliasMap(aliasEntries, 'VENDOR')), merged on top of the built-in display-name
 *   table so a single Thesaurus entry covers both CVE matching and news evidence.
 * @param customProductAliases - Operator-managed product aliases from the Alias Thesaurus
 *   (buildAliasMap(aliasEntries, 'PRODUCT')), used to catch product name variants in article prose.
 * @param scopeHours - Pipeline timeline window in hours. Vendor + product news matches use the
 *   latest of each article's publishedDate and modifiedDate, so an article is evidence only
 *   while it is inside the same window that scopes CVE matching. Zero disables the filter.
 * @param now - Reference time for the timeline window (injectable for deterministic tests).
 */
/** Memoised per alias-table object, keyed by (scope, identity) within it. The
 * WeakMap holds one cache per operator-table identity, so two tables can never
 * serve each other's variants.
 */
const identityVariantCache = new WeakMap<Record<string, string[]>, Map<string, string[]>>();
const IDENTITY_VARIANT_CACHE_LIMIT = 20_000;
function identityVariants(
  scope: 'VENDOR' | 'PRODUCT',
  value: string,
  customAliases: Record<string, string[]>,
): string[] {
  // Cache per alias table. Keying on the identity alone was wrong: two calls
  // with different operator tables (different runs, different tests) would
  // reuse variants computed from the other table and silently drop aliases.
  let table = identityVariantCache.get(customAliases);
  if (!table) {
    table = new Map();
    identityVariantCache.set(customAliases, table);
  }
  const key = `${scope}\u0000${value.toLowerCase()}`;
  const cached = table.get(key);
  if (cached) return cached;
  const variants = newsIdentityVariants(
    value,
    customAliases,
    scope === 'VENDOR' ? BUILTIN_VENDOR_ALIASES : {},
  );
  if (table.size >= IDENTITY_VARIANT_CACHE_LIMIT) {
    const first = table.keys().next().value;
    if (first !== undefined) table.delete(first);
  }
  table.set(key, variants);
  return variants;
}

export function matchIntelligence(
  articles: IntelligenceArticle[],
  inventory: WatchListItem[],
  findings: Finding[],
  corpus: NormalizedCVE[] = [],
  customVendorAliases: Record<string, string[]> = {},
  customProductAliases: Record<string, string[]> = {},
  scopeHours = 0,
  now: Date = new Date(),
  credibilityWeights: { feedWeight: number; keywordWeight: number } = { feedWeight: 0.6, keywordWeight: 0.4 },
): IntelligenceMatch[] {
  const matches = new Map<string, IntelligenceMatch>();
  const current = new Map(findings.map((finding) => [`${finding.cveId}:${finding.matchedAssetId}`, finding]));
  const authoritative = new Set(
    corpus
      .filter((cve) => !cve.applicabilityRequiresReview && (cve.cpeMatches.length || cve.purls?.length))
      .map((cve) => cve.cveId),
  );
  // Filter the inventory once; the per-asset alias variants are recomputed for
  // every article otherwise, which dominated the cost of this pass on a large
  // corpus (audit M-7 sibling: `inventory.filter` allocated per article).
  const activeAssets = inventory.filter((item) => item.active);
  for (const article of mergeArticles(articles)) {
    // News evidence is subject to the same published/modified window as the
    // CVE it corroborates. Using the latest activity keeps an updated story
    // eligible even when it was first published before the window opened.
    if (!isWithinTimelineScope(article.publishedDate, article.modifiedDate, scopeHours, now)) continue;
    const document = text(`${article.title} ${article.summary}`);
    // The vendor/product variants are properties of the asset, not of the
    // article, so resolve them once per asset instead of rebuilding the arrays
    // (and their alias lookups) for every article in the corpus.
    for (const asset of activeAssets) {
      // Merge compound decomposition, built-in display-name variants and any
      // operator-managed aliases from the Alias Thesaurus, then test each
      // spelling against the article. Variants are memoised per inventory
      // identity: they depend on the asset and the alias tables only, and a news
      // corpus is evaluated against the full inventory on every run.
      const vendorMentioned = identityVariants('VENDOR', asset.vendor, customVendorAliases).some(
        (variant) => mentions(document, variant),
      );
      // Also check product aliases so e.g. "globalprotect" in an article matches
      // an inventory item tagged as "globalprotect" even if the CPE uses "pan_os".
      const productMentioned = identityVariants('PRODUCT', asset.product, customProductAliases).some(
        (variant) => mentions(document, variant),
      );
      const references = article.cveIds.length ? article.cveIds : [null];
      for (const cveId of references) {
        const finding = cveId ? current.get(`${cveId}:${asset.id}`) : undefined;
        if (finding && ['RESOLVED', 'FALSE_POSITIVE', 'PATCH_APPLIED'].includes(finding.status)) continue;
        // News cannot override a structured exclusion (for example, an installed patched version).
        if (cveId && authoritative.has(cveId) && !finding) continue;
        // A pre-CVE cluster that was resolved to a published CVE contributes
        // to the canonical identifier even without keyword corroboration:
        // the earlier zero-day report was the same incident and the cluster
        // linkage (not loose phrasing) establishes that continuity.
        const clusterResolved = article.resolvedCveId && article.resolvedCveId === cveId;
        if (!finding && !(vendorMentioned && productMentioned) && !clusterResolved) continue;
        const id = quickHash(`${cveId || article.id}:${asset.id}`);
        // NOT_APPLICABLE and VEX-suppressed findings are explicit exclusions:
        // news coverage must not turn them back into corroborated evidence.
        const confirmed =
          finding &&
          ![
            'REVIEW_REQUIRED',
            'NOT_APPLICABLE',
            'SUPPRESSED_VEX_NOT_AFFECTED',
          ].includes(finding.notificationStatus) &&
          finding.status !== 'RESOLVED' &&
          finding.status !== 'FALSE_POSITIVE';
        const old = matches.get(id);
        const isZeroDay = article.zeroDay === true;
        const articleFeedWeight = Math.max(...article.sourceFeeds.map((feed) => FEED_WEIGHTS[feed] ?? 10), 10);
        const sourceFeedWeight = Math.max(old?.sourceFeedWeight ?? 10, articleFeedWeight);
        const keywordScore = confirmed ? 100 : isZeroDay ? 70 : 50;
        const credibilityScore = computeCredibilityScore(
          { id, cveId, assetId: asset.id, assetName: '', articleIds: [], status: confirmed ? 'CORROBORATED' : 'REVIEW_REQUIRED', evidence: '', zeroDay: isZeroDay },
          article.sourceFeeds,
          Boolean(finding && confirmed),
          credibilityWeights,
        );
        matches.set(id, {
          id,
          cveId,
          assetId: asset.id,
          assetName: `${asset.assetTag} (${asset.vendor} ${asset.product})`,
          articleIds: [...new Set([...(old?.articleIds || []), article.id])].sort(),
          status: confirmed ? 'CORROBORATED' : 'REVIEW_REQUIRED',
          findingId: finding?.id,
          zeroDay: old?.zeroDay || isZeroDay,
          credibilityScore: Math.max(old?.credibilityScore ?? 0, credibilityScore),
          sourceFeedWeight,
          keywordScore: Math.max(old?.keywordScore ?? 0, keywordScore),
          evidence: confirmed
            ? 'Article references a CVE independently matched to this product by structured applicability.'
            : isZeroDay
              ? 'Potential zero-day: vendor and product mentioned in threat intelligence without an assigned CVE. Confirm affected versions and exploitability before acting.'
              : 'Vendor and product are mentioned together, or a review-only CVE correlation exists. Confirm affected versions and the CVE-to-product relationship before acting.',
        });
      }
    }
  }
  return [...matches.values()];
}
