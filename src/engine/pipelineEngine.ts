import type {
  ThreatFeed,
  WatchListItem,
  NormalizedCVE,
  Finding,
  Advisory,
  AlertedCVE,
  PipelineExecution,
  AppSettings,
  ExploitRiskLevel,
  IntelligenceMatch,
  EmailDeliveryLog,
  AuditLog,
  AliasEntry,
} from '../types';
import { normalizeCveId, isWithinTimelineScope, mergeCveRecords } from '../utils/deduplicator';
import {
  DEFAULT_PRODUCT_ALIASES,
  DEFAULT_VENDOR_ALIASES,
  aliasGroupKeys,
  buildAliasMap,
  matchesWatchlistItem,
  normalizeAliasToken,
  parseCPE23,
  type MatchResult,
} from '../utils/cpeMatcher';
import { deriveInventoryAliases } from '../utils/aliasLifecycle';
import { formatExecutionName } from '../utils/executionName';
import { isPublicAddress } from '../utils/ipSafety';
import ipaddr from 'ipaddr.js';
import { shouldAutoDispatch } from '../../server/ml/integration.ts';

/** Package identity (`npm/express`) used to index PURL inventory.
 *
 * Audit H-2: one parser only. The engine previously kept a private copy whose
 * `lastIndexOf('@')` did not respect the npm scope boundary, so scoped packages
 * were indexed differently here than in the PostgreSQL candidate index.
 */
import { purlIdentity } from '../utils/cpeMatcher';
export { purlIdentity };
export interface PipelineRunResult {
  execution: PipelineExecution;
  newFindings: Finding[];
  newAdvisories: Advisory[];
  updatedAlertedCves: AlertedCVE[];
  newEmailLogs: EmailDeliveryLog[];
  newAuditLogs: AuditLog[];
}
/** Client-side hint only. The server validates DNS and pins every connection. */
export function validateSsrfSafety(value: string): { safe: boolean; reason?: string } {
  try {
    const u = new URL(value),
      host = u.hostname
        .replace(/^\[|\]$/g, '')
        .replace(/\.$/, '')
        .toLowerCase();
    if (u.protocol !== 'https:' || u.username || u.password)
      return { safe: false, reason: 'HTTPS without URL credentials required' };
    if (u.port && u.port !== '443')
      return { safe: false, reason: 'Non-default port on HTTPS is not permitted' };
    if (
      host === 'localhost' ||
      /\.(localhost|local|internal)$/.test(host) ||
      (ipaddr.isValid(host) && !isPublicAddress(host))
    )
      return { safe: false, reason: 'Non-public destination' };
    return { safe: true };
  } catch {
    return { safe: false, reason: 'Malformed URL' };
  }
}
export function determineExploitRisk(cve: NormalizedCVE): ExploitRiskLevel {
  return cve.cisaKev?.isKev
    ? 'CISA_KEV_EXPLOITED'
    : cve.exploitationSources?.length || cve.exploitStatus === 'Reported In Wild'
      ? 'REPORTED_IN_WILD_EXPLOIT'
      : cve.exploitStatus === 'Active Weaponized'
        ? 'WEAPONIZED_EXPLOIT'
        : (cve.epss?.score ?? 0) >= 0.4
          ? 'HIGH_EPSS_PROBABILITY'
          : cve.cvss.score >= 7
            ? 'ELEVATED'
            : 'STANDARD';
}
/**
 * VEX enforcement and the exploitability lattice live in their own module so
 * the resolution rules can be tested independently of correlation.
 */
export {
  applyVexSuppression,
  resolveExploitability,
  hasExploitIntelligence,
  vexImpact,
  vexStatementsFor,
} from './exploitability';
/**
 * Rate-limit zero-day matches and consolidate into digests.
 *
 * Zero-day matches (findings without a CVE, or with active exploit indicators)
 * are capped at MAX_ZERO_DAYS_PER_RUN to prevent notification storms.
 * Multiple zero-day matches for the same vendor/product are consolidated into
 * a single advisory (the "zero-day digest" mode).
 */
export const MAX_ZERO_DAYS_PER_RUN = 50;
export interface ZeroDayDigest {
  advisoryId: string;
  vendor: string;
  product: string;
  findingIds: string[];
  matchCount: number;
  /** Matches this digest replaces. Server drops them from the persisted set. */
  matchIds: string[];
}

/**
 * Recovers the vendor/product tail from the `"tag (vendor product)"` string
 * that intelligenceMatcher writes into `assetName`.
 *
 * The asset tag itself may contain a parenthesis (`prod (legacy) (acme web)`),
 * so the split must anchor on the LAST '(' — splitting on the first one yields
 * vendor `legacy` and product `prod`. Anything unparseable degrades to the tag
 * rather than inventing structured identity.
 */
function assetIdentity(assetName: string): { vendor: string; product: string; tag: string } {
  const openParen = assetName.lastIndexOf('(');
  const closeParen = openParen >= 0 ? assetName.indexOf(')', openParen) : -1;
  const tail = openParen >= 0 && closeParen > openParen ? assetName.slice(openParen + 1, closeParen) : '';
  const words = tail.split(/\s+/).filter(Boolean);
  const tag = openParen > 0 ? assetName.slice(0, openParen).trim() : assetName.trim();
  return {
    vendor: words[0] || tag || 'unknown',
    product: words.length > 1 ? words.slice(1).join(' ') : tag || 'unknown',
    tag,
  };
}

/**
 * Rate-limit zero-day matches and consolidate them into per-product digests.
 *
 * A match is zero-day evidence when it carries the zero-day flag or has no CVE
 * identity at all. Only the zero-day evidence is capped: non-zero-day matches
 * are always preserved, even when the cap is exceeded.
 *
 * Audit C-2 / M-1 / M-4 / M-9 fixes:
 *  - `matchCount` is the size of the digest group, not of the whole match array
 *    (it previously reported every match in the run, so digests misstated their
 *    own severity).
 *  - `findingIds` is populated from the suppressed matches; it was hardcoded
 *    empty, leaving every digest unactionable.
 *  - grouping is by vendor/product, as documented. Keying on `assetId` produced
 *    one digest per asset, i.e. exactly the notification storm the cap exists to
 *    prevent.
 *  - the digest id uses a `DIGEST_` namespace instead of `ZDIGEST_`, which
 *    mimicked `formatAdvisoryId()` output for an advisory that is never written.
 *  - the counterpart findings of suppressed matches are removed from the
 *    returned finding set. The cap previously limited only the news evidence
 *    while the finding still queued for dispatch.
 */
export function rankAndRateLimitZeroDays(
  findings: Finding[],
  matches: IntelligenceMatch[],
  cap = MAX_ZERO_DAYS_PER_RUN,
): { findings: Finding[]; matches: IntelligenceMatch[]; digests: ZeroDayDigest[] } {
  if (!Number.isInteger(cap) || cap < 1 || cap > MAX_ZERO_DAYS_PER_RUN)
    throw new Error('Zero-day cap must be an integer within the configured maximum');
  const isZeroDayEvidence = (m: IntelligenceMatch) =>
    Boolean(m.zeroDay) || (!m.cveId && m.status === 'REVIEW_REQUIRED');
  const zeroDayMatches = matches.filter(isZeroDayEvidence);
  if (zeroDayMatches.length <= cap) {
    return { findings, matches, digests: [] };
  }
  // Rank by credibility. Ties break on corroboration depth and then on the
  // stable match id: credibility alone leaves genuinely tied scores ordered by
  // whatever order the database returned, so two identical runs could suppress
  // different zero-days (audit H-1).
  const ranked = [...zeroDayMatches].sort(
    (a, b) =>
      (b.credibilityScore ?? 0) - (a.credibilityScore ?? 0) ||
      b.articleIds.length - a.articleIds.length ||
      a.id.localeCompare(b.id),
  );
  const dropped = ranked.slice(cap);
  if (!dropped.length) return { findings, matches, digests: [] };
  const byProduct = new Map<string, { vendor: string; product: string; matches: IntelligenceMatch[] }>();
  for (const match of dropped) {
    const { vendor, product } = assetIdentity(match.assetName);
    const key = `${vendor.toLowerCase()}\u0000${product.toLowerCase()}`;
    const group = byProduct.get(key) || { vendor, product, matches: [] };
    group.matches.push(match);
    byProduct.set(key, group);
  }
  const digests: ZeroDayDigest[] = [];
  for (const { vendor, product, matches: group } of byProduct.values()) {
    digests.push({
      advisoryId: `DIGEST_${vendor}_${product}`.replace(/[^A-Za-z0-9_.-]+/g, '_'),
      vendor,
      product,
      findingIds: [...new Set(group.map((m) => m.findingId).filter((id): id is string => Boolean(id)))],
      matchCount: group.length,
      matchIds: group.map((m) => m.id),
    });
  }
  const droppedIds = new Set(dropped.map((m) => m.id));
  const droppedFindingIds = new Set(digests.flatMap((d) => d.findingIds));
  return {
    findings: droppedFindingIds.size ? findings.filter((finding) => !droppedFindingIds.has(finding.id)) : findings,
    matches: matches.filter((match) => !droppedIds.has(match.id)),
    digests,
  };
}
/** Pure correlation. Network ingestion and transactional outbox delivery live on the server. */
export function runVulnerabilityPipeline(
  _feeds: ThreatFeed[],
  corpus: NormalizedCVE[],
  watchlist: WatchListItem[],
  alerted: AlertedCVE[],
  existing: Finding[],
  settings: AppSettings,
  _caller = 'Server worker',
  includeExistingCandidates = false,
  vendorAliases: Record<string, string[]> = {},
  productAliases: Record<string, string[]> = {},
  candidatePairs?: Map<string, Set<string>>,
  aliasEntries: readonly AliasEntry[] = [],
  /**
   * Reference instant for timeline filtering and finding timestamps. The
   * production pipeline passes nothing and gets wall-clock time; tests pin it so
   * week-scoped window assertions stay deterministic instead of drifting out of
   * range a few days after they are written.
   */
  evaluatedAt: Date = new Date(),
): PipelineRunResult {
  const started = evaluatedAt,
    known = new Set(existing.map((f) => `${normalizeCveId(f.cveId)}:${f.matchedAssetId}`)),
    knownCves = new Set(existing.map((f) => normalizeCveId(f.cveId)).filter((id): id is string => Boolean(id)));
  const newFindings: Finding[] = [];
  const executionId = crypto.randomUUID();
  let processed = 0;
  const normalizationStarted = performance.now();
  const latest = mergeCveRecords(corpus);
  const duplicates = corpus.filter((cve) => normalizeCveId(cve.cveId)).length - latest.size;
  const normalizationDurationMs = Math.round(performance.now() - normalizationStarted);
  const activeAssets = watchlist.filter((asset) => asset.active);
  // Auto aliases are derived from the operator's own inventory declarations
  // (vendor/product plus CPEs). They are ephemeral here and persisted by the
  // server pipeline, so both the browser simulation and server correlation
  // resolve the same spellings. Manual aliases always take precedence and are
  // never removed by this merge.
  const autoAliasEntries = deriveInventoryAliases(activeAssets, aliasEntries);
  const mergeAliasMaps = (
    base: Record<string, string[]>,
    extra: Record<string, string[]>,
  ): Record<string, string[]> => {
    const merged: Record<string, string[]> = Object.assign(Object.create(null), base);
    for (const [key, values] of Object.entries(extra))
      merged[key] = [...new Set([...(merged[key] || []), ...values])];
    return merged;
  };
  const effectiveVendorAliases = mergeAliasMaps(vendorAliases, buildAliasMap(autoAliasEntries, 'VENDOR'));
  const effectiveProductAliases = mergeAliasMaps(productAliases, buildAliasMap(autoAliasEntries, 'PRODUCT'));
  // Index inventory once. Matching the entire CVE cache against every asset
  // on every run is the dominant avoidable cost for large installations.
  // The candidate selection is deliberately a superset: wildcard criteria,
  // unstructured assets, and package assets stay eligible for full matching.
  const assetsByProduct = new Map<string, WatchListItem[]>();
  const assetsByPurl = new Map<string, WatchListItem[]>();
  // Assets with neither a CPE nor a PURL can only be matched by the text/alias
  // fallback, so they remain candidates for every CVE. PURL-only assets are
  // reachable through their package bucket instead of being scanned every time.
  const assetsWithoutIdentifiers: WatchListItem[] = [];
  const assetsWithBroadCpes: WatchListItem[] = [];
  // Build alias-expanded indices so assets are candidates when their vendor
  // or product differs from a CVE's by an alias rather than a canonical name.
  // Built-in aliases are included: the matcher accepts them, so the candidate
  // prefilter must not drop the pair before it can be evaluated. Punctuation
  // variants are accepted by the matcher's normalizer (`widget_pro` versus
  // `widget-pro`), so the normalized token is indexed alongside every spelling.
  const aliasVendorKeys = (v: string): string[] =>
    !v
      ? [v]
      : [
          ...new Set([
            v.toLowerCase(),
            normalizeAliasToken(v),
            ...aliasGroupKeys(v, DEFAULT_VENDOR_ALIASES, effectiveVendorAliases),
          ]),
        ];
  const aliasProductKeys = (p: string): string[] =>
    !p
      ? [p]
      : [
          ...new Set([
            p.toLowerCase(),
            normalizeAliasToken(p),
            ...aliasGroupKeys(p, DEFAULT_PRODUCT_ALIASES, effectiveProductAliases),
          ]),
        ];
  for (const asset of activeAssets) {
    const seenPurls = new Set<string>();
    for (const purl of asset.purls ?? []) {
      const identity = purlIdentity(purl);
      if (!identity || seenPurls.has(identity)) continue;
      seenPurls.add(identity);
      const bucket = assetsByPurl.get(identity) || [];
      bucket.push(asset);
      assetsByPurl.set(identity, bucket);
    }
    if (!asset.cpes.length) {
      if (!asset.purls?.length) assetsWithoutIdentifiers.push(asset);
      continue;
    }
    const seenProducts = new Set<string>();
    for (const cpe of asset.cpes) {
      const parsed = parseCPE23(cpe);
      if (!parsed.isValid) continue;
      if (/[?*]/.test(parsed.vendor) || /[?*]/.test(parsed.product)) {
        assetsWithBroadCpes.push(asset);
        break;
      }
      // Register asset under all alias-expanded vendor/product keys.
      for (const vendorKey of aliasVendorKeys(parsed.vendor))
        for (const productKey of aliasProductKeys(parsed.product)) {
          const key = `${vendorKey}\u0000${productKey}`;
          if (seenProducts.has(key)) continue;
          seenProducts.add(key);
          const bucket = assetsByProduct.get(key) || [];
          bucket.push(asset);
          assetsByProduct.set(key, bucket);
        }
    }
    // Keep assets with non-empty but invalid CPE lists out of text fallback;
    // the matcher correctly treats structured identifiers as authoritative.
  }
  const candidateAssets = (cve: NormalizedCVE): WatchListItem[] => {
    const criteria = cve.cpeMatchDetails?.length
      ? cve.cpeMatchDetails.map((detail) => detail.criteria)
      : cve.cpeMatches;
    const candidates = new Map<string, WatchListItem>();
    const add = (items: WatchListItem[]) => items.forEach((asset) => candidates.set(asset.id, asset));
    add(assetsWithoutIdentifiers);
    add(assetsWithBroadCpes);
    if (cve.purls?.length)
      for (const purl of cve.purls) {
        const identity = purlIdentity(purl);
        if (identity) add(assetsByPurl.get(identity) || []);
      }
    if (!criteria.length) {
      // A CVE with no structured identifiers has to use the text/alias fallback
      // against the whole inventory. A package-only advisory stays bounded to
      // the matching package buckets.
      if (!cve.purls?.length) return activeAssets;
      return [...candidates.values()];
    }
    for (const criterion of criteria) {
      const parsed = parseCPE23(criterion);
      if (!parsed.isValid || /[?*]/.test(parsed.vendor) || /[?*]/.test(parsed.product)) {
        add(activeAssets);
        break;
      }
      for (const vendorKey of aliasVendorKeys(parsed.vendor))
        for (const productKey of aliasProductKeys(parsed.product))
          add(assetsByProduct.get(`${vendorKey}\u0000${productKey}`) || []);
    }
    return [...candidates.values()];
  };
  // Assets that can never be reached through a structured identity join are
  // added to every CVE's candidate set, matching candidateAssets' fallback.
  const alwaysCandidateAssets = [...assetsWithoutIdentifiers, ...assetsWithBroadCpes];
  const assetById = new Map(activeAssets.map((asset) => [asset.id, asset]));
  /**
   * When PostgreSQL supplied candidate pairs, iterate only those assets. A CVE
   * absent from the map has a wildcard/unstructured criterion and falls back to
   * the in-process candidate selection, preserving the text/alias path.
   */
  const assetsForCve = (cve: NormalizedCVE, canonical: string): WatchListItem[] => {
    const allowed = candidatePairs?.get(canonical);
    if (!allowed) return candidateAssets(cve);
    const candidates = new Map<string, WatchListItem>();
    for (const id of allowed) {
      const asset = assetById.get(id);
      if (asset) candidates.set(asset.id, asset);
    }
    for (const asset of alwaysCandidateAssets) candidates.set(asset.id, asset);
    return [...candidates.values()];
  };
  const matchingStarted = performance.now();
  for (const raw of latest.values()) {
    const canonical = normalizeCveId(raw.cveId);
    const inTimelineScope = isWithinTimelineScope(raw.publishedDate, raw.modifiedDate, settings.scopeHours, started);
    // Filter before candidate selection so every match method (strict CPE/PURL,
    // alias, and vendor/product fallback) sees only CVEs whose latest published
    // or modified date is inside the run's timeline scope. Existing findings
    // are still re-evaluated outside that window so scope expiry alone cannot
    // turn an active finding into NOT_APPLICABLE during reconciliation.
    if (!canonical || (!inTimelineScope && !knownCves.has(canonical))) continue;
    processed++;
    const cve = { ...raw, cveId: canonical };
    for (const asset of assetsForCve(cve, canonical)) {
      const key = `${canonical}:${asset.id}`;
      if (!inTimelineScope && !known.has(key)) continue;
      if (known.has(key) && !includeExistingCandidates) continue;
      // An explicit CPE match criteria is authoritative for its own entry: a
      // per-entry range without bounds means "any version of this product", so the
      // product-level versionRange must not be applied across all criteria. The
      // product-level range is only a fallback when the CVE has no match details
      // at all.
      const applicabilitySets = cve.cpeMatchDetails?.length
        ? cve.cpeMatchDetails.map(({ criteria, range }) => ({
            cpes: [criteria],
            range: range && Object.values(range).some(Boolean) ? range : undefined,
          }))
        : [{ cpes: cve.cpeMatches, range: cve.versionRange }];
      // Per-CPE ranges apply only to that CPE criterion. PURLs use the
      // package-level range and must never borrow another product's bounds.
      const matches = applicabilitySets.map(({ cpes, range }) =>
        matchesWatchlistItem(
          asset.cpes,
          asset.vendor,
          asset.product,
          cpes,
          cve.title,
          cve.description,
          range,
          asset.purls,
          cve.purls,
          asset.targetHw,
          undefined,
          false,
          effectiveVendorAliases,
          effectiveProductAliases,
          asset.version,
          cve.cisaKev?.isKev === true &&
            !cve.cpeMatches?.length &&
            !cve.cpeMatchDetails?.length &&
            !cve.purls?.length,
        ),
      );
      if (asset.purls?.length && cve.purls?.length)
        matches.push(
          matchesWatchlistItem(
            [],
            '',
            '',
            [],
            '',
            '',
            cve.versionRange,
            asset.purls,
            cve.purls,
            asset.targetHw,
          ),
        );
      // Audit C-1: applicability is a conjunction, not a competition.
      //
      // CPE criteria and package identities describe the same advisory outcome:
      // a CVE affects the asset when *any* of its own criteria applies AND no
      // independent identifier proves it does not. Selecting only the
      // highest-confidence result let a CPE match outrank a PURL that proved a
      // different package version, so an unaffected dependency was dispatched at
      // 90% confidence whenever the advisory also named the product by CPE.
      //
      // Two distinct verdicts are treated as authoritative exclusions:
      //  - the package identity is exact (`matchPurl` requires identity and
      //    version to agree), so a PURL mismatch is a proof, not a spelling
      //    difference;
      //  - `matchesWatchlistItem` returns it early only when nothing else in its
      //    own applicability set matched.
      const packageRejected = matches.some(
        (match) => !match.matched && match.evidence === 'Package identifiers did not match',
      );
      const result = matches.filter((match) => match.matched).sort((a, b) => b.confidence - a.confidence)[0];
      if (!result?.matched) continue;
      if (packageRejected) {
        // A confirmed CPE match on a *different* identifier can still be a real
        // correlation (the product is vulnerable even if this bundled package
        // version is not). It can never be auto-dispatched on the strength of
        // contradicting evidence; hold it for an operator.
        result.confidence = Math.min(result.confidence, 70);
        result.applicabilityRequiresReview = true;
      }
      // Distinguish the two sources of review requirement so each is held only
      // for its own reason:
      //  - cve.applicabilityRequiresReview is an ingestion-time flag set when the
      //    CVE configuration uses AND/negate operators that cannot be safely
      //    flattened. When the advisory has NO CPE data at all, this flag is just
      //    "NVD hasn't analyzed applicability yet" — a match from the
      //    vendor/product fallback is still a real product correlation, so it is
      //    not held purely on that basis.
      //  - result.applicabilityRequiresReview is a match-level signal that the
      //    match itself is uncertain (version range cannot be verified, package
      //    identity without a version, etc.). This holds the finding unless
      //    autoDispatchUnverifiableMatches is set, in which case it participates
      //    in the confidence threshold like any other match.
      // L-1: an advisory can assert applicability through package identifiers
      // alone. Treating only CPE data as "applicability data" made a package-only
      // advisory look unanalyzed, which silently disabled the AND/negate review
      // override for the one advisory shape that needs it most.
      const advisoryLacksApplicabilityData = !(
        cve.cpeMatches?.length ||
        cve.cpeMatchDetails?.length ||
        cve.purls?.length
      );
      // A complete product-wide registration (every component but vendor/product
      // wildcarded) is a deliberate, broad "monitor everything" choice by the
      // operator, the same choice that already releases the per-match version
      // hold. The AND/negate flag protects against flattening a CVE's config
      // tree into an OR when a concrete asset might not satisfy every branch;
      // a product-wide registration matches every branch by construction, so
      // the flag has nothing left to protect against for this asset.
      const confirmedProductWideMatch = Boolean(result.productWideAllVersions) && !result.applicabilityRequiresReview;
      const confirmedKevProductOnlyMatch =
        confirmedProductWideMatch && result.method === 'VENDOR_PRODUCT_FALLBACK' && cve.cisaKev?.isKev === true;
      const cveReviewOverride =
        cve.applicabilityRequiresReview && !advisoryLacksApplicabilityData && !confirmedProductWideMatch;
      const sourceRequiresReview = cve.applicabilityPolicy === 'REVIEW_ONLY' && !confirmedKevProductOnlyMatch;
      const unverifiableMatch = sourceRequiresReview || cveReviewOverride || result.applicabilityRequiresReview;
      const threshold = settings.autoDispatchConfidenceThreshold ?? 90;
      if (sourceRequiresReview || cveReviewOverride) result.confidence = 0;
      else if (confirmedKevProductOnlyMatch) result.confidence = Math.max(result.confidence, threshold);
      (result as MatchResult & { contradicted?: true }).contradicted = packageRejected || undefined;
      const confirmed =
        !packageRejected &&
        !sourceRequiresReview &&
        !cveReviewOverride &&
        (!unverifiableMatch || settings.autoDispatchUnverifiableMatches) &&
        shouldAutoDispatch(result.confidence, settings);
      // Say *why* a match is held. A held finding is re-derived before every
      // delivery attempt, so the reason has to name the actual blocker (policy
      // threshold vs. missing inventory version vs. unverifiable CVE evidence)
      // instead of implying one the operator cannot act on. The reason is tied to
      // the finding's notificationStatus so the evidence and the hold agree.
      const holdReason = confirmed
        ? undefined
        : packageRejected
          ? 'the package identifiers prove a different version, while the product matches by CPE; confirm which identifier is authoritative'
          : sourceRequiresReview
            ? 'the source classifies applicability evidence as review-only'
          : cveReviewOverride
          ? 'the CVE configuration uses complex AND/negate criteria that require manual verification'
          : result.applicabilityRequiresReview
            ? !asset.version || asset.version === '*'
              ? 'the inventory item has no version, so the version range cannot be verified'
              : 'the available CVE evidence cannot verify this version'
            : `${result.confidence}% confidence is below the ${threshold}% auto-dispatch threshold`;
      const evidence = confirmed
        ? advisoryLacksApplicabilityData
          ? `Product correlation; the advisory has no CPE data yet, so the ${result.confidence}% match was dispatched under the workspace policy`
          : 'Structured package/version correlation'
        : `Product correlation; held for review because ${holdReason}`;
      newFindings.push({
        id: crypto.randomUUID(),
        cveId: canonical,
        cve,
        matchedAssetId: asset.id,
        matchedAssetName: `${asset.assetTag} (${asset.vendor} ${asset.product})`,
        matchedAssetVendor: asset.vendor,
        matchedAssetProduct: asset.product,
        matchedAssetPurls: asset.purls,
        matchedCpe: result.matchedCpe || '',
        matchingMethod: result.method,
        matchingEvidence: evidence,
        confidence: result.confidence,
        exposure: asset.exposure,
        exploitRisk: determineExploitRisk(cve),
        notificationStatus: confirmed ? 'QUEUED_FOR_DISPATCH' : 'REVIEW_REQUIRED',
        status: 'MONITORED',
        autoDispatchedAt: null,
        advisoryId: null,
        executionId: executionId,
        reviewNotifiedAt: null,
        timeline: [
          {
            timestamp: started.toISOString(),
            action: 'Matched inventory',
            system: 'Server correlation engine',
            details: evidence,
          },
        ],
      });
      known.add(key);
    }
  }
  const matchingDurationMs = Math.round(performance.now() - matchingStarted);
  const execution: PipelineExecution = {
    id: executionId,
    name: formatExecutionName(executionId),
    startTime: started.toISOString(),
    endTime: started.toISOString(),
    status: 'COMPLETED',
    scopeHours: settings.scopeHours,
    phases: [
      {
        name: 'Normalize & deduplicate',
        status: 'SUCCESS',
        durationMs: normalizationDurationMs,
        details: `${latest.size} canonical CVEs; ${duplicates} duplicates removed`,
      },
      {
        name: 'Product matching',
        status: 'SUCCESS',
        durationMs: matchingDurationMs,
        details: `${processed} CVEs evaluated against ${activeAssets.length} active products; ${newFindings.length} matches`,
      },
    ],
    stats: {
      rawIngested: corpus.length,
      normalized: processed,
      deduplicated: processed,
      inRunDuplicatesDropped: duplicates,
      // The engine knows this run's matches but not which of them were already
      // known from earlier runs, so this is the current-match count. The
      // pipeline worker replaces it with the new-detection count before
      // persisting the execution; see countNewFindings.
      matchedWatchlist: newFindings.length,
      autoDispatchedNotifications: 0,
      advisoriesDispatched: 0,
      webhooksFired: 0,
      vexSuppressedCount: 0,
    },
    logs: [],
  };
  return {
    execution,
    newFindings,
    newAdvisories: [],
    updatedAlertedCves: structuredClone(alerted),
    newEmailLogs: [],
    newAuditLogs: [],
  };
}
