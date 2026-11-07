import type { Config } from './config';
import type { Requester } from './network';
import type { NormalizedCVE, ThreatSearchHit, ThreatSearchResponse } from '../src/types/index.ts';
import { loadNvdApiKey } from './cpeSearch';
import { normalizeNvd } from './ingestion';
import {
  parseCPE23,
  matchVendorWithAliases,
  matchProductWithAliases,
  buildAliasMap,
  aliasGroupKeys,
  DEFAULT_VENDOR_ALIASES,
  DEFAULT_PRODUCT_ALIASES,
} from '../src/utils/cpeMatcher';
import { normalizeCveId } from '../src/utils/deduplicator';
import type { Db } from './db';
import { list } from './db';
import { HttpError } from './validation';

const NVD_CVE_ENDPOINT = 'https://services.nvd.nist.gov/rest/json/cves/2.0';

interface AliasEntry {
  scope: 'VENDOR' | 'PRODUCT';
  canonical: string;
  aliases: string[];
}

export interface ThreatSearchOptions {
  vendor: string;
  product: string;
  limit: number;
  /**
   * Optional start date (YYYY-MM-DD) constraining the scan to CVEs published
   * on or after this date. Forwarded to the NVD API as `pubStartDate` and used
   * to filter the local threat-feed cache.
   */
  startDate?: string;
}

export class ThreatSearchRateLimitError extends Error {
  readonly retryAfter: number | null;
  constructor(message: string, retryAfter: number | null = null) {
    super(message);
    this.name = 'ThreatSearchRateLimitError';
    this.retryAfter = retryAfter;
  }
}

/**
 * The upstream search could not be completed (all CPE lookups and the keyword
 * fallback failed). Distinct from an empty result set: the route maps this to a
 * 502 so the UI reports a failure to search rather than "no vulnerabilities".
 */
export class ThreatSearchUpstreamError extends Error {
  readonly reasons: string[];
  constructor(message: string, reasons: string[] = []) {
    super(message);
    this.name = 'ThreatSearchUpstreamError';
    this.reasons = reasons;
  }
}

/**
 * Searches the NVD CVE API for vulnerabilities affecting the given vendor
 * and product. Uses NVD's CPE virtual match (`virtualMatchString`) as the
 * primary path so every version of a product is covered, falling back to
 * keyword search when the CPE dictionary yields no results. Custom aliases
 * from the operator-managed thesaurus are merged onto the built-in baseline
 * to broaden the vendor/product match.
 *
 * All requests go through the shared SSRF-protected requester, so the NVD
 * host must appear in EGRESS_ALLOWED_HOSTS (it is present by default).
 */
export async function searchThreatIntelligence(
  request: Requester,
  db: Db,
  config: Config,
  options: ThreatSearchOptions,
): Promise<ThreatSearchResponse> {
  const { vendor, product, limit, startDate } = options;
  const apiKey = await loadNvdApiKey(db, config);
  const apiKeyUsed = Boolean(apiKey);
  const trimmedVendor = vendor.trim().toLowerCase();
  const trimmedProduct = product.trim().toLowerCase();
  // NVD expects ISO 8601 with milliseconds; the client sends YYYY-MM-DD.
  const nvdStartDate = startDate ? `${startDate}T00:00:00.000` : undefined;

  // A blank vendor or product cannot produce a CPE prefix (it would become the
  // wildcard prefix `…:*::*` and return the whole corpus). Treat it as a client
  // error instead of an empty result, which previously read as "no matches".
  if (!trimmedVendor || !trimmedProduct)
    throw new HttpError(400, 'A vendor and product are required for a threat intelligence search');

  const allAliases = await list<AliasEntry>(db, 'aliases');
  const customVendorAliases = buildAliasMap(
    allAliases.filter((e) => e.scope === 'VENDOR'),
    'VENDOR',
  );
  const customProductAliases = buildAliasMap(
    allAliases.filter((e) => e.scope === 'PRODUCT'),
    'PRODUCT',
  );

  const hits: ThreatSearchHit[] = [];
  const seenCves = new Set<string>();
  let totalResults = 0;
  let rateLimited = false;
  let retryAfter: number | undefined;

  const cpePrefixes = generateCpePrefixes(
    trimmedVendor,
    trimmedProduct,
    customVendorAliases,
    customProductAliases,
  );

  // Try exact CPE 2.3 match first (parts a, o, h)
  let exactHits = 0;
  // Every prefix that errored, with the status/message, so a total failure can
  // be reported instead of being flattened into an empty result set. Previously
  // a 404 (bad CPE spelling) or 403/5xx on all three prefixes produced
  // `hits: []`, which the UI renders as "No vulnerabilities matched" — a lie
  // that sends the operator hunting for a spelling error in a correct query.
  const prefixFailures: string[] = [];
  let rateLimitSeen = false;
  // Set once any upstream request returns a usable response (200). Distinguishes
  // "NVD answered, there is nothing to report" from "NVD never answered".
  let answered = false;
  for (const cpePrefix of cpePrefixes) {
    try {
      const result = await fetchNvdCves(request, apiKey, cpePrefix, limit, nvdStartDate);
      answered = true;
      for (const cve of result.cves) {
        const matchingCpes = findMatchingCpes(
          cve,
          cpePrefix,
          trimmedVendor,
          trimmedProduct,
          customVendorAliases,
          customProductAliases,
        );
        // A virtual-match response is evidence, not a substitute for identity
        // verification. Verify the normalized record's CPE vendor and product;
        // this blocks unrelated fixtures/upstream payloads and prevents false
        // positives while still accepting any version or edition of the match.
        if (matchingCpes.length === 0) continue;
        const acceptedCpes = matchingCpes;
        const normId = normalizeCveId(cve.cveId);
        if (!normId || !seenCves.has(normId)) {
          if (normId) seenCves.add(normId);
          hits.push({
            cve,
            matchingCpes: acceptedCpes,
            source: 'NVD_API',
          });
          exactHits++;
        }
        totalResults++;
        if (hits.length >= limit) break;
      }
      if (hits.length >= limit) break;
    } catch (err) {
      if (err instanceof ThreatSearchRateLimitError) {
        rateLimited = true;
        rateLimitSeen = true;
        retryAfter = err.retryAfter ?? undefined;
        break;
      }
      prefixFailures.push(err instanceof Error ? err.message : String(err));
      // On any other error, log and continue to next CPE prefix
      console.warn(
        JSON.stringify({
          level: 'warn',
          event: 'nvd_cpe_search_error',
          cpePrefix,
          error: err instanceof Error ? err.message : String(err),
        }),
      );
    }
  }

  // Fall back to keyword search when the CPE path produced no hits OR when every
  // prefix failed. A failed CPE lookup (404 on an unusual vendor spelling, an
  // upstream 5xx, a proxy rejection) is exactly when keyword search is the only
  // way to answer the question; gating the fallback on `hits.length === 0`
  // alone would turn a transport problem into "no results".
  let keywordError: string | undefined;
  if (hits.length === 0 && !rateLimitSeen) {
    const canonicalKeyword = `${trimmedVendor} ${trimmedProduct}`.replace(/_/g, ' ').replace(/\s+/g, ' ').trim();
    const vendorAliases = aliasGroupKeys(trimmedVendor, DEFAULT_VENDOR_ALIASES, customVendorAliases).slice(0, 2);
    const productAliases = aliasGroupKeys(trimmedProduct, DEFAULT_PRODUCT_ALIASES, customProductAliases).slice(0, 2);
    const keywordCandidates = [...new Set([
      canonicalKeyword,
      ...vendorAliases.map((alias) => `${alias.replace(/_/g, ' ')} ${trimmedProduct.replace(/_/g, ' ')}`),
      ...productAliases.map((alias) => `${trimmedVendor.replace(/_/g, ' ')} ${alias.replace(/_/g, ' ')}`),
    ])].slice(0, 3);

    try {
      for (const keyword of keywordCandidates) {
        const result = await fetchNvdCvesByKeyword(request, apiKey, keyword, limit * 2, nvdStartDate);
        answered = true;
        for (const cve of result.cves) {
          const matchingCpes = findMatchingCpesByAlias(
            cve,
            trimmedVendor,
            trimmedProduct,
            customVendorAliases,
            customProductAliases,
          );
          // Keyword fallback is an evidence candidate, not an exact CPE match.
          // Keep only CVEs with a vendor/product-bearing CPE alias or a description
          // that names both terms; this prevents unrelated NVD keyword hits from
          // entering the review queue.
          const text = `${cve.title} ${cve.description}`.toLowerCase();
          const vendorText = trimmedVendor.replace(/[_-]+/g, ' ').trim();
          const productText = trimmedProduct.replace(/[_-]+/g, ' ').trim();
          const textCorrelation =
            Boolean(vendorText) && Boolean(productText) &&
            text.includes(vendorText) && text.includes(productText);
          if (matchingCpes.length === 0 && !textCorrelation) continue;
          const acceptedCpes = matchingCpes.length > 0 ? matchingCpes : cve.cpeMatches;
          const normId = normalizeCveId(cve.cveId);
          if (!normId || !seenCves.has(normId)) {
            if (normId) seenCves.add(normId);
            hits.push({ cve, matchingCpes: acceptedCpes, source: 'KEYWORD_FALLBACK' });
          }
          totalResults++;
        }
        if (hits.length >= limit) break;
      }
    } catch (err) {
      if (err instanceof ThreatSearchRateLimitError) {
        rateLimited = true;
        rateLimitSeen = true;
        retryAfter = err.retryAfter ?? undefined;
      } else {
        keywordError = err instanceof Error ? err.message : String(err);
        console.warn(
          JSON.stringify({
            level: 'warn',
            event: 'nvd_keyword_fallback_error',
            keyword: canonicalKeyword,
            error: keywordError,
          }),
        );
      }
    }
  }

  // Nothing came back and nothing is merely rate-limited. Whether that is an
  // empty answer or a failure depends on a single fact: did *any* upstream
  // request succeed? A 200 with zero records (or records we could not
  // normalise) is a legitimate empty result; every request failing is not, and
  // reporting it as "no vulnerabilities matched" is what made a broken search
  // look valid to the operator.
  if (hits.length === 0 && !rateLimited && !answered) {
    const reasons = [...new Set([...prefixFailures, ...(keywordError ? [keywordError] : [])])];
    throw new ThreatSearchUpstreamError(
      `NVD threat search failed: ${reasons[0] ?? 'upstream unavailable'}`,
      reasons,
    );
  }

  // Sort by CVSS severity descending
  hits.sort((a, b) => {
    const sa = severityScore(a.cve.cvss.severity);
    const sb = severityScore(b.cve.cvss.severity);
    if (sb !== sa) return sb - sa;
    return b.cve.cvss.score - a.cve.cvss.score;
  });

  return {
    hits: hits.slice(0, Math.max(1, Math.min(limit, 200))),
    totalResults,
    vendor,
    product,
    rateLimited,
    retryAfter,
    apiKeyUsed,
    startDate,
  };
}

interface NvdFetchResult {
  cves: NormalizedCVE[];
  /** Records in the upstream response, before normalization filtered any out. */
  returned: number;
  /** Records that failed normalization and were skipped. */
  skipped: number;
}

async function fetchNvdCves(
  request: Requester,
  apiKey: string,
  matchString: string,
  limit: number,
  startDate?: string,
): Promise<NvdFetchResult> {
  const url = new URL(NVD_CVE_ENDPOINT);
  // `cpeName` requires an exact dictionary entry; a wildcard version suffix
  // (…:product:*:*) returns 404. `virtualMatchString` matches every version
  // of the CPE prefix, which is what an operator searching a product expects.
  url.searchParams.set('virtualMatchString', matchString);
  url.searchParams.set('resultsPerPage', String(Math.min(Math.max(1, limit), 2000)));
  if (apiKey) url.searchParams.set('apiKey', apiKey);
  if (startDate) url.searchParams.set('pubStartDate', startDate);

  return fetchNvdResponse(request, url.href);
}

async function fetchNvdCvesByKeyword(
  request: Requester,
  apiKey: string,
  keyword: string,
  limit: number,
  startDate?: string,
): Promise<NvdFetchResult> {
  const url = new URL(NVD_CVE_ENDPOINT);
  url.searchParams.set('keywordSearch', keyword);
  url.searchParams.set('resultsPerPage', String(Math.min(Math.max(1, limit), 2000)));
  if (apiKey) url.searchParams.set('apiKey', apiKey);
  if (startDate) url.searchParams.set('pubStartDate', startDate);

  return fetchNvdResponse(request, url.href);
}

async function fetchNvdResponse(request: Requester, url: string): Promise<NvdFetchResult> {
  const response = await request(url, {
    timeoutMs: 30000,
    socketTimeoutMs: 20000,
    maxResponseBytes: 10 * 1024 * 1024,
  });

  if (response.status === 429) {
    const retryAfterHeader = response.headers['retry-after'];
    const retryAfter = retryAfterHeader
      ? typeof retryAfterHeader === 'string'
        ? parseRetryAfter(retryAfterHeader)
        : parseRetryAfter(retryAfterHeader[0])
      : null;
    throw new ThreatSearchRateLimitError('NVD rate limit reached; retry later', retryAfter);
  }

  if (response.status !== 200) {
    throw new Error(`NVD CVE search returned HTTP ${response.status}`);
  }

  let data: any;
  try {
    data = JSON.parse(response.body);
  } catch {
    throw new Error('NVD returned a non-JSON CVE search response');
  }

  const vulns = Array.isArray(data?.vulnerabilities) ? data.vulnerabilities : [];
  const cves: NormalizedCVE[] = [];
  let skipped = 0;
  for (const item of vulns) {
    // NVD occasionally returns a record that does not satisfy our normalized
    // schema (invalid CPE criteria, a CVSS score outside 0–10, a missing
    // timestamp). normalizeNvd() throws a ZodError for those. One malformed
    // record must not fail the operator's whole query, and it must not be
    // confused with an upstream transport failure — skip it and count it.
    try {
      const normalized = normalizeNvd(item, 'NVD_API');
      if (normalized) cves.push(normalized);
    } catch {
      skipped++;
    }
  }
  if (skipped)
    console.warn(
      JSON.stringify({
        level: 'warn',
        event: 'nvd_search_record_skipped',
        skipped,
        returned: vulns.length,
      }),
    );

  return {
    cves,
    // `returned` lets the caller tell "upstream answered with no records" from
    // "upstream answered but every record was unusable".
    returned: vulns.length,
    skipped,
  };
}

function parseRetryAfter(header: string): number | undefined {
  const asSeconds = Number(header);
  if (Number.isFinite(asSeconds)) return Math.max(1, Math.round(asSeconds));
  const asDate = Date.parse(header);
  return Number.isFinite(asDate) ? Math.max(1, Math.round((asDate - Date.now()) / 1000)) : undefined;
}

function escapeCpeComponent(value: string): string {
  const normalized = value.trim().toLowerCase().replace(/\s+/g, '_');
  return normalized.replace(/([\\:*?])/g, '\\$1');
}

export function generateCpePrefixes(
  vendor: string,
  product: string,
  customVendorAliases: Record<string, string[]> = {},
  customProductAliases: Record<string, string[]> = {},
): string[] {
  const wildcards = ['*', '*', '*', '*', '*', '*', '*', '*'].join(':');
  const vendorVariants = Object.keys(customVendorAliases).length
    ? [vendor, ...aliasGroupKeys(vendor, DEFAULT_VENDOR_ALIASES, customVendorAliases)].slice(0, 3)
    : [vendor];
  const productVariants = Object.keys(customProductAliases).length
    ? [product, ...aliasGroupKeys(product, DEFAULT_PRODUCT_ALIASES, customProductAliases)].slice(0, 3)
    : [product];

  const identities = [{ vendor, product }];
  for (const aliasVendor of vendorVariants.slice(1)) identities.push({ vendor: aliasVendor, product });
  for (const aliasProduct of productVariants.slice(1)) identities.push({ vendor, product: aliasProduct });

  const prefixes = identities.flatMap(({ vendor: aliasVendor, product: aliasProduct }) =>
    (['a', 'o', 'h'] as const).map(
      (part) => `cpe:2.3:${part}:${escapeCpeComponent(aliasVendor)}:${escapeCpeComponent(aliasProduct)}:${wildcards}`,
    ),
  );
  return [...new Set(prefixes)].slice(0, 12);
}

function findMatchingCpes(
  cve: NormalizedCVE,
  cpePrefix: string,
  assetVendor: string,
  assetProduct: string,
  customVendorAliases: Record<string, string[]>,
  customProductAliases: Record<string, string[]>,
): string[] {
  return cve.cpeMatches.filter((cpe) => {
    const parsed = parseCPE23(cpe);
    if (!parsed.isValid) return false;

    const vendorMatch =
      parsed.vendor === assetVendor ||
      parsed.vendor === '*' ||
      matchVendorWithAliases(parsed.vendor, assetVendor, customVendorAliases);

    const productMatch =
      parsed.product === assetProduct ||
      parsed.product === '*' ||
      matchProductWithAliases(parsed.product, assetProduct, customProductAliases);

    return vendorMatch && productMatch;
  });
}

function findMatchingCpesByAlias(
  cve: NormalizedCVE,
  assetVendor: string,
  assetProduct: string,
  customVendorAliases: Record<string, string[]>,
  customProductAliases: Record<string, string[]>,
): string[] {
  return cve.cpeMatches.filter((cpe) => {
    const parsed = parseCPE23(cpe);
    if (!parsed.isValid) return false;

    return (
      matchVendorWithAliases(parsed.vendor, assetVendor, customVendorAliases) &&
      matchProductWithAliases(parsed.product, assetProduct, customProductAliases)
    );
  });
}

function severityScore(severity: NormalizedCVE['cvss']['severity']): number {
  switch (severity) {
    case 'CRITICAL':
      return 4;
    case 'HIGH':
      return 3;
    case 'MEDIUM':
      return 2;
    case 'LOW':
      return 1;
    default:
      return 0;
  }
}
