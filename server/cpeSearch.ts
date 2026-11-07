import type { Db } from './db';
import { list } from './db';
import { decrypt, encryptionKeys } from './secrets';
import { parseCPE23, normalizeCpeForComparison } from '../src/utils/cpeMatcher.ts';
import type { Config } from './config';
import type { Requester } from './network';
import type { ThreatFeed, NvdCpeSearchResult, NvdCpeSearchResponse } from '../src/types/index.ts';

import { isProductWildcard, dictionaryEntryMatchesWildcard } from '../src/utils/registrationCpe.ts';

const NVD_CPE_ENDPOINT = 'https://services.nvd.nist.gov/rest/json/cpes/2.0';

export function buildCpeUrl(keyword: string, resultsPerPage: number): URL {
  const url = new URL(NVD_CPE_ENDPOINT);
  url.searchParams.set('keywordSearch', keyword);
  url.searchParams.set('resultsPerPage', String(resultsPerPage));
  return url;
}

/**
 * Builds a URL for the NVD CPE dictionary API using a cpeMatchString query
 * with wildcard support. Unlike keywordSearch (which matches titles and
 * reference text), cpeMatchString performs structural pattern matching
 * against CPE 2.3 component names, so a wildcard vendor (`*`) finds
 * dictionary entries regardless of the NVD-registered vendor label.
 */
export function buildCpeMatchStringUrl(matchString: string, resultsPerPage: number): URL {
  const url = new URL(NVD_CPE_ENDPOINT);
  url.searchParams.set('cpeMatchString', matchString);
  url.searchParams.set('resultsPerPage', String(resultsPerPage));
  return url;
}

/**
 * Escapes special characters in a CPE 2.3 component value for use in a
 * cpeMatchString query. The NVD dictionary stores CPE names with certain
 * characters escaped (e.g. "+" -> "\+", "(" -> "\("), so the match string
 * must apply the same escaping to find matching entries. Wildcard
 * characters `*` and `?` are also escaped so a literal occurrence in the
 * product name is matched rather than treated as a cpeMatchString wildcard.
 */
function escapeCpeComponent(value: string): string {
  return value
    .replace(/\\/g, '\\\\')
    .replace(/\+/g, '\\+')
    .replace(/\(/g, '\\(')
    .replace(/\)/g, '\\)')
    .replace(/\:/g, '\\:')
    .replace(/\*/g, '\\*')
    .replace(/\?/g, '\\?');
}

/**
 * Parses the NVD CPE API response body into structured results, deduplicating
 * against an optional set of already-seen CPE names (case-insensitive).
 */
function parseNvdCpeProducts(
  body: string,
  exactCpe?: string,
  seenCpes?: Set<string>,
  viaWildcardVendor?: boolean,
): { results: NvdCpeSearchResult[]; totalResults: number } {
  let data: any;
  try {
    data = JSON.parse(body);
  } catch {
    throw new Error('NVD returned a non-JSON CPE search response');
  }

  if (!Array.isArray(data?.products) || !Number.isSafeInteger(data?.totalResults) || data.totalResults < 0)
    throw new Error('NVD returned an invalid CPE search response');

  const configurations: any[] = data.products;
  const results: NvdCpeSearchResult[] = [];
  for (const entry of configurations) {
    const cpe = entry?.cpe || entry;
    const name = typeof cpe?.cpeName === 'string' ? cpe.cpeName : '';
    if (!name || cpe?.deprecated === true) continue;
    if (exactCpe && normalizeCpeForComparison(name) !== normalizeCpeForComparison(exactCpe)) continue;
    if (seenCpes && seenCpes.has(normalizeCpeForComparison(name))) continue;
    const parsed = parseCPE23(name);
    if (!parsed.isValid) continue;
    const title =
      Array.isArray(cpe?.titles) && typeof cpe.titles[0]?.title === 'string'
        ? cpe.titles[0].title
        : undefined;
    results.push({
      cpeName: name,
      cpeNameId: typeof cpe?.cpeNameId === 'string' ? cpe.cpeNameId : '',
      part: parsed.part,
      vendor: parsed.vendor,
      product: parsed.product,
      version: parsed.version,
      update: parsed.update,
      targetSw: parsed.targetSw,
      targetHw: parsed.targetHw,
      ...(title ? { title } : {}),
      ...(viaWildcardVendor ? { viaWildcardVendor: true } : {}),
    });
    seenCpes?.add(name.toLowerCase());
  }

  const total = Number.isInteger(data?.totalResults) ? Number(data.totalResults) : results.length;
  return { results, totalResults: total };
}

/**
 * Reads the API key from the first enabled NVD feed configured with API-key
 * authentication. Returns an empty string when no NVD key is configured, in
 * which case the NVD CPE search is served from the public, unauthenticated
 * rate budget (5 requests / 30s).
 */
export async function loadNvdApiKey(db: Db, config: Config): Promise<string> {
  let feeds: ThreatFeed[];
  try {
    feeds = await list<ThreatFeed>(db, 'feeds');
  } catch {
    console.warn(JSON.stringify({ level: 'warn', event: 'nvd_api_key_feed_query_failed' }));
    return '';
  }
  const nvd = feeds.find((f) => f.type === 'NVD_API' && f.authType === 'API_KEY' && f.enabled);
  if (!nvd) {
    const nvdFeeds = feeds.filter((f) => f.type === 'NVD_API');
    console.warn(
      JSON.stringify({
        level: 'warn',
        event: 'nvd_api_key_not_configured',
        nvdFeedCount: nvdFeeds.length,
        authTypes: nvdFeeds.map((f) => f.authType),
        enabledFlags: nvdFeeds.map((f) => f.enabled),
      }),
    );
    return '';
  }
  if (!nvd.authSecretKey) {
    console.warn(
      JSON.stringify({
        level: 'warn',
        event: 'nvd_api_key_secret_missing',
        feedId: nvd.id,
        authType: nvd.authType,
      }),
    );
    return '';
  }
  try {
    return decrypt(nvd.authSecretKey, encryptionKeys(config), `feed:${nvd.id}`);
  } catch (err) {
    console.warn(
      JSON.stringify({
        level: 'warn',
        event: 'nvd_api_key_decrypt_failed',
        feedId: nvd.id,
        error: err instanceof Error ? err.message : String(err),
      }),
    );
    return '';
  }
}

/**
 * Queries the NVD CPE dictionary for verified CPE 2.3 names matching the
 * supplied vendor and product keywords. Only well-formed CPE 2.3 entries are
 * returned; partial matches that the NVD keyword search surfaces are parsed and
 * filtered so the operator only selects structurally valid CPEs.
 *
 * The request is issued through the shared SSRF-protected requester, so the NVD
 * host must appear in EGRESS_ALLOWED_HOSTS (it is present by default).
 */
export async function searchNvdCpes(
  request: Requester,
  apiKey: string,
  vendor: string,
  product: string,
  limit: number,
  exactCpe?: string,
  cpeNameId?: string,
): Promise<NvdCpeSearchResponse> {
  // NVD keywordSearch matches titles/reference text, not CPE component names.
  const keyword = `${vendor} ${product}`.replace(/_/g, ' ').replace(/\s+/g, ' ').trim();
  const pageSize = Math.min(Math.max(1, limit), 200);
  const url = buildCpeUrl(keyword, pageSize);
  if (exactCpe) {
    if (!parseCPE23(exactCpe).isValid) throw new Error('Invalid CPE 2.3 expression');
    url.searchParams.delete('keywordSearch');
    if (cpeNameId) url.searchParams.set('cpeNameId', cpeNameId);
    else url.searchParams.set('cpeMatchString', exactCpe);
  }
  const fetchPage = (key: string, urlObj: URL = url) =>
    request(urlObj.href, {
      headers: { Accept: 'application/json', ...(key ? { apiKey: key } : {}) },
      timeoutMs: 20000,
      socketTimeoutMs: 15000,
      maxResponseBytes: 4 * 1024 * 1024,
      sameHostRedirects: true,
    });
  let response = await fetchPage(apiKey);

  let effectiveKey = apiKey;

  // NVD reports rejected credentials with 404 and a diagnostic message header.
  // Only that case can fall back to the public budget: an unrelated 404 is an
  // upstream failure, never evidence that the dictionary has no matches.
  // HTTP headers are case-insensitive; access by lowercased key to avoid relying
  // on the implementation detail that Node lowercases response header names.
  const allHeaders = response.headers as Record<string, string | string[] | undefined>;
  const message = allHeaders['message'] ?? allHeaders['Message'] ?? allHeaders['MESSAGE'];
  if (
    response.status === 404 &&
    apiKey &&
    /invalid\s+api\s*key/i.test(Array.isArray(message) ? message.join(' ') : message || '')
  ) {
    effectiveKey = '';
    response = await fetchPage(effectiveKey);
  }

  if (response.status === 429) {
    throw {
      __nvdRateLimit: true,
      retryAfter: response.headers['retry-after'],
      status: 429,
      message: 'NVD rate limit reached; retry later',
    } as NvdRateLimitError;
  }

  if (response.status !== 200) throw new Error(`NVD CPE search returned HTTP ${response.status}`);

  const seenCpes = new Set<string>();
  const productWildcard = Boolean(exactCpe && isProductWildcard(exactCpe));
  const { results, totalResults } = parseNvdCpeProducts(
    response.body,
    productWildcard ? undefined : exactCpe,
    seenCpes,
  );
  if (productWildcard) {
    const matching = results.filter((entry) => dictionaryEntryMatchesWildcard(exactCpe!, entry.cpeName));
    if (matching.length) return { results: matching, totalResults };
  }

  // When no exact CPE lookup is requested and a product name is supplied,
  // also search with a cpeMatchString that uses a wildcard vendor (`*`).
  // This surfaces NVD dictionary entries even when the operator's vendor
  // label differs from the published NVD vendor (e.g. "notepad_plus_plus"
  // vs. the registered "don_ho"), so the operator can still select a
  // published, verified identifier before saving.
  //
  // These matches are put at the FRONT of the list: a product-name-only
  // match is what the operator is most likely looking for when their typed
  // vendor didn't produce a hit (or wasn't supplied at all), and every
  // result returned here is still an exact, verified NVD dictionary CPE —
  // only the search path differs, never the accuracy of the entry itself.
  if (!exactCpe && product.trim()) {
    const escapedProduct = escapeCpeComponent(product.trim());
    const matchString = `cpe:2.3:*:*:${escapedProduct}:*:*:*:*:*:*:*:*`;
    const wildcardUrl = buildCpeMatchStringUrl(matchString, pageSize);
    try {
      const wildcardResponse = await fetchPage(effectiveKey, wildcardUrl);
      if (wildcardResponse.status === 429) {
        throw {
          __nvdRateLimit: true,
          retryAfter: wildcardResponse.headers['retry-after'],
          status: 429,
          message: 'NVD rate limit reached; retry later',
        } as NvdRateLimitError;
      }
      if (wildcardResponse.status === 200) {
        const wildcardParsed = parseNvdCpeProducts(wildcardResponse.body, undefined, seenCpes, true);
        return {
          results: [...wildcardParsed.results, ...results],
          totalResults: totalResults + wildcardParsed.totalResults,
        };
      }
    } catch (error) {
      if (isNvdRateLimitError(error)) throw error;
      // Non-fatal: a failed wildcard search still returns the keyword results
    }
    return { results, totalResults };
  }

  // If an exact CPE was requested but no exact match was returned, retry
  // with a wildcard-vendor matchString built from the CPE's product. This
  // handles the common case where the operator's vendor label differs from
  // the NVD-registered vendor (e.g. "notepad-plus-plus" vs. "don_ho").
  if (exactCpe && results.length === 0) {
    const parsed = parseCPE23(exactCpe);
    if (parsed.isValid && parsed.product && parsed.product !== '*') {
      const escapedProduct = escapeCpeComponent(parsed.product);
      const matchString = `cpe:2.3:*:*:${escapedProduct}:*:*:*:*:*:*:*:*`;
      const wildcardUrl = buildCpeMatchStringUrl(matchString, pageSize);
      try {
        const wildcardResponse = await fetchPage(effectiveKey, wildcardUrl);
        if (wildcardResponse.status === 429) {
          throw {
            __nvdRateLimit: true,
            retryAfter: wildcardResponse.headers['retry-after'],
            status: 429,
            message: 'NVD rate limit reached; retry later',
          } as NvdRateLimitError;
        }
        if (wildcardResponse.status === 200) {
          const wildcardParsed = parseNvdCpeProducts(wildcardResponse.body, undefined, seenCpes, true);
          return {
            results: [...results, ...wildcardParsed.results],
            totalResults: totalResults + wildcardParsed.totalResults,
          };
        }
      } catch (error) {
        if (isNvdRateLimitError(error)) throw error;
        // Non-fatal: fall through to return empty results
      }
    }
  }

  return { results, totalResults };
}

export interface NvdRateLimitError {
  __nvdRateLimit: boolean;
  retryAfter: string | string[] | undefined;
  status: 429;
  message: string;
}

export function isNvdRateLimitError(error: unknown): error is NvdRateLimitError {
  return typeof error === 'object' && error !== null && (error as NvdRateLimitError).__nvdRateLimit === true;
}

export function nvdRetryAfterSeconds(error: NvdRateLimitError): number | null {
  const raw = error.retryAfter;
  const single = Array.isArray(raw) ? raw[0] : raw;
  if (!single) return null;
  const asSeconds = Number(single);
  if (Number.isFinite(asSeconds)) return Math.max(1, Math.round(asSeconds));
  const asDate = Date.parse(single);
  return Number.isFinite(asDate) ? Math.max(1, Math.round((asDate - Date.now()) / 1000)) : null;
}
