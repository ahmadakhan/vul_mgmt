/**
 * Google Custom Search JSON API client.
 *
 * This is the live-web half of the OSINT layer: it searches the operator's
 * configured Programmable Search Engine for fresh write-ups, vendor notices,
 * and press coverage that may not have reached OSV/NVD yet. The API key and
 * search-engine ID stay on the server; only normalized results cross the
 * network boundary to the browser.
 *
 * Security properties:
 *   - The destination is a compile-time constant and must remain in
 *     EGRESS_ALLOWED_HOSTS (`www.googleapis.com`).
 *   - The query is control-character stripped and length bounded; it never
 *     becomes a host, path, or header.
 *   - Redirects are disabled because the API is not expected to redirect and a
 *     redirect error would otherwise echo a URL containing the API key.
 *   - Provider HTML (`<b>` highlights, entities) is reduced to plain text, and
 *     result links are restricted to HTTP(S) without embedded credentials.
 */
import type { LiveOsintResult } from '../src/types/index.ts';
import type { Requester } from './network';

const GOOGLE_CSE_ENDPOINT = 'https://www.googleapis.com/customsearch/v1';
const MAX_QUERY = 200;
const MAX_RESULTS = 10;
const MAX_TITLE = 300;
const MAX_SNIPPET = 1_200;
const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;

export interface GoogleCseCredentials {
  apiKey: string;
  /** Programmable Search Engine ID (`cx`). */
  cx: string;
}

export interface GoogleCseOptions {
  query: string;
  /** The API accepts at most 10 results per request. Defaults to 10. */
  limit?: number;
}

export class GoogleCseError extends Error {
  readonly status: number | null;
  readonly retryAfter: number | null;

  constructor(message: string, status: number | null = null, retryAfter: number | null = null) {
    super(message);
    this.name = 'GoogleCseError';
    this.status = status;
    this.retryAfter = retryAfter;
  }
}

/** True when both credentials are present, so a query can actually be made. */
export function googleCseConfigured(
  credentials: GoogleCseCredentials | null | undefined,
): credentials is GoogleCseCredentials {
  return Boolean(credentials?.apiKey?.trim() && credentials?.cx?.trim());
}

/** Collapse control characters and whitespace, then enforce the API limit. */
export function normalizeGoogleCseQuery(value: unknown): string {
  if (typeof value !== 'string') return '';
  return value
    .replace(/[\u0000-\u001f\u007f]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, MAX_QUERY);
}

const NAMED_ENTITIES: Record<string, string> = {
  amp: '&',
  apos: "'",
  gt: '>',
  lt: '<',
  nbsp: ' ',
  quot: '"',
};

/** Decode the small entity set Google snippets use, without evaluating code. */
function decodeEntities(value: string): string {
  return value.replace(/&(#x?[0-9a-f]+|[a-z]+);/gi, (match, raw: string) => {
    const entity = raw.toLowerCase();
    if (entity.startsWith('#x')) {
      const code = Number.parseInt(entity.slice(2), 16);
      return Number.isFinite(code) && code > 0 && code <= 0x10ffff
        ? String.fromCodePoint(code)
        : match;
    }
    if (entity.startsWith('#')) {
      const code = Number.parseInt(entity.slice(1), 10);
      return Number.isFinite(code) && code > 0 && code <= 0x10ffff
        ? String.fromCodePoint(code)
        : match;
    }
    return NAMED_ENTITIES[entity] ?? match;
  });
}

/** Strip provider markup and bound the text before it reaches React. */
function cleanText(value: unknown, max: number): string {
  if (typeof value !== 'string') return '';
  return decodeEntities(value.replace(/<[^>]*>/g, ' '))
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, max);
}

/** Parse an HTTP(S) link and reject credentials or non-web schemes. */
function safeHttpUrl(value: unknown): URL | null {
  if (typeof value !== 'string' || !value.trim()) return null;
  try {
    const url = new URL(value.trim());
    if (!['https:', 'http:'].includes(url.protocol) || url.username || url.password) return null;
    return url;
  } catch {
    return null;
  }
}

/** Canonical link used only for de-duplication; the stored link keeps its shape. */
function dedupeKey(url: URL): string {
  const copy = new URL(url.href);
  copy.hash = '';
  if (copy.pathname !== '/') copy.pathname = copy.pathname.replace(/\/+$/, '');
  return copy.href;
}

/** The provider's `displayLink` when plausible, otherwise the real hostname. */
function sourceDomain(displayLink: unknown, url: URL): string {
  const raw =
    typeof displayLink === 'string'
      ? displayLink
          .trim()
          .toLowerCase()
          .replace(/^https?:\/\//, '')
          .replace(/\/.*$/, '')
      : '';
  if (/^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$/.test(raw)) return raw;
  return url.hostname.replace(/^www\./, '');
}

/** Pull a publication timestamp from the page metadata Google returns. */
function publishedDate(item: any): string | null {
  const meta = item?.pagemap?.metatags?.[0];
  if (!meta || typeof meta !== 'object') return null;
  for (const key of [
    'article:published_time',
    'date',
    'og:updated_time',
    'article:modified_time',
  ]) {
    const value = meta[key];
    if (typeof value !== 'string') continue;
    const timestamp = Date.parse(value);
    if (Number.isFinite(timestamp)) return new Date(timestamp).toISOString();
  }
  return null;
}

function retryAfterSeconds(header: string | string[] | undefined): number | null {
  const value = Array.isArray(header) ? header[0] : header;
  if (!value) return null;
  const seconds = Number(value);
  if (Number.isFinite(seconds)) return Math.max(1, Math.round(seconds));
  const timestamp = Date.parse(value);
  return Number.isFinite(timestamp)
    ? Math.max(1, Math.round((timestamp - Date.now()) / 1000))
    : null;
}

/**
 * Search the configured Programmable Search Engine and normalize the hits.
 *
 * Throws `GoogleCseError` for configuration, transport, and provider failures.
 * The caller treats that as a non-fatal warning so the vulnerability search
 * still returns OSV/NVD/KEV data.
 */
export async function searchGoogleCse(
  request: Requester,
  credentials: GoogleCseCredentials,
  options: GoogleCseOptions,
  timeoutMs = 12_000,
): Promise<LiveOsintResult[]> {
  const query = normalizeGoogleCseQuery(options.query);
  const apiKey = credentials.apiKey.trim();
  const cx = credentials.cx.trim();
  if (!query || !apiKey || !cx) return [];

  const limit = Math.max(1, Math.min(Math.floor(options.limit ?? MAX_RESULTS) || MAX_RESULTS, MAX_RESULTS));
  const url = new URL(GOOGLE_CSE_ENDPOINT);
  url.searchParams.set('key', apiKey);
  url.searchParams.set('cx', cx);
  url.searchParams.set('q', query);
  url.searchParams.set('num', String(limit));
  url.searchParams.set('safe', 'off');
  url.searchParams.set('hl', 'en');

  const response = await request(url.href, {
    timeoutMs,
    socketTimeoutMs: timeoutMs,
    maxResponseBytes: MAX_RESPONSE_BYTES,
    // The API is not expected to redirect; a redirect error would otherwise
    // put a URL containing the key into an error message.
    allowRedirects: false,
  });

  if (response.status === 429) {
    throw new GoogleCseError(
      'Google Custom Search rate limit reached',
      429,
      retryAfterSeconds(response.headers['retry-after']),
    );
  }
  if (response.status === 400)
    throw new GoogleCseError(
      'Google Custom Search rejected the request; check the search engine ID and query',
      400,
    );
  if (response.status === 401 || response.status === 403)
    throw new GoogleCseError('Google Custom Search rejected the API key', response.status);
  if (response.status < 200 || response.status >= 300)
    throw new GoogleCseError(`Google Custom Search returned HTTP ${response.status}`, response.status);

  let payload: any;
  try {
    payload = JSON.parse(response.body);
  } catch {
    throw new GoogleCseError('Google Custom Search returned a non-JSON response');
  }
  if (!payload || typeof payload !== 'object')
    throw new GoogleCseError('Google Custom Search returned an unexpected payload');
  // Do not echo provider error text: it is unnecessary for the UI and could
  // contain request details the operator did not ask to surface.
  if (payload.error) throw new GoogleCseError('Google Custom Search returned an error response');

  const items = Array.isArray(payload.items) ? payload.items.slice(0, 50) : [];
  const seen = new Set<string>();
  const results: LiveOsintResult[] = [];

  for (const item of items) {
    const link = safeHttpUrl(item?.link);
    if (!link) continue;
    const key = dedupeKey(link);
    if (seen.has(key)) continue;
    seen.add(key);

    const title = cleanText(item?.title, MAX_TITLE) || link.hostname;
    results.push({
      title,
      snippet: cleanText(item?.snippet, MAX_SNIPPET),
      url: link.href,
      domain: sourceDomain(item?.displayLink, link),
      displayLink: cleanText(item?.displayLink, 200) || null,
      publishedDate: publishedDate(item),
    });
    if (results.length >= limit) break;
  }

  return results;
}
