import { XMLParser, XMLValidator } from 'fast-xml-parser';
import { createHash } from 'node:crypto';
import type { IntelligenceArticle } from '../src/types/index.ts';

// A syndication document is a list of headlines, not an article store. The
// largest default feed (Google Project Zero: ten full posts of long technical
// prose) decodes to ~10.8 MiB, and the decompressed size is not something the
// publisher controls per request, so the ceiling has to be above the biggest
// real feed rather than just above the average. 16 MiB holds it with headroom
// while still bounding a decompression bomb at a fixed, modest size.
export const RSS_MAX_BYTES = 16 * 1024 * 1024;
export const RSS_MAX_ENTRIES = 10000;

// Identify the actual client. BleepingComputer challenges the old Chrome
// impersonation with HTTP 403, while allowing this RSS reader identity.
// Both connectivity tests and pipeline ingestion use this value.
export const RSS_USER_AGENT = 'VulnStream/1.0 RSS reader';

export function canonicalArticleUrl(value: string): string | null {
  try {
    const url = new URL(value);
    if (!['https:', 'http:'].includes(url.protocol) || url.username || url.password) return null;
    url.hash = '';
    for (const key of [...url.searchParams.keys()])
      if (/^utm_|^(fbclid|gclid|mc_cid|mc_eid)$/i.test(key)) url.searchParams.delete(key);
    url.searchParams.sort();
    return url.href;
  } catch {
    return null;
  }
}
const array = (value: any): any[] => (value == null ? [] : Array.isArray(value) ? value : [value]);
/**
 * Entries whose body lists more distinct CVEs than this are monthly round-up
 * posts ("The October 2026 Security Update Review") whose embedded tables
 * enumerate every vendor fix. They are real, useful articles, but they are not
 * evidence about any one product, and a single entry can carry thousands of
 * IDs. The list is dropped from such an entry; the article is kept.
 */
export const MAX_ENTRY_CVE_IDS = 100;
const string = (value: any): string =>
  typeof value === 'string'
    ? value
    : typeof value === 'number'
      ? String(value)
      : string(value?.['#text'] ?? '');
const decode = (value: string) =>
  value.replace(/&(amp|lt|gt|quot|apos|#\d{1,7}|#x[0-9a-f]{1,6});/gi, (whole, entity: string) => {
    const known: Record<string, string> = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'" };
    if (known[entity.toLowerCase()]) return known[entity.toLowerCase()];
    const code = entity[1]?.toLowerCase() === 'x' ? parseInt(entity.slice(2), 16) : Number(entity.slice(1));
    // Numeric references must not create lone UTF-16 surrogates. They are not
    // valid Unicode scalar values and can corrupt downstream JSON/text output.
    const surrogate = code >= 0xd800 && code <= 0xdfff;
    return code > 0 && code <= 0x10ffff && !surrogate ? String.fromCodePoint(code) : whole;
  });
function plain(value: string) {
  return decode(value)
    .replace(/<(script|style)\b[^>]*>[\s\S]*?<\/\1>/gi, ' ')
    .replace(/<[^>]*>/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}
export function parseSyndication(
  xml: string,
  sourceId: string,
  scopeHours: number,
  now = new Date(),
): {
  articles: IntelligenceArticle[];
  warnings: string[];
} {
  if (Buffer.byteLength(xml) > RSS_MAX_BYTES)
    throw new Error(`RSS/Atom feed exceeds ${RSS_MAX_BYTES / (1024 * 1024)} MiB`);
  if (XMLValidator.validate(xml) !== true) throw new Error('Feed is not valid XML');
  const parsed = new XMLParser({
    ignoreAttributes: false,
    parseTagValue: false,
    parseAttributeValue: false,
    // DTDs are accepted, but declared entity references remain literal text.
    processEntities: false,
    maxNestedTags: 64,
    trimValues: true,
  }).parse(xml);
  if (!parsed.rss?.channel && !parsed.feed && !parsed['rdf:RDF'])
    throw new Error('Expected an RSS or Atom feed, not an HTML page');
  const rows = parsed.feed
    ? array(parsed.feed.entry)
    : parsed.rss
      ? array(parsed.rss.channel.item)
      : array(parsed['rdf:RDF'].item);
  if (rows.length > RSS_MAX_ENTRIES) throw new Error('RSS/Atom feed exceeds 10,000 entries');
  const records = new Map<string, IntelligenceArticle>(),
    warnings: string[] = [];
  let invalid = 0,
    bulkCveArticles = 0;
  for (const row of rows) {
    const link =
      typeof row.link === 'string'
        ? row.link
        : array(row.link).find((entry) => !entry['@_rel'] || entry['@_rel'] === 'alternate')?.['@_href'];
    const url = canonicalArticleUrl(decode(string(link)));
    const title = plain(string(row.title)).slice(0, 500);
    const published = Date.parse(string(row.pubDate || row.published || row['dc:date'] || row.updated));
    const modified = Date.parse(string(row.updated || row['dc:date'] || row.pubDate || row.published));
    if (
      !url ||
      !title ||
      !Number.isFinite(published) ||
      !Number.isFinite(modified) ||
      published > now.getTime() ||
      modified > now.getTime()
    ) {
      invalid++;
      continue;
    }
    if (scopeHours > 0 && Math.max(published, modified) < now.getTime() - scopeHours * 3600000) continue;
    // The summary is stored truncated and only the title and this excerpt are
    // scanned for CVEs, so a full post body is flattened and then thrown away.
    // Doing it after the scope filter above bounds the cost of an archive feed
    // that ships every entry's complete HTML.
    const full = plain(string(row['content:encoded'] || row.content || row.summary || row.description));
    // Summaries are context only; never infer that every CVE in a multi-product article affects every product.
    const mentioned = [
      ...new Set(
        (`${title} ${full} ${url}`.match(/\bCVE-\d{4}-\d{4,}\b/gi) || []).map((id) => id.toUpperCase()),
      ),
    ].sort();
    // Dropping the article lost the whole post; dropping only the list keeps the
    // post as evidence (title, summary, link) without a claim about any product.
    const cveIds = mentioned.length > MAX_ENTRY_CVE_IDS ? [] : mentioned;
    if (mentioned.length > MAX_ENTRY_CVE_IDS) bulkCveArticles++;
    // Zero-day heuristic: articles without a CVE ID that mention exploitation,
    // zero-day, or in-the-wild activity are flagged for priority review.
    const zeroDay =
      cveIds.length === 0 &&
      /\b(zero[- ]?day|0[- ]?day|actively exploited|in the wild|unpatched|no (?:patch|fix|cve))\b/i.test(
        `${title} ${full}`,
      );
    const id = createHash('sha256').update(url).digest('hex');
    const article: IntelligenceArticle = {
      id,
      url,
      title,
      summary: full.slice(0, 1500),
      publishedDate: new Date(published).toISOString(),
      modifiedDate: new Date(modified).toISOString(),
      cveIds,
      sourceFeeds: [sourceId],
      zeroDay,
    };
    const old = records.get(id);
    if (
      !old ||
      modified > Date.parse(old.modifiedDate) ||
      (modified === Date.parse(old.modifiedDate) && JSON.stringify(article) > JSON.stringify(old))
    )
      records.set(id, article);
  }
  if (bulkCveArticles)
    warnings.push(
      `${bulkCveArticles} entries listed more than ${MAX_ENTRY_CVE_IDS} CVEs; kept the article and dropped its CVE list`,
    );
  if (invalid)
    warnings.push(
      `${invalid} entries quarantined for missing/invalid URL, title, or date`,
    );
  return { articles: [...records.values()], warnings };
}
