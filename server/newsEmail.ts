import type { IntelligenceArticle, IntelligenceMatch } from '../src/types/index.ts';

/**
 * Consolidated security-news rendering.
 *
 * Every `IntelligenceMatch` is a piece of evidence tied to one monitored asset.
 * The matcher keys a match on `hash(cveId || articleId)`, so re-correlating the
 * same coverage produces new match rows for evidence the team has already been
 * given — which is how the news path previously emailed the same article more
 * than once. This module makes the *article*, not the match, the unit of
 * delivery:
 *
 *  - one email per recipient per pipeline run, containing every new article;
 *  - an article that is already present in an accepted or queued news email for
 *    that recipient is never included again (`selectUnnotifiedArticles`).
 *
 * The HTML format is preserved: the same card layout, palette and typography
 * used by the original per-match news alert, extended so a consolidated email
 * lists every article and every matched asset.
 */

type NewsArticle = Pick<
  IntelligenceArticle,
  'id' | 'title' | 'url' | 'sourceFeeds' | 'publishedDate' | 'modifiedDate' | 'cveIds'
>;

export interface ConsolidatedNewsItem {
  article: NewsArticle;
  /** Assets this article was correlated with in this run. */
  assets: string[];
  /** CVEs reference by the article (or by the match), de-duplicated. */
  cveIds: string[];
  /** Per-match evidence lines, de-duplicated. */
  evidence: string[];
  /** True when at least one match describes an unassigned vulnerability. */
  zeroDay: boolean;
  /** Highest credibility score observed across the matches for this article. */
  credibilityScore?: number;
  /** IntelligenceMatch ids consolidated into this item, for audit. */
  matchIds: string[];
}

/** Collapses feed-controlled text into a single safe line. */
export const newsSafeLine = (value: string | undefined) =>
  (value || '')
    .replace(/[\r\n\t]+/g, ' ')
    .replace(/[\u0000-\u001f\u007f\u2028\u2029]/g, '')
    .trim();

const escapeHtml = (value: string) =>
  value.replace(/[&<>"']/g, (character) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character]!,
  );

/** Only absolute http(s) URLs without credentials may be hyperlinked. */
const safeHref = (value: string): string => {
  try {
    const url = new URL(value);
    if (!['https:', 'http:'].includes(url.protocol) || url.username || url.password) return '';
    return url.href;
  } catch {
    return '';
  }
};

/**
 * Builds one consolidated item per article from a set of matches and their
 * articles. Items are ordered by publication date (newest first) then id, which
 * keeps the rendered document deterministic across runs.
 */
export function consolidateNewsMatches(
  matches: readonly IntelligenceMatch[],
  articles: ReadonlyMap<string, NewsArticle>,
  assetNameFor: (assetId: string) => string | undefined,
): ConsolidatedNewsItem[] {
  const byArticle = new Map<string, ConsolidatedNewsItem>();
  for (const match of matches) {
    const assetName = assetNameFor(match.assetId) || match.assetName || 'unknown asset';
    for (const articleId of match.articleIds) {
      const article = articles.get(articleId);
      if (!article) continue;
      const identity = newsArticleIdentity(article);
      const item = byArticle.get(identity) ?? {
        article,
        assets: [],
        cveIds: [],
        evidence: [],
        zeroDay: false,
        credibilityScore: undefined,
        matchIds: [],
      };
      if (!item.assets.includes(assetName)) item.assets.push(assetName);
      if (!item.matchIds.includes(match.id)) item.matchIds.push(match.id);
      for (const cveId of [...(article.cveIds || []), ...(match.cveId ? [match.cveId] : [])])
        if (cveId && !item.cveIds.includes(cveId)) item.cveIds.push(cveId);
      const evidence = newsSafeLine(match.evidence);
      if (evidence && !item.evidence.includes(evidence)) item.evidence.push(evidence);
      item.zeroDay ||= match.zeroDay === true;
      if (
        typeof match.credibilityScore === 'number' &&
        Number.isFinite(match.credibilityScore) &&
        (item.credibilityScore === undefined || match.credibilityScore > item.credibilityScore)
      )
        item.credibilityScore = match.credibilityScore;
      byArticle.set(identity, item);
    }
  }
  return [...byArticle.values()]
    .map((item) => ({
      ...item,
      assets: [...item.assets].sort(),
      cveIds: [...item.cveIds].sort(),
      matchIds: [...item.matchIds].sort(),
    }))
    .sort(
      (left, right) =>
        Date.parse(right.article.publishedDate || '') - Date.parse(left.article.publishedDate || '') ||
        left.article.id.localeCompare(right.article.id),
    );
}

/** Stable identity for "this evidence was already sent to this recipient". */
export const newsNotifiedKey = (recipientId: string, articleId: string) => `${recipientId}\u0000${articleId}`;

/**
 * Query parameters that never identify an article.
 *
 * These are campaign/click tracking, session and referrer markers. They are
 * stripped so the same story syndicated through two feeds is recognised as one
 * article. Everything else is KEPT: many sites identify an article by a query
 * parameter (`?id=100` and `?id=200` are different stories), and discarding the
 * whole query string suppressed genuinely distinct articles (AUD-003).
 */
const TRACKING_PARAMETERS = new Set([
  'fbclid',
  'gclid',
  'dclid',
  'gbraid',
  'wbraid',
  'msclkid',
  'yclid',
  'twclid',
  'igshid',
  'mc_cid',
  'mc_eid',
  '_hsenc',
  '_hsmi',
  'mkt_tok',
  'ref',
  'referrer',
  'source',
  'spm',
  'cmpid',
  'campaign',
  'sessionid',
  'phpsessid',
  'jsessionid',
]);

const isTrackingParameter = (name: string): boolean => {
  const key = name.toLowerCase();
  return key.startsWith('utm_') || TRACKING_PARAMETERS.has(key);
};

/**
 * Canonical query string: tracking parameters removed, the rest kept in a
 * stable order so two spellings of the same URL compare equal.
 */
const canonicalQuery = (parsed: URL): string => {
  const kept = [...parsed.searchParams.entries()]
    .filter(([name]) => !isTrackingParameter(name))
    .sort(([leftName, leftValue], [rightName, rightValue]) =>
      leftName.localeCompare(rightName) || leftValue.localeCompare(rightValue),
    );
  if (!kept.length) return '';
  return `?${kept
    .map(([name, value]) => `${encodeURIComponent(name)}=${encodeURIComponent(value)}`)
    .join('&')}`;
};

/**
 * URL identity is stable across tracking parameters and article-id changes,
 * while still distinguishing articles that differ only by a meaningful query
 * parameter.
 */
export function newsArticleIdentity(article: Pick<IntelligenceArticle, 'id' | 'url'>): string {
  const url = (article.url || '').trim();
  if (url) {
    try {
      const parsed = new URL(url);
      if (!['https:', 'http:'].includes(parsed.protocol)) return `id:${article.id}`;
      const path = parsed.pathname.replace(/\/+$/, '') || '/';
      return `url:${parsed.hostname.toLowerCase()}${path}${canonicalQuery(parsed)}`;
    } catch { /* malformed article URL falls back to id */ }
  }
  return `id:${article.id}`;
}

/**
 * Removes articles the recipient has already received.
 *
 * `alreadyNotified` is derived from queued/accepted news deliveries and from the
 * per-article delivery ledger, so an article is sent at most once per recipient
 * no matter how many matches, runs or retries reference it.
 */
export function selectUnnotifiedArticles(
  items: readonly ConsolidatedNewsItem[],
  recipientId: string,
  alreadyNotified: ReadonlySet<string>,
): ConsolidatedNewsItem[] {
  // A syndication feed may assign a different article id to the same URL.
  return items.filter((item) =>
    !alreadyNotified.has(newsNotifiedKey(recipientId, item.article.id)) &&
    !alreadyNotified.has(newsNotifiedKey(recipientId, newsArticleIdentity(item.article)))
  );
}

export interface ConsolidatedNewsDocument {
  subject: string;
  text: string;
  html: string;
  /**
   * Articles that did not fit the HTML size budget and are listed in the
   * overflow summary instead of as full cards. They are still named in the
   * email, so nothing is silently dropped.
   */
  overflow: ConsolidatedNewsItem[];
}

/**
 * HTML size budget for a consolidated news email.
 *
 * The body must stay valid, styled HTML: substituting the plain-text document
 * when the render is too large dropped every colour, card and link (AUD-004).
 * Instead the renderer keeps the full card layout for as many articles as fit
 * and lists the remainder in a styled summary table. The budget is well below
 * the PDF renderer's hard limit so the attachment path never has to degrade.
 */
export const NEWS_HTML_MAX_BYTES = 1_500_000;

/**
 * Renders the consolidated news email within `maxBytes` of HTML.
 *
 * Articles are added in order until the next card would exceed the budget; the
 * rest are rendered as a compact, styled overflow summary (title, source, link)
 * so every article still appears in the same email. The plain-text alternative
 * always lists every article.
 */
export function renderConsolidatedNewsEmailWithin(
  items: readonly ConsolidatedNewsItem[],
  maxBytes: number = NEWS_HTML_MAX_BYTES,
): ConsolidatedNewsDocument {
  const full = renderConsolidatedNewsEmail(items);
  if (Buffer.byteLength(full.html, 'utf8') <= maxBytes) return full;
  // Binary search the largest prefix whose full render fits. The render is
  // monotonic in the number of cards, so this is exact and costs O(log n)
  // renders rather than one per article.
  let low = 0;
  let high = items.length - 1;
  let best = renderConsolidatedNewsEmail(items.slice(0, 0), items.slice(0));
  while (low <= high) {
    const middle = Math.floor((low + high) / 2);
    const candidate = renderConsolidatedNewsEmail(items.slice(0, middle), items.slice(middle));
    if (Buffer.byteLength(candidate.html, 'utf8') <= maxBytes) {
      best = candidate;
      low = middle + 1;
    } else {
      high = middle - 1;
    }
  }
  return best;
}

/**
 * Renders the consolidated news email.
 *
 * All article titles, URLs, feed names and evidence strings are feed-controlled
 * and are escaped everywhere they appear. The document is intentionally
 * self-contained (inline styles, table-free single column) because it is
 * rendered to PDF with the same HTML when `ATTACH_ADVISORY_PDF` is enabled.
 */
export function renderConsolidatedNewsEmail(
  items: readonly ConsolidatedNewsItem[],
  /** Articles listed in the overflow summary instead of as full cards. */
  overflow: readonly ConsolidatedNewsItem[] = [],
): ConsolidatedNewsDocument {
  const count = items.length + overflow.length;
  const countLabel = `${count} article${count === 1 ? '' : 's'}`;
  const leadTitle = newsSafeLine(items[0]?.article.title ?? overflow[0]?.article.title) || 'Security news';
  const subject =
    count === 1
      ? `[Threat intelligence] [NEWS] ${leadTitle}`
      : `[Threat intelligence] [NEWS] ${countLabel}: ${leadTitle}`;
  const footer =
    'This is applicability evidence, not a confirmed advisory. Confirm source authenticity and consult the vendor before remediation.';

  const text = [
    'VulnStream Enterprise | Threat Intelligence',
    `Security news (${countLabel})`,
    ...items.map((item, index) => {
      const source = item.article.sourceFeeds.length
        ? item.article.sourceFeeds.map(newsSafeLine).join(', ')
        : 'security news';
      return [
        `${index + 1}. ${newsSafeLine(item.article.title)}`,
        `Source: ${newsSafeLine(item.article.url)}`,
        `Published: ${newsSafeLine(item.article.modifiedDate || item.article.publishedDate)}`,
        `Source feed: ${source}`,
        `Matched asset(s): ${item.assets.map(newsSafeLine).join(', ') || 'unknown asset'}`,
        ...(item.cveIds.length ? [`CVE reference(s): ${item.cveIds.join(', ')}`] : []),
        ...(item.evidence.length ? [`Evidence: ${item.evidence.join(' | ')}`] : []),
        ...(typeof item.credibilityScore === 'number' ? [`Credibility: ${Math.round(item.credibilityScore)}/100`] : []),
        ...(item.zeroDay ? ['Potential zero-day: no assigned CVE'] : []),
      ].join('\n');
    }),
    ...(overflow.length
      ? [
          `Additional articles (${overflow.length}) listed in summary form because the email reached its size limit:`,
          ...overflow.map(
            (item, index) =>
              `${items.length + index + 1}. ${newsSafeLine(item.article.title)}\nSource: ${newsSafeLine(item.article.url)}`,
          ),
        ]
      : []),
    footer,
  ].join('\n\n');

  const cards = items
    .map((item, index) => {
      const href = safeHref(item.article.url);
      const source = item.article.sourceFeeds.length
        ? item.article.sourceFeeds.map(newsSafeLine).join(', ')
        : 'security news';
      const published = newsSafeLine(item.article.modifiedDate || item.article.publishedDate);
      const title = newsSafeLine(item.article.title);
      const titleHtml = href
        ? `<a href="${escapeHtml(href)}" style="color:#155e75;text-decoration:underline;">${escapeHtml(title)}</a>`
        : escapeHtml(title);
      const evidence = item.evidence.map(escapeHtml).join('<br>');
      return `<tr><td style="padding:20px 24px;border-top:1px solid #e2e8f0;border-left:4px solid #1e40af;">
        <p style="margin:0 0 6px;font-size:11px;line-height:16px;color:#52606d;font-weight:600;letter-spacing:0.5px;">ARTICLE ${index + 1} OF ${count}</p>
        <h2 style="margin:0 0 8px;font-size:17px;line-height:24px;font-weight:700;color:#111827;">${titleHtml}</h2>
        <p style="margin:0 0 4px;font-size:13px;line-height:19px;color:#374151;"><strong>Source:</strong> ${escapeHtml(newsSafeLine(item.article.url))}</p>
        <p style="margin:0 0 4px;font-size:13px;line-height:19px;color:#374151;"><strong>Published:</strong> ${escapeHtml(published)}</p>
        <p style="margin:0 0 10px;font-size:13px;line-height:19px;color:#374151;"><strong>Source feed:</strong> ${escapeHtml(source)}</p>
        <p style="margin:0 0 4px;font-size:13px;line-height:19px;color:#374151;"><strong>Matched asset(s):</strong> ${escapeHtml(item.assets.join(', ') || 'unknown asset')}</p>
        ${item.cveIds.length
          ? `<p style="margin:0 0 4px;font-size:13px;line-height:19px;color:#374151;"><strong>CVE reference(s):</strong> ${item.cveIds
            .map(
              (cveId) =>
                `<a href="https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cveId)}" style="color:#2563eb;text-decoration:none;">${escapeHtml(cveId)}</a>`,
            )
            .join(', ')}</p>`
          : ''}
        ${typeof item.credibilityScore === 'number'
          ? `<p style="margin:0 0 4px;font-size:13px;line-height:19px;color:#374151;"><strong>Credibility:</strong> ${Math.round(item.credibilityScore)}/100</p>`
          : ''}
        ${evidence
          ? `<p style="margin:8px 0 0;padding:10px 12px;background:#f7f8fa;border-left:3px solid #b7791f;font-size:13px;line-height:20px;color:#374151;">${evidence}</p>`
          : ''}
        ${item.zeroDay
          ? '<p style="margin:10px 0 0;padding:8px 10px;background:#fef3c7;border:1px solid #fcd34d;font-size:13px;line-height:19px;font-weight:600;color:#92400e;">Potential zero-day: no assigned CVE</p>'
          : ''}
      </td></tr>`;
    })
    .join('');

  // Overflow summary: the articles that did not fit the size budget are still
  // named, linked and styled like the rest of the email. The body therefore
  // stays valid, styled HTML instead of degrading to the plain-text document.
  const overflowRows = overflow
    .map((item, index) => {
      const href = safeHref(item.article.url);
      const title = escapeHtml(newsSafeLine(item.article.title));
      const titleHtml = href
        ? `<a href="${escapeHtml(href)}" style="color:#155e75;text-decoration:underline;">${title}</a>`
        : title;
      const source = item.article.sourceFeeds.length
        ? item.article.sourceFeeds.map(newsSafeLine).join(', ')
        : 'security news';
      return `<tr><td style="padding:10px 24px;border-top:1px solid #e2e8f0;font-size:13px;line-height:19px;color:#374151;">
        <span style="color:#52606d;font-weight:600;">${items.length + index + 1}.</span> ${titleHtml}
        <br><span style="color:#52606d;">${escapeHtml(source)}</span>
      </td></tr>`;
    })
    .join('');
  const overflowSection = overflow.length
    ? '<tr><td style="padding:20px 24px 8px;border-top:1px solid #e2e8f0;border-left:4px solid #b7791f;background:#fffbeb;">' +
      `<p style="margin:0 0 4px;font-size:11px;line-height:16px;color:#92400e;font-weight:600;letter-spacing:0.5px;">ADDITIONAL ARTICLES (${overflow.length})</p>` +
      '<p style="margin:0;font-size:13px;line-height:19px;color:#374151;">These articles matched your inventory but were listed in summary form because the email reached its size limit.</p></td></tr>' +
      overflowRows
    : '';

  const html =
    '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">' +
    `<title>${escapeHtml(subject)}</title></head>` +
    '<body style="margin:0;padding:0;background:#f1f3f5;color:#17212b;font-family:-apple-system,BlinkMacSystemFont,\'Segoe UI\',Roboto,\'Helvetica Neue\',Arial,sans-serif;">' +
    '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="width:100%;background:#f1f3f5;border-collapse:collapse;"><tr><td align="center" style="padding:24px 8px;">' +
    '<!--[if mso]><table role="presentation" width="640" align="center"><tr><td><![endif]-->' +
    '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="width:100%;max-width:640px;table-layout:fixed;background:#ffffff;border:1px solid #dfe4e8;border-top:4px solid #1e40af;border-collapse:collapse;">' +
    '<tr><td style="padding:20px 24px;border-bottom:1px solid #dfe4e8;">' +
    '<p style="margin:0;font-size:14px;line-height:20px;font-weight:700;color:#17212b;">VulnStream Enterprise</p>' +
    '<p style="margin:3px 0 0;font-size:12px;line-height:18px;color:#52606d;">THREAT INTELLIGENCE / SECURITY NEWS</p></td></tr>' +
    '<tr><td style="padding:26px 24px 24px;">' +
    '<p style="margin:0 0 12px;"><span style="display:inline-block;padding:4px 9px;border-radius:4px;background:#1e40af;color:#ffffff;font-size:11px;line-height:16px;font-weight:700;letter-spacing:0.5px;">NEWS</span></p>' +
    '<h1 style="margin:0 0 12px;font-size:24px;line-height:32px;font-weight:700;color:#111827;">Security news</h1>' +
    `<p style="margin:0;font-size:14px;line-height:23px;color:#374151;">${escapeHtml(countLabel)} matched your monitored inventory in this intelligence run.</p></td></tr>` +
    cards +
    overflowSection +
    `<tr><td style="padding:18px 24px;border-top:1px solid #dfe4e8;background:#fafbfc;"><p style="margin:0;font-size:13px;line-height:20px;color:#52606d;">${escapeHtml(footer)}</p></td></tr>` +
    '</table><!--[if mso]></td></tr></table><![endif]--></td></tr></table></body></html>';

  return { subject: newsSafeLine(subject), text, html, overflow: [...overflow] };
}
