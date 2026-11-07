import type { IntelligenceArticle } from '../src/types/index.ts';

export const OTX_SUBSCRIBED_PULSES_URL = 'https://otx.alienvault.com/api/v1/pulses/subscribed/';
export const OTX_MAX_PAGES = 50;
export const OTX_PAGE_SIZE = 100;

export interface OtxPulsePage {
  articles: IntelligenceArticle[];
  next: string | null;
}

const text = (value: unknown, maxLength: number): string =>
  typeof value === 'string'
    ? value.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, ' ').trim().slice(0, maxLength)
    : '';

export function parseOtxPulsePage(
  value: unknown,
  sourceId: string,
  modifiedSince: number,
): OtxPulsePage {
  if (!value || typeof value !== 'object' || Array.isArray(value))
    throw new Error('OTX returned an invalid pulse page');
  const page = value as { results?: unknown; next?: unknown };
  if (!Array.isArray(page.results) || (page.next !== null && typeof page.next !== 'string'))
    throw new Error('OTX returned an invalid pulse page');
  if (page.results.length > OTX_PAGE_SIZE)
    throw new Error('OTX exceeded the requested pulse page size');

  const articles: IntelligenceArticle[] = [];
  for (const raw of page.results) {
    if (!raw || typeof raw !== 'object' || Array.isArray(raw))
      throw new Error('OTX returned a malformed pulse');
    const pulse = raw as Record<string, unknown>;
    const id = text(pulse.id, 128);
    const title = text(pulse.name, 500);
    const description = text(pulse.description, 10000);
    const created = text(pulse.created, 64);
    const modified = text(pulse.modified, 64);
    const createdAt = Date.parse(created);
    const modifiedAt = Date.parse(modified);
    if (!/^[a-z0-9-]{1,128}$/i.test(id) || !title ||
      !Number.isFinite(createdAt) || !Number.isFinite(modifiedAt))
      throw new Error('OTX returned a malformed pulse');
    if (modifiedAt < modifiedSince) continue;

    const tags = Array.isArray(pulse.tags)
      ? pulse.tags.filter((tag): tag is string => typeof tag === 'string').map((tag) => text(tag, 100)).filter(Boolean).slice(0, 50)
      : [];
    const summary = [description, tags.length ? `Tags: ${tags.join(', ')}` : ''].filter(Boolean).join('\n').slice(0, 12000);
    const cveIds = [...new Set(`${title}\n${summary}`.match(/\bCVE-\d{4}-\d{4,}\b/gi) || [])]
      .map((cveId) => cveId.toUpperCase())
      .slice(0, 100);
    articles.push({
      id: `otx-pulse-${id}`,
      url: `https://otx.alienvault.com/pulse/${encodeURIComponent(id)}`,
      title,
      summary,
      publishedDate: new Date(createdAt).toISOString(),
      modifiedDate: new Date(modifiedAt).toISOString(),
      cveIds,
      sourceFeeds: [sourceId],
    });
  }
  return { articles, next: page.next as string | null };
}

export function validateOtxNextUrl(next: string, currentUrl: string): URL {
  let url: URL;
  try {
    url = new URL(next, currentUrl);
  } catch {
    throw new Error('OTX returned an invalid pagination URL');
  }
  const current = new URL(currentUrl);
  const normalizedPath = (path: string) => path.replace(/\/+$/, '') || '/';
  if (
    url.origin !== current.origin ||
    normalizedPath(url.pathname) !== normalizedPath(current.pathname) ||
    url.username ||
    url.password ||
    url.hash
  )
    throw new Error('OTX returned an invalid pagination URL');
  return url;
}
