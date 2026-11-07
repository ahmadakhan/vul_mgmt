import { createHash } from 'node:crypto';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import puppeteer, { type Browser } from 'puppeteer-core';
import { convert, type HtmlToTextOptions } from 'html-to-text';
import { resolveTimezone } from '../src/utils/dateTime.ts';

const PDF_CACHE_TTL_MS = 5 * 60_000;
const PDF_CACHE_MAX = 64;
/** Hard input ceiling for the PDF renderer, shared with the delivery gate. */
export const PDF_MAX_HTML_BYTES = 2_000_000;
const pdfCache = new Map<string, { content: Uint8Array; expires: number }>();
let pdfQueue: Promise<void> = Promise.resolve();
let browserPromise: Promise<Browser> | undefined;
let cacheAccess = 0;
const HTML_TO_TEXT_OPTIONS: HtmlToTextOptions = {
  baseElements: { selectors: ['body'], returnDomByDefault: false },
  wordwrap: 92,
  limits: { maxInputLength: PDF_MAX_HTML_BYTES },
  selectors: [
    { selector: 'script', format: 'skip' },
    { selector: 'style', format: 'skip' },
    { selector: 'img', format: 'skip' },
    { selector: 'svg', format: 'skip' },
    { selector: 'a', options: { hideLinkHrefIfSameAsText: true, linkBrackets: [' (', ')'] } },
  ],
};

export interface PdfAttachment {
  filename: string;
  content: Uint8Array;
  contentType: 'application/pdf';
}

/** Use the advisory's real ID so the attachment is easy to identify and file. */
export function advisoryFilename(advisoryId: string): string {
  const safeId = /^[A-Za-z0-9._-]+$/.test(advisoryId) ? advisoryId : 'advisory';
  return `${safeId}.pdf`;
}

/**
 * Timestamped `ddMMMyyyyHHMM.pdf` name for a document without an advisory id.
 *
 * Retained for callers that snapshot a rendered document outside a delivery (the
 * review bulletin that used it has been replaced by consolidated finding
 * emails, which are named after their batch id).
 */
export function timestampedAdvisoryFilename(at: Date = new Date(), timezone?: string): string {
  const tz = resolveTimezone(timezone);
  const parts = new Intl.DateTimeFormat('en-GB', {
    timeZone: tz,
    day: '2-digit',
    month: 'short',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    hourCycle: 'h23',
  }).formatToParts(at);
  const pick = (type: string) => parts.find((part) => part.type === type)?.value || '';
  const month = pick('month');
  if (!month) return 'advisory.pdf';
  return `${pick('day')}${month}${pick('year')}${pick('hour')}${pick('minute')}.pdf`;
}

export function advisoryHtmlToText(html: string): string {
  if (Buffer.byteLength(html, 'utf8') > PDF_MAX_HTML_BYTES)
    throw new Error('Advisory HTML exceeds the PDF size limit');
  return convert(html, HTML_TO_TEXT_OPTIONS).trim();
}

function resolveChromiumExecutable(): string {
  const candidates = [
    process.env.PUPPETEER_EXECUTABLE_PATH,
    process.env.CHROME_EXECUTABLE_PATH,
    '/usr/bin/chromium',
    '/usr/bin/chromium-browser',
    process.env.ProgramFiles &&
      join(process.env.ProgramFiles, 'Google', 'Chrome', 'Application', 'chrome.exe'),
    process.env['ProgramFiles(x86)'] &&
      join(process.env['ProgramFiles(x86)'], 'Google', 'Chrome', 'Application', 'chrome.exe'),
    process.env.LOCALAPPDATA &&
      join(process.env.LOCALAPPDATA, 'Google', 'Chrome', 'Application', 'chrome.exe'),
    process.env.ProgramFiles &&
      join(process.env.ProgramFiles, 'Microsoft', 'Edge', 'Application', 'msedge.exe'),
  ];
  const executable = candidates.find((candidate): candidate is string => !!candidate && existsSync(candidate));
  if (!executable) {
    throw new Error(
      'Chromium is required for advisory PDF rendering; set PUPPETEER_EXECUTABLE_PATH to its executable.',
    );
  }
  return executable;
}

function getBrowser(): Promise<Browser> {
  if (!browserPromise) {
    browserPromise = puppeteer
      .launch({
        executablePath: resolveChromiumExecutable(),
        headless: true,
        args: [
          '--no-sandbox',
          '--disable-setuid-sandbox',
          '--disable-dev-shm-usage',
          '--disable-gpu',
          '--no-zygote',
          '--disable-crash-reporter',
          '--disable-crashpad',
        ],
      })
      .catch((error: unknown) => {
        browserPromise = undefined;
        throw new Error(
          `Unable to launch Chromium for advisory PDF rendering: ${error instanceof Error ? error.message : String(error)}`,
          { cause: error },
        );
      });
  }
  return browserPromise;
}

async function renderHtmlPdf(html: string): Promise<Uint8Array> {
  const browser = await getBrowser();
  const page = await browser.newPage();
  try {
    await page.setJavaScriptEnabled(false);
    await page.setRequestInterception(true);
    page.on('request', (request) => {
      void request.abort('blockedbyclient').catch(() => undefined);
    });
    await page.setViewport({ width: 816, height: 1056, deviceScaleFactor: 1 });
    await page.emulateMediaType('print');
    await page.setContent(html, { waitUntil: 'load', timeout: 15_000 });

    await page.evaluate(() => {
      document.querySelectorAll('script, iframe, frame, object, embed, applet, base, form').forEach((node) => node.remove());
      document.querySelectorAll('link[rel~="import"], link[rel~="stylesheet"]').forEach((node) => node.remove());
      document.querySelectorAll('*').forEach((element) => {
        for (const attribute of [...element.attributes]) {
          if (/^on/i.test(attribute.name) || ['src', 'srcset', 'poster', 'background', 'action', 'formaction'].includes(attribute.name.toLowerCase())) {
            element.removeAttribute(attribute.name);
          }
        }
      });
      document.querySelectorAll('a[href]').forEach((anchor) => {
        const href = anchor.getAttribute('href') || '';
        if (href.startsWith('#')) return;
        try {
          const url = new URL(href);
          if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password)
            anchor.removeAttribute('href');
          else
            anchor.setAttribute('href', url.href);
        } catch {
          anchor.removeAttribute('href');
        }
        anchor.removeAttribute('target');
      });
      const policy = document.createElement('meta');
      policy.httpEquiv = 'Content-Security-Policy';
      policy.content = "default-src 'none'; img-src data:; font-src data:; style-src 'unsafe-inline' data:; script-src 'none'; connect-src 'none'; frame-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'";
      document.head.prepend(policy);
      const printStyle = document.createElement('style');
      printStyle.textContent = `
        @page { size: A4; margin: 0; }
        html, body { width: auto !important; min-width: 0 !important; margin: 0 !important; }
        *, *::before, *::after { -webkit-print-color-adjust: exact !important; print-color-adjust: exact !important; }
        table, tr, td, .vulnstream-pdf-card { break-inside: avoid; page-break-inside: avoid; }
      `;
      document.head.append(printStyle);
    });
    await page.evaluate(async () => {
      await document.fonts.ready;
      document.documentElement.getBoundingClientRect();
    });
    return new Uint8Array(await page.pdf({
      format: 'A4',
      printBackground: true,
      preferCSSPageSize: true,
      displayHeaderFooter: false,
      margin: { top: '0', right: '0', bottom: '0', left: '0' },
    }));
  } catch (error) {
    throw new Error(
      `Chromium advisory PDF rendering failed: ${error instanceof Error ? error.message : String(error)}`,
      { cause: error },
    );
  } finally {
    await page.close().catch(() => undefined);
  }
}

function serializePdf<T>(operation: () => Promise<T>): Promise<T> {
  const result = pdfQueue.then(operation);
  pdfQueue = result.then(() => undefined, () => undefined);
  return result;
}

export async function renderAdvisoryPdf(html: string): Promise<Uint8Array> {
  if (Buffer.byteLength(html, 'utf8') > PDF_MAX_HTML_BYTES)
    throw new Error('Advisory HTML exceeds the PDF size limit');
  const key = createHash('sha256').update(html).digest('hex');
  const content = await serializePdf(async () => {
    const cached = pdfCache.get(key);
    if (cached && cached.expires > Date.now()) return cached.content;
    const rendered = await renderHtmlPdf(html);
    if (!rendered.length) throw new Error('Chromium returned an empty advisory PDF');
    pdfCache.set(key, { content: rendered, expires: Date.now() + PDF_CACHE_TTL_MS });
    return rendered;
  });
  if (++cacheAccess > PDF_CACHE_MAX * 2) evictPdfCache();
  return content;
}

function evictPdfCache(): void {
  const now = Date.now();
  cacheAccess = 0;
  for (const [key, value] of pdfCache) if (value.expires < now) pdfCache.delete(key);
  while (pdfCache.size > PDF_CACHE_MAX) {
    const first = pdfCache.keys().next().value;
    if (first === undefined) break;
    pdfCache.delete(first);
  }
}

export async function closePdfRenderer(): Promise<void> {
  pdfCache.clear();
  if (browserPromise) {
    const currentBrowser = await browserPromise.catch(() => undefined);
    browserPromise = undefined;
    if (currentBrowser?.connected) await currentBrowser.close();
  }
}
