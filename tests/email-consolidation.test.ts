import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { Advisory, EmailRecipient, Finding, IntelligenceArticle, IntelligenceMatch } from '../src/types/index.ts';
import {
  consolidateNewsMatches,
  newsArticleIdentity,
  newsNotifiedKey,
  renderConsolidatedNewsEmail,
  renderConsolidatedNewsEmailWithin,
  selectUnnotifiedArticles,
} from '../server/newsEmail.ts';
import {
  deliveryAdvisoryView,
  deliveryHtmlIsAttachable,
  renderFindingsDocument,
  renderFindingsText,
} from '../server/deliveryDocument.ts';
import { confidenceIsLimited, renderAdvisory } from '../server/advisoryRender.ts';
import { DEFAULT_TEMPLATE_CUSTOMIZATION, compileCustomizedTemplate } from '../src/utils/templateCompiler.ts';
import { eligibleForDispatch, isFindingDelivery } from '../src/utils/findingDelivery.ts';

const finding = (overrides: Partial<Finding> & { id: string; cveId: string }): Finding =>
  ({
    matchedAssetId: `asset-${overrides.id}`,
    matchedAssetName: 'server-1 (acme widget)',
    matchedAssetVendor: 'acme',
    matchedAssetProduct: 'widget',
    matchedCpe: 'cpe:2.3:a:acme:widget:1.5:*:*:*:*:*:*:*',
    matchingMethod: 'STRICT_CPE_INTERVAL',
    matchingEvidence: 'Matched strict CPE 2.3 component tokens (70% confidence)',
    confidence: 70,
    notificationStatus: 'REVIEW_REQUIRED',
    status: 'MONITORED',
    autoDispatchedAt: null,
    advisoryId: null,
    reviewNotifiedAt: null,
    exploitRisk: 'NONE',
    timeline: [],
    cve: {
      cveId: overrides.cveId,
      title: 'Acme widget flaw',
      description: 'A flaw in the Acme widget allows remote code execution.',
      publishedDate: '2026-01-01T00:00:00Z',
      modifiedDate: '2026-01-02T00:00:00Z',
      cvss: { version: '3.1', score: 9.1, vector: 'AV:N/AC:L', severity: 'CRITICAL' },
      cwe: [],
      cpeMatches: ['cpe:2.3:a:acme:widget:1.5:*:*:*:*:*:*:*'],
      epss: { score: 0.4, percentile: 90 },
      cisaKev: { inKev: false, dueDate: null, cveNotes: '', isKev: false },
      exploitStatus: 'None',
      remediation: { play: [], nextSteps: [], vendorAdvisoryRef: 'https://vendor.example/advisory' },
      sourceFeeds: ['NVD'],
    },
    ...overrides,
  }) as unknown as Finding;

const advisory: Advisory = {
  id: 'ADV-TEST',
  title: 'Security finding notification',
  severity: 'CRITICAL',
  cveIds: [],
  findingIds: [],
  createdDate: '2026-01-01T00:00:00Z',
  deliveryStatus: 'PENDING',
  recipientCount: 0,
  executiveSummary: 'summary',
  remediationInstructions: 'patch',
  vendorLink: '',
  affectedSystems: [],
  isDigestBatch: true,
};

test('every finding is dispatched, including low-confidence ones', () => {
  const low = finding({ id: 'f1', cveId: 'CVE-2026-10001', confidence: 70 });
  const zero = finding({ id: 'f2', cveId: 'CVE-2026-10002', confidence: 0 });
  const exact = finding({ id: 'f3', cveId: 'CVE-2026-10003', confidence: 100 });
  assert.equal(eligibleForDispatch(low), true);
  assert.equal(eligibleForDispatch(zero), true);
  assert.equal(eligibleForDispatch(exact), true);
  assert.equal(eligibleForDispatch({ ...low, reviewNotifiedAt: '2026-01-05T00:00:00Z' }), false);
  assert.equal(eligibleForDispatch({ ...low, status: 'FALSE_POSITIVE' }), false);
});

test('the advisory states the confidence limitation on the finding itself', () => {
  const low = finding({ id: 'f1', cveId: 'CVE-2026-10001', confidence: 70 });
  const exact = finding({ id: 'f2', cveId: 'CVE-2026-10002', confidence: 100 });
  assert.equal(confidenceIsLimited(low), true);
  assert.equal(confidenceIsLimited(exact), false);
  const view = deliveryAdvisoryView(advisory, [low, exact]);
  const html = renderAdvisory(
    compileCustomizedTemplate(DEFAULT_TEMPLATE_CUSTOMIZATION),
    view,
    [low, exact],
    { generatedAt: new Date('2026-01-01T00:00:00Z') },
  );
  assert.match(html, /Low confidence/);
  assert.match(html, /70% match confidence/);
  assert.match(html, /Matched strict CPE 2\.3 component tokens/, 'the reason is stated');
  assert.ok(!html.includes('70% confidence)'), 'the machine-readable suffix is not repeated');
  // A fully confident finding carries no limitation notice.
  const single = renderAdvisory(
    compileCustomizedTemplate(DEFAULT_TEMPLATE_CUSTOMIZATION),
    deliveryAdvisoryView(advisory, [exact]),
    [exact],
  );
  assert.ok(!single.includes('Low confidence'));
});

test('the email body is the document attached to it', () => {
  const findings = [finding({ id: 'f1', cveId: 'CVE-2026-10001' }), finding({ id: 'f2', cveId: 'CVE-2026-10002' })];
  const view = deliveryAdvisoryView(advisory, findings);
  const generatedAt = new Date('2026-01-01T12:34:00Z');
  const document = renderFindingsDocument({ advisory: view, findings, generatedAt });
  assert.ok(document.html.includes('Security Advisory'));
  assert.match(document.html, /Report Generated/);
  assert.equal(deliveryHtmlIsAttachable(document.html), true);
  // Re-rendering with the pinned instant is byte-identical: the attachment render
  // can never drift from the body.
  assert.equal(renderFindingsDocument({ advisory: view, findings, generatedAt }).html, document.html);
  // The text alternative describes the same findings.
  assert.match(document.text, /CVE-2026-10001/);
  assert.match(document.text, /CVE-2026-10002/);
  assert.match(renderFindingsText(view, findings), /Limited confidence/);
});

test('delivery documents escape feed-controlled content everywhere', () => {
  const hostile = finding({
    id: '<script>',
    cveId: 'CVE-2026-10001',
    matchingEvidence: '<img src=x onerror=alert(1)>',
  });
  hostile.matchedAssetName = '<b>server</b>';
  hostile.cve.description = '<script>alert(1)</script>';
  const document = renderFindingsDocument({
    advisory: deliveryAdvisoryView(advisory, [hostile]),
    findings: [hostile],
  });
  assert.ok(!document.html.includes('<script>'));
  assert.ok(!document.html.includes('<img src=x'));
  assert.ok(!document.html.includes('<b>server</b>'));
});

const article = (id: string, url: string, title: string, publishedDate = '2026-01-01T00:00:00Z'): IntelligenceArticle => ({
  id,
  url,
  title,
  summary: '',
  publishedDate,
  modifiedDate: publishedDate,
  cveIds: ['CVE-2026-12345'],
  sourceFeeds: ['THREAT_FEED'],
});

const match = (id: string, assetId: string, articleIds: string[], evidence = 'Acme widget referenced'): IntelligenceMatch => ({
  id,
  cveId: 'CVE-2026-12345',
  assetId,
  assetName: `server-${assetId}`,
  articleIds,
  status: 'REVIEW_REQUIRED',
  evidence,
  credibilityScore: 80,
});

test('news is consolidated to one item per article, regardless of match count', () => {
  const a1 = article('a1', 'https://example.com/story-1', 'Story one');
  const a2 = article('a2', 'https://example.com/story-2', 'Story two');
  const articles = new Map([
    [a1.id, a1],
    [a2.id, a2],
  ]);
  const items = consolidateNewsMatches(
    [
      match('m1', 'asset-1', ['a1']),
      // The same article re-correlated to a second asset is still one item.
      match('m2', 'asset-2', ['a1'], 'Acme widget two referenced'),
      match('m3', 'asset-1', ['a2']),
    ],
    articles,
    (assetId) => `server-${assetId}`,
  );
  assert.equal(items.length, 2);
  const first = items.find((item) => item.article.id === 'a1')!;
  assert.deepEqual(first.assets, ['server-asset-1', 'server-asset-2']);
  assert.deepEqual(first.matchIds, ['m1', 'm2']);
  assert.equal(first.evidence.length, 2);
});

test('an article already sent to a recipient is never selected again', () => {
  const a1 = article('a1', 'https://example.com/story-1', 'Story one');
  const a2 = article('a2', 'https://example.com/story-2', 'Story two');
  const items = consolidateNewsMatches(
    [match('m1', 'asset-1', ['a1', 'a2'])],
    new Map([
      [a1.id, a1],
      [a2.id, a2],
    ]),
    (assetId) => `server-${assetId}`,
  );
  const already = new Set([newsNotifiedKey('r1', 'a1')]);
  assert.deepEqual(
    selectUnnotifiedArticles(items, 'r1', already).map((item) => item.article.id),
    ['a2'],
  );
  assert.equal(selectUnnotifiedArticles(items, 'r2', already).length, 2, 'the ledger is per recipient');
});

test('the consolidated news email lists every article and escapes feed content', () => {
  const a1 = article('a1', 'javascript:alert(1)', '<script>alert(1)</script>');
  const items = consolidateNewsMatches(
    [match('m1', 'asset-1', ['a1'], '<b>evidence</b>')],
    new Map([[a1.id, a1]]),
    () => 'server-1',
  );
  const document = renderConsolidatedNewsEmail(items);
  assert.ok(!document.html.includes('<script>'));
  assert.ok(!document.html.includes('<b>evidence</b>'));
  assert.ok(!document.html.includes('href="javascript:'), 'a non-http URL is never hyperlinked');
  assert.match(document.html, /Matched asset\(s\)/);
  assert.match(document.text, /Matched asset\(s\): server-1/);
  assert.match(document.subject, /\[NEWS\]/);
  const many = renderConsolidatedNewsEmail([...items, ...consolidateNewsMatches(
    [match('m2', 'asset-1', ['a2'])],
    new Map([['a2', article('a2', 'https://example.com/b', 'Second story')]]),
    () => 'server-1',
  )]);
  assert.match(many.subject, /2 articles/);
  assert.match(many.html, /ARTICLE 1 OF 2/);
  assert.match(many.html, /ARTICLE 2 OF 2/);
});

test('synthetic bundles are excluded from Action Center follow-up actions', () => {
  for (const id of ['NEWS:a1', 'FINDINGS:abc', 'ZERODAY:DIGEST', 'TEST', 'DAILY_20260101'])
    assert.equal(isFindingDelivery(id), false, id);
  assert.equal(isFindingDelivery('ADV-0001'), true);
});

test('recipient subscription filters which findings a document may carry', async () => {
  const { recipientAllows } = await import('../server/delivery.ts');
  const critical = finding({ id: 'f1', cveId: 'CVE-2026-10001' });
  const low = finding({ id: 'f2', cveId: 'CVE-2026-10002' });
  low.cve.cvss.severity = 'LOW';
  const kevOnly: EmailRecipient = {
    id: 'r1', name: 'r1', email: 'r1@example.invalid', role: 'ADMIN',
    deliveryGroup: 'SECURITY_TEAM', subscriptionTier: 'CISA_KEV_ONLY', enabled: true, deliverySuccessRate: 100,
  };
  assert.equal(recipientAllows(kevOnly, critical), false);
  assert.equal(recipientAllows(kevOnly, low), false);
  assert.equal(
    recipientAllows(kevOnly, { ...critical, cve: { ...critical.cve, cisaKev: { ...critical.cve.cisaKev, isKev: true } } }),
    true,
  );
});

test('syndicated URLs with different article ids and query strings are one story', () => {
  const a1 = article('a1', 'https://example.com/story-1?utm_source=first', 'Story one');
  const a3 = article('a3', 'https://example.com/story-1?utm_source=second', 'Story one syndicated');
  const items = consolidateNewsMatches(
    [match('m1', 'asset-1', ['a1', 'a3'])],
    new Map([[a1.id, a1], [a3.id, a3]]),
    (assetId) => `server-${assetId}`,
  );
  assert.equal(items.length, 1, 'same canonical URL must occur once in a consolidated email');
  const ledger = new Set([newsNotifiedKey('r1', newsArticleIdentity(a1))]);
  assert.equal(selectUnnotifiedArticles(items, 'r1', ledger).length, 0);
  assert.equal(selectUnnotifiedArticles(items, 'r2', ledger).length, 1);
});

test('meaningful query parameters distinguish articles; tracking parameters do not', () => {
  // AUD-003: `?id=100` and `?id=200` are different stories.
  const first = article('a1', 'https://example.com/article?id=100', 'Story 100');
  const second = article('a2', 'https://example.com/article?id=200', 'Story 200');
  assert.notEqual(newsArticleIdentity(first), newsArticleIdentity(second));
  const items = consolidateNewsMatches(
    [match('m1', 'asset-1', ['a1', 'a2'])],
    new Map([[first.id, first], [second.id, second]]),
    () => 'server-1',
  );
  assert.equal(items.length, 2, 'distinct query-identified articles are not collapsed');

  // Tracking parameters are still ignored, in any order.
  const tracked = article('a3', 'https://example.com/article?id=100&utm_source=x&fbclid=abc&gclid=def', 'Story 100');
  assert.equal(newsArticleIdentity(tracked), newsArticleIdentity(first));
  const reordered = article('a4', 'https://example.com/article?utm_campaign=y&id=100', 'Story 100');
  assert.equal(newsArticleIdentity(reordered), newsArticleIdentity(first));
  // A different meaningful parameter is a different article.
  const other = article('a5', 'https://example.com/article?id=100&page=2', 'Story 100 page 2');
  assert.notEqual(newsArticleIdentity(other), newsArticleIdentity(first));
});

test('an oversized consolidated news email keeps styled HTML and summarises the overflow', () => {
  // AUD-004: the body must never be replaced by the plain-text document.
  const items = consolidateNewsMatches(
    [match('m1', 'asset-1', ['a1', 'a2', 'a3'])],
    new Map([
      ['a1', article('a1', 'https://example.com/1', 'First story')],
      ['a2', article('a2', 'https://example.com/2', 'Second story')],
      ['a3', article('a3', 'https://example.com/3', 'Third story')],
    ]),
    () => 'server-1',
  );
  const full = renderConsolidatedNewsEmail(items);
  assert.equal(full.overflow.length, 0);
  // A budget that fits the shell plus one card but not all three.
  const oneCard = renderConsolidatedNewsEmail(items.slice(0, 1), items.slice(1));
  const budget = Buffer.byteLength(oneCard.html, 'utf8');
  const bounded = renderConsolidatedNewsEmailWithin(items, budget);
  assert.ok(Buffer.byteLength(bounded.html, 'utf8') <= budget, 'the HTML stays within the budget');
  assert.ok(bounded.overflow.length > 0, 'the articles that did not fit are reported');
  assert.match(bounded.html, /<!doctype html>/i, 'the body is still an HTML document');
  assert.match(bounded.html, /ADDITIONAL ARTICLES/, 'the overflow summary is rendered');
  assert.match(bounded.html, /background:#fffbeb/, 'the summary keeps the styled palette');
  assert.match(bounded.html, /ARTICLE 1 OF 3/, 'the full cards are still styled cards');
  for (const item of bounded.overflow)
    assert.ok(bounded.html.includes(item.article.title), `overflow article ${item.article.id} is still named`);
  assert.match(bounded.text, /Third story/, 'the text alternative lists every article');
  assert.equal(bounded.subject, full.subject, 'the subject describes the whole batch');
});

test('a previously queued legacy article URL suppresses a new syndication id', () => {
  const oldArticle = article('old-id', 'https://example.com/story-1?utm_source=old', 'Earlier syndication');
  const newer = article('new-id', 'https://example.com/story-1?utm_source=new', 'Same story');
  const items = consolidateNewsMatches(
    [match('m1', 'asset-1', ['new-id'])],
    new Map([[newer.id, newer]]),
    () => 'server-1',
  );
  const legacyReceipt = new Set([newsNotifiedKey('r1', newsArticleIdentity(oldArticle))]);
  assert.equal(selectUnnotifiedArticles(items, 'r1', legacyReceipt).length, 0);
  assert.equal(selectUnnotifiedArticles(items, 'r2', legacyReceipt).length, 1);
});
