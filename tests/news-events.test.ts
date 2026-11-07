import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { parseSyndication } from '../server/rss';
import * as matchIntelligenceModule from '../src/utils/intelligenceMatcher';
import { matchIntelligence, mergeArticles } from '../src/utils/intelligenceMatcher';
import {
  describeError,
  describeRequestFailure,
  redactEventContext,
  writeEvent,
  readEvents,
} from '../server/events';
import { createPool, migrate, put, get, state } from '../server/db.ts';
import { queueRun, processPipeline } from '../server/pipeline';
import { loadConfig } from '../server/config.ts';
import { applyCommand } from '../server/commands.ts';
import { DEFAULT_SETTINGS } from '../shared/state.ts';
import type {
  WatchListItem,
  NormalizedCVE,
  Finding,
  IntelligenceArticle,
  EmailRecipient,
} from '../src/types/index.ts';
import { deliverNext } from '../server/delivery';
const now = new Date('2026-10-21T12:00:00Z');
const rss = (items: string) => `<rss version="2.0"><channel><title>Security</title>${items}</channel></rss>`;
const item = (
  url = 'https://example.com/story?utm_source=test',
  description = 'Acme Widget CVE-2026-12345 cve-2026-12345',
) =>
  `<item><title>Acme Widget vulnerability</title><link>${url.replaceAll('&', '&amp;')}</link><pubDate>Wed, 21 Oct 2026 10:00:00 GMT</pubDate><description>${description}</description></item>`;
const articles = () => parseSyndication(rss(item()), 'news', 24, now).articles;
const asset: WatchListItem = {
  id: 'asset',
  vendor: 'acme',
  product: 'widget',
  version: '2',
  cpes: [],
  assetTag: 'Production',
  ownerGroup: 'Security',
  active: true,
  createdAt: now.toISOString(),
};
test('RSS scopes ingestion, normalizes references and deduplicates tracked URLs', () => {
  const result = parseSyndication(
    rss(
      item() +
        item('https://example.com/story#fragment') +
        item('https://example.com/old').replace('21 Oct', '01 Oct') +
        '<item><title>No date</title></item>',
    ),
    'news',
    24,
    now,
  );
  assert.equal(result.articles.length, 1);
  assert.deepEqual(result.articles[0].cveIds, ['CVE-2026-12345']);
  assert.equal(result.articles[0].url, 'https://example.com/story');
  assert.equal(result.warnings.length, 1);
});
test('Atom handles alternate links and rejects HTML and future timestamps', () => {
  const xml =
    '<feed xmlns="http://www.w3.org/2005/Atom"><entry><title>Acme Widget</title><link rel="alternate" href="https://example.com/atom"/><updated>2026-10-21T10:00:00Z</updated><summary>CVE-2026-12345</summary></entry></feed>';
  assert.equal(parseSyndication(xml, 'atom', 24, now).articles.length, 1);
  assert.equal(parseSyndication(xml, 'atom', 24, new Date('2026-10-20')).articles.length, 0);
  assert.throws(() => parseSyndication('<html/>', 'x', 24), /Expected/);
  assert.throws(() => parseSyndication('<rss>', 'x', 24), /valid XML/);
  assert.throws(() =>
    parseSyndication('<rss>' + '<nested>'.repeat(100) + '</nested>'.repeat(100) + '</rss>', 'x', 24),
  );
});
test('escaped and CDATA-wrapped HTML documents are content, not declarations', () => {
  // Squarespace (the Zero Day Initiative blog) escapes a whole <html> document
  // into <description>; other feeds wrap the body in CDATA. Neither is a
  // declaration to a parser, so neither may fail the feed.
  const escaped = parseSyndication(
    rss(item('https://example.com/zd', '&lt;!DOCTYPE html&gt;&lt;html&gt;&lt;body&gt;CVE-2026-12345&lt;/body&gt;&lt;/html&gt;')),
    'zdi',
    24,
    now,
  );
  assert.equal(escaped.articles.length, 1);
  assert.deepEqual(escaped.articles[0].cveIds, ['CVE-2026-12345']);
  const cdata = parseSyndication(
    rss(item('https://example.com/cdata', '<![CDATA[<p>Intro</p><!DOCTYPE html><html><body>CVE-2026-12345</body></html>]]>')),
    'cdata',
    24,
    now,
  );
  assert.equal(cdata.articles.length, 1);
  assert.deepEqual(cdata.articles[0].cveIds, ['CVE-2026-12345']);
  // Double-escaped text stays text: it is not decoded a second time into a declaration.
  assert.equal(parseSyndication(rss(item('https://example.com/dbl', '&amp;lt;!DOCTYPE html&amp;gt;')), 'dbl', 24, now).articles.length, 1);
});

test('DOCTYPE and internal entity declarations parse without expanding entities', () => {
  const xml =
    '<?xml version="1.0"?>' +
    '<!DOCTYPE rss [<!ENTITY product "Expanded entity content">]>' +
    rss(item('https://example.com/entity', '&product; CVE-2026-12345'));
  const [article] = parseSyndication(xml, 'x', 24, now).articles;
  assert.ok(article);
  assert.match(article.summary, /&product;/);
  assert.doesNotMatch(article.summary, /Expanded entity content/);

  const externalDtd = '<?xml version="1.0"?><!DOCTYPE rss SYSTEM "https://example.test/feed.dtd">' + rss(item());
  assert.equal(parseSyndication(externalDtd, 'external-dtd', 24, now).articles.length, 1);
});

test('external entity declarations are not resolved', () => {
  const xml =
    '<!DOCTYPE rss [<!ENTITY secret SYSTEM "https://example.test/secret">]>' +
    rss(item('https://example.com/external-entity', '&secret;'));
  assert.throws(() => parseSyndication(xml, 'x', 24, now), /External entities are not supported/);
});

test('a round-up post keeps its article but not its thousands of CVE IDs', () => {
  const ids = Array.from({ length: 150 }, (_, i) => `CVE-2026-${10000 + i}`).join(' ');
  const result = parseSyndication(
    rss(item('https://example.com/roundup', `Microsoft October 2026 updates: ${ids}`)),
    'zdi',
    24,
    now,
  );
  assert.equal(result.articles.length, 1, 'the post is still usable evidence');
  assert.deepEqual(result.articles[0].cveIds, [], 'no per-product claim is inferred from a bulk list');
  assert.match(result.warnings.join(' '), /more than 100 CVEs/);
  const small = parseSyndication(rss(item('https://example.com/small', ids.split(' ').slice(0, 100).join(' '))), 'zdi', 24, now);
  assert.equal(small.articles[0].cveIds.length, 100, 'exactly the limit is still kept');
});

test('numeric entities cannot emit lone UTF-16 surrogates', () => {
  const xml = rss(
    '<item><title>Acme &#xD800; Widget &#x1F600;</title><link>https://example.com/story</link><pubDate>Wed, 21 Oct 2026 10:00:00 GMT</pubDate><description>CVE-2026-12345</description></item>',
  );
  const [article] = parseSyndication(xml, 'news', 24, now).articles;
  assert.ok(article);
  assert.ok(
    !/[\uD800-\uDFFF]/u.test(article.title),
    'a lone surrogate must never reach normalized article text',
  );
  assert.match(article.title, /😀/, 'valid astral-plane references must still decode');
});
test('cross-feed evidence deduplicates by URL and CVE/product without producing findings', () => {
  const news = articles();
  const other = { ...news[0], id: 'other', url: 'https://example.org/report', sourceFeeds: ['other'] };
  const merged = mergeArticles([...news, { ...news[0], sourceFeeds: ['second'] }, other]);
  assert.equal(merged.length, 2);
  assert.deepEqual(merged.find((a) => a.id === news[0].id)!.sourceFeeds, ['news', 'second']);
  const matches = matchIntelligence(merged, [asset], []);
  assert.equal(matches.length, 1);
  assert.equal(matches[0].articleIds.length, 2);
  assert.equal(matches[0].status, 'REVIEW_REQUIRED');
  assert.equal(matchIntelligence(news, [{ ...asset, vendor: 'unrelated' }], []).length, 0);
  assert.equal(matchIntelligence(news, [{ ...asset, product: 'wid' }], []).length, 0);
  assert.equal(matchIntelligence(news, [{ ...asset, active: false }], []).length, 0);
});
test('corrected article revisions replace obsolete CVE references instead of unioning them', () => {
  const original = articles()[0];
  const corrected = {
    ...original,
    modifiedDate: '2026-10-21T11:00:00Z',
    cveIds: [],
  };
  const merged = mergeArticles([original, corrected]);
  assert.equal(merged.length, 1);
  assert.deepEqual(merged[0].cveIds, []);
});

test('structured exclusions and operator resolutions cannot be overridden by article mentions', () => {
  const corpus = [
    { cveId: 'CVE-2026-12345', cpeMatches: ['cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*'] } as NormalizedCVE,
  ];
  assert.equal(matchIntelligence(articles(), [asset], [], corpus).length, 0);
  const finding = {
    id: 'finding',
    cveId: 'CVE-2026-12345',
    matchedAssetId: asset.id,
    status: 'OPEN',
    notificationStatus: 'QUEUED_FOR_DISPATCH',
  } as unknown as Finding;
  assert.equal(matchIntelligence(articles(), [asset], [finding], corpus)[0].status, 'CORROBORATED');
  for (const status of ['RESOLVED', 'FALSE_POSITIVE', 'PATCH_APPLIED'])
    assert.equal(
      matchIntelligence(articles(), [asset], [{ ...finding, status } as Finding], corpus).length,
      0,
    );
  assert.equal(
    matchIntelligence(articles(), [asset], [{ ...finding, notificationStatus: 'REVIEW_REQUIRED' }], corpus)[0]
      .status,
    'REVIEW_REQUIRED',
  );
  for (const notificationStatus of ['NOT_APPLICABLE', 'SUPPRESSED_VEX_NOT_AFFECTED'] as const)
    assert.equal(
      matchIntelligence(
        articles(),
        [asset],
        [{ ...finding, notificationStatus } as Finding],
        corpus,
      )[0].status,
      'REVIEW_REQUIRED',
      `${notificationStatus} must not become corroborated by a news mention`,
    );
});
test('event context redacts credentials recursively and bounds arbitrary values', () => {
  assert.deepEqual(
    redactEventContext({ nested: { apiKey: 'private', password: 'private', ok: 1 }, body: 'private' }),
    { nested: { apiKey: '[redacted]', password: '[redacted]', ok: 1 }, body: '[redacted]' },
  );
  assert.equal((redactEventContext({ value: 'x'.repeat(3000) }) as any).value.length, 2000);
});
test('describeError records message, database code, driver detail and stack', () => {
  const dbError = Object.assign(new Error('cannot start subtransactions during a parallel operation'), {
    name: 'error',
    code: '0A000',
    detail: 'subtransaction started in a parallel worker',
    hint: 'avoid exception blocks in parallel-safe functions',
    constraint: 'records_pkey',
    table: 'records',
    column: 'data',
    schema: 'public',
    severity: 'ERROR',
  });

  const described = describeError(dbError);

  assert.equal(described.error, 'cannot start subtransactions during a parallel operation');
  assert.equal(described.errorType, 'error');
  assert.equal(described.errorCode, '0A000');
  assert.equal(described.errorDetail, 'subtransaction started in a parallel worker');
  assert.equal(described.errorHint, 'avoid exception blocks in parallel-safe functions');
  assert.equal(described.errorConstraint, 'records_pkey');
  assert.equal(described.errorTable, 'records');
  assert.equal(described.errorColumn, 'data');
  assert.equal(described.errorSeverity, 'ERROR');
  assert.match(String(described.stack), /cannot start subtransactions/);
});
test('describeError handles plain values, wrapped causes and oversized text', () => {
  assert.deepEqual(describeError('boom'), { error: 'boom' });
  assert.deepEqual(describeError(null), {});

  const wrapped = new Error('fetch failed', {
    cause: { code: 'ECONNREFUSED', message: 'connect ECONNREFUSED 127.0.0.1:5432' },
  });
  const described = describeError(wrapped);
  assert.equal(described.error, 'fetch failed');
  assert.deepEqual(described.cause, {
    error: 'connect ECONNREFUSED 127.0.0.1:5432',
    errorCode: 'ECONNREFUSED',
  });
  assert.equal(String(describeError(new Error('x'.repeat(5000))).error).length, 4000);
});
test('request failure context carries route, caller, query and error detail', () => {
  const error = Object.assign(new Error('relation "records" does not exist'), { code: '42P01' });
  const context = describeRequestFailure(
    error,
    {
      method: 'GET',
      path: '/api/threat/analytics',
      route: { path: '/api/threat/analytics' },
      query: { range: '30d' },
      ip: '127.0.0.1',
      operator: { username: 'admin', role: 'ADMIN' },
    },
    'ref-1',
  );

  assert.equal(context.error, 'relation "records" does not exist');
  assert.equal(context.errorCode, '42P01');
  assert.equal(context.reference, 'ref-1');
  assert.equal(context.httpStatus, 500);
  assert.equal(context.method, 'GET');
  assert.equal(context.path, '/api/threat/analytics');
  assert.equal(context.route, '/api/threat/analytics');
  assert.deepEqual(context.query, { range: '30d' });
  assert.equal(context.actor, 'admin');
  assert.equal(context.role, 'ADMIN');
  assert.equal(context.ip, '127.0.0.1');
});
test('operations event scope excludes categories with dedicated log views', async () => {
  let capturedSql = '';
  let capturedValues: unknown[] = [];
  const db = {
    query: async (sql: string, values: unknown[]) => {
      capturedSql = sql;
      capturedValues = values;
      return { rows: [] };
    },
  };

  const result = await readEvents(db as any, {
    scope: 'OPERATIONS',
    category: 'PIPELINE',
    q: 'retry',
    limit: 20,
  });

  assert.deepEqual(result, { events: [], nextCursor: null });
  assert.match(capturedSql, /category NOT IN \('ML', 'SYSTEM'\)/);
  assert.match(capturedSql, /category=\$1/);
  assert.deepEqual(capturedValues, ['PIPELINE', 'retry', 21]);
});
test(
  'PostgreSQL news ingestion stays idempotent; events paginate and validate filters',
  { skip: !process.env.TEST_DATABASE_URL },
  async () => {
    const base = createPool(process.env.TEST_DATABASE_URL!);
    const schema = 'news_' + randomUUID().replaceAll('-', '');
    await base.query(`CREATE SCHEMA ${schema}`);
    const url = new URL(process.env.TEST_DATABASE_URL!);
    url.searchParams.set('options', `-c search_path=${schema}`);
    const pool = createPool(url.href);
    try {
      await migrate(pool);
      await migrate(pool);
      await put(pool, 'watchlist', asset.id, asset);
      await put(pool, 'feeds', 'news', {
        id: 'news',
        name: 'News',
        enabled: true,
        type: 'RSS_ATOM',
        url: 'https://example.com/feed',
        authType: 'NONE',
        rateLimit: 60,
        healthStatus: 'UNTESTED',
      });
      const config = loadConfig({
        NODE_ENV: 'test',
        DATABASE_URL: url.href,
        APP_ORIGIN: 'http://localhost',
        ENCRYPTION_KEY: randomBytes(32).toString('base64'),
        EGRESS_ALLOWED_HOSTS: 'example.com',
        WORKER_ENABLED: 'false',
      });
      const xml = rss(item()).replaceAll('Wed, 21 Oct 2026 10:00:00 GMT', new Date().toUTCString());
      for (let i = 0; i < 2; i++) {
        await queueRun(pool, 24, 'test');
        await processPipeline(pool, config, async () => ({ status: 200, body: xml, headers: {} }));
      }
      const snapshot = await state(pool);
      assert.equal(snapshot.intelligenceArticles.length, 1);
      assert.equal(snapshot.intelligenceMatches.length, 1);
      assert.equal(snapshot.cveData.length, 0);
      assert.equal(snapshot.findings.length, 0);
      assert.equal((await pool.query('SELECT count(*) FROM outbox')).rows[0].count, '0');
      await writeEvent(pool, {
        category: 'SYSTEM',
        code: 'test.marker',
        message: 'searchable marker',
        context: { token: 'secret' },
      });
      const first = await readEvents(pool, { limit: 1 });
      assert.equal(first.events.length, 1);
      assert.ok(first.nextCursor);
      assert.equal(first.events[0].context.token, '[redacted]');
      const next = await readEvents(pool, { before: first.nextCursor, limit: 1 });
      assert.notEqual(next.events[0].id, first.events[0].id);
      assert.equal((await readEvents(pool, { q: 'searchable', category: 'SYSTEM' })).events.length, 1);
      assert.ok((await readEvents(pool, { category: 'MATCHING' })).events.length >= 2);
      await writeEvent(pool, {
        category: 'ML',
        code: 'test.ml',
        message: 'machine learning event',
      });
      await writeEvent(pool, {
        category: 'PIPELINE',
        code: 'test.pipeline',
        message: 'pipeline event',
      });
      const operations = await readEvents(pool, { scope: 'OPERATIONS', limit: 100 });
      assert.ok(operations.events.some((event) => event.category === 'PIPELINE'));
      assert.ok(operations.events.every((event) => !['ML', 'SYSTEM'].includes(event.category)));
      assert.equal((await readEvents(pool, { scope: 'OPERATIONS', category: 'SYSTEM' })).events.length, 0);

      const filterRunId = randomUUID();
      const interleavedCategories = [
        'PIPELINE',
        'ML',
        'SYSTEM',
        'ISSUE',
        'SYSTEM',
        'ML',
        'PIPELINE',
        'SYSTEM',
        'ML',
        'ISSUE',
        'ML',
        'SYSTEM',
      ] as const;
      for (const [index, category] of interleavedCategories.entries()) {
        await writeEvent(pool, {
          category,
          code: `scope-regression-${index}`,
          message: `Interleaved scope regression event ${index}`,
          runId: filterRunId,
        });
      }

      const readAllPages = async (filters: { scope?: 'OPERATIONS'; category?: 'ML' | 'SYSTEM' }) => {
        const events = [];
        let before: string | undefined;
        let pageCount = 0;
        do {
          const page = await readEvents(pool, {
            ...filters,
            runId: filterRunId,
            limit: 2,
            ...(before ? { before } : {}),
          });
          events.push(...page.events);
          before = page.nextCursor || undefined;
          pageCount += 1;
          assert.ok(pageCount <= interleavedCategories.length, 'cursor pagination must terminate');
        } while (before);
        return { events, pageCount };
      };

      const [pagedOperations, pagedMl, pagedSystem] = await Promise.all([
        readAllPages({ scope: 'OPERATIONS' }),
        readAllPages({ category: 'ML' }),
        readAllPages({ category: 'SYSTEM' }),
      ]);
      const categoryCounts = (categories: readonly string[]) =>
        interleavedCategories.filter((category) => categories.includes(category)).length;
      assert.ok(pagedOperations.pageCount > 1);
      assert.ok(pagedMl.pageCount > 1);
      assert.ok(pagedSystem.pageCount > 1);
      assert.equal(pagedOperations.events.length, categoryCounts(['PIPELINE', 'ISSUE']));
      assert.ok(pagedOperations.events.every((event) => !['ML', 'SYSTEM'].includes(event.category)));
      assert.equal(pagedMl.events.length, categoryCounts(['ML']));
      assert.ok(pagedMl.events.every((event) => event.category === 'ML'));
      assert.equal(pagedSystem.events.length, categoryCounts(['SYSTEM']));
      assert.ok(pagedSystem.events.every((event) => event.category === 'SYSTEM'));
      assert.ok(
        [...pagedOperations.events, ...pagedMl.events, ...pagedSystem.events].every(
          (event) => event.runId === filterRunId,
        ),
      );
      await assert.rejects(readEvents(pool, { before: '9999999999999999999' }));
    } finally {
      await pool.end();
      await base.query(`DROP SCHEMA ${schema} CASCADE`);
      await base.end();
    }
   },
);
test(
  'matching news is consolidated into one Security-team email and never repeated',
  { skip: !process.env.TEST_DATABASE_URL },
  async () => {
    const base = createPool(process.env.TEST_DATABASE_URL!);
    const schema = 'news_dispatch_' + randomUUID().replaceAll('-', '');
    await base.query(`CREATE SCHEMA ${schema}`);
    const url = new URL(process.env.TEST_DATABASE_URL!);
    url.searchParams.set('options', `-c search_path=${schema}`);
    const pool = createPool(url.href);
    try {
      await migrate(pool);
      await put(pool, 'watchlist', asset.id, asset);
      await put(pool, 'feeds', 'news', {
        id: 'news',
        name: 'News',
        enabled: true,
        type: 'RSS_ATOM',
        url: 'https://example.com/feed',
        authType: 'NONE',
        rateLimit: 60,
        healthStatus: 'UNTESTED',
      });
      await put(pool, 'settings', 'main', { ...DEFAULT_SETTINGS, autoDispatchNewsToSecurityTeam: true });
      await put(pool, 'recipients', 'sec-team', {
        id: 'sec-team',
        name: 'Security Team',
        email: 'sec@example.invalid',
        role: 'ADMIN',
        deliveryGroup: 'SECURITY_TEAM',
        subscriptionTier: 'ALL_SEVERITIES',
        enabled: true,
        deliverySuccessRate: 100,
      } as EmailRecipient);
      const config = loadConfig({
        NODE_ENV: 'test',
        DATABASE_URL: url.href,
        APP_ORIGIN: 'http://localhost',
        ENCRYPTION_KEY: randomBytes(32).toString('base64'),
        EGRESS_ALLOWED_HOSTS: 'example.com',
        WORKER_ENABLED: 'false',
      });
      const rssXml = rss(
        item('https://example.com/story', 'Acme Widget CVE-2026-12345 cve-2026-12345').replaceAll(
          'Wed, 21 Oct 2026 10:00:00 GMT',
          new Date().toUTCString(),
        ),
      );
      await queueRun(pool, 24, 'test');
      await processPipeline(pool, config, async () => ({ status: 200, body: rssXml, headers: {} }));
      const queued = (await pool.query('SELECT count(*)::int AS n FROM outbox')).rows[0].n;
      assert.equal(queued, 1, `expected one consolidated news email, got ${queued}`);
      const jobRow = (await pool.query('SELECT advisory_id, payload FROM outbox')).rows[0];
      assert.match(jobRow.advisory_id, /^NEWS:/, 'job key is a news advisory id');
      assert.match(jobRow.payload.subject, /^\[Threat intelligence\] \[NEWS\]/);
      assert.equal(jobRow.payload.cveIds[0], 'CVE-2026-12345');
      assert.equal(jobRow.payload.newsEvidence.articles.length, 1);
      assert.equal(jobRow.payload.newsEvidence.articles[0].id, jobRow.payload.newsEvidence.article.id);
      // The HTML body is the same document the attachment is rendered from.
      assert.match(jobRow.payload.html, /Matched asset/);
      assert.match(jobRow.payload.html, /acme widget/);
      let emails = 0;
      const mail = async () => {
        emails++;
        return 'mock-accepted';
      };
      while (await deliverNext(pool, config, async () => ({ status: 200, body: '', headers: {} }), mail)) {}
      assert.equal(emails, 1);
      assert.equal(
        (await pool.query("SELECT count(*)::int AS n FROM outbox WHERE status='ACCEPTED'")).rows[0].n,
        1,
      );
      // A second run over the same (re-scoped) feed must not email the article again.
      await queueRun(pool, 48, 'test');
      await processPipeline(pool, config, async () => ({ status: 200, body: rssXml, headers: {} }));
      assert.equal(
        (await pool.query("SELECT count(*)::int AS n FROM outbox WHERE status='QUEUED'")).rows[0].n,
        0,
        'an article already sent to the recipient is never queued again',
      );
      assert.equal(
        (await pool.query("SELECT data->>'recipientEmail' AS value FROM records WHERE kind='emailLogs'"))
          .rows[0].value,
        'sec@example.invalid',
      );
    } finally {
      await pool.end();
      await base.query(`DROP SCHEMA ${schema} CASCADE`);
      await base.end();
    }
  },
);
test(
  'settings.save persists the news flag through the schema (retained for compatibility)',
  { skip: !process.env.TEST_DATABASE_URL },
  async () => {
    const base = createPool(process.env.TEST_DATABASE_URL!);
    const schema = 'news_save_' + randomUUID().replaceAll('-', '');
    await base.query(`CREATE SCHEMA ${schema}`);
    const url = new URL(process.env.TEST_DATABASE_URL!);
    url.searchParams.set('options', `-c search_path=${schema}`);
    const pool = createPool(url.href);
    try {
      await migrate(pool);
      const config = loadConfig({
        NODE_ENV: 'test',
        DATABASE_URL: url.href,
        APP_ORIGIN: 'http://localhost',
        ENCRYPTION_KEY: randomBytes(32).toString('base64'),
        EGRESS_ALLOWED_HOSTS: 'example.com',
        WORKER_ENABLED: 'false',
      });
      await put(pool, 'settings', 'main', { ...DEFAULT_SETTINGS });
      assert.equal((await get<any>(pool, 'settings', 'main'))!.autoDispatchNewsToSecurityTeam, false);
      const saved = await applyCommand(pool, config, {
        action: 'settings.save',
        data: { autoDispatchNewsToSecurityTeam: true },
        actor: 'test',
      });
      assert.equal(saved.success, true);
      assert.equal(
        (await get<any>(pool, 'settings', 'main'))!.autoDispatchNewsToSecurityTeam,
        true,
        'the flag must survive settings.save (not be stripped by the schema)',
      );
      // Toggling off must also round-trip; this guards against the zod strip regression.
      await applyCommand(pool, config, {
        action: 'settings.save',
        data: { autoDispatchNewsToSecurityTeam: false },
        actor: 'test',
      });
      assert.equal((await get<any>(pool, 'settings', 'main'))!.autoDispatchNewsToSecurityTeam, false);
    } finally {
      await pool.end();
      await base.query(`DROP SCHEMA ${schema} CASCADE`);
      await base.end();
    }
  },
);
test('large legitimate RSS archives are bounded but filtered by scope instead of failing at 500 entries', () => {
  const oldItem = item('https://example.com/old', 'Historical advisory '.repeat(30)).replace('21 Oct', '01 Oct');
  const xml = rss(oldItem.repeat(5103) + item('https://example.com/current'));
  assert.ok(Buffer.byteLength(xml) > 2 * 1024 * 1024);
  const parsed = parseSyndication(xml, 'msrc-sized', 24, now);
  assert.equal(parsed.articles.length, 1);
  assert.equal(parsed.articles[0].url, 'https://example.com/current');
  assert.throws(() => parseSyndication('x'.repeat(16 * 1024 * 1024 + 1), 'oversized', 24), /16 MiB/);
  assert.throws(() => parseSyndication(rss('<item/>'.repeat(10001)), 'too-many', 24), /10,000 entries/);
});
test('a feed larger than a full archive but under the ceiling parses, and scope still filters it', () => {
  // Google Project Zero ships ten complete posts (~10.8 MiB decoded). The limit
  // must sit above real archives that big and still refuse anything beyond it.
  const oldItem = item('https://example.com/old', 'Historical advisory '.repeat(60)).replace('21 Oct', '01 Oct');
  const xml = rss(oldItem.repeat(9000) + item('https://example.com/current'));
  assert.ok(Buffer.byteLength(xml) > 10 * 1024 * 1024, 'the fixture must exceed the old 8 MiB ceiling');
  const parsed = parseSyndication(xml, 'archive', 24, now);
  assert.equal(parsed.articles.length, 1);
  assert.equal(parsed.articles[0].url, 'https://example.com/current');
});
test('entries outside the scope window are skipped before their bodies are flattened', () => {
  // Only the in-scope entry may reach the expensive text processing, so an
  // archive of huge out-of-scope bodies costs nothing beyond parsing.
  const oldItem = item('https://example.com/old', 'Historical advisory '.repeat(60)).replace('21 Oct', '01 Oct');
  const parsed = parseSyndication(rss(oldItem.repeat(3) + item('https://example.com/current')), 'scope', 24, now);
  assert.equal(parsed.articles.length, 1);
  assert.equal(parsed.warnings.length, 0, 'out-of-scope entries are not counted as invalid');
});

test('custom vendor aliases from the Alias Thesaurus reach news matching', () => {
  // Article says "Acme Corp" but inventory uses the CPE identifier "acmecorp".
  // Without the custom alias, no match. With it, vendor is found.
  const article = {
    id: 'alias-vendor-1',
    title: 'Acme Corp product hit by critical RCE',
    summary: 'The Acme Corp widget server is vulnerable.',
    url: 'https://example.com/acme',
    publishedDate: '2026-10-01T00:00:00Z',
    modifiedDate: '2026-10-01T00:00:00Z',
    cveIds: ['CVE-2026-9001'],
    sourceFeeds: ['test'],
  };
  const asset: WatchListItem = {
    id: 'asset-alias-test',
    assetTag: 'Widget Server',
    vendor: 'acmecorp',
    product: 'widget',
    version: '3.0',
    cpes: [],
    purls: [],
    active: true,
    ownerGroup: 'Test',
    targetHw: '*',
    createdAt: '2026-01-01T00:00:00Z',
  };
  // Audit N-1: the compound vendor `acmecorp` decomposes to `acme corp`, so the
  // article is evidence even without an operator alias. The previous expectation
  // (zero matches) encoded the matching bug itself.
  assert.equal(matchIntelligence([article], [asset], []).length, 1);
  // Match once we supply the custom vendor alias
  const matches = matchIntelligence([article], [asset], [], [], { acmecorp: ['acme corp'] });
  assert.equal(matches.length, 1);
  assert.equal(matches[0].status, 'REVIEW_REQUIRED');
  assert.equal(matches[0].assetId, 'asset-alias-test');
});

test('custom product aliases from the Alias Thesaurus reach news matching', () => {
  // Article uses a marketing name "xenon gateway" — inventory records the product
  // by its CPE identifier "xgateway". The vendor is explicitly named in both.
  const article = {
    id: 'alias-product-1',
    title: 'Critical RCE in acmecorp Xenon Gateway',
    summary: 'The acmecorp Xenon Gateway appliance is affected by CVE-2026-5555.',
    url: 'https://example.com/xenon',
    publishedDate: '2026-10-01T00:00:00Z',
    modifiedDate: '2026-10-01T00:00:00Z',
    cveIds: [],
    sourceFeeds: ['test'],
  };
  const asset: WatchListItem = {
    id: 'asset-product-alias-test',
    assetTag: 'Gateway Appliance',
    vendor: 'acmecorp',
    product: 'xgateway',
    version: '3.0',
    cpes: [],
    purls: [],
    active: true,
    ownerGroup: 'Test',
    targetHw: '*',
    createdAt: '2026-01-01T00:00:00Z',
  };
  // Vendor matches ('acmecorp' decomposes to 'acme corp'); product 'xgateway'
  // is not decomposed into 'xenon', so only the operator alias can reach it.
  assert.equal(matchIntelligence([article], [asset], [], [], {}, {}).length, 0);
  // Once we alias xgateway → 'xenon gateway', the product is found in the article.
  const matches = matchIntelligence([article], [asset], [], [], {}, { xgateway: ['xenon gateway'] });
  assert.equal(matches.length, 1);
  assert.equal(matches[0].status, 'REVIEW_REQUIRED');
});

test('built-in vendor aliases still work after custom-alias merge', () => {
  // 'palo alto networks' is a built-in alias for 'paloaltonetworks'.
  // Adding a custom alias for an unrelated vendor must not break this.
  const article = {
    id: 'builtin-alias-preserved',
    title: 'Palo Alto Networks firewall vulnerability',
    summary: 'A critical vulnerability affects Palo Alto Networks pan os products.',
    url: 'https://example.com/pan',
    publishedDate: '2026-10-01T00:00:00Z',
    modifiedDate: '2026-10-01T00:00:00Z',
    cveIds: ['CVE-2026-9002'],
    sourceFeeds: ['test'],
  };
  const asset: WatchListItem = {
    id: 'asset-pan',
    assetTag: 'Firewall',
    vendor: 'paloaltonetworks',
    product: 'pan os',
    version: '10.2',
    cpes: [],
    purls: [],
    active: true,
    ownerGroup: 'Ops',
    targetHw: '*',
    createdAt: '2026-01-01T00:00:00Z',
  };
  // Should match via the built-in alias even when custom aliases are supplied
  const matches = matchIntelligence(
    [article],
    [asset],
    [],
    [],
    { acmecorp: ['acme corp'] }, // unrelated custom alias
  );
  assert.equal(matches.length, 1);
  assert.equal(matches[0].assetId, 'asset-pan');
});

test('CVE-less article without urgency language is not misclassified as zero-day', () => {
  const routine: IntelligenceArticle = {
    id: 'routine-feature-1',
    url: 'https://example.com/feature',
    title: 'Acme Widget quarterly feature update',
    summary: 'The Acme Widget platform receives a routine maintenance update.',
    publishedDate: '2026-10-01T00:00:00Z',
    modifiedDate: '2026-10-01T00:00:00Z',
    cveIds: [],
    sourceFeeds: ['test'],
    zeroDay: false,
  };
  const matches = matchIntelligence([routine], [asset], []);
  assert.equal(matches.length, 1);
  assert.equal(matches[0].status, 'REVIEW_REQUIRED');
  assert.equal(matches[0].zeroDay, false);
});

test('zero-day flag clears once a merged record carries a CVE ID', () => {
  const preCve: IntelligenceArticle = {
    id: 'zeroday-cve-later',
    url: 'https://example.com/story',
    title: 'Acme Widget zero-day exploit in the wild',
    summary: 'Acme Widget is being actively exploited in the wild without a patch.',
    publishedDate: '2026-10-01T00:00:00Z',
    modifiedDate: '2026-10-01T00:00:00Z',
    cveIds: [],
    sourceFeeds: ['feed1'],
    zeroDay: true,
  };
  const postCve: IntelligenceArticle = {
    ...preCve,
    modifiedDate: '2026-10-02T00:00:00Z',
    cveIds: ['CVE-2026-12345'],
    sourceFeeds: ['feed2'],
    zeroDay: false,
  };
  const merged = mergeArticles([preCve, postCve]);
  assert.equal(merged.length, 1);
  assert.deepEqual(merged[0].cveIds, ['CVE-2026-12345']);
  assert.equal(merged[0].zeroDay, false);

  // Zero-day persists when no CVE ID is ever attached.
  const stillZero = mergeArticles([
    preCve,
    { ...preCve, modifiedDate: '2026-10-02T00:00:00Z', sourceFeeds: ['feed2'] },
  ]);
  assert.equal(stillZero[0].zeroDay, true);
  assert.equal(stillZero[0].cveIds.length, 0);
});

test('news identity decomposition reaches prose without a built-in alias entry', () => {
  // Audit N-1: proposal-style vendor identifiers are reachable through word
  // segmentation (`paloaltonetworks` -> `palo alto networks`). Before the fix
  // only the six hard-coded display names were decomposed.
  const article = {
    id: 'compound-vendor-1',
    title: 'Palo Alto Networks PAN-OS flaw exploited in the wild',
    summary: 'Researchers observed exploitation against Palo Alto Networks firewalls.',
    url: 'https://example.com/paloalto',
    publishedDate: '2026-10-01T00:00:00Z',
    modifiedDate: '2026-10-01T00:00:00Z',
    cveIds: [],
    sourceFeeds: ['RSS_NEWS'],
  };
  const asset: WatchListItem = {
    id: 'asset-panw',
    assetTag: 'Edge Firewall',
    vendor: 'paloaltonetworks',
    product: 'pan-os',
    version: '10.2',
    cpes: [],
    purls: [],
    active: true,
    ownerGroup: 'Test',
    targetHw: '*',
    createdAt: '2026-01-01T00:00:00Z',
  };
  const { newsIdentityVariants } = matchIntelligenceModule;
  const variants = newsIdentityVariants(
    'paloaltonetworks',
    {},
    {},
  ).map((value) => value.toLowerCase());
  assert.ok(
    variants.includes('palo alto networks'),
    `decomposition must propose the spaced spelling; got ${variants.join(', ')}`,
  );
  const matches = matchIntelligence([article], [asset], []);
  assert.equal(matches.length, 1, 'decomposed vendor spelling must reach prose');
  assert.equal(matches[0].status, 'REVIEW_REQUIRED');
});

test('operator aliases resolve regardless of key spelling', () => {
  // Audit N-1: the news matcher looked up `customVendorAliases[normVendor]`,
  // while buildAliasMap keys on the operator's canonical spelling. An operator
  // entry keyed `AcmeCorp` never matched an asset declared `acmecorp`.
  const article = {
    id: 'alias-key-1',
    title: 'Acme Corp product hit by critical RCE',
    summary: 'The Acme Corp widget server is vulnerable.',
    url: 'https://example.com/acme-key',
    publishedDate: '2026-10-01T00:00:00Z',
    modifiedDate: '2026-10-01T00:00:00Z',
    cveIds: [],
    sourceFeeds: ['test'],
  };
  const asset: WatchListItem = {
    id: 'asset-alias-key',
    assetTag: 'Widget Server',
    vendor: 'acmecorp',
    product: 'widget',
    version: '3.0',
    cpes: [],
    purls: [],
    active: true,
    ownerGroup: 'Test',
    targetHw: '*',
    createdAt: '2026-01-01T00:00:00Z',
  };
  const matches = matchIntelligence([article], [asset], [], [], { AcmeCorp: ['Acme Corp'] });
  assert.equal(matches.length, 1, 'operator alias key spelling must not defeat matching');
});

test('newsIdentityVariants is exported for deterministic alias parity', () => {
  const { newsIdentityVariants } = matchIntelligenceModule;
  const variants = newsIdentityVariants('paloaltonetworks', { paloaltonetworks: ['Palo Alto Networks'] });
  const normalized = variants.map((value) => value.toLowerCase().replace(/\s+/g, ' ').trim());
  assert.ok(normalized.includes('palo alto networks'));
  assert.ok(normalized.includes('paloaltonetworks'));
});
test('pluralized and hyphenated article mentions still match inventory', () => {
  // Audit F-5a: whole-token matching lost every inflected mention.
  const cases: Array<[string, string, string, boolean]> = [
    // [articleText, vendor, product, shouldMatch]
    ['acme widgets hit by ransomware', 'acme', 'widget', true],
    ['fortinet fortios appliances exploited', 'fortinet', 'fortios', true],
    ['new intel cpus vulnerability', 'intel', 'cpu', true],
    ['researchers warn about acme widget flaw', 'acme', 'widget', true],
    // Generic words must not conjure a vendor out of a shared substring.
    ['company reports quarterly status update', 'statu', 'widget', false],
    ['unrelated story about weather', 'acme', 'widget', false],
  ];
  let assetId = 0;
  for (const [articleText, vendor, product, shouldMatch] of cases) {
    const article = {
      id: `plural-${assetId}`,
      title: articleText,
      summary: '',
      url: `https://example.com/${assetId}`,
      publishedDate: '2026-10-01T00:00:00Z',
      modifiedDate: '2026-10-01T00:00:00Z',
      cveIds: [],
      sourceFeeds: ['RSS_NEWS'],
    };
    const asset: WatchListItem = {
      id: `asset-plural-${assetId++}`,
      assetTag: 'Test',
      vendor,
      product,
      version: '1',
      cpes: [],
      purls: [],
      active: true,
      ownerGroup: 'Test',
      targetHw: '*',
      createdAt: '2026-01-01T00:00:00Z',
    };
    const matches = matchIntelligence([article], [asset], []);
    assert.equal(
      matches.length > 0,
      shouldMatch,
      `"${articleText}" vs ${vendor}/${product} should ${shouldMatch ? '' : 'not '}match`,
    );
  }
});

test('suffix stripping never invents a generic-word vendor stem', () => {
  // Audit F-5b: `progresssoftware` -> `progress` would correlate any article
  // using the ordinary word "progress" with this vendor.
  const { newsIdentityVariants } = matchIntelligenceModule;
  const variants = newsIdentityVariants('progresssoftware').map((value) => value.toLowerCase());
  assert.ok(!variants.includes('progress'), 'generic stem must be suppressed');
  assert.ok(variants.includes('progresssoftware'), 'full identity still matches');

  // An operator who declares the generic alias explicitly gets it back: the
  // assertion was theirs to make, not the matcher's to invent.
  const opted = newsIdentityVariants('progresssoftware', {
    progress: ['progresssoftware'],
  }).map((value) => value.toLowerCase());
  assert.ok(
    opted.includes('progress'),
    'operator-declared generic alias must be honoured',
  );
});

test('securitymetrics does not degrade into the word security', () => {
  const article = {
    id: 'generic-stem-1',
    title: 'Industry security spending rises again this year',
    summary: 'Analysts report broad security budget growth.',
    url: 'https://example.com/security-budget',
    publishedDate: '2026-10-01T00:00:00Z',
    modifiedDate: '2026-10-01T00:00:00Z',
    cveIds: [],
    sourceFeeds: ['RSS_NEWS'],
  };
  const asset: WatchListItem = {
    id: 'asset-securitymetrics',
    assetTag: 'Metrics',
    vendor: 'securitymetrics',
    product: 'widget',
    version: '1',
    cpes: [],
    purls: [],
    active: true,
    ownerGroup: 'Test',
    targetHw: '*',
    createdAt: '2026-01-01T00:00:00Z',
  };
  assert.equal(
    matchIntelligence([article], [asset], []).length,
    0,
    'a generic-word article must not become vendor evidence',
  );
});
