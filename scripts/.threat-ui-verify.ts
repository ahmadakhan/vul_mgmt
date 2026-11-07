import assert from 'node:assert/strict';
import puppeteer from 'puppeteer-core';
import { emptyState } from '../shared/state.ts';
import { mkdir } from 'node:fs/promises';
const output = '/home/admin1/.codex/visualizations/2026/10/28/01a18360-2c1e-7d71-84d8-c188585994ad';
await mkdir(output, { recursive: true });
const hits = Array.from({ length: 16 }, (_, i) => ({
  source: i % 3 ? 'NVD_API' : 'NVD_KEYWORD',
  matchingCpes: ['cpe:2.3:o:microsoft:windows_server_2022:*:*:*:*:*:*:*:*'],
  cve: {
    cveId: `CVE-2026-${90001 + i}`,
    title: [
      'Remote code execution in Windows Server',
      'Privilege escalation in the Windows authentication service',
      'Security feature bypass in Windows networking',
      'Windows Server information disclosure',
    ][i % 4],
    description:
      'UI verification fixture. This is sample data for checking the search interface, not a live advisory.',
    cvss: { version: '3.1', score: i % 3 ? 8.1 : 9.8, severity: i % 3 ? 'HIGH' : 'CRITICAL', vector: '' },
    publishedDate: '2026-10-27T10:00:00Z',
    modifiedDate: '2026-10-28T10:00:00Z',
    cwe: ['CWE-787'],
    sourceFeeds: ['NVD'],
    cpeMatches: [],
    epss: { score: 0.145, percentile: 0.97 },
    cisaKev: { isKev: i % 4 === 0, dateAdded: '2026-10-27' },
    exploitStatus: i % 4 === 0 ? 'Reported In Wild' : 'None',
    remediation: { patchUrl: '', immediateActions: [], workarounds: [] },
  },
}));
let mode = 'success';
let release: (() => void) | undefined;
const browser = await puppeteer.launch({ executablePath: '/usr/bin/google-chrome', headless: true });
try {
  const page = await browser.newPage();
  const errors: string[] = [];
  page.on('pageerror', (error) => errors.push(String(error)));
  await page.setViewport({ width: 1440, height: 1050 });
  await page.setRequestInterception(true);
  page.on('request', async (request) => {
    const url = new URL(request.url());
    if (!url.pathname.startsWith('/api/')) return void request.continue();
    let body: unknown = {},
      status = 200;
    if (url.pathname === '/api/session')
      body = {
        username: 'ui-preview',
        role: 'ADMIN',
        csrfToken: 'preview',
        expiresAt: new Date(Date.now() + 3600000).toISOString(),
      };
    if (url.pathname === '/api/state') body = emptyState();
    if (url.pathname === '/api/threat/intelligence/search') {
      if (mode === 'delayed')
        await new Promise<void>((resolve) => {
          release = resolve;
        });
      if (mode === 'error') {
        status = 502;
        body = { error: 'NVD is temporarily unavailable. Please retry.' };
      } else
        body = {
          hits: mode === 'empty' ? [] : hits,
          totalResults: mode === 'empty' ? 0 : 640,
          rateLimited: mode === 'partial',
        };
    }
    await request.respond({ status, contentType: 'application/json', body: JSON.stringify(body) });
  });
  await page.goto('http://127.0.0.1:3173', { waitUntil: 'networkidle0' });
  await page.locator('button ::-p-text(Threat intelligence search)').click();
  await page.waitForSelector('.threat-search-welcome');
  await page.screenshot({ path: `${output}/threat-search-dark.png`, fullPage: true });
  await page.click('#threat-vendor');
  await page.keyboard.press('ArrowDown');
  const first = await page.$eval('#threat-vendor', (el) => el.getAttribute('aria-activedescendant'));
  await page.keyboard.press('ArrowDown');
  const second = await page.$eval('#threat-vendor', (el) => el.getAttribute('aria-activedescendant'));
  assert.notEqual(first, second, 'vendor arrow navigation advances');
  await page.keyboard.press('Escape');
  await page.locator('.threat-examples button ::-p-text(Windows Server)').click();
  assert.equal(
    await page.$eval('#threat-product', (el) => (el as HTMLSelectElement).value),
    'windows_server_2022',
  );
  const run = async () => {
    await page.click('.threat-search-submit');
    await page.waitForSelector('.threat-results-table tbody tr');
  };
  await run();
  await page.screenshot({ path: `${output}/threat-search-results-dark.png`, fullPage: true });
  assert.equal(await page.$$eval('.threat-results-table tbody tr', (els) => els.length), 10);
  await page.click('button[aria-label="Next Page"]');
  await page.waitForFunction(
    () => document.querySelector('[aria-label="Page 2"]')?.getAttribute('aria-current') === 'page',
  );
  assert.equal(await page.$$eval('.threat-results-table tbody tr', (els) => els.length), 6);
  await page.select('#severity-filter', 'CRITICAL');
  await page.waitForFunction(() => document.querySelectorAll('.threat-results-table tbody tr').length === 6);
  await page.locator('.threat-desktop-results button[aria-label^="Inspect"]').click();
  await page.waitForSelector('[role="dialog"]');
  await page.evaluate(() => {
    const nodes = document.querySelectorAll<HTMLElement>('[role="dialog"] button, [role="dialog"] a[href]');
    nodes[nodes.length - 1].focus();
  });
  await page.keyboard.press('Tab');
  assert.equal(await page.evaluate(() => !!document.activeElement?.closest('[role="dialog"]')), true);
  await page.keyboard.press('Escape');
  await page.waitForSelector('[role="dialog"]', { hidden: true });
  assert.equal(
    await page.evaluate(() => document.activeElement?.getAttribute('aria-label')?.startsWith('Inspect')),
    true,
  );
  await page.locator('button ::-p-text(Clear filters)').click();
  await page.setViewport({ width: 390, height: 844 });
  await page.evaluate(() => Promise.all(document.getAnimations().map((a) => a.finished.catch(() => {}))));
  await page.screenshot({ path: `${output}/threat-search-mobile.png`, fullPage: true });
  assert.equal(await page.$eval('.threat-desktop-results', (el) => getComputedStyle(el).display), 'none');
  assert.equal(await page.$eval('.threat-mobile-results', (el) => getComputedStyle(el).display), 'grid');
  assert.equal(
    await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth),
    true,
    'mobile page has no horizontal overflow',
  );
  await page.click('.ui-topbar button[aria-label="Switch to light mode"]');
  await page.setViewport({ width: 1440, height: 1050 });
  await page.evaluate(() => Promise.all(document.getAnimations().map((a) => a.finished.catch(() => {}))));
  await page.screenshot({ path: `${output}/threat-search-results-light.png`, fullPage: true });
  mode = 'error';
  await page.click('.threat-search-submit');
  await page.waitForSelector('[role="alert"]');
  assert.ok(
    (await page.$eval('[role="alert"]', (el) => el.textContent))?.includes('Unable to complete the search'),
  );
  mode = 'empty';
  await page.click('.threat-search-submit');
  await page.waitForFunction(() =>
    document.body.textContent?.includes('No vulnerabilities matched this query'),
  );
  mode = 'partial';
  await run();
  assert.ok(
    (await page.$eval('[role="alert"]', (el) => el.textContent))?.includes(
      'Some intelligence is unavailable',
    ),
  );
  mode = 'delayed';
  await page.click('.threat-search-submit');
  await page.waitForSelector('[aria-busy="true"]');
  await page.locator('.threat-search-actions button ::-p-text(Reset)').click();
  release?.();
  await page.waitForSelector('.threat-search-welcome');
  await page.waitForNetworkIdle({ idleTime: 500 });
  assert.equal(await page.$('.threat-results-table'), null, 'reset ignores late responses');
  await page.screenshot({ path: `${output}/threat-search-light.png`, fullPage: true });
  assert.deepEqual(errors, []);
  console.log(
    'UI verification passed: vendor keyboard selection, quick start, pagination, severity filter, dialog focus and Escape, mobile layout, light/dark themes, errors, empty results, partial results, and reset during a pending request.',
  );
} finally {
  await browser.close();
}
