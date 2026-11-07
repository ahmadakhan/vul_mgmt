import puppeteer from 'puppeteer-core';
import { emptyState } from '../shared/state.ts';
const browser = await puppeteer.launch({ executablePath: '/usr/bin/google-chrome', headless: true });
const page = await browser.newPage();
await page.setViewport({ width: 1440, height: 1050 });
page.on('pageerror', (error) => console.error('PAGE ERROR', String(error)));
await page.setRequestInterception(true);
page.on('request', (request) => {
  const url = new URL(request.url());
  if (url.pathname.startsWith('/api/')) {
    let body: unknown = {};
    if (url.pathname === '/api/session')
      body = {
        username: 'ui-preview',
        role: 'ADMIN',
        csrfToken: 'preview',
        expiresAt: new Date(Date.now() + 3600000).toISOString(),
      };
    if (url.pathname === '/api/state') body = emptyState();
    void request.respond({ status: 200, contentType: 'application/json', body: JSON.stringify(body) });
  } else void request.continue();
});
await page.goto('http://127.0.0.1:3173', { waitUntil: 'networkidle0' });
await page.locator('button ::-p-text(Threat intelligence search)').click();
await page.screenshot({ path: '/tmp/threat-search-after.png', fullPage: true });
console.log('Captured baseline');
await browser.close();
