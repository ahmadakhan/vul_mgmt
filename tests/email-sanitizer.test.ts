import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, realpathSync, statSync } from 'node:fs';
import { isAbsolute, join } from 'node:path';
import { build } from 'esbuild';
import puppeteer from 'puppeteer-core';
import { sanitizeEmailHtml } from '../src/utils/sanitizeEmailHtml.ts';

const resolveTestChrome = () => {
  const candidates = [
    process.env.CHROME_EXECUTABLE_PATH,
    '/usr/bin/google-chrome',
    '/usr/bin/google-chrome-stable',
    '/usr/bin/chromium',
    '/usr/bin/chromium-browser',
    process.env.ProgramFiles && join(process.env.ProgramFiles, 'Google', 'Chrome', 'Application', 'chrome.exe'),
    process.env['ProgramFiles(x86)'] && join(process.env['ProgramFiles(x86)'], 'Google', 'Chrome', 'Application', 'chrome.exe'),
    process.env.LOCALAPPDATA && join(process.env.LOCALAPPDATA, 'Google', 'Chrome', 'Application', 'chrome.exe'),
  ];
  for (const candidate of candidates) {
    if (!candidate || !isAbsolute(candidate)) continue;
    try {
      const path = realpathSync(candidate);
      if (statSync(path).isFile()) return path;
    } catch {
      continue;
    }
  }
  return undefined;
};
const chrome = resolveTestChrome();

test('email preview sanitization fails closed without a browser DOM', () => {
  assert.equal(sanitizeEmailHtml('<script>alert(1)</script>'), '');
});

test('email preview sanitization blocks encoded execution and UI/resource injection', { skip: !chrome }, async () => {
  const bundle = await build({ entryPoints: ['src/utils/sanitizeEmailHtml.ts'], bundle: true, write: false,
    platform: 'browser', format: 'iife', globalName: 'EmailSanitizer' });
  const browser = await puppeteer.launch({
    executablePath: chrome,
    headless: true,
    args: ['--no-sandbox', '--disable-setuid-sandbox'],
  });
  try {
    const page = await browser.newPage();
    await page.setRequestInterception(true);
    page.on('request', (request) => { void request.abort(); });
    await page.addScriptTag({ content: bundle.outputFiles[0].text });
    const result = await page.evaluate(() => {
      const api = (window as unknown as { EmailSanitizer: { sanitizeEmailHtml(html: string): string } }).EmailSanitizer;
      const input = `<a href="&#x6a;avascript:window.__auditExecuted=true">encoded</a>
        <a href="java&#x09;script:window.__auditExecuted=true">tabbed</a>
        <a href="https://example.com/advisory" target="_blank">source</a>
        <img src="https://tracker.example/pixel" onerror="window.__auditExecuted=true">
        <svg><animate attributeName="href" values="javascript:alert(1)"></animate></svg>
        <form action="/api/logout"><input name="password"></form>
        <style>body{display:none}</style><div class="fixed" id="app" style="position:fixed;z-index:9999;background-image:url(https://tracker.example/style);color:red;padding:8px">safe text</div>
        <table style="border-collapse:collapse"><tr><td>Advisory content</td></tr></table>`;
      const output = api.sanitizeEmailHtml(input);
      const container = document.createElement('div');
      container.innerHTML = output;
      document.body.append(container);
      const links = Array.from(container.querySelectorAll('a')).map((link) => ({ text: link.textContent, href: link.getAttribute('href'), rel: link.rel }));
      return { output, links, forbidden: container.querySelectorAll('script,style,svg,form,input,iframe,[onerror],[class],[id]').length,
        imageSource: container.querySelector('img')?.getAttribute('src'), style: container.querySelector('div')?.getAttribute('style') };
    });
    assert.equal(result.forbidden, 0);
    assert.equal(result.links[0].href, null);
    assert.equal(result.links[1].href, null);
    assert.equal(result.links[2].href, 'https://example.com/advisory');
    assert.equal(result.links[2].rel, 'noopener noreferrer');
    assert.equal(result.imageSource, null);
    assert.ok(!result.style?.includes('position'));
    assert.ok(!result.style?.includes('url('));
    assert.ok(result.style?.includes('padding: 8px'));
    assert.ok(result.output.includes('<table'));
    assert.ok(result.output.includes('Advisory content'));
  } finally { await browser.close(); }
});