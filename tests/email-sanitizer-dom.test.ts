import { test } from 'node:test';
import assert from 'node:assert/strict';
import { JSDOM } from 'jsdom';

test('preview HTML strips active content while retaining safe styling', async () => {
  const dom = new JSDOM('<!doctype html><html><body></body></html>', {
    url: 'https://console.example.invalid/',
  });
  const priorWindow = Object.getOwnPropertyDescriptor(globalThis, 'window');
  const priorDocument = Object.getOwnPropertyDescriptor(globalThis, 'document');
  Object.defineProperty(globalThis, 'window', { configurable: true, value: dom.window });
  Object.defineProperty(globalThis, 'document', { configurable: true, value: dom.window.document });
  try {
    // Dynamic import ensures the sanitizer initializes after the DOM exists.
    const { sanitizeEmailHtml } = await import('../src/utils/sanitizeEmailHtml.ts');
    const hostile = `<a href="&#x6a;avascript:alert(1)">encoded</a>
      <a href="https://vendor.example/notice" target="_blank">vendor</a>
      <script>alert(1)</script>
      <img src="https://tracker.example/1x1.gif" onerror="alert(1)">
      <form action="/logout"><input name="password"></form>
      <div id="owned" class="fixed" style="position:fixed;background-image:url(https://tracker.example/x);color:red;padding:8px">safe</div>
      <table style="border-collapse:collapse"><tr><td>Advisory</td></tr></table>`;
    const cleaned = sanitizeEmailHtml(hostile);
    const container = dom.window.document.createElement('div');
    container.innerHTML = cleaned;
    const anchors = Array.from(container.querySelectorAll('a'));
    assert.equal(anchors[0]?.getAttribute('href'), null);
    assert.equal(anchors[1]?.getAttribute('href'), 'https://vendor.example/notice');
    assert.equal(anchors[1]?.getAttribute('rel'), 'noopener noreferrer');
    assert.equal(container.querySelectorAll('script,style,form,input,iframe,[onerror],[class],[id]').length, 0);
    assert.equal(container.querySelector('img')?.getAttribute('src'), null);
    const style = container.querySelector('div')?.getAttribute('style') || '';
    assert.ok(!style.includes('position'));
    assert.ok(!style.includes('url('));
    assert.ok(style.includes('padding'));
    assert.match(cleaned, /Advisory/);
  } finally {
    if (priorWindow) Object.defineProperty(globalThis, 'window', priorWindow);
    else Reflect.deleteProperty(globalThis, 'window');
    if (priorDocument) Object.defineProperty(globalThis, 'document', priorDocument);
    else Reflect.deleteProperty(globalThis, 'document');
    dom.window.close();
  }
});
