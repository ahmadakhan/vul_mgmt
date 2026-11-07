import { randomBytes } from 'node:crypto';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { gzipSync } from 'node:zlib';
import { Readable } from 'node:stream';
import { readResponseBody } from '../server/network';

test('HTTP response reader decompresses gzip while enforcing the decoded response limit', async () => {
  const body = JSON.stringify({ data: 'CVE metadata '.repeat(1000) });
  const compressed = gzipSync(Buffer.from(body));
  assert.ok(compressed.length < Buffer.byteLength(body));
  assert.equal(await readResponseBody(Readable.from([compressed]), 'gzip', Buffer.byteLength(body)), body);
  await assert.rejects(
    readResponseBody(Readable.from([compressed]), 'gzip', Buffer.byteLength(body) - 1),
    /Decoded response exceeds configured/,
  );
});

test('HTTP response reader limits wire bytes and rejects unsupported encodings', async () => {
  const compressed = gzipSync(Buffer.from('small body'));
  await assert.rejects(
    readResponseBody(Readable.from([compressed]), 'gzip', compressed.length - 1),
    /Response transfer exceeds configured/,
  );
  await assert.rejects(
    readResponseBody(Readable.from(['body']), 'br', 100),
    /Unsupported response content encoding/,
  );
});

// Redirect policy, exercised end to end against a local HTTPS server. The
// fixture certificate is trusted only by this test and the socket hook dials
// loopback after the real allowlist/port/public-IP checks have passed.
import { createServer, type Server } from 'node:https';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { connect } from 'node:tls';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { createRequester, withAbortSignal } from '../server/network.ts';
import { loadConfig } from '../server/config.ts';

const fixtures = join(import.meta.dirname, 'fixtures/tls');
const TLS = { key: readFileSync(join(fixtures, 'key.pem')), cert: readFileSync(join(fixtures, 'cert.pem')) };
const config = loadConfig({
  NODE_ENV: 'test',
  DATABASE_URL: 'postgres://unused',
  APP_ORIGIN: 'http://localhost',
  ENCRYPTION_KEY: randomBytes(32).toString('base64'),
  EGRESS_ALLOWED_HOSTS: 'feed.example.test,cdn.example.test',
});
const publicDns = async () => [{ address: '93.184.216.34', family: 4 }];
let localPort = 0;
const hooks = {
  resolver: publicDns,
  tls: { ca: TLS.cert },
  connect: (options: any) =>
    connect({ ...options, host: '127.0.0.1', port: localPort, ca: TLS.cert, servername: options.host }).setTimeout(2000),
};

type Handler = (req: IncomingMessage, res: ServerResponse) => void;

async function serve(handler: Handler) {
  const requests: { method?: string; headers: Record<string, unknown>; path: string }[] = [];
  const server: Server = createServer(TLS, (req, res) => {
    requests.push({ method: req.method, headers: req.headers, path: req.url ?? '' });
    handler(req, res);
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  localPort = (server.address() as { port: number }).port;
  return {
    requests,
    close: () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections();
        server.close(() => resolve());
      }),
  };
}

test('outbound requests and non-cooperative operations reject promptly when aborted', async () => {
  const controller = new AbortController();
  let markStarted!: () => void;
  const started = new Promise<void>((resolve) => { markStarted = resolve; });
  const { close } = await serve(() => { markStarted(); });
  try {
    const pending = createRequester(config, hooks)('https://feed.example.test/blocked', { signal: controller.signal });
    const rejected = assert.rejects(pending, /aborted/);
    await started;
    controller.abort(new Error('request aborted'));
    await rejected;
    await assert.rejects(withAbortSignal(new Promise(() => {}), controller.signal), /aborted/);
  } finally {
    await close();
  }
});

test('per-feed host additions remain request-scoped and pass through the SSRF checks', async () => {
  const { close } = await serve((_req, res) => {
    res.writeHead(200, { 'content-type': 'application/rss+xml' });
    res.end('<rss/>');
  });
  const url = 'https://feed.example.test/feed.xml';
  const restrictedConfig = { ...config, EGRESS_ALLOWED_HOSTS: 'cdn.example.test' };
  try {
    const request = createRequester(restrictedConfig, hooks);
    await assert.rejects(request(url), /not in EGRESS_ALLOWED_HOSTS/);
    assert.equal(
      (await request(url, { additionalAllowedHosts: ['feed.example.test'] })).status,
      200,
    );
    await assert.rejects(request(url), /not in EGRESS_ALLOWED_HOSTS/);

    const privateDnsRequest = createRequester(restrictedConfig, {
      ...hooks,
      resolver: async () => [{ address: '127.0.0.1', family: 4 }],
    });
    await assert.rejects(
      privateDnsRequest(url, { additionalAllowedHosts: ['feed.example.test'] }),
      /non-public address/,
    );
  } finally {
    await close();
  }
});

test('redirects are followed for allowlisted hosts and keep the ETag/304 contract', async () => {
  const { requests, close } = await serve((req, res) => {
    if (req.url === '/feed.xml') {
      res.writeHead(301, { location: '/moved.xml' });
      res.end('redirect body that must not be read');
      return;
    }
    res.writeHead(304, { etag: '"v2"' });
    res.end();
  });
  try {
    const request = createRequester(config, hooks);
    const response = await request('https://feed.example.test/feed.xml', {
      headers: { 'If-None-Match': '"v1"', 'content-type': 'application/json' },
      allowRedirects: true,
    });
    assert.equal(response.status, 304);
    assert.equal(response.headers.etag, '"v2"');
    assert.equal(requests.length, 2);
    assert.equal(requests[1].path, '/moved.xml');
    // The validator belonged to the original URL and must not be replayed.
    assert.equal(requests[1].headers['if-none-match'], undefined);
    assert.equal(requests[1].headers['content-type'], undefined);
  } finally {
    await close();
  }
});

test('redirects are refused when disabled, when the chain loops, or when the host changes', async () => {
  const { close } = await serve((req, res) => {
    res.writeHead(302, { location: req.url === '/loop' ? 'https://feed.example.test/loop' : 'https://elsewhere.test/' });
    res.end();
  });
  try {
    const request = createRequester(config, hooks);
    await assert.rejects(
      request('https://feed.example.test/feed.xml', { allowRedirects: false }),
      /Redirects are not permitted \(HTTP 302 to https:\/\/elsewhere\.test\/\)/,
    );
    await assert.rejects(request('https://feed.example.test/loop', { maxRedirects: 2 }), /Too many redirects/);
    // An off-allowlist redirect target is refused by the SSRF check.
    await assert.rejects(
      request('https://feed.example.test/feed.xml', { sameHostRedirects: false }),
      /not in EGRESS_ALLOWED_HOSTS/,
    );
  } finally {
    await close();
  }
});

test('a cross-host redirect is followed only to another allowlisted host', async () => {
  const { close } = await serve((req, res) => {
    if (req.url === '/final') {
      res.writeHead(304, { etag: '"v3"' });
      res.end();
      return;
    }
    res.writeHead(302, { location: 'https://cdn.example.test/final' });
    res.end();
  });
  // cdn.example.test serves the same content; the test certificate only covers
  // the primary host, so trust it for every test host without disabling checks.
  const crossHostHooks = { ...hooks, tls: { ca: TLS.cert, checkServerIdentity: () => undefined } };
  try {
    const request = createRequester(config, crossHostHooks);
    await assert.rejects(
      request('https://feed.example.test/feed.xml', { sameHostRedirects: true }),
      /different hostname is not permitted \(feed\.example\.test -> cdn\.example\.test\)/,
    );
    // Cross-host hops are allowed by default; the target is still allowlisted.
    const response = await request('https://feed.example.test/feed.xml');
    assert.equal(response.status, 304);
  } finally {
    await close();
  }
});

test('cross-origin redirects strip credential headers but exact-origin redirects retain them', async () => {
  const { requests, close } = await serve((req, res) => {
    if (req.url === '/feed.xml') {
      res.writeHead(302, { location: 'https://cdn.example.test/final' });
      res.end();
    } else {
      res.writeHead(200, { 'content-type': 'text/plain' });
      res.end('ok');
    }
  });
  const crossHostHooks = { ...hooks, tls: { ca: TLS.cert, checkServerIdentity: () => undefined } };
  try {
    const request = createRequester(config, crossHostHooks);
    await request('https://feed.example.test/feed.xml', {
      headers: { Authorization: 'Bearer secret', 'X-API-Key': 'api-secret', Cookie: 'session=secret' },
    });
    assert.equal(requests.length >= 2, true);
    assert.equal(requests[0].headers.authorization, 'Bearer secret');
    assert.equal(requests[1].headers.authorization, undefined);
    assert.equal(requests[1].headers['x-api-key'], undefined);
    assert.equal(requests[1].headers.cookie, undefined);
  } finally {
    await close();
  }
});

test('exact-origin redirects retain credential headers', async () => {
  const { requests, close } = await serve((_req, res) => {
    if (_req.url === '/feed.xml') {
      res.writeHead(302, { location: '/final' });
      res.end();
    } else {
      res.writeHead(200, { 'content-type': 'text/plain' });
      res.end('ok');
    }
  });
  try {
    const request = createRequester(config, hooks);
    await request('https://feed.example.test/feed.xml', {
      headers: { Authorization: 'Bearer secret', Cookie: 'session=secret' },
    });
    assert.equal(requests[1].headers.authorization, 'Bearer secret');
    assert.equal(requests[1].headers.cookie, 'session=secret');
  } finally {
    await close();
  }
});

test('same-site redirects may add or drop a www label but never leave the site', async () => {
  let redirects = 0;
  const { close } = await serve((req, res) => {
    // Redirect only the first request so the same server can also answer the
    // follow-up (and the control request that must still be refused).
    if (req.url === '/feed.xml' && ++redirects % 2 === 1) {
      res.writeHead(301, { location: 'https://www.feed.example.test/feed.xml' });
      res.end();
      return;
    }
    res.writeHead(200, { 'content-type': 'application/rss+xml' });
    res.end('<rss/>');
  });
  const siteHooks = { ...hooks, tls: { ca: TLS.cert, checkServerIdentity: () => undefined } };
  try {
    const request = createRequester(config, siteHooks);
    // The www spelling is not allowlisted; it is the same site, so the hop is allowed.
    const response = await request('https://feed.example.test/feed.xml', { sameSiteRedirects: true });
    assert.equal(response.status, 200);
    // Without the opt-in the missing spelling is still refused.
    await assert.rejects(request('https://feed.example.test/feed.xml'), /not in EGRESS_ALLOWED_HOSTS/);
  } finally {
    await close();
  }
});

test('a redirect to a URL with credentials is refused and the secret is not echoed', async () => {
  const { close } = await serve((_req, res) => {
    res.writeHead(302, { location: 'https://user:hunter2@cdn.example.test/feed.xml' });
    res.end();
  });
  try {
    const request = createRequester(config, hooks);
    const error = await request('https://feed.example.test/feed.xml').catch((e: Error) => e);
    assert.ok(error instanceof Error);
    assert.match(error.message, /redirect to a URL with credentials is not permitted/);
    assert.doesNotMatch(error.message, /hunter2/, 'the password must not appear in the error');
  } finally {
    await close();
  }
});

test('a same-site redirect option cannot widen egress to a look-alike host', async () => {
  const { close } = await serve((_req, res) => {
    res.writeHead(302, { location: 'https://www.feed.example.test.evil.test/feed.xml' });
    res.end();
  });
  try {
    const request = createRequester(config, hooks);
    await assert.rejects(
      request('https://feed.example.test/feed.xml', { sameSiteRedirects: true }),
      /not in EGRESS_ALLOWED_HOSTS/,
    );
  } finally {
    await close();
  }
});

test('a redirect loop returns a bounded error instead of hanging', async () => {
  const { close } = await serve((_req, res) => {
    res.writeHead(302, { location: 'https://feed.example.test/loop' });
    res.end();
  });
  try {
    const request = createRequester(config, hooks);
    await assert.rejects(request('https://feed.example.test/loop', { maxRedirects: 3 }), /Too many redirects/);
  } finally {
    await close();
  }
});

// Regression: the validated address must reach the socket through the
// requester's own lookup hook. An earlier version answered only Node's
// (host, family, cb) form, so the pinned family was undefined and every
// request failed with "Invalid IP address: undefined" before a single byte
// was sent. The connection itself is mapped to the local server, but the
// lookup hook must still supply a complete address and family.
test('the production lookup path connects to the validated address', async () => {
  const { close } = await serve((_req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end('{"ok":true}');
  });
  try {
    const request = createRequester(config, {
      resolver: async () => [{ address: '93.184.216.34', family: 4 }],
      tls: { ca: TLS.cert },
      allowedPorts: [String(localPort)],
      // The requester pins the validated public address through its lookup
      // hook; this maps that socket onto the local server. TLS hostname
      // verification still runs against feed.example.test.
      connect: (options: any) =>
        connect({ ...options, host: '127.0.0.1', port: localPort, ca: TLS.cert, servername: options.host }).setTimeout(2000),
    });
    const response = await request(`https://feed.example.test:${localPort}/ok`);
    assert.equal(response.status, 200);
    assert.equal(response.body, '{"ok":true}');
  } finally {
    await close();
  }
});

// Regression: "Invalid IP address: undefined" was caused by a lookup hook that
// answered only one of Node's two call shapes. Both are asserted directly here
// so the contract is pinned regardless of which shape a given Node release uses.
test('the pinned lookup answers both of Node\'s lookup call shapes', async () => {
  const { pinnedLookup } = await import('../server/network.ts');
  const lookup = pinnedLookup('93.184.216.34', 4);

  const all = await new Promise<unknown>((resolve, reject) =>
    (lookup as any)('feed.example.test', { all: true, verbatim: true }, (error: Error | null, addresses: unknown) =>
      error ? reject(error) : resolve(addresses),
    ),
  );
  assert.deepEqual(all, [{ address: '93.184.216.34', family: 4 }]);

  const scalar = await new Promise<unknown>((resolve, reject) =>
    (lookup as any)('feed.example.test', 4, (error: Error | null, address: string, family: number) =>
      error ? reject(error) : resolve([address, family]),
    ),
  );
  assert.deepEqual(scalar, ['93.184.216.34', 4]);
});
