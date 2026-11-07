import { randomBytes } from 'node:crypto';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { searchNvdCpes, loadNvdApiKey, isNvdRateLimitError, nvdRetryAfterSeconds } from '../server/cpeSearch';
import type { RequestOptions, Requester } from '../server/network';
import { loadConfig } from '../server/config';
import { encrypt } from '../server/secrets';

const config = loadConfig({
  NODE_ENV: 'test',
  DATABASE_URL: 'postgres://unused',
  APP_ORIGIN: 'http://localhost',
  ENCRYPTION_KEY: randomBytes(32).toString('base64'),
});

test('searchNvdCpes parses verified NVD CPE configurations and forwards the API key', async () => {
  const calls: { url: string; options: RequestOptions | undefined }[] = [];
  const requester: Requester = async (url, options) => {
    calls.push({ url, options });
    return {
      status: 200,
      body: JSON.stringify({
        totalResults: 3,
        products: [
          {
            cpe: {
              cpeName: 'cpe:2.3:a:microsoft:windows_10:10.0.19041:*:*:*:*:*:*:*',
              cpeNameId: 'id-1',
              titles: [{ title: 'Windows 10' }],
            },
          },
          {
            cpe: {
              cpeName: 'cpe:2.3:o:microsoft:windows_server_2022:20348:*:*:*:*:*:x64:*',
              cpeNameId: 'id-2',
            },
          },
          { cpe: { cpeName: 'not-a-cpe', cpeNameId: 'id-3' } },
        ],
      }),
      headers: {},
    };
  };

  const { results, totalResults } = await searchNvdCpes(
    requester,
    'secret-key',
    'microsoft',
    'windows_10',
    50,
  );

  // First call is the keyword search; second is the wildcard-vendor cpeMatchString search.
  assert.equal(calls.length, 2);
  const keywordUrl = new URL(calls[0].url);
  const wildcardUrl = new URL(calls[1].url);

  assert.equal(keywordUrl.origin + keywordUrl.pathname, 'https://services.nvd.nist.gov/rest/json/cpes/2.0');
  assert.equal(keywordUrl.searchParams.get('keywordSearch'), 'microsoft windows 10');
  assert.equal(wildcardUrl.searchParams.get('cpeMatchString'), 'cpe:2.3:*:*:windows_10:*:*:*:*:*:*:*:*');
  assert.equal(wildcardUrl.searchParams.has('keywordSearch'), false);

  // Both calls forward the API key in headers (never in the URL).
  for (const entry of calls) {
    assert.equal(entry.options?.headers?.apiKey, 'secret-key');
    assert.equal(entry.options?.sameHostRedirects, true);
  }

  // Keyword search returns 2 valid CPEs; wildcard search returns the same
  // CPEs which are deduplicated against the seen-set.
  assert.equal(results.length, 2);
  // totalResults is the sum of both NVD responses.
  assert.equal(totalResults, 6);
  assert.equal(results[0].cpeName, 'cpe:2.3:a:microsoft:windows_10:10.0.19041:*:*:*:*:*:*:*');
  assert.equal(results[0].part, 'a');
  assert.equal(results[0].vendor, 'microsoft');
  assert.equal(results[0].product, 'windows_10');
  assert.equal(results[0].version, '10.0.19041');
  assert.equal(results[0].targetHw, '*');
  assert.equal(results[0].title, 'Windows 10');
  assert.equal(results[1].part, 'o');
});

test('searchNvdCpes omits the API key and falls back to public rate budget', async () => {
  const calls: { url: string; options: RequestOptions | undefined }[] = [];
  const requester: Requester = async (url, options) => {
    calls.push({ url, options });
    return { status: 200, body: JSON.stringify({ totalResults: 0, products: [] }), headers: {} };
  };

  const { results } = await searchNvdCpes(requester, '', 'cisco', 'ios', 20);

  assert.equal(results.length, 0);
  // Two calls: keyword search + wildcard-vendor cpeMatchString search.
  assert.equal(calls.length, 2);
  const keywordUrl = new URL(calls[0].url);
  const wildcardUrl = new URL(calls[1].url);

  assert.ok(!keywordUrl.searchParams.has('apiKey'), 'should not append an apiKey when none configured');
  assert.equal(keywordUrl.searchParams.get('keywordSearch'), 'cisco ios');
  assert.equal(keywordUrl.searchParams.get('resultsPerPage'), '20');

  assert.equal(wildcardUrl.searchParams.get('cpeMatchString'), 'cpe:2.3:*:*:ios:*:*:*:*:*:*:*:*');
  assert.equal(wildcardUrl.searchParams.get('resultsPerPage'), '20');
});

test('searchNvdCpes surfaces NVD rate-limit errors with retry-after guidance', async () => {
  const requester: Requester = async () => ({
    status: 429,
    body: '',
    headers: { 'retry-after': '45' },
  });

  let thrown: unknown;
  try {
    await searchNvdCpes(requester, '', 'vendor', 'product', 10);
  } catch (error) {
    thrown = error;
  }
  assert.ok(thrown, 'expected searchNvdCpes to reject on NVD 429');
  assert.equal(isNvdRateLimitError(thrown), true);
  assert.equal(nvdRetryAfterSeconds(thrown as never), 45);
});

test('searchNvdCpes throws on non-JSON or unexpected NVD responses', async () => {
  const requester: Requester = async () => ({ status: 200, body: '<html>error page</html>', headers: {} });
  await assert.rejects(searchNvdCpes(requester, '', 'vendor', 'product', 10), /non-JSON/);

  const requester500: Requester = async () => ({ status: 500, body: '', headers: {} });
  await assert.rejects(searchNvdCpes(requester500, '', 'vendor', 'product', 10), /HTTP 500/);
});

test('loadNvdApiKey decrypts the configured NVD feed key', async () => {
  const secret = encrypt('nvd-real-key', [config.ENCRYPTION_KEY], 'feed:feed-nvd');
  const db = {
    query: async () => ({
      rows: [
        {
          data: {
            id: 'feed-nvd',
            type: 'NVD_API',
            authType: 'API_KEY',
            enabled: true,
            authSecretKey: secret,
          },
        },
      ],
    }),
  } as unknown as Parameters<typeof loadNvdApiKey>[0];

  assert.equal(await loadNvdApiKey(db, config), 'nvd-real-key');
});

test('loadNvdApiKey returns empty when no NVD key is configured', async () => {
  const db = {
    query: async () => ({
      rows: [
        { data: { id: 'feed-mitre', type: 'MITRE_CVE', authType: 'NONE', enabled: true, authSecretKey: '' } },
      ],
    }),
  } as unknown as Parameters<typeof loadNvdApiKey>[0];

  assert.equal(await loadNvdApiKey(db, config), '');
});

test('an invalid key retries once without credentials using the same CPE query', async () => {
  const calls: { url: string; options: RequestOptions | undefined }[] = [];
  const requester: Requester = async (url, options) => {
    calls.push({ url, options });
    if (calls.length === 1) return { status: 404, body: '', headers: { message: 'Invalid apiKey.' } };
    return { status: 200, body: JSON.stringify({ totalResults: 0, products: [] }), headers: {} };
  };
  assert.deepEqual(
    await searchNvdCpes(requester, 'expired-key', 'Cisco', 'adaptive_security_appliance', 50),
    { results: [], totalResults: 0 },
  );
  // Three calls: keyword search (404 → retry), keyword search retry, wildcard vendor search.
  assert.equal(calls.length, 3);
  assert.equal(calls[0].url, calls[1].url, 'keyword search retry uses same URL');
  assert.equal(calls[0].options?.headers?.apiKey, 'expired-key');
  assert.equal(calls[1].options?.headers?.apiKey, undefined);
  assert.equal(calls[2].options?.headers?.apiKey, undefined, 'wildcard search also uses the effective key');
  assert.equal(new URL(calls[0].url).searchParams.get('keywordSearch'), 'Cisco adaptive security appliance');
  assert.equal(
    new URL(calls[2].url).searchParams.get('cpeMatchString'),
    'cpe:2.3:*:*:adaptive_security_appliance:*:*:*:*:*:*:*:*',
  );
});

test('a genuine 404 is an upstream error rather than an empty dictionary result', async () => {
  for (const apiKey of ['', 'configured-key']) {
    let calls = 0;
    const requester: Requester = async () => {
      calls++;
      return { status: 404, body: '', headers: { message: 'Invalid parameter: unsupported.' } };
    };
    await assert.rejects(searchNvdCpes(requester, apiKey, 'vendor', 'product', 50), /HTTP 404/);
    assert.equal(calls, 1);
  }
});

test('a public fallback preserves rate-limit guidance and never repeats indefinitely', async () => {
  let calls = 0;
  const requester: Requester = async () =>
    ++calls === 1
      ? { status: 404, body: '', headers: { message: 'Invalid apiKey.' } }
      : { status: 429, body: '', headers: { 'retry-after': '30' } };
  await assert.rejects(
    searchNvdCpes(requester, 'bad-key', 'vendor', 'product', 50),
    (error: unknown) => isNvdRateLimitError(error) && nvdRetryAfterSeconds(error) === 30,
  );
  assert.equal(calls, 2);
});

test('malformed JSON payloads cannot masquerade as zero matching CPEs', async () => {
  for (const data of [
    {},
    { products: [] },
    { products: [], totalResults: -1 },
    { products: null, totalResults: 0 },
  ]) {
    const requester: Requester = async () => ({ status: 200, body: JSON.stringify(data), headers: {} });
    await assert.rejects(
      searchNvdCpes(requester, '', 'vendor', 'product', 50),
      /invalid CPE search response/,
    );
  }
});

test('exact CPE verification queries cpeMatchString and excludes deprecated or different names', async () => {
  const name = 'cpe:2.3:a:example:widget:1.0:*:*:*:*:*:*:*';
  let requested = '';
  const requester: Requester = async (url) => {
    requested = url;
    return {
      status: 200,
      headers: {},
      body: JSON.stringify({
        totalResults: 3,
        products: [
          { cpe: { cpeName: name, cpeNameId: 'active-id', deprecated: false } },
          { cpe: { cpeName: name, cpeNameId: 'deprecated-id', deprecated: true } },
          { cpe: { cpeName: name.replace(':1.0:', ':2.0:'), deprecated: false } },
        ],
      }),
    };
  };
  const result = await searchNvdCpes(requester, '', '', '', 200, name);
  const url = new URL(requested);
  assert.equal(url.searchParams.get('cpeMatchString'), name);
  assert.equal(url.searchParams.has('keywordSearch'), false);
  assert.deepEqual(
    result.results.map((entry) => entry.cpeNameId),
    ['active-id'],
  );
});

test('normal CPE search never offers deprecated entries as verified selections', async () => {
  const requester: Requester = async () => ({
    status: 200,
    headers: {},
    body: JSON.stringify({
      totalResults: 1,
      products: [{ cpe: { cpeName: 'cpe:2.3:a:example:widget:1.0:*:*:*:*:*:*:*', deprecated: true } }],
    }),
  });
  const result = await searchNvdCpes(requester, '', 'example', 'widget', 50);
  assert.deepEqual(result.results, []);
});

test('dictionary IDs verify wildcard CPE names without relying on a truncated match page', async () => {
  const name = 'cpe:2.3:a:example:widget:*:*:*:*:*:*:*:*';
  const id = '00000000-0000-4000-8000-000000000001';
  let requested = '';
  const requester: Requester = async (url) => {
    requested = url;
    return {
      status: 200,
      headers: {},
      body: JSON.stringify({
        totalResults: 1,
        products: [{ cpe: { cpeName: name, cpeNameId: id, deprecated: false } }],
      }),
    };
  };
  const result = await searchNvdCpes(requester, '', '', '', 200, name, id);
  const url = new URL(requested);
  assert.equal(url.searchParams.get('cpeNameId'), id);
  assert.equal(url.searchParams.has('cpeMatchString'), false);
  assert.deepEqual(
    result.results.map((entry) => entry.cpeName),
    [name],
  );
});

test('wildcard vendor search escapes special characters in the product name for cpeMatchString', async () => {
  const calls: { url: string; options: RequestOptions | undefined }[] = [];
  const requester: Requester = async (url, options) => {
    calls.push({ url, options });
    if (calls.length <= 1) {
      // Keyword search returns no results for the bogus vendor label.
      return { status: 200, body: JSON.stringify({ totalResults: 0, products: [] }), headers: {} };
    }
    // Wildcard-vendor cpeMatchString search returns the real NVD entry.
    return {
      status: 200,
      headers: {},
      body: JSON.stringify({
        totalResults: 1,
        products: [
          {
            cpe: {
              cpeName: 'cpe:2.3:a:don_ho:notepad\\+\\+:5.5:*:*:*:*:*:*:*',
              cpeNameId: 'notepadpp-id',
              deprecated: false,
              titles: [{ title: 'Notepad++ 5.5' }],
            },
          },
        ],
      }),
    };
  };

  const { results, totalResults } = await searchNvdCpes(
    requester,
    '',
    'notepad_plus_plus',
    'notepad++',
    50,
  );

  // Two calls: keyword search + wildcard-vendor cpeMatchString search.
  assert.equal(calls.length, 2);

  // The wildcard search escapes "+" as "\(" so the NVD API can match
  // against the dictionary entry that stores "notepad\+\+".
  const wildcardUrl = new URL(calls[1].url);
  assert.equal(wildcardUrl.searchParams.get('cpeMatchString'), 'cpe:2.3:*:*:notepad\\+\\+:*:*:*:*:*:*:*:*');
  assert.equal(wildcardUrl.searchParams.has('keywordSearch'), false);

  // The NVD-verified CPE (vendor "don_ho") is included in results even
  // though the operator's vendor label was "notepad_plus_plus".
  assert.equal(results.length, 1);
  assert.equal(results[0].cpeName, 'cpe:2.3:a:don_ho:notepad\\+\\+:5.5:*:*:*:*:*:*:*');
  assert.equal(results[0].vendor, 'don_ho');
  assert.equal(results[0].product, 'notepad\\+\\+');
  assert.equal(results[0].title, 'Notepad++ 5.5');
  assert.equal(totalResults, 1);
});

test('wildcard vendor search is skipped for exact CPE verification', async () => {
  const calls: { url: string; options: RequestOptions | undefined }[] = [];
  const requester: Requester = async (url, options) => {
    calls.push({ url, options });
    return {
      status: 200,
      headers: {},
      body: JSON.stringify({
        totalResults: 1,
        products: [
          { cpe: { cpeName: 'cpe:2.3:a:example:widget:1.0:*:*:*:*:*:*:*', cpeNameId: 'exact-id', deprecated: false } },
        ],
      }),
    };
  };

  await searchNvdCpes(requester, '', '', '', 200, 'cpe:2.3:a:example:widget:1.0:*:*:*:*:*:*:*');
  // Only the cpeMatchString exact-lookup call is made; no wildcard search.
  assert.equal(calls.length, 1);
  const url = new URL(calls[0].url);
  assert.equal(url.searchParams.get('cpeMatchString'), 'cpe:2.3:a:example:widget:1.0:*:*:*:*:*:*:*');
  assert.equal(url.searchParams.has('keywordSearch'), false);
});
