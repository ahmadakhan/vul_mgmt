import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { createPool, migrate, put, get, transaction } from '../server/db.ts';
import { loadConfig } from '../server/config.ts';
import { DEFAULT_SETTINGS } from '../shared/state.ts';
import { runVulnerabilityPipeline } from '../src/engine/pipelineEngine.ts';
import { deliverNext, enqueue } from '../server/delivery.ts';
import {
  lookupProviderDelivery,
  supportsDeliveryLookup,
} from '../server/emailProviders.ts';
import type {
  Advisory,
  EmailConfiguration,
  Finding,
  NormalizedCVE,
  WatchListItem,
} from '../src/types/index.ts';

/**
 * Provider-side confirmation of a prior delivery attempt.
 *
 * Without a lookup, a send that reached the provider but lost its commit was
 * withheld forever (a false negative) and every retry of an unknown outcome
 * risked a duplicate. The lookup resolves both directions: `delivered` never
 * re-sends, `not-delivered` retries normally.
 */

const database = process.env.TEST_DATABASE_URL;
const noNetwork = async () => {
  throw new Error('No outbound request expected');
};

const apiConfig = (provider: EmailConfiguration['provider'], overrides: Partial<EmailConfiguration> = {}) =>
  ({
    provider,
    apiKey: 'encrypted-key',
    fromEmail: 'security@example.com',
    fromName: 'Security',
    replyTo: '',
    unsubscribeUrl: '',
    mailjetApiSecret: '',
    apiEndpoint: '',
    apiSourceDomain: '',
    postmarkMessageStream: 'broadcasts',
    ...overrides,
  }) as unknown as EmailConfiguration;

test('only providers with a queryable message record are looked up', () => {
  assert.equal(supportsDeliveryLookup('SENDGRID'), true);
  assert.equal(supportsDeliveryLookup('POSTMARK'), true);
  // Mailjet and Mailtrap were added with this audit: both expose a fixed,
  // documented message-status endpoint on the same host that sends.
  assert.equal(supportsDeliveryLookup('MAILJET_API'), true);
  assert.equal(supportsDeliveryLookup('MAILTRAP'), true);
  // A custom endpoint has no known contract, so it must never be queried.
  assert.equal(supportsDeliveryLookup('API'), false);
  assert.equal(supportsDeliveryLookup('SMTP'), false);
});

test('SendGrid delivery event contract distinguishes delivered, rejection and unresolved states', async () => {
  const verdicts: Record<string, 'delivered' | 'unknown'> = {
    delivered: 'delivered', bounce: 'unknown', dropped: 'unknown', rejected: 'unknown',
    accepted: 'unknown', queued: 'unknown', processed: 'unknown', deferred: 'unknown', unknown: 'unknown',
  };
  for (const [eventName, expected] of Object.entries(verdicts)) {
    const state = await lookupProviderDelivery(apiConfig('SENDGRID'), 'token', 'msg-1', async () => ({
      status: 200,
      headers: {},
      body: JSON.stringify({ events: [{ event_name: eventName }] }),
    }));
    assert.equal(state, expected, `${eventName} must use the provider delivery contract`);
  }
});

test('SendGrid: a processed-only message is still unresolved', async () => {
  const state = await lookupProviderDelivery(apiConfig('SENDGRID'), 'token', 'msg-2', async () => ({
    status: 200,
    headers: {},
    body: JSON.stringify({ events: [{ event_name: 'processed' }] }),
  }));
  assert.equal(state, 'unknown', 'queued at the provider is not proof of delivery');
});

test('a 404 from the provider proves the message was never accepted', async () => {
  for (const provider of ['SENDGRID', 'POSTMARK'] as const) {
    const state = await lookupProviderDelivery(apiConfig(provider), 'token', 'gone', async () => ({
      status: 404,
      headers: {},
      body: '{}',
    }));
    assert.equal(state, 'not-delivered', `${provider} must allow a retry after 404`);
  }
});

test('server errors and malformed bodies are unresolved, never "not delivered"', async () => {
  for (const [status, body] of [
    [500, 'oops'],
    [200, 'not json'],
    [403, '{"error":"forbidden"}'],
  ] as const) {
    const state = await lookupProviderDelivery(apiConfig('SENDGRID'), 'token', 'msg-3', async () => ({
      status,
      headers: {},
      body,
    }));
    assert.equal(state, 'unknown', `HTTP ${status} must not authorise a resend`);
  }
});

test('Postmark delivery records map to a verdict', async () => {
 const postmark = await lookupProviderDelivery(apiConfig('POSTMARK'), 'key', 'p1', async () => ({
    status: 200,
    headers: {},
    body: JSON.stringify({ MessageID: 'p1', ErrorCode: 0 }),
  }));
  assert.equal(postmark, 'delivered');
});

test('the lookup never follows a redirect and never leaves the provider host', async () => {
  let seenRedirect = '';
  await lookupProviderDelivery(apiConfig('SENDGRID'), 'token', 'msg-4', async (_url, options) => {
    seenRedirect = String(options?.allowRedirects);
    return { status: 200, headers: {}, body: '{"events":[]}' };
  });
  assert.equal(seenRedirect, 'false', 'a redirect must not carry the provider credential elsewhere');
  // An `API` provider pointed at SendGrid is not queried through the SendGrid path.
  const custom = await lookupProviderDelivery(
    apiConfig('API', { apiEndpoint: 'https://evil.example.com/send', apiSourceDomain: 'x' }),
    'token',
    'msg-5',
    noNetwork,
  );
  assert.equal(custom, 'unknown');
});

test(
  'a withheld resend is retried once the provider confirms non-delivery',
  { skip: !database },
  async () => {
    const base = createPool(database!);
    const schema = 'confirm_' + randomBytes(8).toString('hex');
    await base.query(`CREATE SCHEMA ${schema}`);
    const url = new URL(database!);
    url.searchParams.set('options', `-c search_path=${schema},public`);
    const pool = createPool(url.href);
    const config = loadConfig({
      NODE_ENV: 'test',
      DATABASE_URL: url.href,
      APP_ORIGIN: 'http://127.0.0.1:3996',
      ENCRYPTION_KEY: randomBytes(32).toString('base64'),
      WORKER_ENABLED: 'false',
      ATTACH_ADVISORY_PDF: 'false',
      EGRESS_ALLOWED_HOSTS: 'api.sendgrid.com',
      MAIL_CONFIRM_BEFORE_SEND: 'false',
    });
    const cpe = 'cpe:2.3:a:example:widget:1.5:*:*:*:*:*:*:*';
    const asset: WatchListItem = {
      id: 'asset',
      vendor: 'example',
      product: 'widget',
      version: '1.5',
      cpes: [cpe],
      assetTag: 'EDGE-1',
      ownerGroup: 'Security',
      active: true,
      createdAt: new Date().toISOString(),
    };
    const cve: NormalizedCVE = {
      cveId: 'CVE-2026-76001',
      title: 'Fixture',
      description: 'Fixture',
      publishedDate: new Date().toISOString(),
      modifiedDate: new Date().toISOString(),
      cvss: { version: '3.1', score: 8, severity: 'HIGH', vector: '' },
      cwe: [],
      cpeMatches: [cpe],
      sourceFeeds: [],
      epss: { score: 0, percentile: 0 },
      cisaKev: { isKev: false },
      exploitStatus: 'None',
      remediation: {
        patchUrl: '',
        vendorAdvisoryRef: '',
        immediateActions: [],
        workarounds: [],
        rollbackPlan: '',
        stepByStep: [],
      },
    };
    try {
      await migrate(pool);
      await put(pool, 'settings', 'main', {
        ...DEFAULT_SETTINGS,
        autoDispatchEnabled: false,
        // The operator policy must allow retries for a retry to be possible at all.
        emailRetryEnabled: true,
        emailRetryMaxAttempts: 5,
      });
      await put(pool, 'watchlist', asset.id, asset);
      await put(pool, 'cveData', cve.cveId, cve);
      await put(pool, 'emailConfig', 'main', {
        ...apiConfig('SENDGRID', { apiKey: 'cipher' }),
      });
      await transaction(pool, async (db) => {
        const secret = (await import('../server/secrets.ts')).encrypt(
          'token',
          [config.ENCRYPTION_KEY],
          'email-provider:SENDGRID',
        );
        const stored = await get<EmailConfiguration>(db, 'emailConfig', 'main');
        await put(db, 'emailConfig', 'main', { ...stored, apiKey: secret });
      });
      const [finding] = runVulnerabilityPipeline(
        [],
        [cve],
        [asset],
        [],
        [],
        { ...DEFAULT_SETTINGS, scopeHours: 0 },
        'test',
        false,
      ).newFindings;
      assert.ok(finding);
      await put(pool, 'findings', finding.id, finding);
      const advisory: Advisory = {
        id: 'ADV-' + randomUUID().slice(0, 8),
        title: 'Notice',
        severity: 'HIGH',
        cveIds: [cve.cveId],
        findingIds: [finding.id],
        createdDate: new Date().toISOString(),
        deliveryStatus: 'PENDING',
        recipientCount: 1,
        executiveSummary: 'Fixture',
        remediationInstructions: 'Apply the update.',
        affectedSystems: [finding.matchedAssetName],
      };
      await put(pool, 'advisories', advisory.id, advisory);
      await put(pool, 'recipients', 'ops', {
        id: 'ops',
        name: 'ops',
        email: 'ops@example.invalid',
        enabled: true,
        deliveryGroup: 'SECURITY_TEAM',
        subscriptionTier: 'ALL_SEVERITIES',
      });
      const jobId = await enqueue(
        pool,
        'email',
        'ops',
        advisory.id,
        {
          subject: 'Fixture',
          text: 'Fixture',
          html: '<p>Fixture</p>',
          cveIds: [cve.cveId],
          recipientEmail: 'ops@example.invalid',
          // The provider returned this id, but the receipt was never committed.
          unconfirmedProviderId: 'sg-message-1',
        },
        'confirm-lookup',
      );
      assert.ok(jobId);
      await pool.query('UPDATE outbox SET attempts=2, review_approved=true WHERE id=$1', [jobId]);

      // Round 1: the provider reports the message with no terminal event, so the
      // outcome is unresolved and the job must be deferred, not sent or failed.
      let sent = 0;
      await deliverNext(pool, config, async (value) => {
        if (value.includes('/v3/messages/')) {
          return { status: 200, headers: {}, body: JSON.stringify({ events: [{ event_name: 'processed' }] }) };
        }
        throw new Error(`unexpected request ${value}`);
      }, async () => {
        sent++;
        return 'second-copy';
      });
      assert.equal(sent, 0, 'an unresolved outcome is never re-sent');
      assert.equal(
        (await pool.query('SELECT status FROM outbox WHERE id=$1', [jobId])).rows[0].status,
        'QUEUED',
        'an unresolved outcome stays retryable',
      );

      ;
      // Round 2: the provider now reports 404 (it never kept the message), which
      // proves the earlier attempt did not deliver and the retry may proceed.
      await pool.query('UPDATE outbox SET next_attempt=now() WHERE id=$1', [jobId]);
      await deliverNext(pool, config, async (value) => {
        if (value.includes('/v3/messages/')) return { status: 404, headers: {}, body: '{}' };
        throw new Error(`unexpected request ${value}`);
      }, async () => {
        sent++;
        return 'accepted-after-confirmation';
      });
      assert.equal(sent, 1, 'a confirmed non-delivery is retried');
      assert.equal(
        (await pool.query('SELECT status FROM outbox WHERE id=$1', [jobId])).rows[0].status,
        'ACCEPTED',
      );

    } finally {
      await pool.end();
      await base.query(`DROP SCHEMA ${schema} CASCADE`);
      await base.end();
    }
  },
);
