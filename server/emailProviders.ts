import { randomUUID } from 'node:crypto';
import { isSmtpEmailProvider, type EmailConfiguration, type EmailDeliveryLog } from '../src/types/index.ts';
import type { EmailAttachment, Job } from './delivery';
import type { Requester } from './network';

export const EMAIL_PROVIDER_LABELS: Record<EmailConfiguration['provider'], EmailDeliveryLog['provider']> = {
  SMTP: 'SMTP_Relay',
  API: 'Custom API',
  SMTP_CUSTOM: 'SMTP_Relay',
  GMAIL_SMTP: 'SMTP_Relay',
  MAILEROO_SMTP: 'SMTP_Relay',
  LETTR_SMTP: 'SMTP_Relay',
  MAILJET_SMTP: 'SMTP_Relay',
  SENDGRID_SMTP: 'SMTP_Relay',
  MAILTRAP: 'Mailtrap',
  SENDGRID: 'SendGrid',
  POSTMARK: 'Postmark',
  MAILJET_API: 'Mailjet',
};
export function emailEndpoint(config: EmailConfiguration): string | null {
  switch (config.provider) {
    case 'API':
      return config.apiEndpoint.replaceAll('{domain}', encodeURIComponent(config.apiSourceDomain));
    case 'MAILTRAP':
      return config.mailtrapMode === 'SANDBOX'
        ? `https://sandbox.api.mailtrap.io/api/send/${encodeURIComponent(config.mailtrapInboxId)}`
        : 'https://send.api.mailtrap.io/api/send';
    case 'SENDGRID':
      return 'https://api.sendgrid.com/v3/mail/send';
    case 'POSTMARK':
      return 'https://api.postmarkapp.com/email';
    case 'MAILJET_API':
      return 'https://api.mailjet.com/v3.1/send';
    default:
      return null;
  }
}
export function emailIsConfigured(
  config: EmailConfiguration,
  env: { SMTP_HOST: string; SMTP_FROM: string; EGRESS_ALLOWED_HOSTS?: string },
): boolean {
  // `API` is a custom HTTP endpoint, never an SMTP relay. The old form treated it
  // as one, so a deployment with no SMTP host reported the provider as
  // unconfigured while the delivery worker silently fell back to SMTP.
  if (config.provider === 'API') return !!config.apiEndpoint && !!config.fromEmail && !!config.apiKey;
  if (config.provider === 'SMTP' && !config.smtpHost)
    return !!env.SMTP_HOST && !!(config.fromEmail || env.SMTP_FROM);
  if (isSmtpEmailProvider(config.provider)) {
    const allowedHosts = (env.EGRESS_ALLOWED_HOSTS || '').split(',').map((host) => host.trim().toLowerCase());
    const needsAuth = config.provider !== 'SMTP_CUSTOM' && config.provider !== 'SMTP';
    return (
      !!(config.fromEmail || (config.provider === 'SMTP' && env.SMTP_FROM)) &&
      !!config.smtpHost &&
      allowedHosts.includes(config.smtpHost.toLowerCase()) &&
      (!needsAuth || (!!config.smtpUsername && !!config.smtpPassword)) &&
      (needsAuth || !!config.smtpUsername === !!config.smtpPassword)
    );
  }
  return (
    !!config.fromEmail &&
    !!config.apiKey &&
    (config.provider !== 'MAILTRAP' || config.mailtrapMode !== 'SANDBOX' || !!config.mailtrapInboxId) &&
    (config.provider !== 'MAILJET_API' || !!config.mailjetApiSecret)
  );
}
export class EmailProviderError extends Error {
  status: number;
  retryAt: number;
  provider?: EmailDeliveryLog['provider'];
  constructor(message: string, status: number, retryAt = 0, provider?: EmailDeliveryLog['provider']) {
    super(message);
    this.status = status;
    this.retryAt = retryAt;
    this.provider = provider;
  }
}

/** Fixed provider endpoints use the same DNS-pinned, allowlisted HTTPS client as feeds. */
export async function sendProviderEmail(
  config: EmailConfiguration,
  token: string,
  job: Job,
  request: Requester,
  sandboxMode = false,
  attachments: EmailAttachment[] = [],
): Promise<string> {
  const endpoint = emailEndpoint(config);
  if (!endpoint) throw new Error('Select an API email provider');
  if (!job.payload.recipientEmail) throw new Error('Email recipient is missing');
  const from = config.fromName
    ? `${JSON.stringify(config.fromName)} <${config.fromEmail}>`
    : config.fromEmail;
  const headers: Record<string, string> = {
    'content-type': 'application/json',
    [config.provider === 'API' ? config.apiHeaderKey : 'Authorization']:
      `${config.provider === 'API' ? config.apiAuthPrefix : 'Bearer'}${config.provider === 'API' && !config.apiAuthPrefix ? '' : ' '}${token}`,
  };
  const { subject, text, html, recipientEmail } = job.payload;
  const recipients = recipientEmail.split(',').map((e) => e.trim()).filter(Boolean);
  if (!recipients.length) throw new Error('Email recipient is missing');
  const deliveryHeader = {
    'X-BA-Threat-Intel-Delivery-ID': job.id,
    'Auto-Submitted': 'auto-generated',
  };
  const oneClickUnsubscribe = /^https?:\/\//i.test(config.unsubscribeUrl || '');
  const unsubscribeHeader = config.unsubscribeUrl
    ? {
        'List-Unsubscribe': config.unsubscribeUrl,
        ...(oneClickUnsubscribe
          ? { 'List-Unsubscribe-Post': 'List-Unsubscribe=One-Click' }
          : {}),
      }
    : {};
  const encodedAttachments = attachments.map((item) => ({
    filename: item.filename,
    content: item.content.toString('base64'),
    type: item.contentType,
  }));
  let body: string;
  if (config.provider === 'API') {
    body = JSON.stringify({
      from: { email: config.fromEmail, ...(config.fromName ? { name: config.fromName } : {}) },
      to: recipients.map((email) => ({ email })),
      subject,
      text,
      ...(html ? { html } : {}),
      ...(config.replyTo ? { reply_to: { email: config.replyTo } } : {}),
      ...(encodedAttachments.length ? { attachments: encodedAttachments } : {}),
      headers: { ...deliveryHeader, ...unsubscribeHeader },
    });
  } else if (config.provider === 'SENDGRID') {
    body = JSON.stringify({
      personalizations: [
        {
          to: recipients.map((email) => ({ email })),
          custom_args: { delivery_id: job.id },
        },
      ],
      from: { email: config.fromEmail, ...(config.fromName ? { name: config.fromName } : {}) },
      subject,
      headers: { ...deliveryHeader, ...unsubscribeHeader },
      ...(config.replyTo ? { reply_to: { email: config.replyTo } } : {}),
      content: [{ type: 'text/plain', value: text }, ...(html ? [{ type: 'text/html', value: html }] : [])],
      ...(encodedAttachments.length
        ? { attachments: encodedAttachments.map((item) => ({ ...item, disposition: 'attachment' })) }
        : {}),
    });
  } else if (config.provider === 'POSTMARK') {
    delete headers.Authorization;
    headers['X-Postmark-Server-Token'] = token;
    body = JSON.stringify({
      From: from,
      To: recipients.join(', '),
      Subject: subject,
      TextBody: text,
      ...(config.replyTo ? { ReplyTo: config.replyTo } : {}),
      ...(html ? { HtmlBody: html } : {}),
      ...(encodedAttachments.length
        ? { Attachments: encodedAttachments.map((item) => ({
            Name: item.filename, Content: item.content, ContentType: item.type,
          })) }
        : {}),
      MessageStream: config.postmarkMessageStream,
      Metadata: { delivery_id: job.id },
      Headers: [
        { Name: 'X-BA-Threat-Intel-Delivery-ID', Value: job.id },
        { Name: 'Auto-Submitted', Value: 'auto-generated' },
        ...(config.unsubscribeUrl
          ? [
              { Name: 'List-Unsubscribe', Value: config.unsubscribeUrl },
              ...(oneClickUnsubscribe
                ? [{ Name: 'List-Unsubscribe-Post', Value: 'List-Unsubscribe=One-Click' }]
                : []),
            ]
          : []),
      ],
    });
  } else if (config.provider === 'MAILJET_API') {
    delete headers.Authorization;
    headers.Authorization = `Basic ${Buffer.from(`${token}:${config.mailjetApiSecret}`).toString('base64')}`;
    body = JSON.stringify({
      SandboxMode: sandboxMode,
      Messages: [
        {
          From: { Email: config.fromEmail, ...(config.fromName ? { Name: config.fromName } : {}) },
          To: recipients.map((email) => ({ Email: email })),
          Subject: subject,
          TextPart: text,
          HTMLPart: html,
          ...(config.replyTo ? { ReplyTo: config.replyTo } : {}),
          ...(encodedAttachments.length
            ? { Attachments: encodedAttachments.map((item) => ({
                // Mailjet's v3.1 schema spells this key `Filename`. `FileName`
                // is not recognised, so the attachment was dropped or the
                // request rejected.
                Filename: item.filename, ContentType: item.type, Base64Content: item.content,
              })) }
            : {}),
          Headers: [
            { Name: 'X-BA-Threat-Intel-Delivery-ID', Value: job.id },
            { Name: 'Auto-Submitted', Value: 'auto-generated' },
            ...(config.unsubscribeUrl
              ? [
                  { Name: 'List-Unsubscribe', Value: config.unsubscribeUrl },
                  ...(oneClickUnsubscribe
                    ? [{ Name: 'List-Unsubscribe-Post', Value: 'List-Unsubscribe=One-Click' }]
                    : []),
                ]
              : []),
          ],
        },
      ],
    });
  } else {
    body = JSON.stringify({
      from: { email: config.fromEmail, ...(config.fromName ? { name: config.fromName } : {}) },
      to: recipients.map((email) => ({ email })),
      subject,
      text,
      ...(html ? { html } : {}),
      ...(config.replyTo ? { reply_to: config.replyTo } : {}),
      ...(encodedAttachments.length
        ? { attachments: encodedAttachments.map((item) => ({
            content: item.content, type: item.type, name: item.filename,
          })) }
        : {}),
      headers: { ...deliveryHeader, ...unsubscribeHeader },
    });
  }
  const response = await request(endpoint, {
    method: 'POST',
    headers,
    body,
    timeoutMs: 30000,
    socketTimeoutMs: 15000,
    maxResponseBytes: 256 * 1024,
  });
  const provider = EMAIL_PROVIDER_LABELS[config.provider];
  if (response.status < 200 || response.status >= 300) {
    const value = response.headers['retry-after'];
    const raw = Array.isArray(value) ? value[0] : value;
    const seconds = raw ? Number(raw) : NaN;
    const retryAt = Number.isFinite(seconds)
      ? Date.now() + Math.max(0, seconds) * 1000
      : Date.parse(raw || '');
    throw new EmailProviderError(
      `${provider} rejected the message (HTTP ${response.status})`,
      response.status,
      Number.isFinite(retryAt) ? retryAt : 0,
    );
  }
  if (config.provider === 'API') {
    const requestId = response.headers['x-request-id'] || response.headers['x-message-id'];
    if (Array.isArray(requestId)) return requestId[0] || job.id;
    if (requestId) return requestId;
    try {
      const accepted = JSON.parse(response.body);
      return (
        (typeof accepted.id === 'string' && accepted.id) ||
        (typeof accepted.messageId === 'string' && accepted.messageId) ||
        job.id
      );
    } catch {
      return job.id;
    }
  }
  if (config.provider === 'SENDGRID') {
    if (response.status !== 202)
      throw new EmailProviderError('SendGrid did not confirm message acceptance', 502);
    const id = response.headers['x-message-id'];
    return (Array.isArray(id) ? id[0] : id) || job.id;
  }
  let data: any;
  try {
    data = JSON.parse(response.body);
  } catch {
    throw new EmailProviderError(`${provider} returned an invalid acceptance response`, 502);
  }
  if (
    config.provider === 'POSTMARK' &&
    data.ErrorCode === 0 &&
    typeof data.MessageID === 'string' &&
    data.MessageID
  )
    return data.MessageID;
  if (config.provider === 'POSTMARK' && Number.isInteger(data.ErrorCode) && data.ErrorCode !== 0)
    throw new EmailProviderError(`Postmark rejected the message (provider code ${data.ErrorCode})`, 422);
  if (
    config.provider === 'MAILTRAP' &&
    data.success === true &&
    Array.isArray(data.message_ids) &&
    typeof data.message_ids[0] === 'string' &&
    data.message_ids[0]
  )
    return data.message_ids[0];
  if (config.provider === 'MAILJET_API' && Array.isArray(data.Messages) && data.Messages.length > 0) {
    const msg = data.Messages[0];
    if (Array.isArray(msg.To)) {
      for (const to of msg.To) {
        if (typeof to.MessageID === 'string' && to.MessageID) return to.MessageID;
        if (typeof to.Email === 'string' && to.Email) return to.Email;
      }
    }
    if (typeof msg.ID === 'string' && msg.ID) return msg.ID;
  }
  throw new EmailProviderError(`${provider} did not confirm message acceptance`, 502);
}

/**
 * Outcome of a provider-side delivery lookup for one already-sent message.
 *
 * `unknown` is a first-class answer, not an error: a provider may not retain
 * message events, the lookup host may not be allowlisted, or the console may be
 * disabled. Callers must treat it as "keep withholding" rather than "retry".
 */
export type ProviderDeliveryState = 'delivered' | 'not-delivered' | 'unknown';

/** Providers whose delivery state can be queried by the message id we recorded.
 * Mailjet (Message-ID query param, same Basic auth as the send) and Mailtrap
 * (`/api/send/{id}` was never queryable, but the v2 API does expose a message
 * status endpoint keyed by the send's message id) are included; the custom
 * `API` provider stays unqueryable by design — its contract is unknown. */
export function supportsDeliveryLookup(provider: EmailConfiguration['provider']): boolean {
  return (
    provider === 'SENDGRID' ||
    provider === 'POSTMARK' ||
    provider === 'MAILJET_API' ||
    provider === 'MAILTRAP'
  );
}

/**
 * Fixed, never operator-controlled endpoints. A custom `API` provider cannot be
 * queried: its contract is unknown, so it stays unconfirmed by design.
 */
function lookupUrl(provider: EmailConfiguration['provider'], config: EmailConfiguration, messageId: string): string {
  const id = encodeURIComponent(messageId);
  if (provider === 'SENDGRID') return `https://api.sendgrid.com/v3/messages/${id}`;
  if (provider === 'MAILJET_API')
    return `https://api.mailjet.com/v3/REST/messages/${id}`;
  if (provider === 'MAILTRAP')
    return `https://mailtrap.io/api/v1/inboxes/${encodeURIComponent(config.mailtrapInboxId || '')}/messages/${id}`;
  return `https://api.postmarkapp.com/messages/outbound/${id}/details`;
}

function lookupHeaders(
  provider: EmailConfiguration['provider'],
  config: EmailConfiguration,
  token: string,
): Record<string, string> {
  if (provider === 'POSTMARK') return { 'x-postmark-server-token': token, accept: 'application/json' };
  // Mailjet uses the same Basic pair (apiKey:secret) for reads as for sends.
  if (provider === 'MAILJET_API')
    return {
      authorization: `Basic ${Buffer.from(`${token}:${config.mailjetApiSecret}`).toString('base64')}`,
      accept: 'application/json',
    };
  // Mailtrap's v2 API takes a per-inbox API token.
  if (provider === 'MAILTRAP') return { 'Api-Token': token, accept: 'application/json' };
  return { authorization: `Bearer ${token}`, accept: 'application/json' };
}

/** Normalises the three provider payloads into one verdict. */
function interpret(provider: EmailConfiguration['provider'], status: number, body: string): ProviderDeliveryState {
  // The provider does not know this message. It was never accepted.
  if (status === 404) return 'not-delivered';
  if (status < 200 || status >= 300) return 'unknown';
  let data: any;
  try {
    data = JSON.parse(body);
  } catch {
    return 'unknown';
  }
  if (provider === 'SENDGRID') {
    const events: unknown[] = Array.isArray(data?.events) ? data.events : [];
    const names = events.map((event) => String((event as { event_name?: string })?.event_name || ''));
    // A hard bounce or drop means the provider accepted the message and then
    // refused it at the mailbox: it reached the transport and must not be
    // re-sent, or the recipient receives a duplicate attempt.
    if (names.includes('delivered')) return 'delivered';
    if (names.some((name) => ['bounce', 'dropped', 'blocked', 'spamreport', 'unsubscribe'].includes(name)))
      return 'unknown';
    // Explicitly deferred/processed with no terminal event: not yet resolved.
    if (names.length) return 'unknown';
    // A message record with no events yet is accepted but unresolved.
    return data?.id ? 'unknown' : 'not-delivered';
  }
  // Mailjet returns a single message object; only a confirmed delivered status
  // counts, anything else (queued, opened, soft bounces) stays unresolved.
  if (provider === 'MAILJET_API') {
    if (typeof data?.Status === 'string') return data.Status === 'sent' ? 'delivered' : 'unknown';
    return 'unknown';
  }
  // Mailtrap v2 exposes the message with a status string; only "sent" is a
  // terminal positive, everything else keeps the resend withheld.
  if (provider === 'MAILTRAP') {
    if (typeof data?.status === 'string') return data.status === 'sent' ? 'delivered' : 'unknown';
    return 'unknown';
  }
  // Postmark: 200 with a record means the outbound message exists.
  if (typeof data?.MessageID === 'string' && data.MessageID) return 'delivered';
  if (Number.isInteger(data?.ErrorCode) && data.ErrorCode !== 0) return 'not-delivered';
  return 'unknown';
}

/**
 * Asks the provider whether it still has a record of this message.
 *
 * The request goes through the same DNS-pinned, allowlisted HTTPS client as
 * every other outbound call, so enabling the feature never widens the egress
 * surface: a deployment that has not allowlisted the provider's API host simply
 * receives `unknown` and keeps withholding. Never used to send.
 */
export async function lookupProviderDelivery(
  config: EmailConfiguration,
  token: string,
  messageId: string,
  request: Requester,
): Promise<ProviderDeliveryState> {
  if (!supportsDeliveryLookup(config.provider) || !messageId) return 'unknown';
  const url = lookupUrl(config.provider, config, messageId);
  const endpoint = emailEndpoint(config);
  // Defence in depth: a lookup must stay on the host that sends for this
  // provider, so a malformed configuration can never point it elsewhere.
  if (!endpoint || new URL(endpoint).hostname !== new URL(url).hostname) return 'unknown';
  try {
    const response = await request(url, {
      method: 'GET',
      headers: lookupHeaders(config.provider, config, token),
      timeoutMs: 15000,
      socketTimeoutMs: 10000,
      maxResponseBytes: 256 * 1024,
      // A redirect must never carry the provider credential to another host.
      allowRedirects: false,
    });
    return interpret(config.provider, response.status, response.body);
  } catch {
    return 'unknown';
  }
}
