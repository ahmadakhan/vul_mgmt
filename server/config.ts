import { z } from 'zod';
import ipaddr from 'ipaddr.js';
import { FEED_TYPES } from '../src/types/index.ts';
const databaseUrl = z
  .string()
  .min(1)
  .refine((value) => {
    try {
      const url = new URL(value);
      return ['postgres:', 'postgresql:'].includes(url.protocol) && Boolean(url.hostname);
    } catch {
      return false;
    }
  }, 'DATABASE_URL must be a valid PostgreSQL connection URL');
const trustProxy = z
  .string()
  .default('')
  .refine((value) => {
    const entries = value
      .split(',')
      .map((entry) => entry.trim())
      .filter(Boolean);
    if (!entries.length) return true;
    // Express accepts preset names, IPs, and CIDRs. Reject trust-all values:
    // a wildcard proxy setting lets any client spoof X-Forwarded-For and
    // bypass IP-based login throttling and audit attribution.
    return entries.every(
      (entry) =>
        !['true', '*', '0.0.0.0/0', '::/0'].includes(entry.toLowerCase()) &&
        (/^(?:\d{1,3}\.){3}\d{1,3}(?:\/\d{1,2})?$/.test(entry) ||
          /^[0-9a-f:]+(?:\/\d{1,3})?$/i.test(entry) ||
          ['loopback', 'linklocal', 'uniquelocal'].includes(entry.toLowerCase())),
    );
  }, 'TRUST_PROXY must list explicit proxy IPs, CIDRs, or presets (trust-all is not permitted)');
export const DEFAULT_EGRESS_HOSTS = [
  // Feed, API and mail hosts. Every redirect target of the recommended
  // feeds is listed alongside the URL that redirects to it, because the
  // requester re-validates each hop against this list: a feed whose
  // publisher moves to another host fails with "not in
  // EGRESS_ALLOWED_HOSTS" until its final host appears here.
  // Vulnerability data and enrichment
  'services.nvd.nist.gov',
  'api.osv.dev',
  // Live OSINT web search (Google Custom Search JSON API)
  'www.googleapis.com',
  'raw.githubusercontent.com',
  'www.cisa.gov',
  'cisa.gov', // cisa.gov redirects to the www spelling
  'api.first.org',
  'api.github.com',
  'app.opencve.io',
  'api.vulncheck.com',
  'otx.alienvault.com',
  // Mail providers
  'send.api.mailtrap.io',
  'sandbox.api.mailtrap.io',
  'api.sendgrid.com',
  'smtp.sendgrid.net',
  'api.postmarkapp.com',
  'smtp.maileroo.com',
  'smtp.lettr.com',
  'api.mailgun.net',
  'api.eu.mailgun.net',
  'in-v3.mailjet.com',
  'api.mailjet.com',
  'smtp.gmail.com',
  // RSS/Atom sources
  'www.bleepingcomputer.com',
  'isc.sans.edu',
  'api.msrc.microsoft.com',
  'www.fortiguard.com',
  'filestore.fortinet.com',
  'www.kb.cert.org',
  'kb.cert.org', // kb.cert.org redirects to the www spelling
  'thehackernews.com',
  'feeds.feedburner.com', // thehackernews.com redirects here
  'www.securityweek.com',
  'www.rapid7.com',
  'googleprojectzero.blogspot.com',
  'projectzero.google', // googleprojectzero.blogspot.com redirects here
  'krebsonsecurity.com',
  'tools.cisco.com',
  'sec.cloudapps.cisco.com', // tools.cisco.com redirects here
  'security.paloaltonetworks.com',
  'labs.watchtowr.com',
  'www.talosintelligence.com',
  'blog.talosintelligence.com', // the www host has no live feed; the blog serves rss/
  'www.thezdi.com',
  'www.exploit-db.com',
  'www.debian.org',
  'www.cisecurity.com',
  'cisecurity.com', // cisecurity.com redirects to the www spelling
  'cisecurity.org', // www.cisecurity.com -> cisecurity.org -> www.cisecurity.org
  'www.cisecurity.org',
  'seclists.org',
  'blog.sucuri.net',
  'www.welivesecurity.com',
  'wordpress.org',
  // Additional recommended RSS/Atom sources
  'www.darkreading.com',
  'blog.google',
  'cloud.google.com',
  'docs.cloud.google.com', // redirect target of the Google Cloud Security Bulletins feed
  'workspace.google.com',
  'www.greynoise.io',
  'www.malwarebytes.com',
  'cloudblog.withgoogle.com',
  'www.sophos.com',
  'therecord.media',
  'blog.twitter.com',
  'blog.x.com',
  'github.com',
  'github.blog', // github.com/advisories.atom 406s to non-browser agents; github.blog serves the Atom mirror
  'www.pentestpartners.com',
  'www.forbes.com',
  'www.theregister.com',
  'api.theregister.com', // redirect target of The Register Security headlines.atom feed
  'news.google.com',
  // Zero-day and vendor security advisories not previously allowlisted
  'www.cve.org',
  'cve.org', // cve.org redirects to the www spelling
  'support.apple.com',
  'helpx.adobe.com',
  'access.redhat.com',
  'security.redhat.com',
  'usn.ubuntu.com',
  'www.crowdstrike.com',
  'crowdstrike.com',
  'securelist.com',
  'www.securelist.com', // feed-kaspersky-securelist uses www.securelist.com
  // SonicWall PSIRT Security Advisories
  'psirtapi.global.sonicwall.com', // RSS API feed: https://psirtapi.global.sonicwall.com/api/v1/feed/rss.xml
  'psirt.global.sonicwall.com', // Web portal redirect target
].join(',');

const schema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  METRICS_TOKEN: z
    .string()
    .max(256)
    .default('')
    .refine((value) => !value || value.length >= 32, 'Metrics token must contain at least 32 characters'),
  PORT: z.coerce.number().int().min(1).max(65535).default(8080),
  DATABASE_URL: databaseUrl,
  APP_ORIGIN: z.url(),
  ALLOW_INSECURE_HTTP: z.enum(['true', 'false']).default('false'),
  ENCRYPTION_KEY: z.string().regex(/^[A-Za-z0-9+/]{43}=$/, 'Must be a base64 encoded 32-byte key'),
  ENCRYPTION_KEYS: z.string().max(2048).default('').refine((value) => {
    const keys = value.split(',').map((key) => key.trim()).filter(Boolean);
    return keys.length <= 16 && keys.every((key) => /^[A-Za-z0-9+/]{43}=$/.test(key) && Buffer.from(key, 'base64').length === 32);
  }, 'ENCRYPTION_KEYS must contain at most 16 comma-separated base64 32-byte keys'),
  EGRESS_ALLOWED_HOSTS: z
    .string()
    .default(DEFAULT_EGRESS_HOSTS),
  // Appended to the default allowlist instead of replacing it, so a deployment
  // can admit one extra redirect host without having to restate every default.
  EGRESS_ALLOWED_HOSTS_EXTRA: z.string().default(''),
  // Optional live OSINT provider (Google Custom Search JSON API). Leave both
  // empty to disable the Live OSINT Intelligence panel. GOOGLE_CSE_CX is an
  // alias for GOOGLE_CSE_ID for operators used to Google's `cx` parameter.
  GOOGLE_CSE_API_KEY: z.string().trim().max(256).default(''),
  GOOGLE_CSE_ID: z.string().trim().max(128).default(''),
  GOOGLE_CSE_CX: z.string().trim().max(128).default(''),
  TRUST_PROXY: trustProxy,
  SMTP_HOST: z.string().default(''),
  SMTP_PORT: z.coerce.number().int().min(1).max(65535).default(465),
  SMTP_USER: z.string().default(''),
  SMTP_PASSWORD: z.string().default(''),
   SMTP_FROM: z.union([z.email(), z.literal('')]).default(''),
  // A PDF copy of each advisory is attached to outbound emails when enabled.
  // Rendering converts advisory HTML to text and generates a PDF server-side;
  // set ATTACH_ADVISORY_PDF=false to deliver HTML-only messages.
  ATTACH_ADVISORY_PDF: z.enum(['true', 'false']).default('true'),
  // Deprecated compatibility setting. Automatic retries always confirm whether
  // an earlier attempt was delivered; this flag can no longer disable that guard.
  MAIL_CONFIRM_BEFORE_SEND: z.enum(['true', 'false']).default('true'),
  FEED_MAX_DURATION_SECONDS: z.coerce.number().int().min(1).max(7200).default(1800),
  WORKER_ENABLED: z.enum(['true', 'false']).default('true'),
  // Seed the recommended-threat-feed catalog on first bootstrap. Off by default:
  // enabling imports default feeds (CISA, CERT/CC, MITRE CVE, etc.) that fetch
  // over the egress allow-list, which fails in locked-down dev/prod environments
  // until an operator explicitly opts in. Does not run in production until set.
  BOOTSTRAP_RECOMMENDED_FEEDS: z.enum(['true', 'false']).default('false'),
  MAILJET_SANDBOX_MODE: z.enum(['true', 'false']).default('false'),
  // Control-plane fault simulation. Disabled unless an operator opts in, and
  // refused outright in production. It previously keyed off NODE_ENV alone,
  // which meant a staging/production image started with NODE_ENV=development
  // (a routine debugging move) exposed an endpoint that can open the shared
  // circuit breaker and halt ingestion for every replica.
  FAULT_SIMULATION_ENABLED: z.enum(['true', 'false']).default('false'),
  // Dead-man's switch. See server/correlation/heartbeat.ts: this is the only
  // mechanism that detects a TOTAL outage, because every other alert is
  // evaluated by something that also dies in a total outage.
  HEARTBEAT_URL: z.string().max(2048).default(''),
  HEARTBEAT_INTERVAL_SECONDS: z.coerce.number().int().min(15).max(3600).default(60),
  HANG_DETECTION_ENABLED: z.enum(['true', 'false']).default('false'),
  // Dead-letter queue for correlation pipeline. Defaults to an app-local
  // directory instead of /tmp because /tmp is subject to OS cleanup and may be
  // world-readable on shared hosts. The DeadLetterQueue creates this directory
  // with mode 0o700 at startup.
  CORRELATION_DLQ_DIRECTORY: z.string().default('data/correlation-dlq'),
  CORRELATION_DLQ_STORAGE_MODE: z.enum(['database', 'filesystem']).default('filesystem'),
  ML_DIRECTORY: z.string().default('/var/lib/vulnstream/ml'),
  ML_STORAGE_MODE: z.enum(['database', 'filesystem']).default('filesystem'),
  ML_SIGNING_KEY: z.string().optional(),
  ML_LOOKBACK_DAYS: z.coerce.number().int().min(1).max(90).default(7),
  // Controls stdout verbosity for structured operational logs. 'standard' keeps
  // output to lifecycle and error events; 'verbose' adds per-tick detail for
  // pipeline, ingestion, delivery, and retention steps to aid troubleshooting.
  LOG_LEVEL: z.enum(['standard', 'verbose']).default('standard'),
});
export type Config = z.infer<typeof schema>;
/**
 * Union the allowlist with operator additions, lowercased and de-duplicated.
 * Exported so the merge is testable without a full environment.
 */
export function mergeAllowedHosts(...parts: string[]): string {
  return [
    ...new Set(
      parts
        .flatMap((part) => part.split(','))
        .map((h) => h.trim().toLowerCase())
        .filter(Boolean),
    ),
  ].join(',');
}
export function feedEgressHosts(type: unknown, endpoint: unknown, configuredHosts: string[]): string[] {
  const baseline = [
    ...new Set(
      configuredHosts
        .map((host) => host.trim().toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, ''))
        .filter(Boolean),
    ),
  ];
  if (!baseline.length) return baseline;
  if (!FEED_TYPES.includes(type as (typeof FEED_TYPES)[number]) || typeof endpoint !== 'string')
    return baseline;
  if (type === 'OTX_API' && endpoint !== 'https://otx.alienvault.com/api/v1/pulses/subscribed/')
    return baseline;
  let url: URL;
  try {
    url = new URL(endpoint);
  } catch {
    return baseline;
  }
  if (url.protocol !== 'https:' || url.username || url.password || (url.port && url.port !== '443'))
    return baseline;
  const host = url.hostname.replace(/^\[|\]$/g, '').toLowerCase().replace(/\.$/, '');
  return host ? [...new Set([...baseline, host])] : baseline;
}
export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const parsed = schema.parse(env);
  const config = {
    ...parsed,
    EGRESS_ALLOWED_HOSTS: mergeAllowedHosts(
      parsed.EGRESS_ALLOWED_HOSTS,
      parsed.EGRESS_ALLOWED_HOSTS_EXTRA,
    ),
  };
  const origin = new URL(config.APP_ORIGIN);
  if (origin.origin !== config.APP_ORIGIN) throw new Error('APP_ORIGIN must be an origin without a path');
  if (config.ALLOW_INSECURE_HTTP === 'true') {
    let isPrivateIpv4 = false;
    try {
      const address = ipaddr.parse(origin.hostname);
      isPrivateIpv4 = address.kind() === 'ipv4' &&
        ['private', 'carrierGradeNat'].includes(address.range());
    } catch {
      isPrivateIpv4 = false;
    }
    if (config.NODE_ENV !== 'production' || origin.protocol !== 'http:' || !isPrivateIpv4)
      throw new Error('ALLOW_INSECURE_HTTP requires production HTTP on a private or Tailscale IPv4 address');
  }
  if (config.NODE_ENV === 'production' && origin.protocol !== 'https:' && config.ALLOW_INSECURE_HTTP !== 'true')
    throw new Error('Production requires an HTTPS APP_ORIGIN unless ALLOW_INSECURE_HTTP is enabled for a private or Tailscale IPv4 origin');
  if (Buffer.from(config.ENCRYPTION_KEY, 'base64').length !== 32) throw new Error('Invalid encryption key');
  if (config.NODE_ENV === 'production' && config.FAULT_SIMULATION_ENABLED === 'true')
    throw new Error('FAULT_SIMULATION_ENABLED is not permitted in production');
  if (config.HEARTBEAT_URL) {
    // The ping grants the ability to silence the alarm, so it must be https and
    // must not embed credentials in the URL.
    let url: URL;
    try {
      url = new URL(config.HEARTBEAT_URL);
    } catch {
      throw new Error('HEARTBEAT_URL must be a valid absolute URL');
    }
    if (config.NODE_ENV === 'production' && url.protocol !== 'https:')
      throw new Error('HEARTBEAT_URL must use https in production');
    if (url.username || url.password)
      throw new Error('HEARTBEAT_URL must not embed credentials; use a receiver with a token path');
  }
  return config;
}
