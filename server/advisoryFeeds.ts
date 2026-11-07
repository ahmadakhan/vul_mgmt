import type { IntelligenceArticle, NormalizedCVE } from '../src/types/index.ts';
import { normalizeCveId } from '../src/utils/deduplicator';
import { cvssSeverity, normalizeCvssVersion, sanitizeCvssVector } from './cvss.ts';
import { cveSchema } from './validation.ts';
import { z } from 'zod';

export const OSV_QUERY_BATCH_URL = 'https://api.osv.dev/v1/querybatch';
export const GITHUB_ADVISORIES_URL = 'https://api.github.com/advisories';

export interface ParsedAdvisories {
  cves: NormalizedCVE[];
  articles: IntelligenceArticle[];
  withdrawals: { cveId: string; modifiedDate: string }[];
}

const providerTimestamp = (value: unknown, label: string): string => {
  if (typeof value !== 'string' || !Number.isFinite(Date.parse(value)))
    throw new Error(`Invalid ${label} timestamp in security advisory`);
  return new Date(value).toISOString();
};

const severity = z.enum(['critical', 'high', 'medium', 'low', 'unknown']);
const emptyCvss = {
  version: 'UNKNOWN' as const,
  score: 0,
  vector: '',
  severity: 'UNKNOWN' as const,
};

function normalizedCvss(metric: unknown) {
  const parsed = z.object({
    score: z.number().min(0).max(10).optional(),
    vector_string: z.string().max(300).optional(),
  }).passthrough().safeParse(metric);
  if (!parsed.success || parsed.data.score === undefined) return emptyCvss;
  const vector = sanitizeCvssVector(parsed.data.vector_string || '');
  const version = /^CVSS:(4\.0|3\.1|3\.0|2\.0)\//.exec(vector)?.[1];
  return {
    version: normalizeCvssVersion(version, 'UNKNOWN'),
    score: parsed.data.score,
    vector,
    severity: cvssSeverity(parsed.data.score),
  };
}

function advisoryArticle(input: {
  id: string;
  url: string;
  title: string;
  summary: string;
  publishedDate: string;
  modifiedDate: string;
  cveIds: string[];
  feedId: string;
}): IntelligenceArticle {
  return {
    id: input.id,
    url: input.url,
    title: input.title.slice(0, 500),
    summary: input.summary.slice(0, 30000),
    publishedDate: input.publishedDate,
    modifiedDate: input.modifiedDate,
    cveIds: input.cveIds,
    sourceFeeds: [input.feedId],
  };
}

const osvVulnerabilitySchema = z.object({
  id: z.string().min(1).max(200).regex(/^[A-Za-z0-9._-]+$/),
  aliases: z.array(z.string().max(150)).optional(),
  summary: z.string().max(30000).optional(),
  details: z.string().max(30000).optional(),
  published: z.string(),
  modified: z.string(),
  withdrawn: z.string().optional(),
  references: z.array(z.object({ type: z.string().optional(), url: z.url() }).passthrough()).optional(),
  severity: z.array(z.object({ type: z.string().optional(), score: z.string().optional() }).passthrough()).optional(),
}).passthrough();

export function parseOsvVulnerability(
  input: unknown,
  feedId: string,
  affectedPurls: readonly string[],
): ParsedAdvisories {
  const advisory = osvVulnerabilitySchema.parse(input);
  const id = advisory.id;
  const publishedDate = providerTimestamp(advisory.published, 'OSV published');
  const modifiedDate = providerTimestamp(advisory.modified, 'OSV modified');
  const cveIds = [...new Set((advisory.aliases || []).map((alias) => normalizeCveId(alias)).filter((value): value is string => !!value))];
  const title = advisory.summary || advisory.details?.split(/\r?\n/, 1)[0] || id;
  const description = advisory.details || advisory.summary || title;
  const result: ParsedAdvisories = { cves: [], articles: [], withdrawals: [] };
  if (advisory.withdrawn) {
    const withdrawnAt = providerTimestamp(advisory.withdrawn, 'OSV withdrawal');
    result.withdrawals = cveIds.map((cveId) => ({ cveId, modifiedDate: withdrawnAt }));
    return result;
  }
  if (!cveIds.length) {
    result.articles.push(advisoryArticle({
      id: `osv-${id}`,
      url: `https://osv.dev/vulnerability/${encodeURIComponent(id)}`,
      title,
      summary: description,
      publishedDate,
      modifiedDate,
      cveIds: [],
      feedId,
    }));
    return result;
  }
  const metric = advisory.severity?.find((entry) => /^CVSS_V[234]/i.test(entry.type || '') && entry.score);
  for (const cveId of cveIds) {
    result.cves.push(cveSchema.parse({
      cveId,
      title: title.slice(0, 500),
      description,
      publishedDate,
      modifiedDate,
      cvss: normalizedCvss(metric ? { vector_string: metric.score } : undefined),
      cwe: [],
      cpeMatches: [],
      purls: [...new Set(affectedPurls)],
      applicabilityRequiresReview: false,
      sourceFeeds: [feedId],
      epss: { score: 0, percentile: 0 },
      cisaKev: { isKev: false },
      exploitStatus: 'None',
      remediation: {
        patchUrl: '',
        vendorAdvisoryRef: `https://osv.dev/vulnerability/${encodeURIComponent(id)}`,
        immediateActions: [],
        workarounds: [],
        rollbackPlan: '',
        stepByStep: [],
      },
    }));
  }
  return result;
}

const githubAdvisorySchema = z.object({
  ghsa_id: z.string().regex(/^GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}$/i),
  cve_id: z.string().nullable(),
  html_url: z.url(),
  summary: z.string().max(1024),
  description: z.string().nullable(),
  severity: severity,
  cvss: z.unknown().optional(),
  cwes: z.array(z.object({ cwe_id: z.string().max(100) }).passthrough()).nullable().optional(),
  identifiers: z.array(z.object({ type: z.string(), value: z.string() }).passthrough()).nullable().optional(),
  references: z.array(z.string()).nullable().optional(),
  published_at: z.string(),
  updated_at: z.string(),
  withdrawn_at: z.string().nullable().optional(),
}).passthrough();

export function parseGitHubAdvisories(
  input: unknown,
  feedId: string,
  start: Date,
  end: Date,
): ParsedAdvisories {
  const page = z.array(githubAdvisorySchema).max(100).parse(input);
  const result: ParsedAdvisories = { cves: [], articles: [], withdrawals: [] };
  for (const raw of page) {
    const advisory = githubAdvisorySchema.parse(raw);
    const publishedDate = providerTimestamp(advisory.published_at, 'GitHub published');
    const modifiedDate = providerTimestamp(advisory.updated_at, 'GitHub updated');
    const modifiedAt = Date.parse(modifiedDate);
    if (modifiedAt < start.getTime() || modifiedAt > end.getTime()) continue;
    const cveIds = [...new Set([
      ...(advisory.cve_id ? [advisory.cve_id] : []),
      ...(advisory.identifiers || []).filter((item) => item.type === 'CVE').map((item) => item.value),
    ].map((value) => normalizeCveId(value)).filter((value): value is string => !!value))];
    if (advisory.withdrawn_at) {
      const withdrawnAt = providerTimestamp(advisory.withdrawn_at, 'GitHub withdrawal');
      result.withdrawals.push(...cveIds.map((cveId) => ({ cveId, modifiedDate: withdrawnAt })));
      continue;
    }
    const title = advisory.summary || advisory.ghsa_id;
    const description = advisory.description || advisory.summary;
    if (!cveIds.length) {
      result.articles.push(advisoryArticle({
        id: advisory.ghsa_id.toLowerCase(),
        url: advisory.html_url,
        title,
        summary: description,
        publishedDate,
        modifiedDate,
        cveIds: [],
        feedId,
      }));
      continue;
    }
    const cvss = normalizedCvss(advisory.cvss);
    for (const cveId of cveIds) {
      result.cves.push(cveSchema.parse({
        cveId,
        title: title.slice(0, 500),
        description,
        publishedDate,
        modifiedDate,
        cvss,
        cwe: (advisory.cwes || []).map((item) => item.cwe_id),
        cpeMatches: [],
        applicabilityRequiresReview: true,
        sourceFeeds: [feedId],
        epss: { score: 0, percentile: 0 },
        cisaKev: { isKev: false },
        exploitStatus: 'None',
        remediation: {
          patchUrl: '',
          vendorAdvisoryRef: advisory.html_url,
          immediateActions: [],
          workarounds: [],
          rollbackPlan: '',
          stepByStep: [],
        },
      }));
    }
  }
  return result;
}
