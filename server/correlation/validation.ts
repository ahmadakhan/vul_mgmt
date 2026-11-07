import { z } from 'zod';
import { parseCPE23 } from '../../src/utils/cpeMatcher.ts';
import { canonicalArticleUrl } from '../rss.ts';
import { boundedJson } from './boundedJson.ts';
const bounded = (max: number) =>
  z
    .string()
    .max(max)
    .transform((s) => s.trim())
    .pipe(z.string().min(1));
const entity = z
  .object({
    vendor: bounded(200).transform((s) => s.toLowerCase()),
    product: bounded(200).transform((s) => s.toLowerCase()),
    affectedRange: bounded(200).optional(),
  })
  .strict();
const advisoryShape = z
  .object({
    title: bounded(200),
    content: bounded(50_000),
    url: z
      .string()
      .max(255)
      .trim()
      .url()
      .refine((s) => canonicalArticleUrl(s) !== null)
      .transform((s) => canonicalArticleUrl(s)!)
      .pipe(z.string().max(255)),
    cpes: z
      .array(
        z
          .string()
          .max(1000)
          .refine((s) => parseCPE23(s).isValid),
      )
      .max(100)
      .default([]),
    purls: z
      .array(
        z
          .string()
          .max(1000)
          .regex(/^pkg:[a-z][a-z0-9.+-]*\/[^\s]+$/),
      )
      .max(100)
      .default([]),
    entities: z.array(entity).max(100).default([]),
  })
  .strict();
// Reject hostile array lengths before Zod traverses their elements. This also
// prevents refinements from processing giant identity strings after a max error.
const guardedShape = z
  .unknown()
  .refine((raw) => {
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return false;
    const value = raw as Record<string, unknown>;
    for (const [field, limit] of [
      ['title', 200],
      ['content', 50_000],
      ['url', 255],
    ] as const)
      if (typeof value[field] === 'string' && value[field].length > limit) return false;
    for (const field of ['cpes', 'purls', 'entities']) {
      const items = value[field];
      if (
        Array.isArray(items) &&
        (items.length > 100 || items.some((item) => typeof item === 'string' && item.length > 1000))
      )
        return false;
    }
    return true;
  }, 'Input exceeds ingestion boundary budget')
  .pipe(advisoryShape);
const PREPROCESSED = z.preprocess((raw) => {
  const encoded = boundedJson(raw);
  return encoded === null ? null : JSON.parse(encoded);
}, guardedShape);

export const AdvisoryInputSchema = PREPROCESSED;

/**
 * Describe why an advisory was rejected, without echoing its content.
 *
 * The ingest pipeline dead-letters malformed input instead of throwing, which
 * is right, but a publisher needs to know *which* rule was broken. Only the
 * field path and the rule name are returned: the rejected values themselves
 * may contain customer data or be the payload of an injection attempt.
 */
export function describeAdvisoryError(raw: unknown): string {
  const result = PREPROCESSED.safeParse(raw);
  if (result.success) return 'VALID';
  const first = result.error.issues[0];
  const field = first?.path.filter((part) => typeof part === 'string').join('.') || 'payload';
  return `${field}:${first?.code ?? 'invalid'}`;
}
export type AdvisoryInput = z.infer<typeof AdvisoryInputSchema>;
export interface ExtractedText {
  text: string;
  cleanContent: string;
  ranges: { productPhrase: string; range: string }[];
  cveIds: string[];
  zeroDay: boolean;
  securitySignal: boolean;
  negated: boolean;
  zeroDayDensity: number;
}
