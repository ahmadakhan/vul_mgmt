import { createHash } from 'node:crypto';
import { z } from 'zod';
import type { Db } from '../db.ts';
import type { Job } from '../delivery.ts';
export const nativeDeliverySchema = z
  .object({
    advisoryId: z.uuid(),
    evidenceHash: z.string().regex(/^[a-f0-9]{64}$/),
    confidence: z.enum(['HIGH', 'MEDIUM']),
  })
  .strict();
export type NativeDelivery = z.infer<typeof nativeDeliverySchema>;
interface EvidenceMatch {
  assetId: string;
  vendor: string;
  product: string;
  confidence: 'HIGH' | 'MEDIUM';
  reason: string;
  assetRevision: string | null;
  currentRevision: string | null;
}
export async function readNativeEvidence(db: Db, advisoryId: string) {
  const article = await db.query<{ title: string; url: string; fingerprint: string; content: string }>(
    'SELECT title,url,fingerprint,content FROM unstructured_advisories WHERE id=$1',
    [advisoryId],
  );
  const matches = await db.query<EvidenceMatch>(
    `SELECT m.asset_id AS "assetId",m.vendor,m.product,m.confidence,m.reason,
     e.asset_revision AS "assetRevision",i.revision AS "currentRevision" FROM correlation_matches m
     LEFT JOIN correlation_match_evidence e ON e.advisory_id=m.advisory_id AND e.asset_id=m.asset_id
     LEFT JOIN correlation_asset_inventory i ON i.id=m.asset_id WHERE m.advisory_id=$1 ORDER BY m.asset_id LIMIT 1001`,
    [advisoryId],
  );
  const freshMatches = matches.rows.filter((match) => match.assetRevision && match.assetRevision === match.currentRevision);
  if (
    !article.rows[0] ||
    !freshMatches.length ||
    matches.rows.length > 1000
  )
    return null;
  const confidence: 'HIGH' | 'MEDIUM' = freshMatches.every((match) => match.confidence === 'HIGH')
    ? 'HIGH'
    : 'MEDIUM';
  const evidenceHash = createHash('sha256')
    .update(JSON.stringify([article.rows[0], freshMatches]))
    .digest('hex');
  return { article: article.rows[0], matches: freshMatches, confidence, evidenceHash };
}
export async function validateNativeDelivery(db: Db, job: Job): Promise<NativeDelivery> {
  const input = nativeDeliverySchema.parse(job.payload.nativeCorrelation);
  if (job.advisory_id !== `NATIVE:${input.advisoryId}`)
    throw new Error('Native notification identity mismatch');
  const policy = await db.query<{ notifications_enabled: boolean }>(
    'SELECT notifications_enabled FROM correlation_policy WHERE id=1',
  );
  if (!policy.rows[0]?.notifications_enabled) throw new Error('Native notification policy is disabled');
  const evidence = await readNativeEvidence(db, input.advisoryId);
  if (!evidence || evidence.evidenceHash !== input.evidenceHash || evidence.confidence !== input.confidence)
    throw new Error('Native evidence is no longer applicable; operator verification required');
  return input;
}
