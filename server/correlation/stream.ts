import { Readable } from 'node:stream';
import { randomUUID } from 'node:crypto';
import type { Pool } from 'pg';
import type { PipelineSupervisor, IngestPriority } from './supervisor.ts';
import type { AdvisoryInput } from './validation.ts';
const MAX_RECORD_BYTES = 262144;
const QUEUE_DEADLINE_MS = 60_000;
/**
 * Absolute processing deadline for one advisory, in-queue wait excluded.
 * The ingest retry ladder is bounded inside this window (see ingest.ts
 * ATTEMPT_BUDGET_MS): four attempts at 3.5 s statement + 2 s lock timeout each
 * would exceed this deadline, and the processing timer would then abort the
 * *last* attempt instead of letting its own rollback and dead-letter capture
 * complete. The two budgets must fit inside one another, not race.
 */
const PROCESSING_DEADLINE_MS = 30_000;
type AdvisoryRecord = AdvisoryInput | { invalidFrame: string; raw?: string };
/** Object-mode records or UTF-8 NDJSON. A record is bounded even across chunks. */
export async function* advisoryRecords(input: Readable): AsyncGenerator<AdvisoryRecord> {
  if (input.readableObjectMode) {
    for await (const item of input) yield item;
    return;
  }
  // One allocation per stream: one-byte chunks must not create 262,144 Buffer objects.
  const record = Buffer.allocUnsafe(MAX_RECORD_BYTES);
  let bytes = 0;
  let oversized = false;
  const decode = (): AdvisoryRecord => {
    if (oversized) return { invalidFrame: 'OVERSIZED_NDJSON' };
    let raw: string;
    try {
      raw = new TextDecoder('utf-8', { fatal: true }).decode(record.subarray(0, bytes));
    } catch {
      return { invalidFrame: 'INVALID_UTF8_NDJSON' };
    }
    try {
      return JSON.parse(raw);
    } catch {
      return { invalidFrame: 'MALFORMED_NDJSON', raw: '' };
    }
  };
  for await (const chunk of input) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as string);
    let offset = 0;
    while (offset < buffer.length) {
      const newline = buffer.indexOf(10, offset);
      const end = newline < 0 ? buffer.length : newline;
      const length = end - offset;
      if (!oversized) {
        if (length > MAX_RECORD_BYTES - bytes) oversized = true;
        else {
          buffer.copy(record, bytes, offset, end);
          bytes += length;
        }
      }
      if (newline >= 0) {
        if (oversized || bytes) yield decode();
        bytes = 0;
        oversized = false;
      }
      offset = newline < 0 ? buffer.length : newline + 1;
    }
  }
  if (oversized || bytes) yield decode();
}
export class AdvisoryStreamProcessor {
  constructor(readonly supervisor: PipelineSupervisor) {}
  async processAdvisoryStream(inputStream: Readable, concurrencyLimit: number, dbPool: Pool): Promise<void> {
    if (!Number.isInteger(concurrencyLimit) || concurrencyLimit < 1 || concurrencyLimit > 32)
      throw new Error('INVALID_CONCURRENCY');
    // Read ahead by a bounded factor. A LOW advisory waiting for a slot must
    // not prevent a later HIGH advisory in the same stream from being parsed
    // and handed to the priority scheduler.
    const lookahead = Math.max(concurrencyLimit * 2, 8);
    const outstanding = new Set<Promise<void>>();
    let failure: unknown;
    // Failed records are remembered by identity, not by position: a batch is
    // acknowledged by its pending ids and every *other* record in the batch is
    // durable, so only the failed ones may be kept. Position-based inference
    // broke for object-mode sources whose promises settle out of order.
    const failedRecords: AdvisoryRecord[] = [];
    try {
      for await (const raw of advisoryRecords(inputStream)) {
        if (typeof raw === 'object' && raw !== null && 'invalidFrame' in raw) {
          // A structurally broken NDJSON frame has no addressable identity to
          // acknowledge; it is counted once per frame, not once per stream.
          this.supervisor.ingestor.telemetry.log('WARN', 'stream.invalid_frame', { count: 1 });
          continue;
        }
        const trackingId = randomUUID();
        const controller = new AbortController();
        const priority = this.inferPriority(raw);
        const promise = this.processRecord(raw, dbPool, trackingId, controller, priority)
          .catch((error) => {
            // A single record whose durability could not be established must
            // not abort the whole stream: the remaining records in the batch
            // are still processable. The batch is not acknowledged (see
            // runtime.ts), so the record itself is replayed from its durable
            // pending row rather than lost.
            this.supervisor.ingestor.telemetry.log('CRITICAL', 'stream.durable_capture_failed', {
              trackingId,
            });
            failedRecords.push(raw);
            failure ??= error;
          })
          .finally(() => {
            outstanding.delete(promise);
          });
        outstanding.add(promise);
        if (outstanding.size >= lookahead) await Promise.race(outstanding);
      }
    } finally {
      await Promise.allSettled(outstanding);
    }
    if (failure) throw Object.assign(failure as Error, { failedRecords });
  }

  /**
   * One advisory lifecycle. The queue deadline is separate from the execution
   * deadline: waiting behind high-priority work is not a processing failure,
   * and the previous design counted both against the same 15-second timer.
   */
  private async processRecord(
    raw: AdvisoryRecord,
    dbPool: Pool,
    trackingId: string,
    controller: AbortController,
    priority: IngestPriority,
  ): Promise<void> {
    let admitted = false;
    const queueTimer = setTimeout(() => controller.abort(), QUEUE_DEADLINE_MS);
    try {
      await this.supervisor.acquire(trackingId, controller, priority);
      admitted = true;
    } finally {
      clearTimeout(queueTimer);
    }
    const processingTimer = setTimeout(() => controller.abort(), PROCESSING_DEADLINE_MS);
    try {
      const result = await this.supervisor.ingestor.processIncomingAdvisory(
        raw,
        dbPool,
        trackingId,
        controller.signal,
      );
      // DEAD_LETTER is only returned after the dead-letter queue confirmed
      // durability. UNDURABLE means neither the spool nor the database accepted
      // the payload; the caller must keep the pending row instead of deleting
      // the last copy.
      if (result === 'UNDURABLE') throw new Error('UNDURABLE_CAPTURE');
    } finally {
      clearTimeout(processingTimer);
      if (admitted) this.supervisor.release(trackingId);
    }
  }

  /** Infer priority from advisory content. HIGH = CVE present or critical keywords.
   * The record is untrusted stream input and may not match the advisory shape
   * at all, so every field is validated before it is dereferenced. */
  private inferPriority(raw: AdvisoryRecord): 'HIGH' | 'MEDIUM' | 'LOW' {
    if (!raw || typeof raw !== 'object' || 'invalidFrame' in raw) return 'LOW';
    const advisory = raw as Partial<AdvisoryInput>;
    // HIGH: structured identity or explicit critical keywords
    if ((advisory.cpes?.length ?? 0) > 0 || (advisory.purls?.length ?? 0) > 0) return 'HIGH';
    // Check for critical keywords in title/content
    const text = `${advisory.title ?? ''} ${advisory.content ?? ''}`.toLowerCase();
    if (
      /\b(remote code execution|rce|zero.day|zero-day|actively exploited|in.the.wild|unpatched|critical|severity)\b/.test(
        text,
      )
    )
      return 'HIGH';
    // MEDIUM: Has security signals but no CVE
    if (/\b(vulnerability|exploit|patch|update|security|advisory)\b/.test(text)) return 'MEDIUM';
    return 'LOW';
  }
}
