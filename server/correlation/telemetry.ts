import type { CorrelationLog } from '../../shared/correlation.ts';
import type { Pool, PoolClient } from 'pg';

/**
 * Which telemetry entries are persisted at `standard` verbosity.
 *
 * The rule is about operational significance, not severity alone: a per-advisory
 * `ingestion.committed` line is normal throughput and carries no investigative
 * value, while `database.transaction_retry` on an INFO-ish path, an extraction
 * isolation, or anything WARN/CRITICAL is exactly what an operator needs during
 * an incident — those are never dropped.
 *
 * Entries are matched by exact name, so a new event is retained unless it is
 * explicitly listed here. Burning forensic evidence by default is worse than
 * writing an extra row.
 */
const STANDARD_DROP = new Set([
  'ingestion.started',
  'ingestion.committed',
  'extraction.completed',
  'ingestion.duplicate',
]);
const STANDARD_KEEP_PREFIXES = ['dead_letter.', 'database.', 'extraction.isolated', 'validation.'];
/**
 * Hard cap on the telemetry rows one advisory may persist in its own
 * transaction. 48 rows x 14 bound parameters stays far from the 65,535
 * parameter limit, and the INSERT stays well inside the ingest
 * statement_timeout; exceeding it is reported through `droppedLogs`.
 */
const MAX_PERSIST_ROWS = 48;

/**
 * Fixed allowlist: caller-controlled strings, errors, URLs and payloads cannot
 * enter context. Also enforces the operator-selected logging detail level.
 */
export class CorrelationTelemetry {
  private sequence = 0;
  readonly logs: CorrelationLog[] = [];
  completed = 0;
  deadLetters = 0;
  /** Files currently in the durable spool, for the saturation gauge. */
  deadLetterSpoolFiles = 0;
  latencyTotal = 0;
  readonly startedAt = performance.now();
  private outputBlocked = false;
  private pendingOutput: string[] = [];
  private drainWaiters = new Set<(error?: Error) => void>();
  private outputError?: Error;
  droppedLogs = 0;
  /** Count of advisories whose telemetry was truncated at MAX_PERSIST_ROWS. */
  truncatedPersists = 0;
  /**
   * Operational logging detail. Mutated at runtime from settings so an
   * operator can raise verbosity without restarting the worker; defaults to
   * standard so an unconfigured process never writes forensic volume.
   */
  verbosity: 'standard' | 'verbose' = 'standard';
  /** Count of entries suppressed by standard verbosity, for the health view. */
  suppressedByVerbosity = 0;
  constructor(private readonly output: NodeJS.WritableStream = process.stdout) {
    output.on('error', () => this.failOutput());
    output.on('close', () => this.failOutput());
  }
  private failOutput(): void {
    this.outputError = new Error('TELEMETRY_OUTPUT_UNAVAILABLE');
    this.droppedLogs += this.pendingOutput.length;
    this.pendingOutput = [];
    for (const settle of this.drainWaiters) settle(this.outputError);
    this.drainWaiters.clear();
  }
  async ready(signal?: AbortSignal): Promise<void> {
    signal?.throwIfAborted();
    if (this.outputError) throw this.outputError;
    if (this.outputBlocked || this.pendingOutput.length)
      await new Promise<void>((resolve, reject) => {
        const settle = (error?: Error) => {
          signal?.removeEventListener('abort', abort);
          this.drainWaiters.delete(settle);
          if (error) reject(error); else resolve();
        };
        const abort = () => settle(new Error('TELEMETRY_WAIT_ABORTED'));
        this.drainWaiters.add(settle);
        signal?.addEventListener('abort', abort, { once: true });
      });
  }
  /** Scrub PII, secrets, and credentials from log entries before emission. */
  private scrub(entry: CorrelationLog): CorrelationLog {
    const scrubbed = { ...entry };
    if (scrubbed.trackingId) scrubbed.trackingId = '[REDACTED]';
    // Scrub any metrics that might contain sensitive data
    for (const key of ['ingestionLatencyMs', 'extractionLatencyMs', 'totalDatabaseTimeMs', 'count', 'attempt'] as const) {
      if (typeof scrubbed[key] === 'number' && scrubbed[key] > 1000000) {
        // Likely a timestamp or large ID - redact
        delete scrubbed[key];
      }
    }
    return scrubbed;
  }
  log(
    level: CorrelationLog['level'],
    event: string,
    metrics: Partial<CorrelationLog> = {},
  ): void {
    // Event names are constants at every call site. Never accept external event names.
    const entry: CorrelationLog = {
      sequence: ++this.sequence,
      timestamp: new Date().toISOString(),
      level,
      event,
    };
    if (metrics.trackingId && /^[a-f0-9-]{36}$/i.test(metrics.trackingId))
      entry.trackingId = metrics.trackingId;
    for (const key of [
      'ingestionLatencyMs',
      'extractionLatencyMs',
      'totalDatabaseTimeMs',
      'count',
      'attempt',
    ] as const) {
      const value = metrics[key];
      if (typeof value === 'number' && Number.isFinite(value)) entry[key] = Math.round(value * 100) / 100;
    }
    // Suppression is decided before the entry joins the viewer ring, so the
    // in-memory view matches what is actually durable. Stdout is emitted
    // regardless of verbosity: an operator watching the worker live still sees
    // every line, while the shared event table stays small in standard mode.
    // WARN/CRITICAL and the diagnostic prefixes are never suppressed.
    const suppressed = this.verbosity === 'standard' && !this.shouldPersistInStandard(entry);
    if (suppressed) this.suppressedByVerbosity++;
    else {
      this.logs.push(entry);
      // Bound the viewer ring. Under verbose logging this fills quickly, which
      // is the operator's choice; standard logging keeps it mostly idle.
      if (this.logs.length > (this.verbosity === 'verbose' ? 1000 : 300)) this.logs.shift();
    }
    // Bound both the viewer ring and the stdout queue. Admission waits for drain.
    const outputEntry = this.scrub(entry);
    if (!this.outputError && this.pendingOutput.length < 512) this.pendingOutput.push(JSON.stringify(outputEntry) + '\n');
    else this.droppedLogs++;
    this.flushOutput();
  }
  /** True when a routine, non-diagnostic entry is worth a durable row at the
   * standard detail level. Only INFO-level chatter is a candidate for
   * suppression; WARN and CRITICAL always persist. */
  private shouldPersistInStandard(entry: CorrelationLog): boolean {
    if (entry.level !== 'INFO') return true;
    if (STANDARD_KEEP_PREFIXES.some((prefix) => entry.event.startsWith(prefix))) return true;
    return !STANDARD_DROP.has(entry.event);
  }
  /**
   * Drop the buffered entries of an advisory whose transaction will never
   * commit. Without this, every failed advisory leaves its log lines in the
   * shared ring until the ring cap evicts them — they are never persisted and
   * never attributed, and under a systematic failure (worker timeout, database
   * outage) the ring fills with entries that are silently discarded later.
   */
  discard(trackingId: string): void {
    for (let index = this.logs.length - 1; index >= 0; index--)
      if (this.logs[index].trackingId === trackingId) this.logs.splice(index, 1);
  }

  /** Write-ahead logging: persist telemetry entries to operational_events before commit.
   * Caller MUST call this inside the same transaction that commits the advisory.
   *
   * Values are bound as parameters, never interpolated: event names and
   * tracking ids originate outside the process, and the previous string-built
   * INSERT both broke on any embedded quote and allowed SQL injection through
   * a crafted log event. */
  async persistBeforeCommit(db: PoolClient, trackingId?: string): Promise<void> {
    // Only drain the entries that belong to this advisory. The buffer is shared
    // by every in-flight ingest in the worker, so clearing all of it on one
    // commit discarded (and misattributed) the telemetry of concurrent
    // advisories — silent data loss that scales with concurrency.
    const inFlight = trackingId
      ? this.logs.filter((entry) => entry.trackingId === trackingId)
      : this.logs;
    if (!inFlight.length) return;
    if (inFlight.length > MAX_PERSIST_ROWS) {
      // A pathological advisory (verbose mode, many stages) would otherwise
      // build a statement large enough to trip its own statement_timeout and
      // abort the advisory it is recording. The oldest rows are kept, the
      // remainder is counted so the operator can see the truncation.
      this.droppedLogs += inFlight.length - MAX_PERSIST_ROWS;
      this.truncatedPersists++;
      inFlight.splice(0, inFlight.length - MAX_PERSIST_ROWS);
    }
    const entries = inFlight;
    const values: unknown[] = [];
    const params = entries.map((log, index) => {
      const first = index * 15 + 1;
      // The pipeline-event columns (category/code/message) are NOT NULL in
      // migration 002. Telemetry rows are correlation-worker events, so they
      // are classified explicitly rather than left null and rejected.
      const category = 'PIPELINE' as const;
      // Map the correlation severity vocabulary onto the stored one. Ingest
      // emits 'WARN' and 'CRITICAL', neither of which the 002 CHECK constraint
      // accepts ('INFO','WARNING','ERROR'); persisting them unvalidated failed
      // the whole advisory transaction.
      const level =
        log.level === 'WARN' ? 'WARNING' : log.level === 'CRITICAL' ? 'ERROR' : log.level;
      const message = `${log.event}${log.trackingId ? ` [${log.trackingId}]` : ''}`;
      values.push(
        log.sequence,
        // Single clock. occurred_at (the durable column retention and the event
        // viewer use) is derived from this value by the
        // operational_events_sync_clock trigger, so the writer cannot produce a
        // row that one consumer sees and the other does not.
        log.timestamp,
        level,
        log.event,
        log.trackingId ?? null,
        log.ingestionLatencyMs ?? null,
        log.extractionLatencyMs ?? null,
        log.totalDatabaseTimeMs ?? null,
        log.count ?? null,
        log.attempt ?? null,
        category,
        log.event,
        message,
        null,
        JSON.stringify({
          sequence: log.sequence,
          timestamp: log.timestamp,
          level: log.level,
          event: log.event,
          trackingId: log.trackingId ?? null,
          ingestionLatencyMs: log.ingestionLatencyMs ?? null,
          extractionLatencyMs: log.extractionLatencyMs ?? null,
          totalDatabaseTimeMs: log.totalDatabaseTimeMs ?? null,
          count: log.count ?? null,
          attempt: log.attempt ?? null,
        }),
      );
      return `($${first},$${first + 1},$${first + 2},$${first + 3},$${first + 4}::uuid,
        $${first + 5},$${first + 6},$${first + 7},$${first + 8},$${first + 9},
        $${first + 10},$${first + 11},$${first + 12},$${first + 13}::uuid,$${first + 14}::jsonb)`;
    });
    await db.query(
      `INSERT INTO operational_events(sequence,timestamp,level,event,tracking_id,
        ingestion_latency_ms,extraction_latency_ms,total_database_time_ms,count,attempt,
        category,code,message,run_id,context)
       VALUES ${params.join(',')}`,
      values,
    );
    // Remove only the persisted entries; anything logged by another advisory
    // stays buffered for its own transaction.
    const persisted = new Set(entries);
    for (let index = this.logs.length - 1; index >= 0; index--)
      if (persisted.has(this.logs[index])) this.logs.splice(index, 1);
  }
  private flushOutput(): void {
    if (this.outputBlocked || this.outputError) return;
    while (this.pendingOutput.length) {
      let accepted: boolean;
      try { accepted = this.output.write(this.pendingOutput.shift()!); }
      catch { this.droppedLogs++; this.failOutput(); return; }
      if (!accepted) {
        this.outputBlocked = true;
        this.output.once('drain', () => {
          this.outputBlocked = false;
          this.flushOutput();
        });
        return;
      }
    }
    for (const resolve of this.drainWaiters) resolve();
    this.drainWaiters.clear();
  }
}