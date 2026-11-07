import type { PipelineSupervisor } from './supervisor.ts';
import type { Heartbeat } from './heartbeat.ts';
import { getMlRuntime } from '../ml/integration.ts';
import { mlMetrics } from '../ml/metrics.ts';

/** ML model state metrics referenced by alert rules in deploy/monitoring/vulnstream-alerts.yml. */
const ML_METRIC_NAMES = [
  'vulnstream_ml_model_drift_detected',
  'vulnstream_ml_quality_gate_failed_total',
  'vulnstream_ml_model_last_trained_age_seconds',
];
/** Available without a database roundtrip; the HTTP route requires a dedicated token. */
export function correlationMetrics(
  supervisor: PipelineSupervisor,
  heartbeat?: Heartbeat,
  /** Pending durable jobs, sampled by the caller on an interval (it needs a DB read). */
  pending = -1,
  /** Epoch ms of the last pending sample; 0 = never sampled. */
  pendingSampledAt = 0,
  /** Epoch ms of the last pipeline scheduled-run; 0 = never ran. */
  pipelineLastRun = 0,
  /** Epoch ms of when pipelineLastRun was sampled; 0 = never sampled. */
  pipelineLastRunSampledAt = 0,
  /** Whether the in-app scheduler setting is enabled. */
  pipelineSchedulerEnabled = false,
): string {
  const telemetry = supervisor.ingestor.telemetry;
  // The pipeline is only expected to make progress while the worker is enabled
  // and the supervisor is admitting. Every stall rule must qualify on this, or
  // a deployment that intentionally runs as monitoring-only (`WORKER_ENABLED`
  // false, or disabled until an operator completes setup) alarms forever about
  // "stalled ingestion" for a consumer nobody asked to start.
  const workerEnabled = process.env.WORKER_ENABLED !== 'false';
  const gauges: Record<string, number> = {
    vulnstream_correlation_memory_percent: supervisor.memoryPercent(),
    vulnstream_correlation_workers: supervisor.active.size,
    vulnstream_correlation_concurrency_limit: supervisor.concurrencyLimit,
    vulnstream_correlation_worker_enabled: workerEnabled ? 1 : 0,
    vulnstream_database_pool_total: supervisor.pool.totalCount,
    vulnstream_database_pool_waiting: supervisor.pool.waitingCount,
    // -1 means "not sampled yet". A real value is only ever >= 0, so every rule
    // must be written as `> 0`; `-1 > 0` is false and the sentinel is inert.
    vulnstream_correlation_pending: pending,
    // Staleness of the queue sample. The alert engine is called through a path
    // that can be reached before the first sample, and a sampler that has
    // stopped (drain loop wedged) would otherwise keep publishing an old depth
    // forever. -1 means never sampled.
    vulnstream_correlation_pending_sample_age_seconds: pendingSampledAt
      ? Math.round((Date.now() - pendingSampledAt) / 1000)
      : -1,
    // Age of the last pipeline scheduled run. 0 means "never ran"; -1 means the
    // sample itself is stale (last refresh failed or stopped). An alert must guard
    // on `vulnstream_pipeline_scheduler_enabled == 1` so a monitoring-only node does
    // not alarm about runs nobody asked it to make.
    vulnstream_pipeline_last_run_age_seconds:
      pipelineLastRunSampledAt && pipelineLastRun
        ? Math.round((Date.now() - pipelineLastRun) / 1000)
        : pipelineLastRunSampledAt && !pipelineLastRun
          ? 0
          : -1,
    vulnstream_pipeline_scheduler_enabled: pipelineSchedulerEnabled ? 1 : 0,
  };
  const counters: Record<string, number> = {
    vulnstream_correlation_items_total: telemetry.completed,
    vulnstream_correlation_dead_letters_total: telemetry.deadLetters,
    vulnstream_correlation_dropped_logs_total: telemetry.droppedLogs,
    vulnstream_correlation_latency_milliseconds_total: telemetry.latencyTotal,
  };
  const gaugesExtra: Record<string, number> = {
    // Spool saturation: the durable fallback accepts at most 256 letters before
    // `capture` reports capacity and the ingest path falls through to the
    // database. Without this gauge, a deployment whose database fallback is also
    // degraded reaches the last-resort loss window with no monitoring signal.
    vulnstream_correlation_dead_letter_spool_files: telemetry.deadLetterSpoolFiles,
  };
  const lines: string[] = [];
  for (const [name, value] of Object.entries(gauges))
    lines.push(`# TYPE ${name} gauge`, `${name} ${Number.isFinite(value) ? value : 0}`);
  for (const [name, value] of Object.entries(gaugesExtra))
    lines.push(`# TYPE ${name} gauge`, `${name} ${Number.isFinite(value) ? value : 0}`);
  for (const [name, value] of Object.entries(counters))
    lines.push(`# TYPE ${name} counter`, `${name} ${value}`);
  lines.push('# TYPE vulnstream_correlation_health gauge');
  for (const state of ['HEALTHY', 'DEGRADED_BACKPRESSURE', 'RECOVERING_DB_SEVERANCE'])
    lines.push(`vulnstream_correlation_health{state="${state}"} ${supervisor.health === state ? 1 : 0}`);
  if (heartbeat)
    lines.push(
      '# TYPE vulnstream_heartbeat_enabled gauge',
      `vulnstream_heartbeat_enabled ${heartbeat.enabled ? 1 : 0}`,
      '# TYPE vulnstream_heartbeat_age_seconds gauge',
      // Age of the last successful ping, or -1 when no ping has ever succeeded.
      // -1 is a sentinel, NOT a measurement: any rule must guard on
      // `vulnstream_heartbeat_state{state="pinged"} == 1`, because `-1 > 180`
      // is false and an unstarted or disabled heartbeat would otherwise be
      // silently exempt from the staleness check.
      `vulnstream_heartbeat_age_seconds ${heartbeat.lastPingAt ? Math.round((Date.now() - heartbeat.lastPingAt) / 1000) : -1}`,
      '# TYPE vulnstream_heartbeat_consecutive_failures gauge',
      `vulnstream_heartbeat_consecutive_failures ${heartbeat.consecutiveFailures}`,
      '# TYPE vulnstream_heartbeat_failed_pings_total counter',
      `vulnstream_heartbeat_failed_pings_total ${heartbeat.failedPingsTotal}`,
      '# TYPE vulnstream_heartbeat_state gauge',
      ...['pinged', 'failed', 'suppressed', 'idle', 'disabled'].map(
        (state) => `vulnstream_heartbeat_state{state="${state}"} ${heartbeat.state.status === state ? 1 : 0}`,
      ),
    );

  // ML model state metrics referenced by alert rules in
  // deploy/monitoring/vulnstream-alerts.yml.
  const runtime = getMlRuntime();
  if (runtime) {
    for (const name of ML_METRIC_NAMES) {
      const entry = mlMetrics.get(name);
      if (entry) {
        lines.push(`# TYPE ${name} ${entry.type}`, `${name} ${entry.value}`);
      }
    }
  }

  return lines.join('\n') + '\n';
}
