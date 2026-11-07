export type Confidence = 'HIGH' | 'MEDIUM' | 'LOW';
export type PipelineHealth = 'HEALTHY' | 'DEGRADED_BACKPRESSURE' | 'RECOVERING_DB_SEVERANCE';
export interface CorrelationMatch {
  assetId: string;
  vendor: string;
  product: string;
  confidence: Confidence;
  reason: string;
  assetRevision?: string;
}
export interface CorrelationLog {
  sequence: number;
  timestamp: string;
  level: 'INFO' | 'WARN' | 'ERROR' | 'CRITICAL';
  event: string;
  trackingId?: string;
  ingestionLatencyMs?: number;
  extractionLatencyMs?: number;
  totalDatabaseTimeMs?: number;
  count?: number;
  attempt?: number;
  // Extended fields for supervisor and stream telemetry
  highPool?: number;
  mediumPool?: number;
  lowPool?: number;
  crashCount?: number;
  pauseDurationMs?: number;
  frame?: string;
}
export interface CorrelationSnapshot {
  instanceId: string;
  health: PipelineHealth;
  concurrencyLimit: number;
  activeWorkers: number;
  memoryPercent: number;
  itemsPerSecond: number;
  averageLatencyMs: number;
  deadLetters: number;
  droppedLogs: number;
  pool: { total: number; idle: number; waiting: number };
  logs: CorrelationLog[];
  matches: (CorrelationMatch & { advisoryId: string; createdAt: string })[];
}
export interface CorrelationPolicy {
  notificationsEnabled: boolean;
  retentionEnabled: boolean;
  retentionHours: number;
  /** Days a pre-CVE vulnerability cluster stays open for corroboration. */
  preCveClusterWindowDays: number;
}
export interface CorrelationWorkflows {
  policy: CorrelationPolicy;
  /** Fleet-wide fault-simulation gate state (`correlation_policy.fault_simulation_armed`). */
  faultSimulationArmed: boolean;
  counts: { pending: number; reviews: number; deadLetters: number };
  reviews: {
    id: string;
    advisoryId: string;
    assetId: string | null;
    reason: string;
    title: string;
    content: string;
    url: string;
    createdAt: string;
  }[];
  deadLetters: { id: string; trackingId: string; errorCode: string; createdAt: string }[];
}
