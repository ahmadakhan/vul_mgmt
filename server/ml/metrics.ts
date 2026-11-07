/**
 * Minimal in-memory metrics registry for ML model state.
 *
 * Exposes gauges and counters that a Prometheus exporter can scrape.
 * Values are process-local; in a multi-replica deployment each replica
 * tracks its own state and the alert rules evaluate per-instance.
 */
export type MetricType = 'gauge' | 'counter';

interface MetricEntry {
  type: MetricType;
  value: number;
  labels: Record<string, string>;
}

export class MetricsRegistry {
  private metrics = new Map<string, MetricEntry>();

  gauge(name: string, value: number, labels: Record<string, string> = {}): void {
    this.metrics.set(name, { type: 'gauge', value, labels });
  }

  counter(name: string, value: number, labels: Record<string, string> = {}): void {
    const existing = this.metrics.get(name);
    const current = existing && existing.type === 'counter' ? existing.value : 0;
    this.metrics.set(name, { type: 'counter', value: current + value, labels });
  }

  inc(name: string, labels: Record<string, string> = {}): void {
    this.counter(name, 1, labels);
  }

  get(name: string): MetricEntry | undefined {
    return this.metrics.get(name);
  }

  all(): [string, MetricEntry][] {
    return [...this.metrics.entries()];
  }

  /** Render in Prometheus text exposition format. */
  render(): string {
    const lines: string[] = [];
    const byName = new Map<string, { type: MetricType; labels: Record<string, string>; values: number[] }>();

    for (const [name, entry] of this.all()) {
      if (!byName.has(name)) {
        byName.set(name, { type: entry.type, labels: entry.labels, values: [] });
      }
      byName.get(name)!.values.push(entry.value);
    }

    for (const [name, info] of byName) {
      lines.push(`# TYPE ${name} ${info.type}`);
      // Simple single-value rendering; multi-label variants would need
      // full label-set enumeration.
      lines.push(`${name} ${info.values[info.values.length - 1]}`);
      lines.push('');
    }
    return lines.join('\n');
  }
}

export const mlMetrics = new MetricsRegistry();
