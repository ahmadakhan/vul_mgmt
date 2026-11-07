/**
 * Dead-man's switch heartbeat.
 *
 * Every other alert in `deploy/monitoring/vulnstream-alerts.yml` evaluates a
 * expression *against* VulnStream and fires when that expression is unhealthy.
 * That design has one blind spot it cannot cover: if VulnStream, the database,
 * and the monitor collector are all gone — one node, a lost cluster, a wiped
 * volume — there is nothing left to evaluate the rule, so **no alert fires**.
 * The absence of data looks identical to the absence of a problem.
 *
 * The only reliable way to detect a total outage is to invert the direction:
 * the monitored system must affirmatively say "I am alive" to a party that does
 * not live inside it, and *that* party must alert on silence. This module
 * publishes that affirmation.
 *
 * Delivery is deliberately dumb: a single HTTP POST to an operator-configured
 * URL (an uptime service such as healthchecks.io, a PagerDuty Events endpoint,
 * or any receiver that alarms on missed pings). It is fire-and-forget, bounded,
 * and failure of the ping itself never affects ingestion — a heartbeat that can
 * take down the system it monitors is worse than no heartbeat.
 */

export interface HeartbeatOptions {
  /** Absolute URL that alarms when pings stop. Empty disables the heartbeat. */
  url: string;
  /** Interval between pings. Must be shorter than the receiver's grace period. */
  intervalMs: number;
  /**
   * A ping is suppressed while the pipeline is known-bad, so the receiver's
   * silence rule fires. This is the *only* correct behaviour: pinging "alive"
   * through a total ingestion outage would make the dead-man's switch lie.
   * Set false to ping regardless of health (liveness-only monitoring).
   */
  suppressOnUnhealthy: boolean;
  /** Injected for tests. Defaults to global fetch. */
  fetchImpl?: typeof fetch;
  /** The reason the last ping was skipped, surfaced on /metrics. */
  onState?: (state: HeartbeatState) => void;
}

export type HeartbeatState =
  | { status: 'disabled' }
  | { status: 'idle' }
  | { status: 'pinged'; at: number; latencyMs: number }
  | { status: 'failed'; at: number; error: string }
  | { status: 'suppressed'; since: number; reason: string };

const PING_TIMEOUT_MS = 5_000;

export class Heartbeat {
  private timer?: ReturnType<typeof setInterval>;
  private readonly controller = new AbortController();
  private inFlight = false;
  state: HeartbeatState = { status: 'idle' };
  lastPingAt = 0;
  /**
   * Consecutive failed pings, reset on success. Exported as a GAUGE, not a
   * counter: it resets on every success, so calling it `_total` and applying
   * `increase()` to it made the failure alert fire on ordinary recovery
   * (any nonzero -> 0 is read as a counter reset, and the spike it computes is
   * an artefact).
   */
  consecutiveFailures = 0;
  /** Monotonic count of failed pings; this one IS a counter. */
  failedPingsTotal = 0;

  constructor(private readonly options: HeartbeatOptions) {
    if (!options.url) this.state = { status: 'disabled' };
  }

  get enabled(): boolean {
    return Boolean(this.options.url);
  }

  start(isHealthy: () => { healthy: boolean; reason: string }): void {
    if (!this.enabled || this.timer) return;
    // Ping immediately, then on an interval. The receiver is configured with a
    // grace period longer than the interval, so one dropped ping is tolerated
    // but two in a row alarm.
    void this.ping(isHealthy);
    this.timer = setInterval(() => void this.ping(isHealthy), this.options.intervalMs);
    // The heartbeat must not hold the process open during shutdown.
    this.timer.unref();
  }

  async ping(isHealthy: () => { healthy: boolean; reason: string }): Promise<void> {
    if (!this.enabled || this.inFlight) return;
    if (this.options.suppressOnUnhealthy) {
      let health: { healthy: boolean; reason: string };
      try {
        health = isHealthy();
      } catch {
        health = { healthy: false, reason: 'health_check_failed' };
      }
      if (!health.healthy) {
        this.state = { status: 'suppressed', since: this.lastPingAt || Date.now(), reason: health.reason };
        this.options.onState?.(this.state);
        return;
      }
    }
    this.inFlight = true;
    const started = Date.now();
    try {
      const response = await (this.options.fetchImpl ?? fetch)(this.options.url, {
        method: 'POST',
        // No body, and no advisory content, inventory identity or credentials:
        // the receiver is an external service outside the trust boundary.
        headers: { 'content-type': 'text/plain' },
        body: 'ok',
        signal: AbortSignal.any([this.controller.signal, AbortSignal.timeout(PING_TIMEOUT_MS)]),
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      this.lastPingAt = Date.now();
      this.consecutiveFailures = 0;
      this.state = { status: 'pinged', at: this.lastPingAt, latencyMs: this.lastPingAt - started };
    } catch (error) {
      this.consecutiveFailures++;
      this.failedPingsTotal++;
      this.state = {
        status: 'failed',
        at: Date.now(),
        error: error instanceof Error ? error.name : 'PING_FAILED',
      };
      // Never log the URL: it is a secret that grants the ability to silence the
      // alarm by pinging it.
    } finally {
      this.inFlight = false;
      this.options.onState?.(this.state);
    }
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = undefined;
    this.controller.abort();
  }
}
