import { PageHeading } from './PageHeading';
import { CorrelationOperations } from './CorrelationOperations';
import { useEffect, useMemo, useRef, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  ArrowDownToLine,
  ArrowRight,
  CheckCircle2,
  Clock3,
  Code2,
  Database,
  Gauge,
  Layers3,
  LoaderCircle,
  Search,
  Settings2,
  ShieldCheck,
  Terminal,
  Workflow,
  Zap,
} from 'lucide-react';
import { useApp } from '../context/AppContext';
import { formatTime } from '../utils/dateTime';
import type { CorrelationSnapshot } from '../../shared/correlation';
import './correlation.css';

const sample = JSON.stringify({
  title: 'Kubernetes unpatched vulnerability actively exploited',
  content: 'Researchers report a zero-day vulnerability in k8s. Affected releases are under investigation.',
  url: 'https://example.org/security/kubernetes-early-warning',
});
const tabs = [
  { id: 'telemetry', label: 'Live telemetry', icon: Activity },
  { id: 'review', label: 'Review & policy', icon: ShieldCheck },
  { id: 'controls', label: 'Stream controls', icon: Settings2 },
] as const;
const healthLabels = {
  HEALTHY: 'Healthy',
  DEGRADED_BACKPRESSURE: 'Backpressure detected',
  RECOVERING_DB_SEVERANCE: 'Database recovering',
};
const percent = (value: number) => Math.min(100, Math.max(0, value));

export function CorrelationDashboard() {
  const { csrfToken, session, settings } = useApp();
  const [snapshot, setSnapshot] = useState<CorrelationSnapshot | null>(null);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [noticeError, setNoticeError] = useState(false);
  const [limit, setLimit] = useState(4);
  const [ndjson, setNdjson] = useState(sample);
  const [filter, setFilter] = useState('');
  const [pendingAction, setPendingAction] = useState('');
  const [confirmIngest, setConfirmIngest] = useState(false);
  const [confirmConcurrency, setConfirmConcurrency] = useState(false);
  const [confirmFaultDatabase, setConfirmFaultDatabase] = useState(false);
  const [confirmFaultMemory, setConfirmFaultMemory] = useState(false);
  const [follow, setFollow] = useState(true);
  const [rawLogs, setRawLogs] = useState(false);
  const [logLevel, setLogLevel] = useState('ALL');
  const [view, setView] = useState<(typeof tabs)[number]['id']>('telemetry');
  const [updatedAt, setUpdatedAt] = useState<Date | null>(null);
  const consoleRef = useRef<HTMLDivElement>(null);
  const initializedLimit = useRef(false);
  const busy = !!pendingAction;
  const confirmationPending = confirmIngest || confirmConcurrency || confirmFaultDatabase || confirmFaultMemory;
  const canControl = session?.role === 'ADMIN' || session?.role === 'OPERATOR';

  useEffect(() => {
    let disposed = false;
    let timer: ReturnType<typeof setTimeout>;
    const controller = new AbortController();
    const refresh = async () => {
      try {
        const response = await fetch('/api/correlation', {
          credentials: 'same-origin',
          signal: AbortSignal.any([controller.signal, AbortSignal.timeout(5000)]),
        });
        if (!response.ok) throw new Error(`Telemetry unavailable (HTTP ${response.status})`);
        const data = (await response.json()) as CorrelationSnapshot;
        if (!disposed) {
          setSnapshot(data);
          setUpdatedAt(new Date());
          setError('');
          if (!initializedLimit.current) {
            setLimit(data.concurrencyLimit);
            initializedLimit.current = true;
          }
        }
      } catch (reason) {
        if (!disposed) setError(reason instanceof Error ? reason.message : 'Telemetry unavailable');
      } finally {
        if (!disposed) timer = setTimeout(() => void refresh(), 1000);
      }
    };
    void refresh();
    return () => {
      disposed = true;
      controller.abort();
      clearTimeout(timer);
    };
  }, []);
  useEffect(() => {
    if (follow && consoleRef.current) consoleRef.current.scrollTop = consoleRef.current.scrollHeight;
  }, [snapshot?.logs, follow, logLevel, rawLogs, view]);

  const matches = useMemo(
    () =>
      (snapshot?.matches || []).filter((match) =>
        `${match.assetId} ${match.vendor} ${match.product} ${match.confidence} ${match.reason}`
          .toLowerCase()
          .includes(filter.toLowerCase()),
      ),
    [snapshot?.matches, filter],
  );
  const logs = useMemo(
    () =>
      (snapshot?.logs || []).filter(
        (log) =>
          logLevel === 'ALL' ||
          (logLevel === 'ERROR' ? ['ERROR', 'CRITICAL'].includes(log.level) : log.level === logLevel),
      ),
    [snapshot?.logs, logLevel],
  );

  const mutate = async (path: string, body: unknown) => {
    if (busy) return;
    setPendingAction(path);
    setNotice('');
    setNoticeError(false);
    try {
      const response = await fetch(`/api/correlation/${path}`, {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'content-type': 'application/json', 'x-csrf-token': csrfToken },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(10000),
      });
      if (!response.ok) {
        const details = (await response.json().catch(() => ({}))) as { error?: string };
        throw new Error(details.error || `Action rejected (HTTP ${response.status})`);
      }
      const result = (await response.json()) as { queued?: number };
      setNotice(
        result.queued !== undefined
          ? `${result.queued} ${result.queued === 1 ? 'record' : 'records'} durably queued`
          : 'Control accepted',
      );
    } catch (reason) {
      setNoticeError(true);
      setNotice(reason instanceof Error ? reason.message : 'Action failed');
    } finally {
      setPendingAction('');
    }
  };

  const executeIngest = async () => {
    setConfirmIngest(false);
    await mutate('ingest', { ndjson });
  };
  const executeConcurrency = async () => {
    setConfirmConcurrency(false);
    await mutate('concurrency', { limit });
  };
  const executeFaultDatabase = async () => {
    setConfirmFaultDatabase(false);
    await mutate('fault', { fault: 'database' });
  };
  const executeFaultMemory = async () => {
    setConfirmFaultMemory(false);
    await mutate('fault', { fault: 'memory' });
  };

  const connected = !!snapshot && !error;
  const healthy = connected && snapshot.health === 'HEALTHY';
  const metrics = [
    {
      label: 'Throughput',
      value: snapshot?.itemsPerSecond.toFixed(2) ?? '—',
      unit: 'items / sec',
      icon: Zap,
      detail: 'Current processing rate',
    },
    {
      label: 'Ingestion latency',
      value: snapshot?.averageLatencyMs.toFixed(1) ?? '—',
      unit: 'ms',
      icon: Clock3,
      detail: 'Average ingestion time',
    },
    {
      label: 'Active workers',
      value: snapshot?.activeWorkers ?? '—',
      unit: snapshot ? `/ ${snapshot.concurrencyLimit}` : '',
      icon: Layers3,
      detail: 'Allocated concurrency',
      progress: snapshot
        ? percent((snapshot.activeWorkers / Math.max(1, snapshot.concurrencyLimit)) * 100)
        : undefined,
    },
    {
      label: 'Memory capacity',
      value: snapshot?.memoryPercent.toFixed(1) ?? '—',
      unit: '%',
      icon: Gauge,
      detail: 'Current memory utilization',
      progress: snapshot ? percent(snapshot.memoryPercent) : undefined,
    },
    {
      label: 'Database pool',
      value: snapshot?.pool.total ?? '—',
      unit: 'connections',
      icon: Database,
      detail: snapshot
        ? `${snapshot.pool.idle} idle · ${snapshot.pool.waiting} waiting`
        : 'Waiting for connection data',
    },
    {
      label: 'Dead letters',
      value: snapshot?.deadLetters ?? '—',
      unit: 'captured',
      icon: ShieldCheck,
      detail: 'Captured by this instance',
    },
  ];

  return (
    <div className="correlation-page space-y-6">
      <div className="ui-page-header">
        <PageHeading page="correlation">
          Follow intelligence as it connects to your inventory. Monitor processing, inspect matches, and
          resolve evidence that needs review.
        </PageHeading>
        <div className="cr-connection" role="status">
          <span className={`cr-status ${healthy ? 'cr-status-good' : 'cr-status-warning'}`}>
            <i aria-hidden="true" />
            {error ? 'Reconnecting' : snapshot ? healthLabels[snapshot.health] : 'Connecting'}
          </span>
          <span className="cr-caption">{error ? 'Retrying automatically' : 'Refreshes every second'}</span>
        </div>
      </div>

      {error && (
        <div role="alert" className="cr-notice cr-notice-warning">
          <AlertTriangle size={16} />
          <div>
            <strong>Live updates interrupted</strong>
            <p>
              {error}.{' '}
              {snapshot
                ? 'The last received metrics remain visible while the connection recovers.'
                : 'Waiting for the first telemetry snapshot.'}
            </p>
          </div>
        </div>
      )}
      {!!snapshot?.droppedLogs && (
        <div role="alert" className="cr-notice cr-notice-warning">
          <AlertTriangle size={16} />
          <p>
            {snapshot.droppedLogs} events exceeded the log queue. Check the log collector for missing
            activity.
          </p>
        </div>
      )}

      <div className="cr-viewbar">
        <div className="ui-segmented cr-view-switch" role="group" aria-label="Correlation views">
          {tabs.map(({ id, label, icon: Icon }) => (
            <button
              type="button"
              key={id}
              aria-pressed={view === id}
              aria-controls={`correlation-${id}`}
              onClick={() => setView(id)}
            >
              <Icon size={15} aria-hidden="true" />
              {label}
            </button>
          ))}
        </div>
        <span className="cr-instance" title={snapshot?.instanceId}>
          <span className={`cr-indicator ${connected ? 'is-connected' : ''}`} />
          {snapshot ? `Instance ${snapshot.instanceId}` : 'Awaiting instance'}
        </span>
      </div>

      <div id="correlation-telemetry" hidden={view !== 'telemetry'} className="cr-view-content">
        <div className="cr-metrics">
          {metrics.map(({ label, value, unit, icon: Icon, detail, progress }) => (
            <div className="cr-metric ui-panel" key={label}>
              <div className="cr-metric-label">
                <span>{label}</span>
                <Icon size={16} aria-hidden="true" />
              </div>
              <div className="cr-metric-value">
                {value}
                <span>{unit}</span>
              </div>
              <div className="cr-metric-detail">{detail}</div>
              {progress !== undefined && (
                <div
                  className="cr-meter"
                  role="meter"
                  aria-label={label}
                  aria-valuenow={Math.round(progress)}
                  aria-valuemin={0}
                  aria-valuemax={100}
                >
                  <span style={{ width: `${progress}%` }} />
                </div>
              )}
            </div>
          ))}
        </div>

        <section className="ui-panel cr-panel" aria-labelledby="correlation-matches-title">
          <div className="cr-panel-header">
            <div className="cr-section-title">
              <span className="ui-section-icon">
                <Workflow size={17} />
              </span>
              <div>
                <h2 id="correlation-matches-title">
                  Correlation matches <span className="cr-count">{snapshot?.matches.length ?? '—'}</span>
                </h2>
                <p>Identity and version evidence linked to monitored assets.</p>
              </div>
            </div>
            <div className="cr-search">
              <Search size={15} aria-hidden="true" />
              <input
                aria-label="Filter correlation matches"
                placeholder="Search assets, products, or confidence…"
                maxLength={200}
                value={filter}
                onChange={(event) => setFilter(event.target.value)}
              />
            </div>
          </div>
          <div className="overflow-x-auto">
            <table className="cr-match-table text-left">
              <thead>
                <tr>
                  {['Monitored asset', 'Vendor / product', 'Confidence', 'Match evidence'].map((label) => (
                    <th key={label}>{label}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {matches.map((match) => (
                  <tr key={`${match.advisoryId}:${match.assetId}`}>
                    <td>
                      <span className="cr-asset">
                        <Database size={14} aria-hidden="true" />
                        <span title={match.assetId}>{match.assetId}</span>
                      </span>
                    </td>
                    <td>
                      <strong className="cr-product">{match.product}</strong>
                      <span className="cr-vendor">{match.vendor}</span>
                    </td>
                    <td>
                      <span
                        className={`cr-status ${match.confidence === 'HIGH' ? 'cr-status-good' : 'cr-status-warning'}`}
                      >
                        <i aria-hidden="true" />
                        {match.confidence === 'HIGH'
                          ? 'High'
                          : match.confidence === 'MEDIUM'
                            ? 'Medium'
                            : 'Low'}
                      </span>
                    </td>
                    <td className="cr-evidence">{match.reason}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {matches.length === 0 && (
            <div className="cr-empty">
              <Workflow size={25} strokeWidth={1.5} aria-hidden="true" />
              <h3>
                {filter
                  ? 'No matching results'
                  : snapshot
                    ? 'Waiting for correlated matches'
                    : 'Connecting to the correlation engine'}
              </h3>
              <p>
                {filter
                  ? 'Try another asset, vendor, product, or confidence level.'
                  : 'Matches appear here as intelligence is linked to inventory. Low-confidence evidence stays in review.'}
              </p>
              {filter && (
                <button type="button" className="cr-text-button" onClick={() => setFilter('')}>
                  Clear search <ArrowRight size={13} />
                </button>
              )}
            </div>
          )}
          <div className="cr-panel-footer">
            <span>
              {matches.length} shown{snapshot ? ` of ${snapshot.matches.length} recent matches` : ''}
            </span>
            <span>Per-instance telemetry</span>
          </div>
        </section>

        <section className="ui-panel cr-panel" aria-labelledby="correlation-activity-title">
          <div className="cr-panel-header">
            <div className="cr-section-title">
              <span className="ui-section-icon">
                <Terminal size={17} />
              </span>
              <div>
                <h2 id="correlation-activity-title">Live activity</h2>
                <p>Structured events from the correlation engine.</p>
              </div>
            </div>
            <div className="cr-log-controls">
              <select
                aria-label="Filter activity level"
                value={logLevel}
                onChange={(event) => setLogLevel(event.target.value)}
              >
                <option value="ALL">All levels</option>
                <option value="INFO">Info</option>
                <option value="WARN">Warning</option>
                <option value="ERROR">Error & critical</option>
              </select>
              <button
                type="button"
                className="cr-icon-button"
                aria-label="Show raw JSON logs"
                aria-pressed={rawLogs}
                onClick={() => setRawLogs(!rawLogs)}
                title="Toggle raw JSON"
              >
                <Code2 size={16} />
              </button>
              <label className="cr-follow">
                <input
                  type="checkbox"
                  checked={follow}
                  onChange={(event) => setFollow(event.target.checked)}
                />
                Auto-follow
              </label>
            </div>
          </div>
          <div
            ref={consoleRef}
            className="cr-console"
            role="region"
            aria-label="Structured correlation logs"
            tabIndex={0}
          >
            {logs.map((log) => (
              <div key={log.sequence} className="cr-log-row" data-level={log.level}>
                {rawLogs ? (
                  <pre>{JSON.stringify(log)}</pre>
                ) : (
                  <>
                    <time dateTime={log.timestamp}>{formatTime(log.timestamp, settings.timezone)}</time>
                    <span className="cr-log-level">{log.level}</span>
                    <div className="cr-log-message">
                      <span>{log.event.replace(/[_\.]+/g, ' ')}</span>
                      {log.trackingId && <small>Tracking: {log.trackingId}</small>}
                    </div>
                    <span className="cr-log-duration">
                      {log.ingestionLatencyMs !== undefined
                        ? `${log.ingestionLatencyMs.toFixed(1)} ms`
                        : `#${log.sequence}`}
                    </span>
                  </>
                )}
              </div>
            ))}
            {!logs.length && (
              <div className="cr-empty">
                <Terminal size={24} strokeWidth={1.5} />
                <h3>{logLevel === 'ALL' ? 'Listening for activity' : 'No events at this level'}</h3>
                <p>
                  {logLevel === 'ALL'
                    ? 'New events will appear here when the engine processes intelligence.'
                    : 'Choose another level to see more activity.'}
                </p>
              </div>
            )}
          </div>
          <div className="cr-panel-footer">
            <span className="cr-inline">
              <span className={`cr-indicator ${connected ? 'is-connected' : ''}`} />
              {connected ? 'Receiving telemetry' : 'Awaiting connection'}
            </span>
            <span>
              {updatedAt
                ? `Last received ${formatTime(updatedAt, settings.timezone)}`
                : 'No snapshot received'}
            </span>
          </div>
        </section>
      </div>

      <div id="correlation-review" hidden={view !== 'review'}>
        <CorrelationOperations />
      </div>

      <div id="correlation-controls" hidden={view !== 'controls'} className="cr-view-content">
        {!canControl && (
          <div className="cr-notice">
            <ShieldCheck size={16} />
            <p>You have read-only access. An operator or administrator can update stream controls.</p>
          </div>
        )}
        <div className="cr-controls-grid">
          <section className="ui-panel cr-control-card" aria-labelledby="advisory-stream-title">
            <div className="cr-section-title">
              <span className="ui-section-icon">
                <ArrowDownToLine size={18} />
              </span>
              <div>
                <h2 id="advisory-stream-title">Advisory stream</h2>
                <p>Submit intelligence to the durable processing queue.</p>
              </div>
            </div>
            <label htmlFor="advisory-ndjson">
              Advisory NDJSON <span className="cr-caption">One JSON object per line</span>
            </label>
            <textarea
              id="advisory-ndjson"
              className="cr-code-input"
              maxLength={524288}
              value={ndjson}
              onChange={(event) => setNdjson(event.target.value)}
              spellCheck={false}
              disabled={!canControl || busy}
            />
            <div className="cr-control-actions">
              <span className="cr-caption">{ndjson.length.toLocaleString()} / 524,288 characters</span>
              <button
                type="button"
                className="ui-primary"
                disabled={!canControl || busy || confirmationPending || !ndjson.trim()}
                onClick={() => setConfirmIngest(true)}
              >
                {pendingAction === 'ingest' ? (
                  <LoaderCircle size={15} className="animate-spin" />
                ) : (
                  <ArrowDownToLine size={15} />
                )}
                {pendingAction === 'ingest' ? 'Queueing…' : 'Queue advisory stream'}
              </button>
            </div>
          </section>
          <section className="ui-panel cr-control-card" aria-labelledby="worker-allocation-title">
            <div className="cr-section-title">
              <span className="ui-section-icon">
                <Layers3 size={18} />
              </span>
              <div>
                <h2 id="worker-allocation-title">Worker allocation</h2>
                <p>Set the concurrency limit for this instance.</p>
              </div>
            </div>
            <div className="cr-allocation">
              <span>Current allocation</span>
              <strong>
                {snapshot?.activeWorkers ?? '—'}{' '}
                <small>active / {snapshot?.concurrencyLimit ?? '—'} limit</small>
              </strong>
            </div>
            <label htmlFor="correlation-concurrency">
              Concurrency limit <span className="cr-caption">1–32 workers</span>
            </label>
            <div className="cr-concurrency">
              <input
                id="correlation-concurrency"
                aria-label="Concurrency limit"
                type="number"
                min={1}
                max={32}
                value={limit}
                disabled={!canControl || busy}
                onChange={(event) => setLimit(Number(event.target.value))}
              />
              <button
                type="button"
                className="ui-secondary"
                disabled={!canControl || busy || confirmationPending || !Number.isInteger(limit) || limit < 1 || limit > 32}
                onClick={() => setConfirmConcurrency(true)}
              >
                {pendingAction === 'concurrency' && <LoaderCircle size={14} className="animate-spin" />}
                {pendingAction === 'concurrency' ? 'Applying…' : 'Apply limit'}
              </button>
            </div>
            <p className="cr-caption">
              Controls and counters apply to this server instance. Changes are reflected in live telemetry.
            </p>
          </section>
        </div>
        <details className="ui-panel cr-diagnostics">
          <summary>
            <span>
              <AlertTriangle size={16} />
              Resilience diagnostics
            </span>
            <span className="cr-caption">Administrator access</span>
          </summary>
          <div>
            <p className="cr-caption">Simulations last five seconds and are disabled in production.</p>
            <div className="cr-control-actions">
              <button
                type="button"
                className="ui-secondary"
                disabled={session?.role !== 'ADMIN' || busy || confirmationPending}
                onClick={() => setConfirmFaultDatabase(true)}
              >
                Simulate DB disconnect
              </button>
              <button
                type="button"
                className="ui-secondary"
                disabled={session?.role !== 'ADMIN' || busy || confirmationPending}
                onClick={() => setConfirmFaultMemory(true)}
              >
                Simulate memory pressure
              </button>
            </div>
          </div>
        </details>
        {notice && (
          <div
            className={`cr-notice ${noticeError ? 'cr-notice-warning' : ''}`}
            role={noticeError ? 'alert' : 'status'}
          >
            {noticeError ? <AlertTriangle size={16} /> : <CheckCircle2 size={16} />}
            <p>{notice}</p>
          </div>
        )}

        {confirmIngest && (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4">
            <div className="ui-panel bg-zinc-900 dark:bg-zinc-900 light:bg-white border border-zinc-800 dark:border-zinc-800 light:border-zinc-200 rounded-2xl max-w-sm w-full p-6 shadow-2xl relative">
              <h2 className="text-sm font-bold text-zinc-100 dark:text-zinc-100 light:text-zinc-900 mb-2">
                Queue advisory stream?
              </h2>
              <p className="text-xs text-zinc-400 dark:text-zinc-400 light:text-zinc-600 leading-relaxed mb-6">
                Submit the advisory NDJSON to the durable processing queue. This cannot be undone once
                queued.
              </p>
              <div className="flex justify-end space-x-2">
                <button
                  type="button"
                  className="ui-secondary"
                  onClick={() => setConfirmIngest(false)}
                  disabled={busy}
                >
                  Cancel
                </button>
                <button
                  type="button"
                  className="ui-primary"
                  onClick={() => void executeIngest()}
                  disabled={busy}
                >
                  {busy ? 'Queuing…' : 'Confirm'}
                </button>
              </div>
            </div>
          </div>
        )}
        {confirmConcurrency && (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4">
            <div className="ui-panel bg-zinc-900 dark:bg-zinc-900 light:bg-white border border-zinc-800 dark:border-zinc-800 light:border-zinc-200 rounded-2xl max-w-sm w-full p-6 shadow-2xl relative">
              <h2 className="text-sm font-bold text-zinc-100 dark:text-zinc-100 light:text-zinc-900 mb-2">
                Apply concurrency limit?
              </h2>
              <p className="text-xs text-zinc-400 dark:text-zinc-400 light:text-zinc-600 leading-relaxed mb-6">
                Set the concurrency limit to <strong>{limit}</strong> workers. Controls and counters apply
                to this server instance.
              </p>
              <div className="flex justify-end space-x-2">
                <button
                  type="button"
                  className="ui-secondary"
                  onClick={() => setConfirmConcurrency(false)}
                  disabled={busy}
                >
                  Cancel
                </button>
                <button
                  type="button"
                  className="ui-primary"
                  onClick={() => void executeConcurrency()}
                  disabled={busy}
                >
                  {busy ? 'Applying…' : 'Confirm'}
                </button>
              </div>
            </div>
          </div>
        )}
        {confirmFaultDatabase && (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4">
            <div className="ui-panel bg-zinc-900 dark:bg-zinc-900 light:bg-white border border-zinc-800 dark:border-zinc-800 light:border-zinc-200 rounded-2xl max-w-sm w-full p-6 shadow-2xl relative">
              <h2 className="text-sm font-bold text-zinc-100 dark:text-zinc-100 light:text-zinc-900 mb-2">
                Simulate database disconnect?
              </h2>
              <p className="text-xs text-zinc-400 dark:text-zinc-400 light:text-zinc-600 leading-relaxed mb-6">
                Inject a database fault for five seconds. Simulations are disabled in production.
              </p>
              <div className="flex justify-end space-x-2">
                <button
                  type="button"
                  className="ui-secondary"
                  onClick={() => setConfirmFaultDatabase(false)}
                  disabled={busy}
                >
                  Cancel
                </button>
                <button
                  type="button"
                  className="ui-primary"
                  onClick={() => void executeFaultDatabase()}
                  disabled={busy}
                >
                  {busy ? 'Simulating…' : 'Confirm'}
                </button>
              </div>
            </div>
          </div>
        )}
        {confirmFaultMemory && (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4">
            <div className="ui-panel bg-zinc-900 dark:bg-zinc-900 light:bg-white border border-zinc-800 dark:border-zinc-800 light:border-zinc-200 rounded-2xl max-w-sm w-full p-6 shadow-2xl relative">
              <h2 className="text-sm font-bold text-zinc-100 dark:text-zinc-100 light:text-zinc-900 mb-2">
                Simulate memory pressure?
              </h2>
              <p className="text-xs text-zinc-400 dark:text-zinc-400 light:text-zinc-600 leading-relaxed mb-6">
                Inject memory pressure for five seconds. Simulations are disabled in production.
              </p>
              <div className="flex justify-end space-x-2">
                <button
                  type="button"
                  className="ui-secondary"
                  onClick={() => setConfirmFaultMemory(false)}
                  disabled={busy}
                >
                  Cancel
                </button>
                <button
                  type="button"
                  className="ui-primary"
                  onClick={() => void executeFaultMemory()}
                  disabled={busy}
                >
                  {busy ? 'Simulating…' : 'Confirm'}
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
