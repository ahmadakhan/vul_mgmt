import { PageHeading } from './PageHeading';
import React, { useEffect, useState } from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  Clock3,
  Cpu,
  Database,
  Mail,
  RefreshCw,
  Server,
  ShieldCheck,
} from 'lucide-react';
import { useApp } from '../context/AppContext';
import type { SystemHealth } from '../types';
import { formatDateTime as fmtDateTime } from '../utils/dateTime';
import './system-health.css';

type Tone = 'good' | 'warning' | 'neutral';
const tones: Record<Tone, string> = {
  good: 'border-emerald-500/20 bg-emerald-500/10 text-emerald-400 light:text-emerald-700',
  warning: 'border-amber-500/25 bg-amber-500/10 text-amber-400 light:text-amber-700',
  neutral: 'border-zinc-500/20 bg-zinc-500/10 text-zinc-400 light:text-zinc-600',
};
const panel =
  'rounded-2xl border border-zinc-800/80 bg-zinc-900/50 shadow-sm light:border-zinc-200 light:bg-white';
const muted = 'text-zinc-400 light:text-zinc-600';
const date = (value: string | null, timezone?: string) =>
  value ? fmtDateTime(value, timezone) : 'Not available';
const duration = (seconds: number) => {
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  return days
    ? `${days}d ${hours}h`
    : hours
      ? `${hours}h ${minutes}m`
      : minutes
        ? `${minutes}m`
        : `${seconds}s`;
};

function Badge({ children, tone = 'neutral' }: { children: React.ReactNode; tone?: Tone }) {
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-[11px] font-medium ${tones[tone]}`}
    >
      <span className="h-1.5 w-1.5 shrink-0 rounded-full bg-current" />
      {children}
    </span>
  );
}

export function SystemHealthView() {
  const { health, settings } = useApp();
  const [status, setStatus] = useState<SystemHealth | null>(null);
  const [busy, setBusy] = useState(false);
  const [refreshFailed, setRefreshFailed] = useState(false);

  const refresh = async () => {
    setBusy(true);
    setRefreshFailed(false);
    try {
      const result = await health();
      if (result) setStatus(result);
      else setRefreshFailed(true);
    } catch {
      setRefreshFailed(true);
    } finally {
      setBusy(false);
    }
  };

  useEffect(() => {
    void refresh();
    const timer = setInterval(() => {
      if (document.visibilityState !== 'hidden') void refresh();
    }, 10_000);
    const onVisibility = () => {
      if (document.visibilityState === 'visible') void refresh();
    };
    document.addEventListener('visibilitychange', onVisibility);
    return () => {
      clearInterval(timer);
      document.removeEventListener('visibilitychange', onVisibility);
    };
  }, []);

  const count = (name: string) => status?.backlog.find((row) => row.status === name)?.count ?? 0;
  const attention =
    !!status &&
    (status.database !== 'connected' ||
      ['STALE', 'NOT_OBSERVED'].includes(status.workerStatus) ||
      !status.emailConfigured ||
      !status.csrfEnforced ||
      !status.ssrfEnforced ||
      status.deliveryQueue.expiredLeases > 0 ||
      count('FAILED') > 0 ||
      (status.schedulerEnabled &&
        !!status.lastScheduledRun &&
        Date.now() - Date.parse(status.lastScheduledRun) >
          status.schedulerIntervalMinutes * 60_000 * 2));
  const workerTone: Tone =
    status?.workerStatus === 'HEALTHY' ? 'good' : status?.workerStatus === 'DISABLED' ? 'neutral' : 'warning';
  const overallTone: Tone = refreshFailed || attention ? 'warning' : 'good';

  return (
    <div className="system-health space-y-6 text-zinc-100 light:text-zinc-900" aria-busy={busy}>
      <header className="ui-page-header">
        <PageHeading page="health">
          Infrastructure status, worker activity, delivery backlog, and runtime safeguards.
        </PageHeading>
        <button
          className="inline-flex shrink-0 items-center justify-center gap-2 rounded-xl border border-zinc-700 bg-zinc-900 px-3.5 py-2.5 text-xs font-medium text-zinc-200 transition hover:border-zinc-600 hover:bg-zinc-800 disabled:cursor-wait disabled:opacity-60 light:border-zinc-300 light:bg-white light:text-zinc-800 light:hover:bg-zinc-100"
          disabled={busy}
          onClick={() => void refresh()}
        >
          <RefreshCw className={`h-3.5 w-3.5 ${busy ? 'animate-spin' : ''}`} />
          {busy ? 'Refreshing status' : 'Refresh status'}
        </button>
      </header>

      {refreshFailed && (
        <div role="alert" className={`flex items-start gap-3 rounded-xl border p-4 text-sm ${tones.warning}`}>
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
          <div>
            <p className="font-medium">Health refresh failed</p>
            <p className="mt-0.5 text-xs opacity-80">
              {status
                ? 'Showing the last successful snapshot.'
                : 'Check the server connection and try again.'}
            </p>
          </div>
        </div>
      )}

      {!status ? (
        busy ? (
          <div
            role="status"
            className={`${panel} flex min-h-56 items-center justify-center gap-3 p-10 text-sm ${muted}`}
          >
            <RefreshCw className="h-4 w-4 animate-spin" /> Checking system components…
          </div>
        ) : (
          <div className={`${panel} flex min-h-56 flex-col items-center justify-center p-10 text-center`}>
            <span className="grid h-11 w-11 place-items-center rounded-full bg-zinc-800 text-zinc-400 light:bg-zinc-100 light:text-zinc-500">
              <Server className="h-5 w-5" />
            </span>
            <h2 className="mt-4 text-sm font-semibold">Health data unavailable</h2>
            <p className={`mt-1 text-xs ${muted}`}>Refresh to check system status.</p>
          </div>
        )
      ) : (
        <>
          <section className={`${panel} relative overflow-hidden p-5 sm:p-6`} aria-live="polite">
            <div
              className={`absolute inset-y-0 left-0 w-1 ${overallTone === 'warning' ? 'bg-amber-400' : 'bg-emerald-400'}`}
            />
            <div className="flex flex-col gap-4 pl-2 sm:flex-row sm:items-center sm:justify-between">
              <div className="flex items-start gap-3.5">
                <span
                  className={`grid h-10 w-10 shrink-0 place-items-center rounded-xl border ${tones[overallTone]}`}
                >
                  {refreshFailed || attention ? (
                    <AlertTriangle className="h-5 w-5" />
                  ) : (
                    <CheckCircle2 className="h-5 w-5" />
                  )}
                </span>
                <div>
                  <h2 className="text-base font-semibold tracking-tight">
                    {refreshFailed
                      ? 'Snapshot may be out of date'
                      : attention
                        ? 'Review system attention items'
                        : status.workerStatus === 'DISABLED'
                          ? 'Services reachable · worker disabled'
                          : 'All monitored services are healthy'}
                  </h2>
                  <p className={`mt-1 max-w-2xl text-xs leading-relaxed ${muted}`}>
                    {refreshFailed
                      ? 'The most recent successful health check is shown below.'
                      : attention
                        ? 'One or more services need review. Details are grouped below by operational area.'
                        : 'Database connectivity and configured runtime checks are passing.'}
                  </p>
                </div>
              </div>
              <div className="shrink-0 border-t border-zinc-800/70 pl-0 pt-3 text-xs sm:border-l sm:border-t-0 sm:pl-5 sm:pt-0 light:border-zinc-200">
                <p className={`text-[10px] font-semibold uppercase tracking-wider ${muted}`}>Last checked</p>
                <time className="mt-1 block font-medium tabular-nums" dateTime={status.checkedAt}>
                  {date(status.checkedAt, settings.timezone)}
                </time>
              </div>
            </div>
          </section>

          <section aria-label="Service status" className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
            {[
              {
                name: 'Database',
                icon: Database,
                value: `${status.databaseLatencyMs} ms`,
                detail: 'Query response time',
                label: status.database === 'connected' ? 'Connected' : 'Unavailable',
                tone: status.database === 'connected' ? 'good' : 'warning',
              },
              {
                name: 'Background worker',
                icon: Server,
                value:
                  status.workerStatus === 'DISABLED'
                    ? 'Disabled'
                    : status.heartbeatAgeSeconds === null
                      ? 'Not observed'
                      : `${status.heartbeatAgeSeconds}s ago`,
                detail: 'Latest worker heartbeat',
                label:
                  status.workerStatus === 'HEALTHY'
                    ? 'Healthy'
                    : status.workerStatus === 'DISABLED'
                      ? 'Disabled'
                      : status.workerStatus === 'STALE'
                        ? 'Stale heartbeat'
                        : 'Waiting for heartbeat',
                tone: workerTone,
              },
              {
                name: 'Email delivery',
                icon: Mail,
                value: status.emailProvider || 'SMTP',
                detail: 'Configured transport provider',
                label: status.emailConfigured ? 'Ready' : 'Setup required',
                tone: status.emailConfigured ? 'good' : 'warning',
              },
              {
                name: 'Process memory',
                icon: Cpu,
                value: `${Math.round(status.heapBytes / 1024 / 1024)} MiB`,
                detail: `Uptime ${duration(status.uptimeSeconds)}`,
                label: 'Heap in use',
                tone: 'neutral',
              },
            ].map((item) => (
              <article key={item.name} className={`${panel} min-w-0 p-5`}>
                <div className="flex items-center justify-between gap-3">
                  <h2 className={`text-xs font-medium ${muted}`}>{item.name}</h2>
                  <span className="grid h-8 w-8 place-items-center rounded-lg border border-zinc-800 bg-zinc-950/60 text-zinc-400 light:border-zinc-200 light:bg-zinc-50 light:text-zinc-500">
                    <item.icon className="h-4 w-4" />
                  </span>
                </div>
                <p className="mt-4 break-words text-2xl font-semibold tracking-tight tabular-nums">
                  {item.value}
                </p>
                <p className={`mt-1 text-xs ${muted}`}>{item.detail}</p>
                <div className="mt-4">
                  <Badge tone={item.tone as Tone}>{item.label}</Badge>
                </div>
              </article>
            ))}
          </section>

          <div className="grid gap-5 lg:grid-cols-3">
            <section
              className={`${panel} min-w-0 p-5 sm:p-6 lg:col-span-2`}
              aria-labelledby="delivery-health-heading"
            >
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div>
                  <h2 id="delivery-health-heading" className="text-base font-semibold">
                    Delivery queue
                  </h2>
                  <p className={`mt-1 text-xs ${muted}`}>
                    Transport acceptance is tracked separately from inbox delivery.
                  </p>
                </div>
                <Badge tone={count('FAILED') ? 'warning' : 'neutral'}>
                  {status.backlog.reduce((sum, row) => sum + row.count, 0).toLocaleString()} total jobs
                </Badge>
              </div>
              <div className="my-5 grid grid-cols-2 gap-3 sm:grid-cols-4">
                {[
                  ['QUEUED', 'Queued'],
                  ['SENDING', 'Sending'],
                  ['ACCEPTED', 'Accepted'],
                  ['FAILED', 'Failed'],
                ].map(([key, label]) => (
                  <div
                    key={key}
                    className={`rounded-xl border p-4 ${key === 'FAILED' && count(key) > 0 ? 'border-amber-500/30 bg-amber-500/[0.06]' : 'border-zinc-800/80 bg-zinc-950/40 light:border-zinc-200 light:bg-zinc-50'}`}
                  >
                    <p
                      className={`text-xs ${key === 'FAILED' && count(key) ? 'text-amber-400 light:text-amber-700' : muted}`}
                    >
                      {label}
                    </p>
                    <p className="mt-2 text-2xl font-semibold tabular-nums">{count(key).toLocaleString()}</p>
                  </div>
                ))}
              </div>
              <dl className="divide-y divide-zinc-800/70 text-xs light:divide-zinc-200">
                {[
                  ['Ready for processing', `${status.deliveryQueue.dueJobs.toLocaleString()} jobs`],
                  [
                    'Oldest due delivery',
                    status.deliveryQueue.oldestDueCreatedAt
                      ? date(status.deliveryQueue.oldestDueCreatedAt, settings.timezone)
                      : 'No deliveries due',
                  ],
                  [
                    'Next delayed retry',
                    status.deliveryQueue.nextScheduledAttempt
                      ? date(status.deliveryQueue.nextScheduledAttempt, settings.timezone)
                      : 'No retries scheduled',
                  ],
                  [
                    'Recoverable delivery leases',
                    `${status.deliveryQueue.expiredLeases.toLocaleString()} expired`,
                  ],
                ].map(([label, value]) => (
                  <div key={label} className="flex flex-col justify-between gap-1 py-3 sm:flex-row sm:gap-4">
                    <dt className={muted}>{label}</dt>
                    <dd className="break-words font-medium tabular-nums sm:text-right">{value}</dd>
                  </div>
                ))}
              </dl>
            </section>

            <section className={`${panel} min-w-0 p-5 sm:p-6`} aria-labelledby="runtime-health-heading">
              <div className="flex items-center gap-2.5">
                <span className="grid h-8 w-8 place-items-center rounded-lg border border-indigo-500/20 bg-indigo-500/10 text-indigo-300 light:text-indigo-700">
                  <ShieldCheck className="h-4 w-4" />
                </span>
                <div>
                  <h2 id="runtime-health-heading" className="text-sm font-semibold">
                    Runtime safeguards
                  </h2>
                  <p className={`mt-0.5 text-[11px] ${muted}`}>Security and scheduling checks</p>
                </div>
              </div>
              <div className="mt-5 space-y-3 text-xs">
                {[
                  {
                    label: 'HTTPS',
                    value: status.httpsRequired ? 'Required' : 'Development mode',
                    tone: status.httpsRequired ? 'good' : 'neutral',
                  },
                  {
                    label: 'CSRF protection',
                    value: status.csrfEnforced ? 'Enforced' : 'Not enforced',
                    tone: status.csrfEnforced ? 'good' : 'warning',
                  },
                  {
                    label: 'Outbound address validation',
                    value: status.ssrfEnforced ? 'Enforced' : 'Not enforced',
                    tone: status.ssrfEnforced ? 'good' : 'warning',
                  },
                ].map((row) => (
                  <div
                    key={row.label}
                    className="flex flex-wrap items-center justify-between gap-2 border-b border-zinc-800/60 pb-3 light:border-zinc-200"
                  >
                    <span className={muted}>{row.label}</span>
                    <Badge tone={row.tone as Tone}>{row.value}</Badge>
                  </div>
                ))}
              </div>
              <div className="mt-5 space-y-4 border-t border-zinc-800/70 pt-4 text-xs light:border-zinc-200">
                <div>
                  <p className={`flex items-center gap-1.5 ${muted}`}>
                    <Clock3 className="h-3.5 w-3.5" />
                    Last scheduled run
                  </p>
                  <p className="mt-1.5 break-words font-medium leading-relaxed">
                    {status.lastScheduledRun ? date(status.lastScheduledRun, settings.timezone) : 'Not yet run'}
                  </p>
                  {status.schedulerEnabled && status.lastScheduledRun
                    ? (() => {
                        const ageMinutes = Math.floor((Date.now() - Date.parse(status.lastScheduledRun)) / 60000);
                        const stale = ageMinutes > status.schedulerIntervalMinutes * 2;
                        return (
                          <>
                            <p className={`mt-1 text-[10px] ${stale ? 'text-amber-400 light:text-amber-700' : muted}`}>
                              Interval: {status.schedulerIntervalMinutes} min · Age: {ageMinutes} min
                            </p>
                            {stale && (
                              <p className="mt-1 text-[11px] text-amber-400 light:text-amber-700">
                                Scheduler is enabled but no run has started in over twice the configured interval.
                              </p>
                            )}
                          </>
                        );
                      })()
                    : !status.schedulerEnabled && (
                      <p className="mt-1 text-[11px] text-zinc-500 light:text-zinc-500">Scheduler is disabled in settings</p>
                    )}
                </div>
                <div>
                  <p className={muted}>Next scheduled run</p>
                  <p className="mt-1.5 break-words font-medium leading-relaxed">
                    {status.schedulerEnabled
                      ? status.nextScheduledRun
                        ? date(status.nextScheduledRun, settings.timezone)
                        : 'Imminent'
                      : 'Scheduler disabled'}
                  </p>
                </div>
                <div>
                  <p className={muted}>Clock synchronization</p>
                  <p className="mt-1.5 leading-relaxed">{status.ntp}</p>
                </div>
              </div>
            </section>
          </div>
        </>
      )}
    </div>
  );
}
