import React from 'react';
import { useDialogFocus } from '../hooks/useDialogFocus';
import {
  X,
  Search,
  Copy,
  Check,
  AlertTriangle,
  Clock,
  Cpu,
  Timer,
  Fingerprint,
  Database,
  RotateCw,
} from 'lucide-react';
import type { OperationalEvent } from '../types';
import { formatEventContext, humanizeEventKey } from '../utils/eventText';
import { formatDateTime, timezoneLabel } from '../utils/dateTime';

const LEVEL_STYLES: Record<OperationalEvent['level'], string> = {
  INFO: 'border-blue-500/20 bg-blue-500/10 text-blue-300 light:text-blue-700',
  WARNING: 'border-amber-500/20 bg-amber-500/10 text-amber-400 light:text-amber-700',
  ERROR: 'border-rose-500/20 bg-rose-500/10 text-rose-400 light:text-rose-700',
};

const ms = (value: number | undefined) =>
  value === undefined ? null : value >= 1000 ? `${(value / 1000).toFixed(2)} s` : `${value.toFixed(0)} ms`;

/** Human title for a telemetry event name: "ingestion.committed" becomes "Ingestion · committed". */
function prettyEventName(event: string): string {
  const [head, ...rest] = event.split('.');
  const main = head ? head.charAt(0).toUpperCase() + head.slice(1) : event;
  return [main, ...rest.map((part) => part.replace(/_/g, ' '))].join(' \u00b7 ');
}

function CopyButton({ value, label }: { value: string; label: string }) {
  const [copied, setCopied] = React.useState(false);
  return (
    <button
      type="button"
      title={`Copy ${label}`}
      aria-label={`Copy ${label}`}
      onClick={() => {
        void navigator.clipboard?.writeText(value).then(
          () => {
            setCopied(true);
            setTimeout(() => setCopied(false), 1500);
          },
          () => undefined,
        );
      }}
      className="inline-flex items-center gap-1 rounded-md px-1.5 py-1 text-[10px] text-zinc-500 transition hover:bg-zinc-800 hover:text-zinc-200 light:hover:bg-zinc-100 light:hover:text-zinc-900"
    >
      {copied ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
      {copied ? 'Copied' : 'Copy'}
    </button>
  );
}

/** One labelled fact in the metric strip. */
function Metric({ icon: Icon, label, value }: { icon: typeof Clock; label: string; value: React.ReactNode }) {
  return (
    <div className="min-w-0 rounded-xl border-zinc-800/80 bg-zinc-950/60 px-3 py-2.5 light:border-zinc-200 light:bg-zinc-50">
      <dt className="flex items-center gap-1.5 text-[9px] font-semibold uppercase tracking-[0.12em] text-zinc-500">
        <Icon className="h-3 w-3" aria-hidden="true" />
        {label}
      </dt>
      <dd className="mt-1 truncate font-mono text-[11px] text-zinc-200 light:text-zinc-800">{value}</dd>
    </div>
  );
}

/**
 * Full-detail inspector for a single operational event.
 *
 * Rendered as a centred modal (matching the audit-trail detail dialog) so a
 * selected event opens as a popup rather than a side drawer, with the backdrop
 * keeping focus on the event and dismissing on Escape or click-away.
 *
 * Structured context is rendered as labelled text, not JSON — the raw JSON stays
 * available behind an explicit toggle for anyone who needs to paste it.
 */
export const EventDetailPanel: React.FC<{
  event: OperationalEvent;
  /** Operator-configured timezone (`settings.timezone`); local when unset. */
  timezone?: string;
  onClose: () => void;
  onFilterByTrackingId?: (trackingId: string) => void;
}> = ({ event, timezone, onClose, onFilterByTrackingId }) => {
  const [raw, setRaw] = React.useState(false);
  const dialogRef = useDialogFocus(onClose);

  const title = event.event ? prettyEventName(event.event) : event.code;
  const errorText = event.context?.error;
  const timings: { icon: typeof Clock; label: string; value: string }[] = [];
  const queue = [
    { icon: Timer, label: 'Ingestion', value: ms(event.ingestionLatencyMs) },
    { icon: Clock, label: 'Extraction', value: ms(event.extractionLatencyMs) },
    { icon: Database, label: 'Database', value: ms(event.totalDatabaseTimeMs) },
  ];
  for (const item of queue) if (item.value) timings.push({ ...item, value: item.value });

  return (
    <div
      ref={dialogRef}
      tabIndex={-1}
      role="dialog"
      aria-modal="true"
      aria-labelledby="event-detail-title"
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <aside className="flex w-full max-w-2xl flex-col rounded-2xl border border-zinc-800 bg-zinc-900 shadow-2xl light:border-zinc-200 light:bg-white max-h-[calc(100dvh-2rem)] overflow-hidden">
        <header className="shrink-0 border-b border-zinc-800/80 px-5 py-4 light:border-zinc-200">
          <div className="flex items-start justify-between gap-3">
            <div className="min-w-0">
              <div className="flex flex-wrap items-center gap-2">
                <span
                  className={`inline-flex rounded-full border px-2 py-0.5 text-[10px] font-semibold ${LEVEL_STYLES[event.level]}`}
                >
                  {event.level}
                </span>
                <span className="rounded-md border-zinc-700/70 bg-zinc-800/60 px-2 py-0.5 font-mono text-[10px] text-zinc-300 light:border-zinc-200 light:bg-zinc-100 light:text-zinc-700">
                  {event.category}
                </span>
                {event.attempt !== undefined && (
                  <span className="inline-flex items-center gap-1 rounded-full border-amber-500/20 bg-amber-500/10 px-2 py-0.5 text-[10px] font-medium text-amber-400 light:text-amber-700">
                    <RotateCw className="h-2.5 w-2.5" />
                    Attempt {event.attempt + 1}
                  </span>
                )}
              </div>
              <h2
                id="event-detail-title"
                className="mt-2 break-words text-base font-semibold text-zinc-100 light:text-zinc-900"
              >
                {title}
              </h2>
              {event.event && event.event !== title && (
                <p className="mt-1 font-mono text-[11px] text-zinc-500">{event.event}</p>
              )}
            </div>
            <button
              onClick={onClose}
              aria-label="Close event details"
              className="shrink-0 rounded-lg border-zinc-700/70 p-1.5 text-zinc-400 transition hover:bg-zinc-800 hover:text-zinc-100 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 light:border-zinc-300 light:hover:bg-zinc-100 light:hover:text-zinc-900"
            >
              <X className="h-4 w-4" />
            </button>
          </div>
        </header>

        <div className="min-h-0 flex-1 overflow-y-auto px-5 py-4">
          <p className="text-sm leading-relaxed text-zinc-200 light:text-zinc-800">{event.message}</p>

          {errorText !== undefined && (
            <div className="mt-4 rounded-xl border-rose-500/25 bg-rose-500/[0.06] p-3">
              <div className="flex items-center gap-2 text-[10px] font-semibold uppercase tracking-wider text-rose-300 light:text-rose-700">
                <AlertTriangle className="h-3.5 w-3.5" />
                Failure detail
              </div>
              <pre className="mt-2 max-h-56 overflow-auto whitespace-pre-wrap break-words font-mono text-[11px] leading-relaxed text-rose-200 light:text-rose-900">
                {String(errorText as string)}
              </pre>
            </div>
          )}

          <dl className="mt-4 grid grid-cols-[repeat(auto-fit,minmax(150px,1fr))] gap-2.5">
            <Metric
              icon={Clock}
              label={`Occurred (${timezoneLabel(timezone)})`}
              value={formatDateTime(event.timestamp, timezone)}
            />
            {event.runId && <Metric icon={Cpu} label="Execution" value={event.runId.slice(0, 8)} />}
            {timings.map((timing) => (
              <Metric key={timing.label} icon={timing.icon} label={timing.label} value={timing.value} />
            ))}
            {event.sequence !== undefined && (
              <Metric icon={Fingerprint} label="Worker seq" value={`#${event.sequence}`} />
            )}
          </dl>

          {event.runId && (
            <div className="mt-3 flex items-center gap-2 rounded-lg border-zinc-800/80 bg-zinc-950/50 px-3 py-2 light:border-zinc-200 light:bg-zinc-50">
              <Cpu className="h-3.5 w-3.5 shrink-0 text-indigo-400 light:text-indigo-600" />
              <span className="text-[10px] font-semibold uppercase tracking-wider text-zinc-500">
                Execution ID
              </span>
              <code className="min-w-0 flex-1 truncate font-mono text-[11px] text-zinc-300 light:text-zinc-700">
                {event.runId}
              </code>
              <CopyButton value={event.runId} label="execution ID" />
            </div>
          )}

          {event.trackingId && (
            <div className="mt-2 flex items-center gap-2 rounded-lg border-zinc-800/80 bg-zinc-950/50 px-3 py-2 light:border-zinc-200 light:bg-zinc-50">
              <Fingerprint className="h-3.5 w-3.5 shrink-0 text-teal-400 light:text-teal-600" />
              <span className="text-[10px] font-semibold uppercase tracking-wider text-zinc-500">
                Tracking ID
              </span>
              <code className="min-w-0 flex-1 truncate font-mono text-[11px] text-zinc-300 light:text-zinc-700">
                {event.trackingId}
              </code>
              {onFilterByTrackingId && (
                <button
                  type="button"
                  onClick={() => onFilterByTrackingId(event.trackingId!)}
                  className="inline-flex items-center gap-1 rounded-md px-1.5 py-1 text-[10px] text-blue-300 transition hover:bg-blue-500/10 light:text-blue-700"
                >
                  <Search className="h-3 w-3" />
                  Trace
                </button>
              )}
              <CopyButton value={event.trackingId} label="tracking ID" />
            </div>
          )}

          <div className="mt-5">
            <div className="flex items-center justify-between">
              <h3 className="text-[10px] font-semibold uppercase tracking-[0.14em] text-zinc-500">
                Structured context
              </h3>
              <button
                type="button"
                onClick={() => setRaw((v) => !v)}
                aria-pressed={raw}
                className="rounded-md border-zinc-700/70 px-2 py-1 text-[10px] font-medium text-zinc-400 transition hover:text-zinc-200 light:border-zinc-300 light:hover:text-zinc-900"
              >
                {raw ? 'Readable view' : 'Raw JSON'}
              </button>
            </div>
            <pre className="mt-2 max-h-[45vh] overflow-auto whitespace-pre-wrap break-words rounded-xl border-zinc-800/80 bg-zinc-950/70 p-3 font-mono text-[11px] leading-relaxed text-zinc-300 light:border-zinc-200 light:bg-zinc-50 light:text-zinc-700">
              {raw ? (JSON.stringify(event.context, null, 2) ?? 'null') : formatEventContext(event.context)}
            </pre>
          </div>
        </div>

        <footer className="shrink-0 border-t border-zinc-800/80 px-5 py-3 light:border-zinc-200">
          <div className="flex items-center justify-between gap-3">
            <code className="truncate font-mono text-[10px] text-zinc-600">#{event.id}</code>
            <CopyButton value={JSON.stringify(event, null, 2)} label="event" />
          </div>
        </footer>
      </aside>
    </div>
  );
};
