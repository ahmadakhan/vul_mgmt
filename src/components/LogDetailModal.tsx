import React, { useId } from 'react';
import { useDialogFocus } from '../hooks/useDialogFocus';
import { X } from 'lucide-react';
import { formatDateTime as fmtDateTime, timezoneLabel } from '../utils/dateTime';

export interface LogDetailField {
  label: string;
  value: React.ReactNode;
  /** Render the value in the monospace/code font. */
  mono?: boolean;
  /** Render the value as a wrapped, scrollable block instead of a single line
   * (long text, JSON, hashes). */
  block?: boolean;
  /** Only render this field when it has a meaningful value. */
  hidden?: boolean;
}

const LEVEL_BADGE: Record<'INFO' | 'WARNING' | 'ERROR', string> = {
  INFO: 'border-blue-500/20 bg-blue-500/10 text-blue-300 light:text-blue-700',
  WARNING: 'border-amber-500/20 bg-amber-500/10 text-amber-400 light:text-amber-700',
  ERROR: 'border-rose-500/20 bg-rose-500/10 text-rose-400 light:text-rose-700',
};

interface LogDetailModalProps {
  icon: React.ReactNode;
  eyebrow: string;
  title: string;
  level: 'INFO' | 'WARNING' | 'ERROR';
  timestamp: string;
  timestampDisplay?: string;
  fields: LogDetailField[];
  /** Operator-configured timezone (`settings.timezone`); local when unset. */
  timezone?: string;
  onClose: () => void;
}

export const LogDetailModal: React.FC<LogDetailModalProps> = ({
  icon,
  eyebrow,
  title,
  level,
  timestamp,
  timestampDisplay,
  fields,
  timezone,
  onClose,
}) => {
  const dialogRef = useDialogFocus(onClose);
  const titleId = useId();
  return (
    <div
      ref={dialogRef}
      role="dialog"
      aria-modal="true"
      aria-labelledby={titleId}
      tabIndex={-1}
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) onClose();
      }}
      className="audit-log-dialog fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4"
    >
      <div className="audit-log-sheet ui-panel relative max-h-[calc(100dvh-2rem)] overflow-y-auto w-full max-w-2xl rounded-2xl border border-zinc-800 bg-zinc-900 p-6 shadow-2xl light:border-zinc-200 light:bg-white">
        <div className="audit-log-header">
          <button
            type="button"
            onClick={onClose}
            aria-label="Close"
            className="absolute right-4 top-4 grid h-9 w-9 place-items-center rounded-lg border border-zinc-700 text-zinc-500 transition hover:text-zinc-200 light:hover:text-zinc-900"
          >
            <X className="h-5 w-5" />
          </button>

          <div className="flex items-start gap-3 pr-8">
            <span className="grid h-9 w-9 shrink-0 place-items-center rounded-xl border border-zinc-700/80 bg-zinc-800/60 text-zinc-300 light:border-zinc-200 light:bg-zinc-100 light:text-zinc-700">
              {icon}
            </span>
            <div className="min-w-0">
              <p className="text-[10px] font-semibold uppercase tracking-[0.18em] text-zinc-500">{eyebrow}</p>
              <h2
                id={titleId}
                className="mt-0.5 break-words text-sm font-semibold text-zinc-100 light:text-zinc-900"
              >
                {title}
              </h2>
            </div>
          </div>

          <div className="mt-4 flex flex-wrap items-center gap-2">
            <span
              className={`inline-flex rounded-full border px-2 py-1 text-[10px] font-semibold ${LEVEL_BADGE[level]}`}
            >
              {level}
            </span>
            <span className="text-[11px] text-zinc-500">
              {timestampDisplay ?? `${fmtDateTime(timestamp, timezone)} ${timezoneLabel(timezone)}`}
            </span>
          </div>
        </div>
        <dl className="audit-log-body text-xs">
          {fields
            .filter((f) => !f.hidden)
            .map((field) => (
              <div key={field.label} className={field.block ? 'audit-log-block' : undefined}>
                <dt className="text-[10px] font-semibold uppercase tracking-wider text-zinc-500">
                  {field.label}
                </dt>
                <dd
                  className={
                    field.block
                      ? `mt-1.5 max-h-64 overflow-auto whitespace-pre-wrap break-words rounded-lg border border-zinc-700/50 bg-zinc-950/80 p-3 text-[11px] leading-relaxed text-zinc-300 light:border-zinc-200 light:bg-zinc-50 light:text-zinc-700 ${field.mono ? 'font-mono' : ''}`
                      : `mt-1 break-words text-[12px] text-zinc-200 light:text-zinc-800 ${field.mono ? 'font-mono' : ''}`
                  }
                >
                  {field.value}
                </dd>
              </div>
            ))}
        </dl>
        <div className="audit-log-footer">
          <span>Retained audit entry · Timestamps in {timezoneLabel(timezone)}</span>
          <button type="button" className="ui-secondary" onClick={onClose}>
            Close details
          </button>
        </div>
      </div>
    </div>
  );
};
