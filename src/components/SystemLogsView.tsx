import React, { useEffect, useRef, useState } from 'react';
import {
  AlertTriangle,
  ArrowLeft,
  ArrowRight,
  ChevronRight,
  Clock3,
  Database,
  Filter,
  HardDrive,
  Play,
  RotateCw,
  Search,
  Server,
  Trash2,
  X,
} from 'lucide-react';
import { useApp } from '../context/AppContext';
import type { OperationalEvent } from '../types';
import { EventDetailPanel } from './EventDetailPanel';
import { formatDate, formatTime, timezoneLabel } from '../utils/dateTime';
import './logs-view.css';

function contextPreview(event: OperationalEvent) {
  const context = event.context || {};
  const priority = [
    'httpStatus',
    'method',
    'route',
    'path',
    'database',
    'table',
    'durationMs',
    'connection',
    'reference',
  ];
  return [...new Set([...priority, ...Object.keys(context)])]
    .filter(
      (key) =>
        context[key] !== undefined &&
        context[key] !== null &&
        ['string', 'number', 'boolean'].includes(typeof context[key]) &&
        ![
          'timestamp', 'error', 'stack', 'query', 'subsystem', 'component', 'service',
          'source', 'runtime', 'container', 'host', 'traceId', 'requestId',
        ].includes(key),
    )
    .slice(0, 5)
    .map((key) => ({
      label: key.charAt(0).toUpperCase() + key.slice(1).replace(/([A-Z])/g, ' $1').trim(),
      value: typeof context[key] === 'boolean' ? (context[key] ? 'Yes' : 'No') : String(context[key]),
    }));
}

function runtimeSource(event: OperationalEvent) {
  const context = event.context || {};
  const key = ['subsystem', 'component', 'service', 'source', 'runtime', 'container', 'host']
    .find((candidate) => {
      const value = context[candidate];
      return ['string', 'number'].includes(typeof value) && String(value).trim() !== '';
    });
  return key ? { label: key.charAt(0).toUpperCase() + key.slice(1), value: String(context[key]) } : null;
}

function systemCorrelations(event: OperationalEvent) {
  const context = event.context || {};
  const traceId = event.trackingId ||
    (['string', 'number'].includes(typeof context.traceId) ? String(context.traceId) : '');
  return [
    event.runId && { label: 'Run', value: event.runId },
    traceId && {
      label: 'Trace',
      value: traceId,
    },
    ['string', 'number'].includes(typeof context.requestId) && {
      label: 'Request',
      value: String(context.requestId),
    },
  ].filter((item): item is { label: string; value: string } => Boolean(item));
}

export const SystemLogsView: React.FC = () => {
  const { fetchEvents, settings, csrfToken, session } = useApp();
  const canDeleteLogs = session?.role === 'ADMIN';
  const [query, setQuery] = useState('');
  const [level, setLevel] = useState('');
  const [history, setHistory] = useState<string[]>([]);
  const cursor = history.at(-1) || '';
  const [next, setNext] = useState<string | null>(null);
  const [events, setEvents] = useState<OperationalEvent[]>([]);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);
  const [updatedAt, setUpdatedAt] = useState('');
  const [selectedEvent, setSelectedEvent] = useState<OperationalEvent | null>(null);
  const [refresh, setRefresh] = useState(0);
  const searchRef = useRef<HTMLInputElement>(null);
  const pendingRequest = useRef(false);
  const filtered = Boolean(query || level);
  const clearFilters = () => {
    setQuery('');
    setLevel('');
    setHistory([]);
  };

  const [deleteDropdownOpen, setDeleteDropdownOpen] = useState(false);
  const [deleteDays, setDeleteDays] = useState<string>('30');
  const [deleting, setDeleting] = useState(false);
  const [deleteError, setDeleteError] = useState('');
  const [deleteSuccess, setDeleteSuccess] = useState('');

  const handleDeleteLogs = async () => {
    if (!canDeleteLogs || deleting || events.length === 0) return;
    const days = parseInt(deleteDays, 10);
    if (!Number.isFinite(days) || days <= 0) {
      setDeleteError('Please select a valid number of days');
      return;
    }
    setDeleting(true);
    setDeleteError('');
    setDeleteSuccess('');
    try {
      const response = await fetch('/api/events/cleanup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-csrf-token': csrfToken },
        body: JSON.stringify({ days, scope: 'SYSTEM' }),
      });
      if (!response.ok) {
        const error = await response.json().catch(() => ({ message: 'Failed to delete logs' }));
        throw new Error(error.message || 'Failed to delete logs');
      }
      const result = await response.json();
      setDeleteSuccess(`Deleted ${result.deleted} system log entries older than ${days} days`);
      setRefresh((value) => value + 1);
    } catch (error) {
      setDeleteError(error instanceof Error ? error.message : 'Failed to delete logs. Please retry.');
    } finally {
      setDeleting(false);
      setDeleteDropdownOpen(false);
    }
  };

  useEffect(() => {
    let disposed = false;
    setLoading(true);
    pendingRequest.current = true;
    setError('');
    const timer = setTimeout(() => {
      fetchEvents(
        new URLSearchParams({
          category: 'SYSTEM',
          ...(level && { level }),
          ...(query && { q: query }),
          ...(cursor && { before: cursor }),
        }).toString(),
      )
        .then((result) => {
          if (!disposed) {
            setEvents(result.events);
            setNext(result.nextCursor);
            setUpdatedAt(new Date().toISOString());
          }
        })
        .catch((error: unknown) => {
          if (!disposed) setError(error instanceof Error ? error.message : 'Please try again.');
        })
        .finally(() => {
          if (!disposed) {
            pendingRequest.current = false;
            setLoading(false);
          }
        });
    }, 250);
    return () => {
      disposed = true;
      clearTimeout(timer);
    };
  }, [query, level, cursor, refresh]);

  useEffect(() => {
    if (cursor) return;
    const update = () => {
      if (!pendingRequest.current && document.visibilityState !== 'hidden') setRefresh((value) => value + 1);
    };
    const interval = setInterval(update, 10_000);
    document.addEventListener('visibilitychange', update);
    return () => {
      clearInterval(interval);
      document.removeEventListener('visibilitychange', update);
    };
  }, [cursor]);

  const errors = events.filter((event) => event.level === 'ERROR').length;
  const warnings = events.filter((event) => event.level === 'WARNING').length;
  return (
    <section id="logs-system-panel" role="tabpanel" aria-labelledby="logs-system-tab" className="system-logs">
      <header className="system-logs-header">
        <div className="system-logs-heading">
          <span className="system-logs-icon">
            <Server size={21} aria-hidden="true" />
          </span>
          <div>
            <h2>System & Application logs</h2>
            <p>Database queries, Docker containers, application errors, and runtime diagnostics.</p>
          </div>
        </div>
        <span className={`system-logs-live ${cursor ? 'is-paused' : ''}`}>
          <span aria-hidden="true" />
          {cursor ? 'History · auto-refresh paused' : 'Auto-refresh · every 10s'}
        </span>
        <div className="relative" role="group" aria-label="Delete system logs" hidden={!canDeleteLogs}>
          <button
            type="button"
            className="system-logs-button text-rose-400 hover:text-rose-300 hover:bg-rose-500/10 light:hover:bg-rose-500/10"
            disabled={events.length === 0 || loading || deleting}
            onClick={() => setDeleteDropdownOpen(!deleteDropdownOpen)}
          >
            <Trash2 size={15} aria-hidden="true" />
            Delete logs
          </button>
          {deleteDropdownOpen && (
            <div className="absolute right-0 top-full mt-1 z-20 rounded-xl border border-zinc-700 bg-zinc-900 py-1.5 shadow-lg min-w-[180px] light:border-zinc-200 light:bg-white">
              <div className="px-3 py-2 border-b border-zinc-700 light:border-zinc-200">
                <p className="text-xs font-medium text-zinc-400 light:text-zinc-600">Delete logs older than</p>
              </div>
              <select
                value={deleteDays}
                onChange={(e) => setDeleteDays(e.target.value)}
                onBlur={() => setTimeout(() => setDeleteDropdownOpen(false), 100)}
                className="w-full px-3 py-2 text-xs text-zinc-100 bg-zinc-900 border-none focus:outline-none light:text-zinc-900 light:bg-white"
              >
                <option value="7">7 days</option>
                <option value="30">30 days</option>
                <option value="90">90 days</option>
                <option value="365">1 year</option>
              </select>
              <div className="px-3 py-2 border-t border-zinc-700 light:border-zinc-200 flex gap-1.5">
                <button
                  type="button"
                  className="system-logs-button flex-1 text-rose-400 hover:text-rose-300 hover:bg-rose-500/10 light:hover:bg-rose-500/10"
                  disabled={deleting}
                  onClick={() => void handleDeleteLogs()}
                >
                  {deleting ? 'Deleting…' : 'Confirm delete'}
                </button>
                <button
                  type="button"
                  className="system-logs-button flex-1"
                  disabled={deleting}
                  onClick={() => setDeleteDropdownOpen(false)}
                >
                  Cancel
                </button>
              </div>
            </div>
          )}
        </div>
      </header>

      <div className="ui-panel system-logs-filters">
        <div className="system-logs-filter-title">
          <Filter size={14} aria-hidden="true" /> Filter system logs
        </div>
        <div className="system-logs-filter-grid">
          <label className="system-logs-search">
            <span>Search logs</span>
            <div className="system-logs-search-control">
              <Search size={16} aria-hidden="true" />
              <input
                ref={searchRef}
                type="search"
                aria-label="Search system logs"
                maxLength={200}
                value={query}
                placeholder="Database queries, Docker, containers, application errors…"
                onChange={(event) => {
                  setQuery(event.target.value);
                  setHistory([]);
                }}
              />
              {query && (
                <button
                  type="button"
                  aria-label="Clear system search"
                  onClick={() => {
                    setQuery('');
                    setHistory([]);
                    searchRef.current?.focus();
                  }}
                >
                  <X size={15} aria-hidden="true" />
                </button>
              )}
            </div>
          </label>
          <label>
            <span>Event level</span>
            <select
              aria-label="System event level"
              value={level}
              onChange={(event) => {
                setLevel(event.target.value);
                setHistory([]);
              }}
            >
              <option value="">All levels</option>
              <option value="INFO">Info</option>
              <option value="WARNING">Warning</option>
              <option value="ERROR">Error</option>
            </select>
          </label>
          <button
            type="button"
            className="system-logs-button system-logs-refresh"
            disabled={loading}
            onClick={() => setRefresh((value) => value + 1)}
          >
            <RotateCw size={15} className={loading ? 'animate-spin' : ''} aria-hidden="true" />
            Refresh
          </button>
        </div>
        {filtered && (
          <div className="system-logs-filter-summary">
            <span>
              Filtered system logs
              {level ? ` · ${level === 'INFO' ? 'Info' : level === 'WARNING' ? 'Warning' : 'Error'}` : ''}
            </span>
            <button type="button" onClick={clearFilters}>
              <X size={13} aria-hidden="true" />
              Clear filters
            </button>
          </div>
        )}
      </div>

      {error && (
        <div role="alert" className="system-logs-error">
          <AlertTriangle size={19} aria-hidden="true" />
          <div>
            <strong>Could not {events.length ? 'refresh' : 'load'} system logs</strong>
            <p>{error}</p>
            {events.length > 0 && <p>The last loaded logs are still shown below.</p>}
          </div>
          <button
            type="button"
            className="system-logs-button"
            disabled={loading}
            onClick={() => setRefresh((value) => value + 1)}
          >
            Try again
          </button>
        </div>
      )}
      {deleteError && (
        <p role="alert" className="system-logs-error-text" style={{ color: 'var(--ui-danger)', fontSize: '13px', padding: '12px 16px', background: 'rgba(244, 63, 94, 0.05)', borderRadius: '8px', border: '1px solid rgba(244, 63, 94, 0.2)' }}>
          {deleteError}
        </p>
      )}
      {deleteSuccess && (
        <p role="status" className="system-logs-success-text" style={{ color: 'var(--ui-success)', fontSize: '13px', padding: '12px 16px', background: 'rgba(34, 197, 94, 0.05)', borderRadius: '8px', border: '1px solid rgba(34, 197, 94, 0.2)' }}>
          {deleteSuccess}
        </p>
      )}

      <div className="ui-panel system-logs-events" aria-busy={loading}>
        <div className="system-logs-events-heading">
          <div>
            <h3>Log history</h3>
            <p>
              {cursor ? 'Earlier system activity' : 'Latest system activity'}
              <span aria-hidden="true"> · </span>Times in {timezoneLabel(settings.timezone)}
            </p>
          </div>
          <div className="system-logs-page-count" role="status" aria-live="polite">
            <span>{loading ? 'Updating…' : `${events.length} logs on this page`}</span>
            {events.length > 0 && (
              <>
                <span className="system-logs-count-error">
                  {errors} {errors === 1 ? 'error' : 'errors'}
                </span>
                <span className="system-logs-count-warning">
                  {warnings} {warnings === 1 ? 'warning' : 'warnings'}
                </span>
              </>
            )}
          </div>
        </div>
        {!events.length && !error && (
          <div className="system-logs-empty" role="status">
            {loading ? (
              <RotateCw size={25} className="animate-spin" aria-hidden="true" />
            ) : (
              <Server size={27} aria-hidden="true" />
            )}
            <h3>{loading ? 'Loading system logs…' : filtered ? 'No matching logs' : 'No system logs yet'}</h3>
            <p>
              {loading
                ? 'Retrieving the system log history.'
                : filtered
                  ? 'Try another search or clear your filters to see more logs.'
                  : 'Database queries, Docker containers, application errors, and runtime diagnostics will appear here when recorded.'}
            </p>
            {filtered && !loading && (
              <button type="button" className="system-logs-button" onClick={clearFilters}>
                Clear filters
              </button>
            )}
          </div>
        )}
        {events.length > 0 && (
          <table className="system-logs-table">
            <caption className="sr-only">System log events with failure details, subsystem sources, trace correlations and local timestamps.</caption>
            <thead>
              <tr>
                <th scope="col">Level</th>
                <th scope="col">Message &amp; failure details</th>
                <th scope="col">Subsystem &amp; trace correlation</th>
                <th scope="col">Recorded</th>
              </tr>
            </thead>
            <tbody>
              {events.map((event) => {
                const preview = contextPreview(event);
                const source = runtimeSource(event);
                const correlations = systemCorrelations(event);
                return (
                  <tr
                    key={event.id}
                    onClick={() => setSelectedEvent(event)}
                    className="cursor-pointer"
                  >
                    <td className="system-logs-level-cell">
                      <span className={`system-logs-level is-${event.level.toLowerCase()}`}>
                        <span aria-hidden="true" />
                        {event.level === 'INFO' ? 'Info' : event.level === 'WARNING' ? 'Warning' : 'Error'}
                      </span>
                    </td>
                    <td className="system-logs-event-cell">
                      <code className="system-logs-code">{event.code}</code>
                      <button
                        type="button"
                        className="system-logs-event-title"
                        onClick={() => setSelectedEvent(event)}
                      >
                        {event.message}
                        <ChevronRight size={15} aria-hidden="true" />
                      </button>
                      {event.level === 'ERROR' && event.context?.error !== undefined && (
                        <p className="system-logs-error-preview" title={String(event.context.error)}>
                          {typeof event.context.error === 'string'
                            ? event.context.error
                            : 'Error details available'}
                        </p>
                      )}
                    </td>
                    <td className="system-logs-context-cell">
                      {source && (
                        <span className="system-logs-origin" title={`${source.label}: ${source.value}`}>
                          <span>{source.label}</span>
                          {source.value}
                        </span>
                      )}
                      {correlations.map((item) => (
                        <span className="system-logs-correlation" key={item.label} title={item.value}>
                          <span>{item.label}</span>
                          {item.value}
                        </span>
                      ))}
                      {preview.length > 0 ? (
                        <dl className="system-logs-context">
                          {preview.map((item) => (
                            <div key={item.label}>
                              <dt>{item.label}</dt>
                              <dd title={item.value}>{item.value}</dd>
                            </div>
                          ))}
                        </dl>
                      ) : !source && correlations.length === 0 ? (
                        <span className="system-logs-unlinked">No runtime context recorded</span>
                      ) : null}
                    </td>
                    <td className="system-logs-time-cell">
                      <time dateTime={event.timestamp} title={event.timestamp}>
                        {formatDate(event.timestamp, settings.timezone)}
                        <span>{formatTime(event.timestamp, settings.timezone)}</span>
                      </time>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
        <footer className="system-logs-footer">
          <span className="system-logs-update">
            <Clock3 size={13} aria-hidden="true" />
            {updatedAt ? `Last updated ${formatTime(updatedAt, settings.timezone)}` : 'Waiting for logs'}
            {cursor && ` · Page ${history.length + 1}`}
          </span>
          <nav aria-label="System log pages">
            <button
              type="button"
              className="system-logs-button"
              disabled={!cursor || loading}
              onClick={() => {
                setHistory([]);
                setRefresh((value) => value + 1);
              }}
            >
              Latest
            </button>
            <button
              type="button"
              className="system-logs-button"
              disabled={!cursor || loading}
              onClick={() => {
                setHistory((value) => value.slice(0, -1));
              }}
            >
              <ArrowLeft size={14} aria-hidden="true" />
              Newer
            </button>
            <button
              type="button"
              className="system-logs-button"
              disabled={!next || loading || Boolean(error)}
              onClick={() => {
                if (next) setHistory((value) => [...value, next]);
              }}
            >
              Older
              <ArrowRight size={14} aria-hidden="true" />
            </button>
          </nav>
        </footer>
      </div>
      {selectedEvent && (
        <EventDetailPanel
          event={selectedEvent}
          timezone={settings.timezone}
          onClose={() => setSelectedEvent(null)}
        />
      )}
    </section>
  );
};