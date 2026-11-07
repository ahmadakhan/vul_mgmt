/**
 * Centralized, timezone-aware date formatting.
 *
 * All human-readable dates in the UI are rendered through these helpers so that
 * the display shape (`dd MMM yyyy`) and the workspace timezone stay consistent.
 * `timezone` is sourced from `settings.timezone`. When the operator has not
 * configured one — or stored a value this runtime cannot render — the system
 * falls back to `DEFAULT_TIMEZONE`, which resolves to the runtime's local zone.
 * That keeps every date/time label aligned with local time instead of UTC.
 */
import { DEFAULT_TIMEZONE } from '../../shared/state';

const CACHE = new Map<string, Intl.DateTimeFormat>();

/**
 * Configured timezone when valid, otherwise the documented system default.
 * The server's daily-digest scheduler uses the same rule, so a displayed time
 * and the schedule that produced it never disagree.
 */
export const resolveTimezone = (timezone?: string | null): string => {
  if (!timezone) return DEFAULT_TIMEZONE;
  try {
    new Intl.DateTimeFormat('en', { timeZone: timezone });
    return timezone;
  } catch {
    return DEFAULT_TIMEZONE;
  }
};

const formatter = (
  timezone: string | undefined,
  options: Intl.DateTimeFormatOptions,
): Intl.DateTimeFormat => {
  const tz = resolveTimezone(timezone);
  const key = `${tz}|${JSON.stringify(options)}`;
  const cached = CACHE.get(key);
  if (cached) return cached;
  const instance = new Intl.DateTimeFormat('en-GB', { timeZone: tz, ...options });
  CACHE.set(key, instance);
  return instance;
};

const toDate = (value: string | Date | undefined | null): Date | null => {
  if (value === undefined || value === null) return null;
  const date = value instanceof Date ? value : new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
};

export const formatTime = (value: string | Date | undefined | null, timezone?: string): string => {
  const date = toDate(value);
  if (!date) return '—';
  return formatter(timezone, { hour: '2-digit', minute: '2-digit', hourCycle: 'h23' }).format(date);
};

export const formatDate = (value: string | Date | undefined | null, timezone?: string): string => {
  const date = toDate(value);
  if (!date) return '—';
  return formatter(timezone, { day: '2-digit', month: 'short', year: 'numeric' }).format(date);
};

/** Timezone label to append to a rendered timestamp, so the reader knows which
 * clock it refers to (e.g. `29 Oct 2026, 14:03 UTC`). */
export const timezoneLabel = (timezone?: string | null): string => resolveTimezone(timezone);

/**
 * Offset of `timezone` from UTC at the instant `at`, as `UTC+N` / `UTC-N` /
 * `UTC+5:30`.
 *
 * The offset is computed per-instant with `Intl.formatToParts` rather than
 * stored, so a zone with daylight saving reports the offset that actually
 * applied when the timestamp was taken (a July timestamp shows UTC+2 in
 * Europe/Berlin; a January one shows UTC+1). A bare `UTC` label is not enough
 * for a distributed security team — two readers in different zones would read
 * the same label as two different times.
 */
export const utcOffsetLabel = (
  value: string | Date | undefined | null = new Date(),
  timezone?: string | null,
): string => {
  const date = toDate(value) ?? new Date();
  const tz = resolveTimezone(timezone);
  try {
    // `longOffset` yields "GMT+02:00"; `shortOffset` yields "GMT+2".
    const parts = new Intl.DateTimeFormat('en-US', {
      timeZone: tz,
      timeZoneName: 'longOffset',
    }).formatToParts(date);
    const raw = parts.find((part) => part.type === 'timeZoneName')?.value ?? '';
    if (!raw) return tz === 'UTC' ? 'UTC+0' : tz;
    // "GMT+02:00" -> "UTC+2", "GMT+05:30" -> "UTC+5:30", "GMT" -> "UTC+0".
    const match = /GMT([+-])(\d{1,2})(?::(\d{2}))?/.exec(raw);
    if (!match) return 'UTC+0';
    const [, sign, hours, minutes] = match;
    const hour = Number(hours);
    const minute = Number(minutes ?? '0');
    if (hour === 0 && minute === 0) return 'UTC+0';
    return `UTC${sign}${hour}${minute ? `:${String(minute).padStart(2, '0')}` : ''}`;
  } catch {
    return 'UTC+0';
  }
};

/** Default for every timestamp rendered in the product: local time plus its
 * UTC offset, e.g. `29 Oct 2026, 14:03 UTC+2`. */
export const formatDateTimeWithOffset = (
  value: string | Date | undefined | null,
  timezone?: string | null,
): string => {
  const date = toDate(value);
  if (!date) return '—';
  return `${formatDateTime(date, timezone ?? undefined)} ${utcOffsetLabel(date, timezone)}`;
};

export const formatDateTime = (value: string | Date | undefined | null, timezone?: string): string => {
  const date = toDate(value);
  if (!date) return '—';
  const rendered = formatter(timezone, {
    day: '2-digit',
    month: 'short',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
  }).format(date);
  // A distributed security team reads the same page from different zones, so
  // every rendered timestamp states which clock it is on (`… UTC+2`). The offset
  // is evaluated at this instant, so DST is reflected per timestamp.
  return `${rendered} ${utcOffsetLabel(date, timezone)}`;
};

export const formatDateTimeShort = (value: string | Date | undefined | null, timezone?: string): string => {
  const date = toDate(value);
  if (!date) return '—';
  return formatter(timezone, {
    day: '2-digit',
    month: 'short',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    hourCycle: 'h12',
  }).format(date);
};

/**
 * `YYYY-MM-DD` in the resolved timezone. Used for `<input type="date">` bounds
 * and export filenames so they follow the same local calendar day as the rest
 * of the UI instead of the UTC day.
 */
export const formatDateKey = (
  value: string | Date | undefined | null = new Date(),
  timezone?: string,
): string => {
  const date = toDate(value);
  if (!date) return '';
  const parts = new Intl.DateTimeFormat('en-CA', {
    timeZone: resolveTimezone(timezone),
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
  }).formatToParts(date);
  const part = (type: Intl.DateTimeFormatPartTypes) =>
    parts.find((item) => item.type === type)?.value ?? '';
  return `${part('year')}-${part('month')}-${part('day')}`;
};
