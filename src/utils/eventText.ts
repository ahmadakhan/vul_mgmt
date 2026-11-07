/** Human-readable rendering for `OperationalEvent.context` values.
 *
 * Operational events store structured context, but operators read these logs
 * during incidents. Raw JSON braces, quotes and escaped newlines make that
 * harder, so render labelled, indented text instead.
 */

const INDENT = '  ';
const EMPTY = 'No additional details recorded.';

const ACRONYMS: Record<string, string> = {
  id: 'ID',
  ip: 'IP',
  url: 'URL',
  uri: 'URI',
  api: 'API',
  json: 'JSON',
  http: 'HTTP',
  https: 'HTTPS',
  cve: 'CVE',
  cpe: 'CPE',
  cvss: 'CVSS',
  uuid: 'UUID',
  sql: 'SQL',
  tls: 'TLS',
  dns: 'DNS',
  smtp: 'SMTP',
  ssrf: 'SSRF',
  nvd: 'NVD',
  kev: 'KEV',
  epss: 'EPSS',
  utc: 'UTC',
};

const isPlainRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

const isScalar = (value: unknown) => !isPlainRecord(value) && !Array.isArray(value);

/** Turn `rawIngested`, `cveId` or `HTTPStatus` into readable labels. */
export function humanizeEventKey(key: string): string {
  const words = key
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1 $2')
    .split(/[\s_.-]+/)
    .filter(Boolean);
  if (words.length === 0) return key;
  return words
    .map((word) => {
      const acronym = ACRONYMS[word.toLowerCase()];
      if (acronym) return acronym;
      return word.charAt(0).toUpperCase() + word.slice(1).toLowerCase();
    })
    .join(' ');
}

const scalarText = (value: unknown): string => {
  if (value === null || value === undefined) return 'none';
  if (typeof value === 'boolean') return value ? 'Yes' : 'No';
  if (typeof value === 'string') return value.trim() === '' ? '(empty)' : value;
  if (typeof value === 'number' || typeof value === 'bigint') return String(value);
  if (typeof value === 'symbol') return value.description ?? value.toString();
  if (typeof value === 'function') return '[function]';
  return String(value);
};

const scalarLines = (value: unknown): string[] => scalarText(value).split(/\r?\n/);

/** Indent continuation lines so multiline errors stay attached to their label. */
const pushContinuation = (lines: string[], value: unknown, depth: number) => {
  const [, ...rest] = scalarLines(value);
  const pad = INDENT.repeat(depth + 1);
  for (const line of rest) lines.push(`${pad}${line}`);
};

const pushEntry = (lines: string[], key: string, value: unknown, depth: number) => {
  const pad = INDENT.repeat(depth);
  const label = `${pad}${humanizeEventKey(key)}:`;

  if (isPlainRecord(value)) {
    const entries = Object.entries(value);
    if (entries.length === 0) {
      lines.push(`${label} none`);
      return;
    }
    lines.push(label);
    for (const [childKey, childValue] of entries) pushEntry(lines, childKey, childValue, depth + 1);
    return;
  }

  if (Array.isArray(value)) {
    if (value.length === 0) {
      lines.push(`${label} none`);
      return;
    }
    if (value.every((item) => isScalar(item) && !String(item).includes('\n'))) {
      lines.push(`${label} ${value.map(scalarText).join(', ')}`);
      return;
    }
    lines.push(label);
    pushList(lines, value, depth + 1);
    return;
  }

  const [first] = scalarLines(value);
  lines.push(`${label} ${first}`);
  pushContinuation(lines, value, depth);
};

const pushListItem = (lines: string[], item: unknown, depth: number) => {
  const pad = INDENT.repeat(depth);

  if (isPlainRecord(item)) {
    const entries = Object.entries(item);
    if (entries.length === 0) {
      lines.push(`${pad}- none`);
      return;
    }
    const nested: string[] = [];
    for (const [key, value] of entries) pushEntry(nested, key, value, depth + 1);
    // Put the first key on the bullet line, keep the remaining keys aligned.
    lines.push(`${pad}- ${nested[0].trimStart()}`);
    for (const line of nested.slice(1)) lines.push(line);
    return;
  }

  if (Array.isArray(item)) {
    lines.push(`${pad}-`);
    pushList(lines, item, depth + 1);
    return;
  }

  const [first] = scalarLines(item);
  lines.push(`${pad}- ${first}`);
  pushContinuation(lines, item, depth);
};

const pushList = (lines: string[], values: unknown[], depth: number) => {
  for (const item of values) pushListItem(lines, item, depth);
};

/**
 * Render event context as plain text:
 *
 *     Worker Enabled: Yes
 *     Stats:
 *       Raw Ingested: 10
 *       Findings: 2
 *     Errors: timeout, retry
 */
export function formatEventContext(context: unknown): string {
  if (context === null || context === undefined) return EMPTY;

  if (isPlainRecord(context)) {
    const entries = Object.entries(context);
    if (entries.length === 0) return EMPTY;
    const lines: string[] = [];
    for (const [key, value] of entries) pushEntry(lines, key, value, 0);
    return lines.join('\n');
  }

  if (Array.isArray(context)) {
    if (context.length === 0) return EMPTY;
    const lines: string[] = [];
    pushList(lines, context, 0);
    return lines.join('\n');
  }

  return scalarText(context);
}
