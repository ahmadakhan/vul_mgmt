/**
 * CVSS normalization shared by every feed adapter.
 *
 * Each adapter used to re-derive the version string and severity band inline.
 * The copies had drifted: one reported an OpenCVE v3.0 metric as "3.1", and the
 * validator/schema rejected the "3.0" label the NVD and MITRE adapters emitted,
 * so a v3.0-scored CVE failed normalization in one adapter and was mislabelled
 * in another. One implementation keeps the persisted contract consistent.
 */
export type CvssVersion = '4.0' | '3.1' | '3.0' | '2.0';

export type CvssSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

/**
 * Maps a provider's metric version onto the versions this application stores.
 * Unknown or absent versions fall back to `fallback`; when that is also absent
 * the score is not presented as a real CVSS measurement.
 */
export function normalizeCvssVersion(
  version: unknown,
  fallback: CvssVersion | 'UNKNOWN' = '3.1',
): CvssVersion | 'UNKNOWN' {
  const value = typeof version === 'string' ? version.trim() : '';
  if (value === '4.0' || value === '3.1' || value === '3.0' || value === '2.0') return value;
  return fallback;
}

/**
 * Severity band for a base score. Mirrors the CVSS v3 specification boundaries:
 * 9.0-10.0 CRITICAL, 7.0-8.9 HIGH, 4.0-6.9 MEDIUM, 0.1-3.9 LOW.
 */
export function cvssSeverity(score: number): CvssSeverity {
  return score >= 9 ? 'CRITICAL' : score >= 7 ? 'HIGH' : score >= 4 ? 'MEDIUM' : 'LOW';
}

/**
 * Ordered list of CVSS versions from oldest to newest. Used to pick the
 * "best" version when a CVE carries multiple CVSS metrics (NVD returns up to
 * four: v4.0, v3.1, v3.0, and v2.0).
 */
export const CVSS_VERSION_ORDER: CvssVersion[] = ['2.0', '3.0', '3.1', '4.0'];

/**
 * Type guard confirming a string is one of the canonical CVSS versions
 * this application persists.
 */
export function isCvssVersion(value: string): value is CvssVersion {
  return CVSS_VERSION_ORDER.includes(value as CvssVersion);
}

/**
 * Returns the higher of two CVSS version strings, or the non-UNKNOWN one
 * when one is present. `undefined` inputs are treated as 'UNKNOWN'.
 */
export function maxCvssVersion(left: CvssVersion | 'UNKNOWN', right: CvssVersion | 'UNKNOWN'): CvssVersion | 'UNKNOWN' {
  if (left === 'UNKNOWN') return right;
  if (right === 'UNKNOWN') return left;
  return CVSS_VERSION_ORDER.indexOf(left) >= CVSS_VERSION_ORDER.indexOf(right) ? left : right;
}

const CVSS_V3_PREFIX = /^CVSS:3\.[01]\/(.+)/;
const CVSS_V4_PREFIX = /^CVSS:4\.0\/(.+)/;
/**
 * CVSS v2 vectors carry no version prefix, so they are recognised by their
 * leading base metric (`AV:N/AC:L/...`). An unknown `CVSS:` prefix must never
 * match here, otherwise `CVSS:9.9/...` would be accepted as a v2 vector.
 */
const CVSS_V2_PREFIX = /^(?!CVSS:)(AV|AC|Au|C|I|A):/i;

/**
 * Parses a CVSS vector string into its constituent metric key/value pairs.
 * Returns an empty object for vectors that cannot be parsed.
 *
 * Supports CVSS v2 (no prefix), v3.0/v3.1 (CVSS:3.x/ prefix), and
 * v4.0 (CVSS:4.0/ prefix). The metric tokens after the prefix are split
 * on `/` and each is further split on the first `:` to separate key from value.
 */
export function parseCvssVector(vector: string): Record<string, string> {
  if (!vector) return {};
  let metrics: string[];
  if (CVSS_V3_PREFIX.test(vector)) {
    metrics = vector.match(CVSS_V3_PREFIX)?.[1]?.split('/') ?? [];
  } else if (CVSS_V4_PREFIX.test(vector)) {
    metrics = vector.match(CVSS_V4_PREFIX)?.[1]?.split('/') ?? [];
  } else {
    metrics = vector.split('/').filter((part) => part.includes(':'));
  }
  const result: Record<string, string> = {};
  for (const metric of metrics) {
    const colon = metric.indexOf(':');
    if (colon > 0) {
      const key = metric.slice(0, colon).trim();
      const value = metric.slice(colon + 1).trim();
      if (key) result[key] = value;
    }
  }
  return result;
}

/**
 * Validates that a CVSS vector string is well-formed for its version.
 * A vector is well-formed when every metric token has the `key:value` shape
 * and, for v3.x/v4.0 vectors, the `CVSS:3.x/` or `CVSS:4.0/` prefix is present.
 */
export function cvssVectorIsValid(vector: string): boolean {
  if (!vector) return true;
  const trimmed = vector.trim();
  const isV3 = CVSS_V3_PREFIX.test(trimmed);
  const isV4 = CVSS_V4_PREFIX.test(trimmed);
  const isV2 = CVSS_V2_PREFIX.test(trimmed);
  if (!isV3 && !isV4 && !isV2) return false;
  const parts = trimmed.split('/');
  const body = isV3 || isV4 ? parts.slice(1) : parts;
  if (body.length === 0) return false;
  return body.every((part) => {
    const colon = part.indexOf(':');
    return colon > 0 && colon < part.length - 1;
  });
}

/**
 * Ingestion-time vector sanitisation (audit finding #6).
 *
 * Feeds occasionally carry malformed vectors — a v3 score with a v2-shaped
 * string, an un-prefixed v3.1 vector, whitespace, or a missing vector entirely.
 * `cvssVectorIsValid` is the strict check used by tests; on the ingest path we
 * want a lenient, lossless repair: keep the vector when it is well-formed,
 * otherwise store it as empty so the UI treats it as "not supplied" rather
 * than rendering a broken string. This is fail-safe, not fail-closed: a bad
 * vector must never abort a source run, and a bad *score* already does
 * (the schema rejects NaN).
 */
export function sanitizeCvssVector(vector: unknown): string {
  const value = typeof vector === 'string' ? vector.trim() : '';
  if (!value) return '';
  return cvssVectorIsValid(value) ? value : '';
}
