/** Build a short, human-friendly display name for a pipeline execution from its id.
 *
 * Executions are keyed by an opaque UUID, but the Execution history list renders a
 * readable label (e.g. `Run 3add6860`) instead of the raw identifier. Legacy rows
 * stored before this name was persisted fall back to this helper on read. */
export const formatExecutionName = (id: string): string => `Run ${id.slice(0, 8)}`;

/** In-memory counter keyed by `prefix|datePart` for sequential daily advisory IDs. */
const advisoryCounter = new Map<string, number>();

/** Reset the in-memory counter for a prefix/date — used by tests to force a known
 * sequence number without spawning across multiple days. */
export const resetAdvisoryCounterForTest = (prefix: string, datePart: string): void => {
  advisoryCounter.delete(`${prefix}|${datePart}`);
};

/** Build a professional, human-readable advisory identifier.
 *
 * Format: `PREFIX-ddMMMyyyy-NNN` (e.g. `ADV-29Oct2026-001`).
 * Each day starts at `001` and increments by one for every subsequent advisory. */
export const formatAdvisoryId = (prefix: string, now: Date = new Date()): string => {
  const datePart = now
    .toLocaleDateString('en-GB', {
      day: '2-digit',
      month: 'short',
      year: 'numeric',
    })
    .replace(/ /g, '');
  const key = `${prefix}|${datePart}`;
  const count = (advisoryCounter.get(key) ?? 0) + 1;
  advisoryCounter.set(key, count);
  const sequence = String(count).padStart(3, '0');
  return `${prefix}${datePart}-${sequence}`;
};
