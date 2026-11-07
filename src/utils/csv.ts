/** Quote every field and neutralize spreadsheet formula prefixes. */
export function csvCell(value: string): string {
  const safe = /^[\s]*[=+@-]|^[\t\r\n]/.test(value) ? `'${value}` : value;
  return `"${safe.replace(/"/g, '""')}"`;
}
