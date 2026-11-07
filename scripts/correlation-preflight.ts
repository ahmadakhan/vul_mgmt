import { createPool } from '../server/db.ts';
import { correlationPreflight } from '../server/correlation/preflight.ts';
if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL required');
const pool = createPool(process.env.DATABASE_URL);
try {
  const report = await correlationPreflight(pool);
  console.log(JSON.stringify(report, null, 2));
  if (!report.compatible) process.exitCode = 1;
} catch {
  console.log(JSON.stringify({ compatible: false, error: 'DATABASE_PREFLIGHT_FAILED' }));
  process.exitCode = 1;
} finally {
  await pool.end();
}
