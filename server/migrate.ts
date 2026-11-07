import { grantRuntimePrivileges } from './runtimePrivileges.ts';
import { createPool, migrate, transaction, get, put } from './db';
import { backfillCorrelationInventory } from './correlation/inventory.ts';
if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL is required');
const pool = createPool(process.env.DATABASE_URL);
try {
  await migrate(pool);
  await transaction(
    pool,
    async (db) => {
      if (await get(db, 'systemState', 'native-inventory-v1')) return;
      await backfillCorrelationInventory(db);
      await put(db, 'systemState', 'native-inventory-v1', { completedAt: new Date().toISOString() });
    },
    undefined,
    { locks: ['native-inventory-bootstrap'] },
  );
  // The runtime role cannot alter the schema or rewrite audit history.
  if (process.env.GRANT_RUNTIME_ROLE === 'true') await grantRuntimePrivileges(pool);
  console.log('Migrations applied.');
} finally {
  await pool.end();
}
