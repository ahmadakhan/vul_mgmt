import { loadConfig } from './config';
import { createPool, migrate } from './db';
import { createUser } from './auth';
import type { Role } from '../shared/state.ts';
const [username, role = 'ADMIN'] = process.argv.slice(2);
if (!username) {
  console.error('Usage: npm run operator:create -- USERNAME [ADMIN|OPERATOR|VIEWER] < password-file');
  process.exit(1);
}
if (process.stdin.isTTY) {
  console.error('Provide the password through stdin (not command-line arguments).');
  process.exit(1);
}
let password = '';
for await (const chunk of process.stdin) {
  password += chunk;
  if (password.length > 1024) throw new Error('Password input too long');
}
const pool = createPool(loadConfig().DATABASE_URL);
try {
  if (process.env.NODE_ENV !== 'production') await migrate(pool);
  await createUser(pool, username, password.trimEnd(), role as Role);
  console.log('Operator created.');
} finally {
  password = '';
  await pool.end();
}
