import { build } from 'esbuild';
import { cp, mkdir } from 'node:fs/promises';
await build({
  entryPoints: ['server/main.ts', 'server/create-user.ts', 'server/migrate.ts'],
  outdir: 'server-dist',
  bundle: true,
  packages: 'external',
  platform: 'node',
  format: 'esm',
  target: 'node22',
  sourcemap: true,
});
await mkdir('server-dist/migrations', { recursive: true });
await cp('server/migrations', 'server-dist/migrations', { recursive: true });
