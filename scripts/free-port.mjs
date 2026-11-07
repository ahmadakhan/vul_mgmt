#!/usr/bin/env node
/**
 * Kill every process listening on a given TCP port so a dev server can bind
 * without hitting EADDRINUSE from a stale process left over by an ungraceful
 * shutdown or a crashed previous run.
 *
 * Usage: node scripts/free-port.mjs <port>
 */
const port = process.argv[2];
if (!port) process.exit(0);

const { execSync } = await import('node:child_process');

try {
  const pids = execSync(`lsof -ti:${port}`, {
    stdio: ['pipe', 'pipe', 'pipe'],
  }).toString().trim();
  if (pids) {
    for (const pid of pids.split('\n').filter(Boolean)) {
      try {
        process.kill(Number(pid), 'SIGKILL');
      } catch {}
    }
    await new Promise((resolve) => setTimeout(resolve, 500));
    const remaining = execSync(`lsof -ti:${port}`, { stdio: ['pipe', 'pipe', 'pipe'] }).toString().trim();
    if (remaining) {
      console.error(JSON.stringify({ level: 'warning', event: 'free_port.conflict_persists', port: Number(port), pids: remaining }));
      process.exit(1);
    }
    console.log(JSON.stringify({ level: 'info', event: 'free_port.freed', port: Number(port) }));
  }
} catch {
  // lsof exits non-zero when nothing is listening — that is the happy path.
  process.exit(0);
}
