#!/usr/bin/env node
/**
 * Crash-recovery supervisor for the VulnStream application process.
 *
 * Spawns the application (`node server-dist/main.js`) and restarts it whenever
 * it exits, with exponential backoff capped at MAX_RESTART_DELAY_MS. This is
 * the "always running" guarantee for installs that have no container
 * orchestrator restarting the process (bare metal, systemd, a VM).
 *
 * Under Docker Compose or Kubernetes the orchestrator already restarts the
 * container; use the orchestrator's restart policy there and run the app
 * directly (`node server-dist/main.js`) instead of this supervisor.
 *
 * A SIGTERM/SIGINT stops the loop: the current child is terminated and the
 * supervisor exits without restarting, so an operator or orchestrator can take
 * the instance out of service cleanly.
 *
 * Environment:
 *   VULNSTREAM_APP_COMMAND          command to run the app (default: node server-dist/main.js)
 *   VULNSTREAM_BASE_RESTART_DELAY_MS initial backoff (default: 2000)
 *   VULNSTREAM_MAX_RESTART_DELAY_MS  cap on backoff (default: 300000)
 *   VULNSTREAM_MAX_CONSECUTIVE_FAST_FAILURES fast-loop trip count (default: 5)
 *   VULNSTREAM_FAST_FAILURE_WINDOW_MS window for fast-failure detection (default: 60000)
 */

import { spawn } from 'node:child_process';

const APP_COMMAND = process.env.VULNSTREAM_APP_COMMAND ?? 'node server-dist/main.js';
const [APP_BIN, ...APP_ARGS] = APP_COMMAND.split(/\s+/);
const BASE_RESTART_DELAY_MS = Number(process.env.VULNSTREAM_BASE_RESTART_DELAY_MS ?? 2_000);
const MAX_RESTART_DELAY_MS = Number(process.env.VULNSTREAM_MAX_RESTART_DELAY_MS ?? 300_000);
const MAX_CONSECUTIVE_FAST_FAILURES = Number(process.env.VULNSTREAM_MAX_CONSECUTIVE_FAST_FAILURES ?? 5);
const FAST_FAILURE_WINDOW_MS = Number(process.env.VULNSTREAM_FAST_FAILURE_WINDOW_MS ?? 60_000);
const CHILD_STOP_GRACE_MS = 10_000;

let stopping = false;
let restartCount = 0;
let currentChild;
const fastFailures = []; // exit timestamps within FAST_FAILURE_WINDOW_MS

const log = (level, event, extra = {}) =>
  process.stdout.write(
    JSON.stringify({ level, event, timestamp: new Date().toISOString(), ...extra }) + '\n',
  );

const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function stopChild() {
  if (!currentChild) return Promise.resolve();
  try {
    currentChild.kill('SIGTERM');
  } catch {}
  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      try {
        currentChild.kill('SIGKILL');
      } catch {}
      resolve();
    }, CHILD_STOP_GRACE_MS);
    currentChild.once('exit', () => {
      clearTimeout(timer);
      resolve();
    });
    currentChild = undefined;
  });
}

function backoffMs() {
  return Math.min(MAX_RESTART_DELAY_MS, BASE_RESTART_DELAY_MS * Math.pow(2, Math.min(restartCount, 10)));
}

function recordFastFailure() {
  const now = Date.now();
  fastFailures.push(now);
  while (fastFailures.length && now - fastFailures[0] >= FAST_FAILURE_WINDOW_MS) {
    fastFailures.shift();
  }
  return fastFailures.length >= MAX_CONSECUTIVE_FAST_FAILURES;
}

function spawnApp() {
  const child = spawn(APP_BIN, APP_ARGS, {
    stdio: 'inherit',
    env: process.env,
  });
  currentChild = child;
  let exited = false;
  const onExit = (code, signal) => {
    if (exited) return;
    exited = true;
    currentChild = undefined;
    log('warn', 'app.exited', { code, signal, restartCount });
    if (stopping) return;
    const fastLoop = recordFastFailure();
    if (fastLoop) {
      log('error', 'app.fast_failure_loop', {
        windowMs: FAST_FAILURE_WINDOW_MS,
        max: MAX_CONSECUTIVE_FAST_FAILURES,
        restartCount,
      });
    }
    scheduleRestart(code, signal);
  };
  child.on('exit', onExit);
  child.on('error', (error) => {
    if (exited) return;
    exited = true;
    currentChild = undefined;
    log('error', 'app.spawn_error', { message: error.message });
    if (stopping) return;
    recordFastFailure();
    scheduleRestart(undefined, undefined);
  });
  return child;
}

async function scheduleRestart(code, signal) {
  const delayMs = backoffMs();
  restartCount++;
  log('info', 'app.restarting', { delayMs, code, signal, restartCount });
  await delay(delayMs);
  if (stopping) return;
  try {
    spawnApp();
  } catch (error) {
    log('error', 'app.restart_failed', { message: error.message });
    scheduleRestart(undefined, undefined);
  }
}

function handleStop() {
  if (stopping) return;
  stopping = true;
  log('info', 'supervisor.stopping');
  void stopChild().finally(() => process.exit(0));
}

process.on('SIGTERM', handleStop);
process.on('SIGINT', handleStop);

log('info', 'supervisor.started', { command: APP_COMMAND });
spawnApp();
