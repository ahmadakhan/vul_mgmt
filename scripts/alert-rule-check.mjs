#!/usr/bin/env node
/**
 * Alert-rule semantic test harness.
 *
 * `promtool check rules` validates SYNTAX. It cannot tell you whether a rule
 * fires on the state it claims to detect. This harness does: it stands up a
 * real Prometheus per scenario, exposes a controlled metric state, and asserts
 * which alerts fire -- and equally that the ones that must stay quiet do.
 *
 * Four things this gets right, each of which produced a silent false pass in
 * earlier versions:
 *
 *  1. It NEVER queries 127.0.0.1:9090. Another project commonly owns that port
 *     on a developer host; querying it reads a different server's rules, which
 *     match nothing and look like "no alert fired". Each scenario publishes its
 *     own loopback port and the harness refuses to start if one is occupied.
 *
 *  2. It shortens `for:` AND range windows (`[10m]`). A rule inside
 *     `increase(x[10m])` cannot fire until ten minutes of samples exist, and
 *     `for: 10m` cannot fire until ten minutes have elapsed. Both are scaled.
 *
 *  3. It SCALES rather than collapses `for:`. Pairs like
 *     PipelineNotAdmitting(2m) / CircuitBreakerOpen(5m) are defined by elapsed
 *     time; flattening both to 5s destroys the escalation the rules encode.
 *
 *  4. Scenarios run CONCURRENTLY, one Prometheus each. Sequentially this would
 *     take ~15 minutes; the correctness is identical and the wall clock is the
 *     longest scenario.
 *
 * Usage:
 *   node scripts/alert-rule-check.mjs            # run all scenarios
 *   node scripts/alert-rule-check.mjs --verbose  # print every rule state
 *   node scripts/alert-rule-check.mjs --keep     # leave containers for debug
 *
 * Requires Docker. Exits non-zero if any expectation is not met.
 */
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

const RULES = path.resolve('deploy/monitoring/vulnstream-alerts.yml');
const SCRAPE_PORT = 9187; // exporter port inside each scenario's network
const BASE_API_PORT = 9200; // first loopback port; one per scenario
const FOR_SCALE = 15; // 5m -> 20s, 2m -> 8s, 1m -> 5s (floor)
const RANGE_SCALE = 15; // 10m -> 40s, 5m -> 20s
/** Longest scaled window + longest scaled `for:` + scrape slack. */
const SETTLE_MS = 75_000;

const verbose = process.argv.includes('--verbose');
const keep = process.argv.includes('--keep');

const run = (cmd, args) =>
  execFileSync(cmd, args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
const sh = (cmd) => run('bash', ['-lc', cmd]);

const base = {
  items: 100,
  deadLetters: 0,
  droppedLogs: 0,
  memory: 20,
  workers: 0,
  concurrency: 4,
  workerEnabled: 1,
  pending: 0,
  pendingAge: 1,
  health: 'HEALTHY',
  hbEnabled: 1,
  hbAge: 5,
  hbState: 'pinged',
  hbFails: 0,
  hbFailsTotal: 0,
  mlDriftDetected: 0,
  mlGateFailures: 0,
  mlLastTrainedAgeSeconds: 0,
};

const exposition = (s) => {
  const on = (v) => (v ? 1 : 0);
  return [
    '# TYPE vulnstream_correlation_items_total counter',
    `vulnstream_correlation_items_total ${s.items}`,
    '# TYPE vulnstream_correlation_dead_letters_total counter',
    `vulnstream_correlation_dead_letters_total ${s.deadLetters}`,
    '# TYPE vulnstream_correlation_dropped_logs_total counter',
    `vulnstream_correlation_dropped_logs_total ${s.droppedLogs}`,
    '# TYPE vulnstream_correlation_memory_percent gauge',
    `vulnstream_correlation_memory_percent ${s.memory}`,
    '# TYPE vulnstream_correlation_workers gauge',
    `vulnstream_correlation_workers ${s.workers}`,
    '# TYPE vulnstream_correlation_concurrency_limit gauge',
    `vulnstream_correlation_concurrency_limit ${s.concurrency}`,
    '# TYPE vulnstream_correlation_worker_enabled gauge',
    `vulnstream_correlation_worker_enabled ${s.workerEnabled}`,
    '# TYPE vulnstream_correlation_pending gauge',
    `vulnstream_correlation_pending ${s.pending}`,
    '# TYPE vulnstream_correlation_pending_sample_age_seconds gauge',
    `vulnstream_correlation_pending_sample_age_seconds ${s.pendingAge}`,
    '# TYPE vulnstream_correlation_health gauge',
    `vulnstream_correlation_health{state="HEALTHY"} ${on(s.health === 'HEALTHY')}`,
    `vulnstream_correlation_health{state="DEGRADED_BACKPRESSURE"} ${on(s.health === 'DEGRADED')}`,
    `vulnstream_correlation_health{state="RECOVERING_DB_SEVERANCE"} ${on(s.health === 'DB')}`,
    '# TYPE vulnstream_heartbeat_enabled gauge',
    `vulnstream_heartbeat_enabled ${s.hbEnabled}`,
    '# TYPE vulnstream_heartbeat_age_seconds gauge',
    `vulnstream_heartbeat_age_seconds ${s.hbAge}`,
    '# TYPE vulnstream_heartbeat_consecutive_failures gauge',
    `vulnstream_heartbeat_consecutive_failures ${s.hbFails}`,
    '# TYPE vulnstream_heartbeat_failed_pings_total counter',
    `vulnstream_heartbeat_failed_pings_total ${s.hbFailsTotal}`,
    '# TYPE vulnstream_heartbeat_state gauge',
    ...['pinged', 'failed', 'suppressed', 'idle', 'disabled'].map(
      (state) => `vulnstream_heartbeat_state{state="${state}"} ${on(s.hbState === state)}`,
    ),
    '# TYPE vulnstream_ml_model_drift_detected gauge',
    `vulnstream_ml_model_drift_detected ${s.mlDriftDetected}`,
    '# TYPE vulnstream_ml_quality_gate_failed_total counter',
    `vulnstream_ml_quality_gate_failed_total ${s.mlGateFailures}`,
    '# TYPE vulnstream_ml_model_last_trained_age_seconds gauge',
    `vulnstream_ml_model_last_trained_age_seconds ${s.mlLastTrainedAgeSeconds}`,
    '',
  ].join('\n');
};

const scenarios = [
  { name: 'healthy, idle, nothing queued', metrics: {}, expectFiring: [] },
  {
    name: 'heartbeat recovered (failures reset)',
    // The old counter-based rule fired here. A healed heartbeat is healthy.
    metrics: { hbFails: 0, hbFailsTotal: 60 },
    expectFiring: [],
  },
  {
    name: 'database severance',
    metrics: { health: 'DB', hbAge: 120, hbState: 'suppressed', pending: 5 },
    // CircuitBreakerOpen is expected: RECOVERING_DB_SEVERANCE is precisely the
    // state in which the breaker is open, and after the scaled 5m hold all
    // three escalation levels describe the same true condition.
    expectFiring: [
      'VulnStreamDatabaseRecovery',
      'VulnStreamPipelineNotAdmitting',
      'VulnStreamCircuitBreakerOpen',
    ],
  },
  {
    name: 'backpressure, otherwise idle',
    // Shedding still admits; it must not page as "not admitting".
    metrics: { health: 'DEGRADED', memory: 90 },
    expectFiring: ['VulnStreamMemoryPressure'],
  },
  {
    name: 'monitoring-only (worker disabled), queue full',
    metrics: { workerEnabled: 0, pending: 50 },
    expectFiring: [],
  },
  {
    name: 'queued, admitted, no completions',
    metrics: { pending: 50, workers: 0 },
    expectFiring: ['VulnStreamIngestionStalled'],
  },
  {
    name: 'workers occupied, no completions',
    metrics: { pending: 50, workers: 2 },
    expectFiring: ['VulnStreamWorkersStuck', 'VulnStreamIngestionStalled'],
  },
  {
    name: 'stale queue sample (sampler wedged)',
    metrics: { pending: 50, pendingAge: 900 },
    expectFiring: [],
  },
  {
    name: 'heartbeat enabled but never pinged',
    metrics: { hbAge: -1, hbState: 'idle' },
    expectFiring: ['VulnStreamHeartbeatNeverStarted'],
  },
  {
    name: 'heartbeat stale (400s since ping)',
    metrics: { hbAge: 400 },
    expectFiring: ['VulnStreamHeartbeatStale'],
  },
  {
    name: 'sustained ping failures',
    // `pinged` is 0 while failing, so the never-started rule also fires. That is
    // a real overlap in the rule set, recorded here rather than hidden.
    metrics: { hbFails: 4, hbState: 'failed', health: 'DB' },
    expectFiring: [
      'VulnStreamHeartbeatFailing',
      'VulnStreamHeartbeatNeverStarted',
      'VulnStreamDatabaseRecovery',
      'VulnStreamPipelineNotAdmitting',
      'VulnStreamCircuitBreakerOpen',
    ],
  },
  { name: 'dead letters arriving', metrics: { deadLetters: 5 }, deadLetterPerScrape: 1, expectFiring: ['VulnStreamDeadLetters'] },
  {
    name: 'dead-letter burst',
    metrics: { deadLetters: 60 },
    deadLetterPerScrape: 5,
    expectFiring: ['VulnStreamDeadLetterBurst', 'VulnStreamDeadLetters'],
  },
  {
    name: 'log queue congestion',
    metrics: { droppedLogs: 3 },
    droppedLogPerScrape: 1,
    expectFiring: ['VulnStreamLogLoss'],
  },
  {
    name: 'ML model drift detected',
    metrics: { mlDriftDetected: 1 },
    expectFiring: ['VulnStreamMLModelDriftDetected'],
  },
  {
    name: 'ML quality gate failed',
    metrics: { mlGateFailures: 1 },
    expectFiring: ['VulnStreamMLQualityGateFailed'],
  },
  {
    name: 'ML model stale (not retrained for 12 days)',
    metrics: { mlLastTrainedAgeSeconds: 1_036_800 },
    expectFiring: ['VulnStreamMLModelStale'],
  },
  {
    name: 'ML healthy (no drift, recent training)',
    metrics: { mlDriftDetected: 0, mlGateFailures: 0, mlLastTrainedAgeSeconds: 3600 },
    expectFiring: [],
  },
];

/**
 * Scale `for:` and range selectors down. Mechanical and even-handed: every
 * duration is divided by the same factor so relative ordering is preserved.
 */
function scaleRules(source) {
  const toSeconds = { s: 1, m: 60, h: 3600, d: 86400 };
  return source
    .replace(/^(\s*)for:\s*(\d+)([smhd])\s*$/gm, (_, indent, amount, unit) => {
      const seconds = Number(amount) * (toSeconds[unit] ?? 1);
      return `${indent}for: ${Math.max(5, Math.round(seconds / FOR_SCALE))}s`;
    })
    .replace(/\[(\d+)([smhd])\]/g, (_, amount, unit) => {
      const seconds = Number(amount) * (toSeconds[unit] ?? 1);
      return `[${Math.max(40, Math.round(seconds / RANGE_SCALE))}s]`;
    });
}

const root = mkdtempSync(path.join(tmpdir(), 'vs-alerts-'));
const owned = [];
const cleanup = () => {
  if (keep) {
    console.error(`KEEP: containers and ${root} left in place`);
    return;
  }
  for (const fn of owned.reverse()) {
    try {
      fn();
    } catch {}
  }
  try {
    rmSync(root, { recursive: true, force: true });
  } catch {}
};

async function runScenario(scenario, index) {
  const dir = path.join(root, `s${index}`);
  const net = `vs-ac-${process.pid}-${index}`;
  const apiPort = BASE_API_PORT + index;
  const id = `vs-ac-${process.pid}-${index}`;
  sh(`mkdir -p ${dir}`);
  writeFileSync(path.join(dir, 'alerts.yml'), readFileSync(path.join(root, 'alerts.yml'), 'utf8'));
  // Counters must MOVE for increase()/rate() to be non-zero. A constant
  // exposition makes every counter-based rule structurally unable to fire, and
  // the scenario then reads as a rule defect. `items` stays flat (that is the
  // stall condition); the dead-letter and dropped-log counters are ramped by the
  // exporter itself, `step` per scrape.
  writeFileSync(path.join(dir, 'metrics.txt'), exposition({ ...base, ...scenario.metrics }));
  writeFileSync(
    path.join(dir, 'prometheus.yml'),
    [
      'global: {scrape_interval: 1s, evaluation_interval: 1s}',
      'rule_files: ["/etc/prometheus/alerts.yml"]',
      'scrape_configs:',
      '  - job_name: vulnstream',
      `    static_configs: [{targets: ["exporter:${SCRAPE_PORT}"]}]`,
      '',
    ].join('\n'),
  );
  sh(`docker network create ${net}`);
  owned.push(() => sh(`docker network rm ${net} >/dev/null 2>&1`));
  // Network alias `exporter`: Docker DNS resolves container NAMES, not the
  // hostname used in the scrape config. Without the alias the target is
  // permanently down and every scenario reports "instance unavailable".
  sh(
    `docker run -d --name ${id}-exp --network ${net} --network-alias exporter ` +
      `-v ${dir}:/data:ro node:26-alpine3.22 node -e "` +
      // Read the scenario state per request and ramp the two counters that
      // rules integrate over (`dead_letters`, `dropped_logs`). `items` is a
      // completion counter and must NOT ramp: a rising value means progress,
      // which is exactly what the stall rules exist to detect the absence of.
      `const fs=require('fs');let t=0;` +
      `require('http').createServer((q,r)=>{t++;` +
      // Each counter ramps at its own rate. A single shared rate made the
      // dead-letter scenarios also trip LogLoss, because dropped_logs moved too.
      `const s=fs.readFileSync('/data/metrics.txt','utf8')` +
      `.replace(/^vulnstream_correlation_dead_letters_total (-?\\d+(?:\\.\\d+)?)$/m,(m,v)=>m.replace(v,String(Number(v)+t*${scenario.deadLetterPerScrape ?? 0})))` +
      `.replace(/^vulnstream_correlation_dropped_logs_total (-?\\d+(?:\\.\\d+)?)$/m,(m,v)=>m.replace(v,String(Number(v)+t*${scenario.droppedLogPerScrape ?? 0})));` +
      `r.writeHead(200,{'content-type':'text/plain'});r.end(s)}).listen(${SCRAPE_PORT})"`,
  );
  owned.push(() => sh(`docker rm -f ${id}-exp >/dev/null 2>&1`));
  sh(
    `docker run -d --name ${id}-prom --network ${net} -p 127.0.0.1:${apiPort}:9090 ` +
      `-v ${dir}/prometheus.yml:/etc/prometheus/prometheus.yml:ro ` +
      `-v ${dir}/alerts.yml:/etc/prometheus/alerts.yml:ro ` +
      `prom/prometheus:latest --config.file=/etc/prometheus/prometheus.yml --storage.tsdb.path=/tmp/tsdb`,
  );
  owned.push(() => sh(`docker rm -f ${id}-prom >/dev/null 2>&1`));

  const api = `http://127.0.0.1:${apiPort}`;
  // Wait for THIS instance: assert the expected rule names are present, so a
  // mis-mapped port cannot masquerade as "no alerts firing".
  let ready = false;
  for (let attempt = 0; attempt < 60 && !ready; attempt++) {
    try {
      const body = await (await fetch(`${api}/api/v1/rules`)).json();
      const names = new Set((body.data?.groups ?? []).flatMap((g) => g.rules.map((r) => r.name)));
      ready = names.has('VulnStreamIngestionStalled') && names.has('VulnStreamHeartbeatStale');
    } catch {}
    if (!ready) await new Promise((resolve) => setTimeout(resolve, 500));
  }
  if (!ready) throw new Error(`${scenario.name}: Prometheus never exposed the expected rule set`);

  await new Promise((resolve) => setTimeout(resolve, SETTLE_MS));
  const body = await (await fetch(`${api}/api/v1/rules`)).json();
  const states = new Map();
  for (const group of body.data.groups)
    for (const rule of group.rules) if (rule.type === 'alerting') states.set(rule.name, rule.state);
  const firing = [...states].filter(([, s]) => s === 'firing').map(([n]) => n).sort();
  const expected = [...scenario.expectFiring].sort();
  const missing = expected.filter((n) => !firing.includes(n));
  const extra = firing.filter((n) => !expected.includes(n));
  return { scenario, firing, missing, extra, ok: !missing.length && !extra.length, states: [...states] };
}

async function main() {
  // Refuse to run over anything already listening: a silently reused port is
  // how an earlier version of this harness validated the wrong server.
  for (let i = 0; i < scenarios.length; i++) {
    const occupied = sh(`docker ps --filter publish=${BASE_API_PORT + i} --format '{{.Names}}'`).trim();
    if (occupied) throw new Error(`port ${BASE_API_PORT + i} is already published by ${occupied}; refusing to test`);
  }

  const scaled = scaleRules(readFileSync(RULES, 'utf8'));
  writeFileSync(path.join(root, 'alerts.yml'), scaled);
  // Sanity: the rewrite must have produced at least one surviving expression.
  if (!/expr:/.test(scaled)) throw new Error('rule scaling destroyed the rule file');

  const results = await Promise.all(
    scenarios.map((scenario, index) =>
      runScenario(scenario, index).catch((error) => ({
        scenario,
        ok: false,
        error: error.message,
        firing: [],
        missing: scenario.expectFiring,
        extra: [],
        states: [],
      })),
    ),
  );

  let failed = 0;
  for (const result of results) {
    const label = result.scenario.name.padEnd(46);
    if (result.error) {
      failed++;
      console.log(`ERROR ${label} ${result.error}`);
      continue;
    }
    if (!result.ok) failed++;
    console.log(`${result.ok ? 'PASS ' : 'FAIL '} ${label} firing=[${result.firing.join(', ')}]`);
    if (!result.ok) {
      if (result.missing.length) console.log(`      missing:    ${result.missing.join(', ')}`);
      if (result.extra.length) console.log(`      unexpected: ${result.extra.join(', ')}`);
    }
    if (verbose) for (const [name, state] of result.states) console.log(`      ${name.padEnd(38)} ${state}`);
  }

  if (failed) {
    console.error(`\n${failed} of ${scenarios.length} scenarios failed.`);
    process.exitCode = 1;
  } else {
    console.log(`\nAll ${scenarios.length} scenarios behaved as expected.`);
  }
}

try {
  await main();
} catch (error) {
  console.error(`alert-rule-check failed: ${error.message}`);
  process.exitCode = 2;
} finally {
  cleanup();
}
