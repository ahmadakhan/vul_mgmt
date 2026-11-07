import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const deployDir = fileURLToPath(new URL('../deploy/', import.meta.url));

test('prometheus actually delivers alerts to an alertmanager', async () => {
  // Rules in vulnstream-alerts.yml were evaluated and discarded: prometheus.yml
  // had no alerting block, and Prometheus has no default receiver. An alert that
  // is never delivered is not an alert, which is why "if it is down, alert"
  // did not hold before this change.
  for (const file of ['prometheus.yml', 'prometheus-compose.yml']) {
    const yaml = await readFile(path.join(deployDir, 'monitoring', file), 'utf8');
    assert.match(yaml, /^alerting:/m, `${file} must configure alertmanagers`);
    assert.match(yaml, /alertmanager:9093/, `${file} must target the alertmanager service`);
    assert.match(yaml, /rule_files:/, `${file} must still load the rule file`);
  }
});

test('alertmanager has a route and every referenced receiver exists', async () => {
  const yaml = await readFile(path.join(deployDir, 'monitoring', 'alertmanager.yml'), 'utf8');
  assert.match(yaml, /^route:/m);
  assert.match(yaml, /repeat_interval:/, 'an ongoing outage must re-notify, not fire once');
  // A receiver name referenced by the route but not defined is a config that
  // fails to load at runtime -- i.e. no alerts, which is the bug being fixed.
  const defined = new Set([...yaml.matchAll(/^\s*-\s+name:\s*(\S+)\s*$/gm)].map((match) => match[1]));
  const referenced = new Set([...yaml.matchAll(/receiver:\s*(\S+)/g)].map((match) => match[1]));
  assert.ok(referenced.size > 0, 'the route must name a receiver');
  for (const name of referenced) assert.ok(defined.has(name), `receiver ${name} is referenced but not defined`);
});

test('alert rules only reference metrics the server exports', async () => {
  // A rule over a metric nobody exports is silent forever, which reads as
  // "healthy". Check each vulnstream_* metric against the exporter source.
  const rules = await readFile(path.join(deployDir, 'monitoring', 'vulnstream-alerts.yml'), 'utf8');
  const metricsSource = await readFile(
    fileURLToPath(new URL('../server/correlation/metrics.ts', import.meta.url)),
    'utf8',
  );
  const referenced = new Set([...rules.matchAll(/(vulnstream_[a-z_]+)/g)].map((match) => match[1]));
  assert.ok(referenced.size > 0);
  for (const metric of referenced)
    assert.ok(metricsSource.includes(metric), `alert rule uses ${metric}, which correlationMetrics does not export`);
});
test('heartbeat failure metrics are typed to survive recovery', async () => {
  // The old exporter published `vulnstream_heartbeat_failures_total` as a
  // COUNTER while the value reset to zero on every successful ping, and the
  // alert applied increase() to it. Prometheus reads each reset as a counter
  // restart, so the alert fired on ordinary healing. Failures must be a gauge
  // (consecutive) and a separate monotonic counter (lifetime).
  const source = await readFile(
    fileURLToPath(new URL('../server/correlation/metrics.ts', import.meta.url)),
    'utf8',
  );
  assert.match(source, /# TYPE vulnstream_heartbeat_consecutive_failures gauge/);
  assert.match(source, /# TYPE vulnstream_heartbeat_failed_pings_total counter/);
  const rules = await readFile(path.join(deployDir, 'monitoring', 'vulnstream-alerts.yml'), 'utf8');
  assert.doesNotMatch(
    rules,
    /increase\(vulnstream_heartbeat_failures_total/,
    'increase() over a reset-on-success gauge is an artefact, not a failure signal',
  );
  assert.match(rules, /vulnstream_heartbeat_consecutive_failures >= 3/);
});

test('stall and admission rules require an enabled, admitting worker', async () => {
  // Verified against a live Prometheus: without this guard a deployment running
  // WORKER_ENABLED=false (monitoring only) alarms forever about a stalled
  // consumer nobody asked to start.
  const rules = await readFile(path.join(deployDir, 'monitoring', 'vulnstream-alerts.yml'), 'utf8');
  for (const alert of ['VulnStreamIngestionStalled', 'VulnStreamWorkersStuck', 'VulnStreamPipelineNotAdmitting', 'VulnStreamPipelineSchedulerDisabled', 'VulnStreamPipelineSchedulerStalled']) {
    const block = rules.slice(rules.indexOf(alert));
    const expr = block.slice(block.indexOf('expr:'), block.indexOf('for:'));
    assert.match(expr, /vulnstream_correlation_worker_enabled == 1/, `${alert} must require the worker to be enabled`);
  }
  // The queue-depth input is a cached sample; a stale sample must not be read as
  // current, or a wedged drain loop reports an old depth forever.
  const stalled = rules.slice(rules.indexOf('VulnStreamIngestionStalled'));
  assert.match(
    stalled.slice(0, stalled.indexOf('for:')),
    /vulnstream_correlation_pending_sample_age_seconds < 120/,
    'the stall rule must reject a stale queue sample',
  );
});

test('heartbeat staleness is gated on a successful ping', async () => {
  // -1 means "never pinged". `-1 > 180` is false, so an unstarted heartbeat
  // would be silently exempt from its own staleness check.
  const rules = await readFile(path.join(deployDir, 'monitoring', 'vulnstream-alerts.yml'), 'utf8');
  const block = rules.slice(rules.indexOf('VulnStreamHeartbeatStale'));
  const expr = block.slice(block.indexOf('expr:'), block.indexOf('for:'));
  assert.match(expr, /vulnstream_heartbeat_state\{state="pinged"\} == 1/);
});

test('no alert rule joins across instances with an unlabelled on()', async () => {
  // `on()` with no label list matches EVERY series on both sides, dropping the
  // instance label and cross-joining. It is safe only when the OTHER operand is
  // a scalar aggregation (one series across all instances, e.g. `sum(...)`).
  // Checking for a stray aggregate call anywhere in the expression proves
  // nothing -- `min_over_time(metric[5m])` on a vector is not a scalar.
  const rules = await readFile(path.join(deployDir, 'monitoring', 'vulnstream-alerts.yml'), 'utf8');
  // Split on alert boundaries first: the YAML block scalar means an expression
  // spans lines and is followed by `for:`/`labels:` at a fixed indent, which a
  // single regex over the raw file gets wrong (it matched nothing, so this test
  // passed vacuously).
  const blocks = rules.split(/\n\s*- alert:/).slice(1);
  assert.ok(blocks.length >= 10, `expected the full rule set, parsed ${blocks.length}`);
  const scalarAggregate = /\b(?:sum|avg|count|group)\s*\(/;
  let checked = 0;
  for (const block of blocks) {
    // The expression may be a YAML block (`expr: |`) or a single line, and is
    // terminated by `for:` or `labels:` at the rule's indent. `labels:` may be
    // inline flow style (`labels: {severity: critical}`), so the newline after
    // the key cannot be required.
    const exprMatch = /expr:\s*(?:\|\s*)?\n?([\s\S]*?)\s{6}(?:for|labels):/.exec(block);
    assert.ok(exprMatch, 'every rule must have an expression');
    const expr = exprMatch[1].replace(/^\s*\|/, '');
    if (!/and on\(\)/.test(expr)) continue;
    checked++;
    // Every operand joined with `and on()` must be either a scalar aggregation
    // or a direct per-instance series selector. Never two multi-instance
    // aggregations being cross-joined.
    const operands = expr
      .split(/and on\(\)/)
      .map((part) => part.replace(/\s+/g, ' ').trim()) // YAML block scalar spans lines
      .filter(Boolean);
    for (const operand of operands.slice(1))
      // A valid operand is either a scalar aggregation or a single series
      // selector (optionally wrapped in a range function / comparison). Two bare
      // multi-series selectors joined with `on()` is the join blowup this
      // guards against; `increase(metric[10m]) == 0` is a per-instance predicate
      // and is fine.
      assert.ok(
        scalarAggregate.test(operand) ||
          /^(?:increase|rate|irate|delta|min_over_time|max_over_time|avg_over_time|sum_over_time)\s*\(\s*[a-z_]+(_total|_seconds)?/.test(operand) ||
          /^[a-z_]+(_total|_seconds)?(\{|\s)/.test(operand),
        `suspicious operand joined with on(): ${operand.slice(0, 60)}`,
      );
  }
  assert.ok(checked > 0, 'expected at least one rule using and on() to be inspected');
});
test('alert-rule harness cannot silently query another Prometheus', async () => {
  // Twice during development a harness reported "nothing fired" because it
  // queried 127.0.0.1:9090, which on this host belongs to a different project's
  // Prometheus. A harness that reads the wrong server turns every rule into a
  // silent pass. Two mechanical guards must stay in place.
  const harness = await readFile(
    fileURLToPath(new URL('../scripts/alert-rule-check.mjs', import.meta.url)),
    'utf8',
  );
  // 1. A dedicated, non-default API port, published on loopback only. The
  //    container's INTERNAL 9090 is correct (that is where Prometheus listens);
  //    what must never appear is a QUERY against the host's default port.
  const code = harness.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\*.*$/gm, '');
  assert.doesNotMatch(
    code,
    /(?:localhost|127\.0\.0\.1):9090/,
    'harness must not query the default Prometheus port',
  );
  assert.match(harness, /const BASE_API_PORT = \d+/);
  // 2. It refuses to run if the port is already published by something else.
  assert.match(harness, /is already published by/, 'harness must refuse to reuse an occupied port');
  // 3. It scales BOTH `for:` and range windows, preserving their relationship.
  //    A rule inside increase(x[10m]) cannot fire while the harness only waits
  //    seconds, and flattening every `for:` to one value destroys escalation
  //    pairs that differ only by elapsed time.
  assert.match(harness, /for: \$\{Math\.max/, 'for: must be scaled, not flattened');
  assert.match(harness, /\[\$\{Math\.max\(40/, 'range windows must be scaled');
  // 4. It asserts, rather than merely printing. A harness that only logs can
  //    never fail a build.
  assert.match(harness, /process\.exitCode = 1/);
  // 5. It confirms it is talking to ITS OWN Prometheus by asserting the rule
  //    set is present, so a wrong port cannot look like "nothing fired".
  assert.match(harness, /never exposed the expected rule set/);
});

test('the alert-rule harness is wired into the test command', async () => {
  const pkg = JSON.parse(await readFile(fileURLToPath(new URL('../package.json', import.meta.url)), 'utf8'));
  // Docker is not available in every CI lane, so this is a separate script, but
  // it must exist as a named entry point that reviewers can run.
  assert.ok(
    pkg.scripts['test:alerts'] || pkg.scripts['alerts:check'],
    'package.json must expose the alert-rule harness as an npm script',
  );
});
