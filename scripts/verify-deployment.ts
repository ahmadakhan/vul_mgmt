/** Read-only deployment checks by default; --exercise explicitly tests one app outage. */
import { execFileSync } from 'node:child_process';
import { request } from 'node:https';
import { rootCertificates } from 'node:tls';
import { performance } from 'node:perf_hooks';
import { setTimeout as delay } from 'node:timers/promises';
import { writeFile } from 'node:fs/promises';
const appNames = ['vulnstream-enterprise-app-1', 'vulnstream-enterprise-app-2'];
const proxy = 'vulnstream-enterprise-proxy-1';
const exercise = process.argv.includes('--exercise');
if (!process.env.APP_ORIGIN) throw new Error('APP_ORIGIN required');
const origin = new URL(process.env.APP_ORIGIN);
if (origin.protocol !== 'https:') throw new Error('HTTPS origin required');
const docker = (args: string[]) =>
  execFileSync('docker', args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], timeout: 30000 });
let additionalCa = '';
try {
  additionalCa = docker(['exec', proxy, 'cat', '/data/caddy/pki/authorities/local/root.crt']);
} catch {
  /* Public certificates use system roots. */
}
async function probe(): Promise<number> {
  const started = performance.now();
  return new Promise((resolve, reject) => {
    const req = request(
      {
        hostname: origin.hostname,
        port: Number(origin.port || 443),
        path: '/ready',
        method: 'GET',
        family: 4,
        lookup: (_name, _options, callback) => callback(null, '127.0.0.1', 4),
        ca: additionalCa ? [...rootCertificates, additionalCa] : undefined,
        headers: { Host: origin.host },
        agent: false,
      },
      (res) => {
        res.resume();
        res.once('end', () =>
          res.statusCode === 200
            ? resolve(performance.now() - started)
            : reject(new Error('PROXY_READINESS_FAILED')),
        );
      },
    );
    req.setTimeout(10000, () => req.destroy(new Error('PROXY_TIMEOUT')));
    req.once('error', reject);
    req.end();
  });
}
function containersHealthy(): boolean {
  return appNames.every((name) => {
    const data = JSON.parse(docker(['inspect', name]))[0] as {
      State: { Health?: { Status: string } };
      Config: { Labels: Record<string, string> };
    };
    if (
      data.Config.Labels['com.docker.compose.project'] !== 'vulnstream-enterprise' ||
      data.Config.Labels['com.docker.compose.service'] !== 'app'
    )
      throw new Error('UNEXPECTED_CONTAINER_OWNERSHIP');
    return data.State.Health?.Status === 'healthy';
  });
}
const latencies: number[] = [];
let stopped = false,
  restored = false;
try {
  if (!containersHealthy()) throw new Error('BOTH_REPLICAS_MUST_BE_HEALTHY');
  latencies.push(await probe());
  if (exercise) {
    stopped = true;
    docker(['stop', '--time', '20', appNames[1]]);
  }
  for (let i = 0; i < 10; i++) latencies.push(await probe());
} finally {
  if (stopped) {
    docker(['start', appNames[1]]);
    for (let i = 0; i < 120; i++) {
      try {
        docker([
          'exec',
          appNames[1],
          'node',
          '--input-type=module',
          '-e',
          'const r=await fetch("http://127.0.0.1:8080/ready");process.exit(r.ok?0:1);',
        ]);
        if (containersHealthy()) {
          restored = true;
          break;
        }
        await delay(500);
      } catch {
        await delay(500);
      }
    }
    if (!restored) throw new Error('REPLICA_DID_NOT_RECOVER');
  }
}
let targets = JSON.parse(
  docker([
    'exec',
    'vulnstream-enterprise-prometheus-1',
    'wget',
    '-qO-',
    'http://127.0.0.1:9090/api/v1/targets',
  ]),
) as { data: { activeTargets: { health: string }[] } };
for (
  let i = 0;
  i < 45 &&
  (targets.data.activeTargets.length < 2 ||
    targets.data.activeTargets.some((target) => target.health !== 'up'));
  i++
) {
  await delay(1000);
  targets = JSON.parse(
    docker([
      'exec',
      'vulnstream-enterprise-prometheus-1',
      'wget',
      '-qO-',
      'http://127.0.0.1:9090/api/v1/targets',
    ]),
  );
}
if (
  targets.data.activeTargets.length < 2 ||
  targets.data.activeTargets.some((target) => target.health !== 'up')
)
  throw new Error('MONITORING_TARGETS_UNHEALTHY');
const report = {
  proxyRequests: latencies.length,
  proxyFailures: 0,
  maxProxyLatencyMs: Math.max(...latencies),
  singleReplicaOutageExercised: exercise,
  replicaRestored: exercise ? restored : null,
  monitoringTargets: targets.data.activeTargets.length,
  healthyMonitoringTargets: targets.data.activeTargets.filter((target) => target.health === 'up').length,
};
console.log(JSON.stringify(report, null, 2));
if (process.env.CORRELATION_DEPLOYMENT_REPORT)
  await writeFile(process.env.CORRELATION_DEPLOYMENT_REPORT, JSON.stringify(report, null, 2) + '\n');
