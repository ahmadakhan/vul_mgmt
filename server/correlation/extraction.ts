import { Worker } from 'node:worker_threads';
import { performance } from 'node:perf_hooks';
import type { ExtractedText } from './validation.ts';
import type { CorrelationTelemetry } from './telemetry.ts';

// Regex executes ONLY inside a disposable worker. A timer around synchronous
// RegExp.exec on the parent event loop cannot interrupt catastrophic backtracking.
const source = String.raw`
const { parentPort } = require('node:worker_threads');
const { performance } = require('node:perf_hooks');

// Linear HTML stripping: scan for tag boundaries without backtracking.
// A quadratic /<script\b[^>]*>[\s\S]*?<\/script\s*>/gi regex on input with
// many unclosed <script starts is a CPU-exhaustion vector. A single-pass
// scanner that skips to the next '>' is O(n) in input length.
function stripTags(input) {
  let out = '';
  let i = 0;
  const n = input.length;
  while (i < n) {
    if (input[i] === '<') {
      const end = input.indexOf('>', i);
      i = end < 0 ? n : end + 1;
    } else {
      out += input[i];
      i++;
    }
  }
  return out;
}

parentPort.on('message', ({ text }) => {
  const start = performance.now();
  const check = () => { if (performance.now() - start > 200) throw new Error('budget'); };
  try {
    const plain = stripTags(text).toLowerCase();
    check();
    const cves = new Set();
    const cvePattern = /\bcve-[0-9]{4}-[0-9]{4,19}\b/g;
    let match;
    while ((match = cvePattern.exec(plain)) !== null) {
      check(); cves.add(match[0].toUpperCase());
      if (cves.size > 100) throw new Error('limit');
    }
    const indicators = ['zero-day', 'zero day', 'actively exploited', 'in the wild', 'unpatched', 'remote code execution', 'vulnerability', 'exploit'];
    let signals = 0;
    for (const word of indicators) { check(); if (plain.includes(word)) signals++; }
    const tokens = plain.split(/[^a-z0-9_.+-]+/).filter(Boolean);
    check();
    const normalized = ' ' + tokens.join(' ') + ' ';
    const ranges = [];
    const consumed = [];
    // Shared with server/correlation/version.ts: the bound grammar accepts 1-4
    // numeric components. A two-component minimum was not capturable as a bound
    // of "patched before 4", so the entity fell through to the versionless
    // branch and scored MEDIUM instead of being reviewed as a coarse bound.
    const VERSION = 'v?[0-9]{1,9}(?:\\.[0-9]{1,9}){0,3}(?:-(?:rc|alpha|beta|pre|preview|RC|ALPHA|BETA|PRE|PREVIEW)(?:[.-][0-9]{1,6})?)?';
    // Product phrase tokens must start with a letter to avoid greedily consuming
    // version-like segments (e.g. "k8s 2.0 through 3.0" must not capture "2.0").
    // Non-greedy {0,3}? lets the operator phrase claim its words first.
    const PROD = '[a-z][a-z0-9_+.-]*(?: [a-z][a-z0-9_+.-]*){0,3}?';
    // Inclusive band: "between X and Y", "from X to Y"
    var bandPattern = new RegExp('(?:^| )(' + PROD + ') (?:versions? )?(?:between|from) (' + VERSION + ') (?:and|to|through|thru) (' + VERSION + ')(?=$|\\s)', 'g');
    while ((match = bandPattern.exec(normalized)) !== null) {
      check();
      if (ranges.length >= 100) throw new Error('limit');
      ranges.push({ productPhrase: match[1].replace(/ versions?$/,''), range: '>=' + match[2] + ' <=' + match[3] });
      consumed.push([match.index, match.index + match[0].length]);
    }
    // Bare band: "5.0 through 5.7", "2.1.0 to 2.3.4" (no "between/from" prefix)
    var bareBand = new RegExp('(?:^| )(' + PROD + ') (' + VERSION + ') (?:through|to|thru) (' + VERSION + ')(?=$|\\s)', 'g');
    while ((match = bareBand.exec(normalized)) !== null) {
      if (consumed.some(([s,e]) => match.index >= s && match.index < e)) continue;
      check();
      if (ranges.length >= 100) throw new Error('limit');
      ranges.push({ productPhrase: match[1].replace(/ versions?$/,''), range: '>=' + match[2] + ' <=' + match[3] });
      consumed.push([match.index, match.index + match[0].length]);
    }
    // Inclusive upper bound: "product up to and including X"
    var inclusiveUpper = new RegExp('(?:^| )(' + PROD + ') up to and including (' + VERSION + ')(?=$|\\s)', 'g');
    while ((match = inclusiveUpper.exec(normalized)) !== null) {
      if (consumed.some(([s,e]) => match.index >= s && match.index < e)) continue;
      check();
      if (ranges.length >= 100) throw new Error('limit');
      ranges.push({ productPhrase: match[1].replace(/ versions?$/,''), range: '<=' + match[2] });
    }
    // Word-based operators (product phrase optional): "product before X", "elasticsearch through 8.0"
    var singleBound = new RegExp('(?:^| )((?:' + PROD + ' )?)?(?:versions? )?(before|prior to|below|earlier than|at most|up to|through)(?: version)? (' + VERSION + ')(?=$|\\s)', 'g');
    while ((match = singleBound.exec(normalized)) !== null) {
      if (consumed.some(([s,e]) => match.index >= s && match.index < e)) continue;
      check();
      if (ranges.length >= 100) throw new Error('limit');
      const op = match[2] === 'through' ? '<=' : '<';
      ranges.push({ productPhrase: match[1] ? match[1].trim().replace(/ versions?$/,'') : '', range: op + match[3] });
    }
    // "in" operators (product phrase optional): "fixed in X", "openssl patched in 2.5.0"
    var inBound = new RegExp('(?:^| )((?:' + PROD + ' )?)?(?:versions? )?(fixed in|patched in|resolved in|remediated in|addressed in)(?: version)? (' + VERSION + ')(?=$|\\s)', 'g');
    while ((match = inBound.exec(normalized)) !== null) {
      if (consumed.some(([s,e]) => match.index >= s && match.index < e)) continue;
      check();
      if (ranges.length >= 100) throw new Error('limit');
      ranges.push({ productPhrase: match[1] ? match[1].trim().replace(/ versions?$/,'') : '', range: '<' + match[3] });
    }
    const density = signals / Math.max(1,tokens.length);
    parentPort.postMessage({ text: normalized, cleanContent: plain.trim(), ranges, cveIds: [...cves],
      zeroDay: cves.size === 0 && signals >= 2 && density >= 0.002,
      securitySignal: signals > 0, negated: /\b(not affected|not vulnerable|unaffected|false positive)\b/.test(plain), zeroDayDensity: density });
  } catch (error) { parentPort.postMessage({ failed: true, reason: String((error && error.message) || error) }); }
});
parentPort.postMessage({ ready: true });
`;
export async function extractText(
  text: string,
  telemetry: CorrelationTelemetry,
  trackingId: string,
  signal?: AbortSignal,
): Promise<ExtractedText> {
  if (text.length > 50_201) throw new Error('EXTRACTION_INPUT_LIMIT');
  signal?.throwIfAborted();
  const start = performance.now();
  return new Promise((resolve, reject) => {
    const worker = new Worker(source, {
      eval: true,
      resourceLimits: { maxOldGenerationSizeMb: 24, stackSizeMb: 2 },
    });
    let done = false;
    let timer: ReturnType<typeof setTimeout>;
    /** Which budget expired, so telemetry reports the real cause instead of a
     * generic "isolated". A worker that exceeds its 24 MB heap limit dies with
     * a Worker error, not with the 200 ms budget — the two require different
     * operator responses (payload shape vs. regex complexity). */
    let stage: 'start' | 'extract' = 'start';
    const finish = (error?: Error, value?: ExtractedText) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      signal?.removeEventListener('abort', abort);
      void worker.terminate();
      const cause = error?.message ?? '';
      const event = !error
        ? 'extraction.completed'
        : cause === 'EXTRACTION_TIMEOUT' || cause === 'EXTRACTION_BUDGET'
          ? 'extraction.budget_exceeded'
          : cause === 'WORKER_ABORTED' || cause === 'EXTRACTION_WORKER_EXIT'
            ? 'extraction.terminated'
            : 'extraction.isolated';
      telemetry.log(error ? 'CRITICAL' : 'INFO', event, {
        trackingId,
        extractionLatencyMs: performance.now() - start,
        ...(error && stage === 'start' ? { count: 1 } : {}),
      });
      if (error) reject(error);
      else resolve(value!);
    };
    const abort = () => finish(new Error('WORKER_ABORTED'));
    signal?.addEventListener('abort', abort, { once: true });
    timer = setTimeout(() => finish(new Error('WORKER_START_TIMEOUT')), 2000);
    worker.on('message', (value: ExtractedText & { ready?: boolean; failed?: boolean }) => {
      if (value.ready) {
        clearTimeout(timer);
        stage = 'extract';
        timer = setTimeout(() => finish(new Error('EXTRACTION_TIMEOUT')), 200);
        worker.postMessage({ text });
      } else if (value.failed) finish(new Error('EXTRACTION_BUDGET'));
      else finish(undefined, value);
    });
    worker.on('error', () => finish(new Error('EXTRACTION_WORKER_FAILED')));
    worker.on('exit', () => {
      if (!done) finish(new Error('EXTRACTION_WORKER_EXIT'));
    });
  });
}
