/**
 * `node:test` compatibility shim for the Vitest runner.
 *
 * The project's suite is written against the Node test runner (`npm test`) and
 * is also executed under Vitest (`npm run test:unit`). Vitest has no `node:test`
 * implementation, so `vitest.config.ts` rewrites the builtin import of test
 * files to this module while transforming them.
 *
 * The API surface used by the suite is intentionally small: `test(name, fn)`,
 * `test(name, options, fn)` and nested `t.test(name, fn)` subtests. Nested
 * subtests run inline and sequentially, exactly like they would in the parent
 * test, so shared database state and ordering are preserved. Failures are
 * re-labelled with the subtest path so a flattened report is still diagnosable.
 */

import { test as vitestTest, describe as vitestDescribe, it as vitestIt, beforeAll as vitestBefore, afterAll as vitestAfter } from 'vitest';

export interface NodeTestOptions {
  skip?: boolean | string;
  todo?: boolean | string;
  only?: boolean;
  timeout?: number;
  concurrency?: boolean | number;
  signal?: AbortSignal;
}

export interface NodeTestContext {
  test: (
    name: string,
    optionsOrFn?: NodeTestOptions | (() => unknown | Promise<unknown>),
    fn?: () => unknown | Promise<unknown>,
  ) => Promise<void>;
  diagnostic: (message: string) => void;
}

type TestFn = (context: NodeTestContext) => unknown | Promise<unknown>;
type TestArgs = [name: string, optionsOrFn?: NodeTestOptions | TestFn, fn?: TestFn];

const subtestPath: string[] = [];

/**
 * Wraps an inline subtest invocation so a failure identifies which nested test
 * failed even though Vitest reports the enclosing test as the failing task.
 */
function failWithPath(error: unknown, path: string[]): never {
  const label = path.join(' › ');
  if (!label) throw error;
  if (error instanceof Error) {
    error.message = `${label}: ${error.message}`;
    throw error;
  }
  throw new Error(`${label}: ${String(error)}`);
}

const context: NodeTestContext = {
  async test(name, optionsOrFn, maybeFn) {
    const options = typeof optionsOrFn === 'function' ? {} : (optionsOrFn ?? {});
    const fn = typeof optionsOrFn === 'function' ? optionsOrFn : maybeFn;
    if (!fn || options.skip || options.todo) return;
    subtestPath.push(name);
    // A subtest has no timeout of its own under Vitest: it runs inside the
    // enclosing test task, so a hang reports only the outer name after the
    // whole suite's 120s budget. Bound each one and name the step that hung.
    const limit = options.timeout ?? 15000;
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      await new Promise<void>((resolve, reject) => {
        timer = setTimeout(() => reject(new Error(`subtest exceeded ${limit}ms`)), limit);
        Promise.resolve(fn()).then(
          () => resolve(),
          reject,
        );
      });
    } catch (error) {
      failWithPath(error, subtestPath);
    } finally {
      if (timer) clearTimeout(timer);
      subtestPath.pop();
    }
  },
  diagnostic(message) {
    // `node:test` writes diagnostics outside the assertion stream; stdout keeps
    // them visible without failing the test.
    console.log(`# ${message}`);
  },
};

function registerTest(
  mode: 'run' | 'skip' | 'todo' | 'only',
  name: string,
  optionsOrFn?: NodeTestOptions | TestFn,
  maybeFn?: TestFn,
): void {
  const options = typeof optionsOrFn === 'function' ? {} : (optionsOrFn ?? {});
  const fn = typeof optionsOrFn === 'function' ? optionsOrFn : maybeFn;
  const skip = mode === 'skip' ? true : options.skip;
  const todo = mode === 'todo' ? true : options.todo;
  const only = mode === 'only' || options.only === true;

  if (todo) {
    vitestTest.todo(name);
    return;
  }
  if (!fn) {
    // A test declared without a body is a placeholder, not a silent pass.
    vitestTest.todo(name);
    return;
  }

  const runner = only ? vitestTest.only : vitestTest;
  runner(name, { skip: skip ? true : undefined, timeout: options.timeout }, async () => {
    subtestPath.length = 0;
    await fn(context);
  });
}

type TestApi = ((...args: TestArgs) => void) & {
  skip: (...args: TestArgs) => void;
  todo: (...args: TestArgs) => void;
  only: (...args: TestArgs) => void;
};

export const test: TestApi = ((...args: TestArgs) => registerTest('run', ...args)) as TestApi;

test.skip = (...args: TestArgs) => registerTest('skip', ...args);
test.todo = (...args: TestArgs) => registerTest('todo', ...args);
test.only = (...args: TestArgs) => registerTest('only', ...args);

// Node:test aliases used by Mocha-style suites (describe/it/before/after).
// Vitest maps these to vitest's describe/it/beforeAll/afterAll.
export const describe = vitestDescribe;
export const it = vitestIt;
export const before = vitestBefore;
export const after = vitestAfter;

export default test;
