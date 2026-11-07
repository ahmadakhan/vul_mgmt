import { defineConfig } from 'vitest/config';
import { randomBytes } from 'node:crypto';
import path from 'node:path';

/**
 * The suite targets the Node test runner and is also executed by Vitest. Vite
 * treats `node:test` as an external builtin before plugins can resolve it, so
 * the import specifier is rewritten while the test file is transformed. Test
 * sources stay valid for `node --test` and no per-file duplication is needed.
 */
const testsDir = path.resolve(import.meta.dirname, 'tests');
const nodeTestCompatPath = path.join(testsDir, 'node-test-compat.ts');
const nodeTestImport = /(from\s*)(["'])node:test\2/g;
const nodeTestImportTest = /from\s*["']node:test["']/;

const nodeTestCompat = {
  name: 'node-test-compat',
  enforce: 'pre' as const,
  transform(code: string, id: string) {
    const cleanId = id.split('?')[0];
    if (!cleanId.startsWith(testsDir + path.sep)) return null;
    if (!nodeTestImportTest.test(code)) return null;
    return {
      code: code.replace(nodeTestImport, `$1${JSON.stringify(nodeTestCompatPath)}`),
      map: null,
    };
  },
};

export default defineConfig({
  plugins: [nodeTestCompat],
  test: {
    globals: false,
    include: ['src/**/*.test.ts', 'tests/**/*.test.ts'],
    exclude: ['node_modules', 'dist', 'server-dist'],
    isolate: true,
    maxConcurrency: 4,
    maxWorkers: 4,
    // Database suites execute their nested subtests inline, so the enclosing
    // test owns the full duration of the file's database scenario.
    testTimeout: 120000,
    hookTimeout: 120000,
    teardownTimeout: 30000,
    globalSetup: ['./tests/global-setup.ts'],
    setupFiles: ['./tests/per-file-setup.ts'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'lcov'],
      exclude: ['node_modules/**', 'dist/**', 'tests/**', '**/*.d.ts'],
    },
    environment: 'node',
    env: {
      NODE_ENV: 'test',
      ENCRYPTION_KEY: process.env.ENCRYPTION_KEY || randomBytes(32).toString('base64'),
    },
  },
  resolve: {
    alias: {
      '@': path.resolve(import.meta.dirname, '.'),
    },
  },
});
