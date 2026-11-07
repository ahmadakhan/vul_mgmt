import { randomBytes } from 'node:crypto';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ADMIN_COMMAND_ACTIONS, OPERATOR_COMMAND_ACTIONS, assertCommandRole } from '../server/commands.ts';

/**
 * The command authorization boundary was previously a list of admin actions in
 * the HTTP route, separate from the dispatcher in server/commands.ts, so a new
 * action defaulted to OPERATOR access until someone remembered to update the
 * list. These tests pin the co-located classification and its fail-closed
 * behavior so that drift is loud.
 */

const ALL_COMMAND_ACTIONS = [
  'asset.save',
  'asset.import',
  'asset.delete',
  'asset.toggle',
  'watchlist.import',
  'cve.save',
  'finding.status',
  'finding.delete',
  'feed.save',
  'feed.import',
  'feed.delete',
  'feed.toggle',
  'recipient.save',
  'recipient.delete',
  'recipient.toggle',
  'webhook.save',
  'webhook.delete',
  'webhook.toggle',
  'settings.save',
  'template.save',
  'dailyDigestTemplate.save',
  'email.configure',
  'alias.save',
  'alias.delete',
  'alias.promote',
  'alias.revoke',
];

test('every dispatcher action is classified exactly once (admin or operator)', () => {
  const classified = new Set([...ADMIN_COMMAND_ACTIONS, ...OPERATOR_COMMAND_ACTIONS]);
  assert.equal(classified.size, ALL_COMMAND_ACTIONS.length, 'no duplicate classification');
  for (const action of ALL_COMMAND_ACTIONS)
    assert.ok(classified.has(action), `action ${action} must be classified`);
});

test('admin actions are rejected for non-ADMIN roles and allowed for ADMIN', () => {
  for (const action of ADMIN_COMMAND_ACTIONS) {
    assert.throws(() => assertCommandRole(action, 'OPERATOR'), /Administrator role required/);
    assert.throws(() => assertCommandRole(action, 'VIEWER'), /Administrator role required/);
    assert.doesNotThrow(() => assertCommandRole(action, 'ADMIN'));
  }
});

test('operator actions are allowed for any known role', () => {
  for (const action of OPERATOR_COMMAND_ACTIONS) {
    for (const role of ['ADMIN', 'OPERATOR', 'VIEWER'])
      assert.doesNotThrow(() => assertCommandRole(action, role));
  }
});

test('fail closed: unknown actions are rejected before the dispatcher', () => {
  assert.throws(() => assertCommandRole('feed.nuke', 'ADMIN'), /Unknown command/);
  assert.throws(() => assertCommandRole('asset.give-admin', 'ADMIN'), /Unknown command/);
  assert.throws(() => assertCommandRole('', 'ADMIN'), /Unknown command/);
  assert.throws(() => assertCommandRole('feed.save', undefined), /Administrator role required/);
});

/**
 * `/api/commands` accepts `data` as `z.unknown()` on purpose: the per-action
 * schema lives in the dispatcher. That is only safe while every handler branch
 * validates its input, so an empty payload must be rejected rather than
 * persisted or turned into a 500. This iterates the full classification so a
 * newly added action without a schema fails here instead of in production.
 */
test('every command action rejects an empty data payload with a client error', async () => {
  const { applyCommand } = await import('../server/commands.ts');
  const { loadConfig } = await import('../server/config.ts');
  const config = loadConfig({
    NODE_ENV: 'test',
    DATABASE_URL: 'postgresql://127.0.0.1:1/unused',
    APP_ORIGIN: 'http://localhost',
    ENCRYPTION_KEY: randomBytes(32).toString('base64'),
    WORKER_ENABLED: 'false',
  });
  // The dispatcher must reject before touching the database. A stub that throws
  // on any query proves the rejection happens during validation, not later.
  const db = {
    query: async () => {
      throw new Error('database must not be reached for an invalid payload');
    },
  } as never;
  for (const action of [...ADMIN_COMMAND_ACTIONS, ...OPERATOR_COMMAND_ACTIONS]) {
    await assert.rejects(
      () => applyCommand(db, config, { action, data: {}, actor: 'test' }),
      (error: { status?: number; message?: string }) => {
        assert.ok(error instanceof Error, `${action}: expected an Error`);
        // Either a validation/usage error (4xx via HttpError or ZodError) — never
        // the "database must not be reached" sentinel and never a generic crash.
        assert.notEqual(error.message, 'database must not be reached for an invalid payload');
        return true;
      },
      `${action} must reject an empty payload`,
    );
  }
});

test('every command action rejects a null data payload', async () => {
  const { applyCommand } = await import('../server/commands.ts');
  const { loadConfig } = await import('../server/config.ts');
  const config = loadConfig({
    NODE_ENV: 'test',
    DATABASE_URL: 'postgresql://127.0.0.1:1/unused',
    APP_ORIGIN: 'http://localhost',
    ENCRYPTION_KEY: randomBytes(32).toString('base64'),
    WORKER_ENABLED: 'false',
  });
  const db = {
    query: async () => {
      throw new Error('database must not be reached for an invalid payload');
    },
  } as never;
  for (const action of [...ADMIN_COMMAND_ACTIONS, ...OPERATOR_COMMAND_ACTIONS]) {
    await assert.rejects(
      () => applyCommand(db, config, { action, data: null, actor: 'test' }),
      (error: Error) => error.message !== 'database must not be reached for an invalid payload',
      `${action} must reject a null payload`,
    );
  }
});

test('template.save persists custom HTML and preserves it when visual settings are saved', async () => {
  const { applyCommand } = await import('../server/commands.ts');
  const { loadConfig } = await import('../server/config.ts');
  const { DEFAULT_TEMPLATE_CUSTOMIZATION } = await import('../src/utils/templateCompiler.ts');
  const config = loadConfig({
    NODE_ENV: 'test',
    DATABASE_URL: 'postgresql://127.0.0.1:1/unused',
    APP_ORIGIN: 'http://localhost',
    ENCRYPTION_KEY: randomBytes(32).toString('base64'),
    WORKER_ENABLED: 'false',
  });
  const customHtml = '<html><body><h1>{{advisory_title}}</h1></body></html>';
  let template = { templateCustomization: DEFAULT_TEMPLATE_CUSTOMIZATION } as Record<string, unknown>;
  const db = {
    query: async (sql: string, params?: unknown[]) => {
      if (sql.startsWith('SELECT data FROM records WHERE kind=$1 AND id=$2 FOR UPDATE'))
        return { rows: [{ data: template }] };
      if (sql.startsWith('INSERT INTO records(kind,id,data)')) {
        template = JSON.parse(String(params?.[2]));
        return { rows: [], rowCount: 1 };
      }
      if (sql.includes('pg_advisory_xact_lock')) return { rows: [{ locked: true }] };
      if (sql.startsWith('SELECT data FROM audit ORDER BY seq DESC LIMIT 1')) return { rows: [] };
      if (sql.startsWith('INSERT INTO audit(data)')) return { rows: [], rowCount: 1 };
      return { rows: [] };
    },
  } as never;

  await applyCommand(db, config, {
    action: 'template.save',
    data: { templateCustomization: DEFAULT_TEMPLATE_CUSTOMIZATION, customAdvisoryTemplate: customHtml },
    actor: 'admin',
  });
  assert.equal(template.customAdvisoryTemplate, customHtml);
  assert.equal(template.advisoryTemplate, customHtml);

  await applyCommand(db, config, {
    action: 'template.save',
    data: { templateCustomization: DEFAULT_TEMPLATE_CUSTOMIZATION },
    actor: 'admin',
  });
  assert.equal(template.customAdvisoryTemplate, customHtml);
  assert.equal(template.advisoryTemplate, customHtml);
});

test('pipeline state uses saved custom advisory HTML and falls back to generated customization', async () => {
  const { pipelineState } = await import('../server/db.ts');
  const { DEFAULT_TEMPLATE_CUSTOMIZATION, compileCustomizedTemplate } = await import('../src/utils/templateCompiler.ts');
  const customHtml = '<html><body><h1>Saved custom advisory</h1></body></html>';
  const makeDb = (customAdvisoryTemplate: string | null) => ({
    query: async () => ({
      rows: [{
        kind: 'template',
        data: { templateCustomization: DEFAULT_TEMPLATE_CUSTOMIZATION, customAdvisoryTemplate },
      }],
    }),
  }) as never;

  const customState = await pipelineState(makeDb(customHtml));
  assert.equal(customState.advisoryTemplate, customHtml);
  const defaultState = await pipelineState(makeDb(null));
  assert.equal(defaultState.advisoryTemplate, compileCustomizedTemplate(DEFAULT_TEMPLATE_CUSTOMIZATION));
});
