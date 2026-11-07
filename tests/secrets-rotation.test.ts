import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { loadConfig } from '../server/config.ts';
import { decrypt, encrypt, encryptionKeys } from '../server/secrets.ts';

const key = () => randomBytes(32).toString('base64');

test('key rotation retains index-zero and legacy ciphertext under the new key order', () => {
  const retired = key();
  const current = key();
  const ciphertext = encrypt('provider-secret', [retired], 'email-provider:SENDGRID');
  const keys = encryptionKeys({ ENCRYPTION_KEY: current, ENCRYPTION_KEYS: `${retired},${current}` });
  assert.deepEqual(keys, [current, retired]);
  assert.equal(decrypt(ciphertext, keys, 'email-provider:SENDGRID'), 'provider-secret');
  const parts = ciphertext.split('.');
  const legacy = [parts[0], ...parts.slice(2)].join('.');
  assert.equal(decrypt(legacy, keys, 'email-provider:SENDGRID'), 'provider-secret');
  assert.equal(decrypt(encrypt('fresh', keys, 'feed:new'), [current], 'feed:new'), 'fresh');
  assert.throws(() => decrypt(ciphertext, keys, 'feed:other'), /Failed to decrypt/);
  assert.throws(() => decrypt(ciphertext, [current], 'email-provider:SENDGRID'), /Failed to decrypt/);
  assert.throws(() => decrypt(`${ciphertext}.extra`, keys, 'email-provider:SENDGRID'), /encoding/);
  const tampered = [...parts];
  tampered[3] = randomBytes(16).toString('base64');
  assert.throws(() => decrypt(tampered.join('.'), keys, 'email-provider:SENDGRID'), /Failed to decrypt/);
});

test('configuration preserves and validates the retained decryption key ring', () => {
  const current = key();
  const retired = key();
  const environment = { NODE_ENV: 'test', DATABASE_URL: 'postgres://unused', APP_ORIGIN: 'http://localhost', ENCRYPTION_KEY: current };
  assert.deepEqual(encryptionKeys(loadConfig({ ...environment, ENCRYPTION_KEYS: retired })), [current, retired]);
  assert.equal(loadConfig(environment).ENCRYPTION_KEYS, '');
  assert.throws(() => loadConfig({ ...environment, ENCRYPTION_KEYS: 'invalid' }), /ENCRYPTION_KEYS/);
  assert.throws(() => loadConfig({ ...environment, ENCRYPTION_KEYS: Array.from({ length: 17 }, key).join(',') }), /ENCRYPTION_KEYS/);
});