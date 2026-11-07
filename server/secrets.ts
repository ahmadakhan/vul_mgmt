import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
  scrypt as scryptCallback,
  timingSafeEqual,
  createHash,
} from 'node:crypto';
import { WorkLimiter } from './workLimiter.ts';
// A single scrypt operation consumes about 128 MiB. libuv's default four-way
// concurrency can exceed the entire application container's memory allowance.
const passwordWork = new WorkLimiter(1, 8, 5000);
const scrypt = (password: string, salt: string, length: number) =>
  passwordWork.run(
    () =>
      new Promise<Buffer>((resolve, reject) =>
        scryptCallback(
          password,
          salt,
          length,
          { N: 131072, r: 8, p: 1, maxmem: 256 * 1024 * 1024 },
          (error, result) => (error ? reject(error) : resolve(result)),
        ),
      ),
  );
export const tokenHash = (value: string) => createHash('sha256').update(value).digest('hex');
export const randomToken = () => randomBytes(32).toString('base64url');
export async function passwordHash(password: string) {
  const salt = randomBytes(16).toString('hex');
  const result = (await scrypt(password, salt, 64)) as Buffer;
  return `scrypt131072$${salt}$${result.toString('hex')}`;
}
export async function checkPassword(password: string, stored: string) {
  const [algorithm, salt, expected] = stored.split('$');
  if (
    algorithm !== 'scrypt131072' ||
    !/^[0-9a-f]{32}$/.test(salt || '') ||
    !/^[0-9a-f]{128}$/.test(expected || '')
  )
    return false;
  const result = (await scrypt(password, salt, 64)) as Buffer;
  return timingSafeEqual(result, Buffer.from(expected, 'hex'));
}
/**
 * Resolves the ordered list of encryption keys from configuration.
 *
 * `ENCRYPTION_KEY` is the current (write) key. `ENCRYPTION_KEYS` (comma-separated)
 * lists all keys that can decrypt, with the current key first. This enables
 * key rotation: data encrypted with a retired key can still be decrypted, and
 * re-encryption with the current key happens on the next write.
 */
export function encryptionKeys(config: { ENCRYPTION_KEY?: string; ENCRYPTION_KEYS?: string }): string[] {
  const keys: string[] = [];
  if (config.ENCRYPTION_KEYS) {
    for (const raw of config.ENCRYPTION_KEYS.split(',')) {
      const key = raw.trim();
      if (key && !keys.includes(key)) keys.push(key);
    }
  }
  if (config.ENCRYPTION_KEY) {
    const current = keys.indexOf(config.ENCRYPTION_KEY);
    if (current >= 0) keys.splice(current, 1);
    keys.unshift(config.ENCRYPTION_KEY);
  }
  if (!keys.length) throw new Error('No encryption keys configured');
  return keys;
}
export function encrypt(value: string, keys: string[], context: string): string {
  if (!value) return '';
  const key = Buffer.from(keys[0], 'base64');
  if (key.length !== 32) throw new Error('Invalid encryption key: must be 32 bytes');
  const iv = randomBytes(12),
    cipher = createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(Buffer.from(context));
  const payload = Buffer.concat([cipher.update(value, 'utf8'), cipher.final()]);
  return [
    'v1',
    '0', // key index: current key is always index 0
    iv.toString('base64'),
    cipher.getAuthTag().toString('base64'),
    payload.toString('base64'),
  ].join('.');
}
export function decrypt(value: string, keys: string[], context: string): string {
  if (!value) return '';
  const parts = value.split('.');
  if (parts.length !== 4 && parts.length !== 5) throw new Error('Invalid encrypted secret encoding');
  // Legacy envelope (pre key-rotation): `v1.<iv>.<tag>.<body>` — four segments,
  // encrypted under the single configured key. Secrets written before the
  // key-index segment was introduced stayed in this shape in the database, and
  // every decrypt of them threw "Invalid encrypted secret encoding", breaking
  // feed authentication, webhook URLs and provider tokens wholesale. Normalise
  // to the current shape by inserting index 0; the AAD context is identical, so
  // the ciphertext verifies exactly as before.
  const [version, keyIndex, iv, tag, body] =
    parts.length === 4 && parts[0] === 'v1'
      ? ['v1', '0', parts[1], parts[2], parts[3]]
      : (parts as [string, string, string, string, string]);
  if (
    version !== 'v1' ||
    !iv ||
    !tag ||
    !body ||
    !/^[A-Za-z0-9+/]+={0,2}$/.test(iv) ||
    !/^[A-Za-z0-9+/]+={0,2}$/.test(tag) ||
    !/^[A-Za-z0-9+/]+={0,2}$/.test(body) ||
    Buffer.from(iv, 'base64').length !== 12 ||
    Buffer.from(tag, 'base64').length !== 16
  )
    throw new Error('Invalid encrypted secret encoding');
  const index = Number(keyIndex);
  if (!/^\d+$/.test(keyIndex) || !Number.isInteger(index) || index < 0 || index >= keys.length)
    throw new Error('Invalid encrypted secret key index');
  const candidates = [
    index,
    ...keys.map((_key, position) => position).filter((position) => position !== index),
  ];
  for (const candidate of candidates) {
    const key = Buffer.from(keys[candidate], 'base64');
    if (key.length !== 32) continue;
    try {
      const cipher = createDecipheriv('aes-256-gcm', key, Buffer.from(iv, 'base64'));
      cipher.setAAD(Buffer.from(context));
      cipher.setAuthTag(Buffer.from(tag, 'base64'));
      return Buffer.concat([cipher.update(Buffer.from(body, 'base64')), cipher.final()]).toString('utf8');
    } catch {
      continue;
    }
  }
  throw new Error('Failed to decrypt secret: invalid key or corrupted ciphertext');
}
export function secureEqual(a: string, b: string) {
  const MAX_COMPARE_LENGTH = 1024;
  if (a.length > MAX_COMPARE_LENGTH || b.length > MAX_COMPARE_LENGTH) return false;
  const aBuffer = Buffer.from(tokenHash(a));
  const bBuffer = Buffer.from(tokenHash(b));
  if (aBuffer.length !== bBuffer.length) return false;
  return timingSafeEqual(aBuffer, bBuffer);
}
