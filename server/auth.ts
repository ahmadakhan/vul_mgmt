import type { Request, Response, NextFunction } from 'express';
import type pg from 'pg';
import { randomUUID } from 'node:crypto';
import { z } from 'zod';
import type { Config } from './config';
import { checkPassword, passwordHash, randomToken, tokenHash, secureEqual } from './secrets';
import { WorkCapacityError } from './workLimiter.ts';
import { transaction, appendAudit, get } from './db';
import { DEFAULT_SETTINGS, type Role } from '../shared/state.ts';
import type { AppSettings } from '../src/types/index.ts';
import { HttpError } from './validation';
/**
 * The address a password-reset code is delivered to.
 *
 * Kept as a plain column rather than a username convention: the reset flow used
 * to fall back to `username.includes('@') ? username : SMTP_FROM`, which sent
 * every non-email login's code to the shared deployment mailbox. Codes must go
 * to a mailbox the operator controls.
 */
export const accountEmail = z
  .string()
  .trim()
  .toLowerCase()
  .max(254)
  .pipe(z.email('Must be a valid email address'));
export interface Operator {
  id: string;
  username: string;
  email: string | null;
  role: Role;
  sessionHash: string;
  csrf: string;
  expiresAt: string;
}
declare global {
  namespace Express {
    interface Request {
      operator?: Operator;
    }
  }
}
export const asyncRoute =
  (fn: (req: Request, res: Response, next: NextFunction) => Promise<unknown>) =>
  (req: Request, res: Response, next: NextFunction) => {
    void fn(req, res, next).catch(next);
  };
export function cookieName(config: Config) {
  return config.NODE_ENV === 'production' && config.ALLOW_INSECURE_HTTP !== 'true'
    ? '__Host-vulnstream'
    : 'vulnstream';
}
/**
 * Parses the Cookie header into exact name/value pairs. Prefix matching is not
 * sufficient: a header such as `vulnstream_attacker=...; vulnstream=...` would
 * otherwise let the first prefix-matching entry shadow the real session token.
 */
/**
 * Attributes shared by the session cookie and its deletion. `__Host-` cookies
 * require Secure, so a development deployment served over HTTPS must set and
 * clear the cookie with the same attributes.
 */
export function sessionCookieOptions(config: Config) {
  return {
    httpOnly: true,
    secure: (config.NODE_ENV === 'production' && config.ALLOW_INSECURE_HTTP !== 'true') ||
      new URL(config.APP_ORIGIN).protocol === 'https:',
    sameSite: 'strict' as const,
    path: '/',
  };
}
export function readCookie(header: string | undefined, name: string): string {
  if (!header) return '';
  for (const part of header.split(';')) {
    const separator = part.indexOf('=');
    if (separator < 0) continue;
    if (part.slice(0, separator).trim() !== name) continue;
    return part.slice(separator + 1).trim();
  }
  return '';
}
export function requireAuth(pool: pg.Pool, config: Config) {
  return asyncRoute(async (req, res, next) => {
    const token = readCookie(req.headers.cookie, cookieName(config));
    if (!/^[\w-]{43}$/.test(token)) throw new HttpError(401, 'Authentication required');
    const hash = tokenHash(token);
    const found = (
      await pool.query(
        `SELECT u.id,u.username,u.email,u.role,s.csrf,s.expires_at FROM sessions s JOIN users u ON u.id=s.user_id WHERE token_hash=$1 AND s.expires_at>now() AND s.absolute_expires_at>now() AND NOT u.disabled`,
        [hash],
      )
    ).rows[0];
    if (!found) throw new HttpError(401, 'Session expired');
    req.operator = {
      id: found.id,
      username: found.username,
      email: found.email ?? null,
      role: found.role,
      sessionHash: hash,
      csrf: found.csrf,
      expiresAt: found.expires_at.toISOString(),
    };
    if (
      !['GET', 'HEAD', 'OPTIONS'].includes(req.method) &&
      !secureEqual(String(req.headers['x-csrf-token'] || ''), found.csrf)
    )
      throw new HttpError(403, 'Invalid CSRF token');
    next();
  });
}
export function requireRole(...roles: Role[]) {
  return (req: Request, _res: Response, next: NextFunction) => {
    // Fail closed if the authentication middleware was not applied. A missing
    // operator must never turn into a 500 or an implicit authorization pass.
    if (!req.operator) return next(new HttpError(401, 'Authentication required'));
    return roles.includes(req.operator.role)
      ? next()
      : next(new HttpError(403, 'Insufficient role'));
  };
}
export async function createUser(
  pool: pg.Pool,
  username: string,
  password: string,
  role: Role,
  ipAddress = '',
  email: string | null = null,
  actor = 'system',
) {
  // Usernames may contain '@' (they were historically used as addresses),
  // but a login name is not proof of ownership of a mailbox, so it is never
  // copied into the email column.
  z.string()
    .regex(/^[a-zA-Z0-9._@-]{3,100}$/)
    .parse(username);
  z.string().min(14).max(128).parse(password);
  z.enum(['ADMIN', 'OPERATOR', 'VIEWER']).parse(role);
  const address = email === null || email === '' ? null : accountEmail.parse(email);
  const policy = (await get<AppSettings>(pool, 'settings', 'main')) || DEFAULT_SETTINGS;
  if (password.length < policy.securityPolicy.minPasswordLen)
    throw new HttpError(400, 'Password does not meet configured minimum');
  const hash = await passwordHash(password);
  await transaction(pool, async (db) => {
    const userId = randomUUID();
    await db.query('INSERT INTO users(id,username,password_hash,role,email) VALUES($1,$2,$3,$4,$5)', [
      userId,
      username.toLowerCase(),
      hash,
      role,
      address,
    ]);
    await appendAudit(
      db,
      'Operator created',
      `Operator ${username.toLowerCase()}; role ${role}; reset email ${address ? 'set' : 'not set'}`,
      actor,
      'SECURITY',
      'INFO',
      ipAddress,
      { action: 'operator.create', resourceType: 'operator', resourceId: userId, outcome: 'SUCCESS', fields: ['username', 'role', 'email'] },
    );
  });
}
/**
 * Apply an account edit, session revocation, and audit entry atomically.
 *
 * Password is deliberately not part of this: changing it revokes sessions and
 * has its own endpoint, so folding it in here would let an email-only edit log
 * the operator out. `email: null` clears the address, `undefined` leaves it.
 */
export async function updateUser(
  pool: pg.Pool,
  userId: string,
  change: { role?: Role; disabled?: boolean; email?: string | null },
  actor: string,
  ipAddress = '',
) {
  const email = change.email === undefined ? undefined : change.email === null || change.email === '' ? null : accountEmail.parse(change.email);
  const changed = await transaction(pool, async (db) => {
    const result = await db.query(
      `UPDATE users SET role=COALESCE($2,role), disabled=COALESCE($3,disabled), email=CASE WHEN $4 THEN $5 ELSE email END
       WHERE id=$1 RETURNING username,role,disabled,email`,
      [userId, change.role ?? null, change.disabled ?? null, email !== undefined, email ?? null],
    );
    if (!result.rowCount) throw new HttpError(404, 'Operator not found');
    // A code delivered before a mailbox/access change must not remain usable.
    if (email !== undefined || change.disabled === true)
      await db.query('DELETE FROM password_reset_tokens WHERE username=$1', [result.rows[0].username]);
    if (change.disabled === true || change.role !== undefined)
      await db.query('DELETE FROM sessions WHERE user_id=$1', [userId]);
    const account = result.rows[0];
    await appendAudit(
      db,
      'Operator access changed',
      `Operator ${account.username}; role ${account.role}; disabled ${account.disabled}; reset email ${account.email ? 'set' : 'not set'}`,
      actor,
      'SECURITY',
      'INFO',
      ipAddress,
      { action: 'operator.update', resourceType: 'operator', resourceId: userId, outcome: 'SUCCESS', fields: Object.keys(change).filter((key) => change[key as keyof typeof change] !== undefined) },
    );
    return account;
  });
  return changed as { username: string; role: Role; disabled: boolean; email: string | null };
}
export async function deleteUser(pool: pg.Pool, userId: string, actor: string, ipAddress = '') {
  await transaction(pool, async (db) => {
    const removed = await db.query('DELETE FROM users WHERE id=$1 RETURNING username,role', [userId]);
    if (!removed.rowCount) throw new HttpError(404, 'Operator not found');
    await db.query('DELETE FROM password_reset_tokens WHERE username=$1', [removed.rows[0].username]);
    await appendAudit(
      db,
      'Operator deleted',
      `Operator ${removed.rows[0].username} (${removed.rows[0].role})`,
      actor,
      'SECURITY',
      'INFO',
      ipAddress,
      { action: 'operator.delete', resourceType: 'operator', resourceId: userId, outcome: 'SUCCESS' },
    );
  });
}
export function loginHandler(pool: pg.Pool, config: Config) {
  return asyncRoute(async (req, res) => {
    const { username, password } = z
      .object({
        username: z
          .string()
          .min(1)
          .max(100)
          .transform((s) => s.toLowerCase()),
        password: z.string().min(1).max(128),
      })
      .parse(req.body);
    const settings = (await get<AppSettings>(pool, 'settings', 'main')) || DEFAULT_SETTINGS;
    const { maxLoginAttempts, lockoutMins } = settings.securityPolicy;
    const keys = ['ip:' + tokenHash(req.ip || ''), 'user:' + tokenHash(username)];
    // Increment before doing expensive password work, atomically across workers.
    const allowed = await transaction(pool, async (db) => {
      let okay = true;
      for (const key of keys) {
        const result = await db.query(
          `INSERT INTO login_attempts(key,attempts,window_start) VALUES($1,1,now()) ON CONFLICT(key) DO UPDATE SET attempts=CASE WHEN login_attempts.window_start<now()-($2::int * interval '1 minute') THEN 1 ELSE login_attempts.attempts+1 END,window_start=CASE WHEN login_attempts.window_start<now()-($2::int * interval '1 minute') THEN now() ELSE login_attempts.window_start END RETURNING attempts`,
          [key, lockoutMins],
        );
        // Per-account threshold uses the configured limit; the IP-scope threshold
        // is scaled up to keep absorbing distributed credential-stuffing attacks.
        const threshold = key.startsWith('ip:') ? maxLoginAttempts * 5 : maxLoginAttempts;
        if (result.rows[0].attempts > threshold) okay = false;
      }
      return okay;
    });
    if (!allowed) {
      res.setHeader('Retry-After', String(lockoutMins * 60));
      throw new HttpError(429, `Too many login attempts; retry in ${lockoutMins} minutes`);
    }
    const user = (await pool.query('SELECT * FROM users WHERE username=$1', [username])).rows[0];
    // A fixed valid dummy hash keeps nonexistent accounts on the same password KDF path.
    const dummy = 'scrypt131072$00000000000000000000000000000000$' + '0'.repeat(128);
    const valid = await (async () => {
      try {
        return await checkPassword(password, user?.password_hash || dummy);
      } catch (error) {
        // Bounded scrypt admission is exhausted: fail closed with a controlled
        // 429 (not a 500) and let the client retry once a work slot frees.
        if (error instanceof WorkCapacityError) {
          res.setHeader('Retry-After', '5');
          throw new HttpError(429, 'Too many concurrent login attempts; retry shortly');
        }
        throw error;
      }
    })();
    if (!user || user.disabled || !valid) throw new HttpError(401, 'Invalid username or password');
    const token = randomToken(),
      csrf = randomToken(),
      expires = new Date(Date.now() + settings.securityPolicy.sessionTimeoutMins * 60000);
    await transaction(pool, async (db) => {
      await db.query('DELETE FROM login_attempts WHERE key=$1', [keys[1]]);
      await db.query(
        "INSERT INTO sessions(token_hash,user_id,csrf,expires_at,absolute_expires_at) VALUES($1,$2,$3,$4,now()+interval '12 hours')",
        [tokenHash(token), user.id, csrf, expires],
      );
      await appendAudit(db, 'Login succeeded', 'Operator session established', username, 'SECURITY', 'INFO', req.ip || '',
        { action: 'session.create', resourceType: 'operator', resourceId: user.id, outcome: 'SUCCESS' });
    });
    res.cookie(cookieName(config), token, {
      ...sessionCookieOptions(config),
      maxAge: 12 * 3600000,
    });
    res.json({ username, role: user.role, csrfToken: csrf, expiresAt: expires.toISOString() });
  });
}
