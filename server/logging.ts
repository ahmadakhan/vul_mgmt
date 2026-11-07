// Comprehensive logging utilities for audit and operational logging
import type pg from 'pg';
import type { Db, PoolClient } from './db';
import type { AuditLog } from '../src/types/index.ts';
import { appendAudit } from './db';

/**
 * Structured audit logger for critical operations
 */
export class AuditLogger {
  static async logOperation(
    db: Db,
    event: string,
    message: string,
    actor: string,
    category: AuditLog['category'] = 'SECURITY',
    level: AuditLog['level'] = 'INFO',
    ipAddress: string = '',
    context: Record<string, unknown> = {},
  ): Promise<void> {
    const timestamp = new Date().toISOString();
    
    try {
      await appendAudit(db, event, message, actor, category, level, ipAddress);
      
      // Also output structured JSON for external monitoring
      console.log(JSON.stringify({
        level: level.toLowerCase(),
        timestamp,
        event,
        message,
        actor,
        category,
        ipAddress,
        context: {
          ...context,
          timestamp,
        },
      }));
    } catch (error) {
      // Log to stderr if audit append fails
      console.error(JSON.stringify({
        level: 'error',
        timestamp,
        event: 'audit_write_failed',
        message: `Failed to write audit log: ${(error as Error).message}`,
        originalEvent: event,
        originalMessage: message,
      }));
      // Re-throw to ensure caller knows audit logging failed
      throw error;
    }
  }

  static async logLockOperation(
    db: Db,
    operation: string,
    details: string,
    actor: string,
    lockKey: string,
    context: Record<string, unknown> = {},
  ): Promise<void> {
    await this.logOperation(
      db,
      `lock.${operation}`,
      details,
      actor,
      'SECURITY',
      'INFO',
      '',
      {
        lockKey,
        ...context,
      },
    );
  }

  static async logError(
    db: Db,
    event: string,
    message: string,
    actor: string,
    error: Error,
    context: Record<string, unknown> = {},
  ): Promise<void> {
    await this.logOperation(
      db,
      event,
      `${message}: ${error.message}`,
      actor,
      'SECURITY',
      'ERROR',
      '',
      {
        stack: error.stack,
        ...context,
      },
    );
  }

  static async logPerformance(
    db: Db,
    operation: string,
    durationMs: number,
    context: Record<string, unknown> = {},
  ): Promise<void> {
    if (durationMs > 5000) { // Log slow operations (>5s)
      await this.logOperation(
        db,
        `performance.slow_${operation}`,
        `Operation took ${durationMs}ms (slow)`,
        'system',
        'PIPELINE',
        'WARNING',
        '',
        {
          operation,
          durationMs,
          ...context,
        },
      );
    }
  }
}

/**
 * Lock operation utilities with comprehensive error handling and logging
 */
export class LockManager {
  static async tryAcquireLock(
    client: PoolClient,
    lockClass: number | string,
    schemaKey: string,
    lockKey: string,
    operation: string,
  ): Promise<{ locked: boolean; error?: string }> {
    try {
      const query = `SELECT pg_try_advisory_lock(${lockClass}, ${schemaKey}) AS locked`;
      const result = await client.query<{ locked: boolean }>(query);
      
      const locked = result.rows[0]?.locked === true;
      
      if (!locked) {
        console.log(JSON.stringify({
          level: 'info',
          event: 'lock.acquisition_failed',
          operation,
          lockClass,
          lockKey,
          message: 'Lock acquisition failed - resource temporarily unavailable',
          timestamp: new Date().toISOString(),
        }));
      } else {
        console.log(JSON.stringify({
          level: 'info',
          event: 'lock.acquisition_success',
          operation,
          lockClass,
          lockKey,
          message: 'Lock acquired successfully',
          timestamp: new Date().toISOString(),
        }));
      }
      
      return { locked };
    } catch (error) {
      return {
        locked: false,
        error: (error as Error).message,
      };
    }
  }

  static async releaseLock(
    client: PoolClient,
    lockClass: number | string,
    schemaKey: string,
    lockKey: string,
    operation: string,
  ): Promise<boolean> {
    try {
      await client.query(`SELECT pg_advisory_unlock(${lockClass}, ${schemaKey})`);
      console.log(JSON.stringify({
        level: 'info',
        event: 'lock.release_success',
        operation,
        lockClass,
        lockKey,
        message: 'Lock released successfully',
        timestamp: new Date().toISOString(),
      }));
      return true;
    } catch (error) {
      console.error(JSON.stringify({
        level: 'error',
        event: 'lock.release_failed',
        operation,
        lockClass,
        lockKey,
        message: 'Failed to release advisory lock',
        error: (error as Error).message,
        timestamp: new Date().toISOString(),
      }));
      return false;
    }
  }

  static async safeReleaseLock(
    client: PoolClient,
    lockClass: number | string,
    schemaKey: string,
    lockKey: string,
    operation: string,
  ): Promise<void> {
    const success = await this.releaseLock(client, lockClass, schemaKey, lockKey, operation);
    if (!success) {
      // Log critical error but don't throw - allow operation to continue
      // as the primary work may have completed successfully
      console.error(JSON.stringify({
        level: 'error',
        event: 'lock_cleanup_warning',
        operation,
        lockClass,
        lockKey,
        message: 'Advisory lock cleanup failed but primary operation succeeded',
        timestamp: new Date().toISOString(),
      }));
    }
  }
}

/**
 * Operation tracking utilities for performance monitoring and auditing
 */
export class OperationTracker {
  static startTimer(operation: string, context: Record<string, unknown> = {}) {
    const startTime = Date.now();
    return {
      operation,
      context,
      startTime,
      
      end: async (db: Db, actor: string, result?: unknown) => {
        const durationMs = Date.now() - startTime;
        
        // Log performance metrics
        await AuditLogger.logPerformance(db, operation, durationMs, {
          ...context,
          result: result ? 'success' : 'failure',
        });
        
        return { durationMs, result };
      },
      
      error: async (db: Db, error: Error, actor: string) => {
        const durationMs = Date.now() - startTime;
        
        await AuditLogger.logError(
          db,
          `operation.failed.${operation}`,
          `Operation failed after ${durationMs}ms`,
          actor,
          error,
          {
            ...context,
            durationMs,
          },
        );
        
        return { durationMs, error };
      },
    };
  }
}

/**
 * Connection pool health monitoring utilities
 */
export class PoolHealthMonitor {
  static trackPoolEvents(pool: pg.Pool) {
    pool.on('connect', () => {
      console.log(JSON.stringify({
        level: 'info',
        event: 'database-pool-connected',
        timestamp: new Date().toISOString(),
        totalCount: pool.totalCount,
        idleCount: pool.idleCount,
      }));
    });
    
    pool.on('acquire', () => {
      console.log(JSON.stringify({
        level: 'info',
        event: 'database-pool-acquired',
        timestamp: new Date().toISOString(),
        idleCount: pool.idleCount,
      }));
    });
    
    pool.on('remove', () => {
      console.log(JSON.stringify({
        level: 'warn',
        event: 'database-pool-connection-removed',
        timestamp: new Date().toISOString(),
        totalCount: pool.totalCount,
      }));
    });
    
    pool.on('error', (error) => {
      console.error(JSON.stringify({
        level: 'error',
        event: 'database-pool-error',
        error: error.message,
        code: (error as { code?: string }).code,
        timestamp: new Date().toISOString(),
      }));
    });
  }
}