export class WorkCapacityError extends Error {
  constructor() {
    super('Expensive operation capacity exhausted');
    this.name = 'WorkCapacityError';
  }
}

/** FIFO admission with a bounded queue and a finite wait. Slots transfer atomically. */
export class WorkLimiterAbortedError extends Error {
  constructor() {
    super('Work aborted before completion');
    this.name = 'WorkLimiterAbortedError';
  }
}
export class WorkLimiterDeadlineError extends Error {
  constructor(public readonly deadlineMs: number) {
    super(`Work exceeded deadline of ${deadlineMs}ms`);
    this.name = 'WorkLimiterDeadlineError';
  }
}
export class WorkLimiter {
  private active = 0;
  private readonly waiting: Array<{ admit: () => void }> = [];
  constructor(
    private readonly concurrency: number,
    private readonly queueLimit: number,
    private readonly waitMs: number,
  ) {
    if (!Number.isInteger(concurrency) || concurrency < 1 || !Number.isInteger(queueLimit) || queueLimit < 0 || !Number.isFinite(waitMs) || waitMs <= 0)
      throw new Error('INVALID_WORK_LIMIT');
  }
  async run<T>(work: () => Promise<T>, options?: { signal?: AbortSignal; deadlineMs?: number }): Promise<T> {
    if (options?.signal?.aborted) throw new WorkLimiterAbortedError();
    if (this.active < this.concurrency) this.active++;
    else {
      if (this.waiting.length >= this.queueLimit) throw new WorkCapacityError();
      await new Promise<void>((resolve, reject) => {
        const entry = { admit: () => { clearTimeout(timer); resolve(); } };
        const timer = setTimeout(() => {
          const index = this.waiting.indexOf(entry);
          if (index >= 0) this.waiting.splice(index, 1);
          reject(new WorkCapacityError());
        }, this.waitMs);
        this.waiting.push(entry);
      });
    }
    try {
      return await this.withDeadline(work, options);
    } finally {
      const next = this.waiting.shift();
      if (next) next.admit();
      else this.active--;
    }
  }
  /**
   * Races the admitted work against an optional deadline and AbortSignal so a
   * caller that wraps unbounded work is cancelled instead of pinning its slot.
   * Either failure rejects and releases the slot via the caller's `finally`.
   */
  private async withDeadline<T>(
    work: () => Promise<T>,
    options?: { signal?: AbortSignal; deadlineMs?: number },
  ): Promise<T> {
    let deadlineTimer: ReturnType<typeof setTimeout> | undefined;
    let onAbort: (() => void) | undefined;
    const cleanup = () => {
      if (deadlineTimer) clearTimeout(deadlineTimer);
      if (onAbort && options?.signal) options.signal.removeEventListener('abort', onAbort);
    };
    return new Promise<T>((resolve, reject) => {
      if (options?.signal?.aborted) {
        cleanup();
        reject(new WorkLimiterAbortedError());
        return;
      }
      if (options?.deadlineMs && options.deadlineMs > 0) {
        const deadlineMs = options.deadlineMs;
        deadlineTimer = setTimeout(
          () => reject(new WorkLimiterDeadlineError(deadlineMs)),
          deadlineMs,
        );
        deadlineTimer.unref?.();
      }
      onAbort = () => {
        reject(new WorkLimiterAbortedError());
      };
      options?.signal?.addEventListener('abort', onAbort, { once: true });
      work().then(resolve, reject);
    }).finally(cleanup);
  }
}
