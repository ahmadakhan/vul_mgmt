/**
 * Runs `fn` over `items` with bounded concurrency, dispatching at most one
 * new call every `intervalMs`. This preserves the exact request *rate* of a
 * strictly serial `for (...) { await sleep(interval); await fn(item) }` loop,
 * but lets up to `concurrency` requests be in flight at once so each item's
 * network latency is overlapped rather than added on top of every wait —
 * the dominant cost in a large per-CVE detail-fetch loop.
 *
 * Fails closed: once any call throws, no further work is dispatched and the
 * first error is rethrown after in-flight work settles, matching the
 * all-or-nothing semantics of the serial loop it replaces (a partially
 * fetched batch is never returned as if it were complete).
 *
 * Results are written back by index, so the returned array preserves the
 * same order as `items` regardless of completion order.
 */
export async function paceConcurrent<T, R>(
  items: T[],
  intervalMs: number,
  concurrency: number,
  sleep: (ms: number) => Promise<unknown>,
  fn: (item: T, index: number) => Promise<R>,
): Promise<R[]> {
  const results: R[] = new Array(items.length);
  let nextIndex = 0;
  let nextAllowedDispatch = 0;
  let failure: { error: unknown } | undefined;
  const worker = async () => {
    while (nextIndex < items.length) {
      if (failure) return;
      const i = nextIndex++;
      try {
        // Recheck after sleeping: timers can wake late or bunch together when
        // the event loop is busy. Reserve synchronously immediately before the
        // request so a delayed wakeup cannot dispatch a burst.
        while (true) {
          const wait = nextAllowedDispatch - Date.now();
          if (wait > 0) {
            await sleep(wait);
            if (failure) return;
            continue;
          }
          nextAllowedDispatch = Date.now() + intervalMs;
          break;
        }
        if (failure) return;
        results[i] = await fn(items[i], i);
      } catch (error) {
        if (!failure) failure = { error };
        return;
      }
    }
  };
  // Await every worker after cancellation/deadline errors too. Returning on the
  // first rejected worker would let already sleeping workers dispatch requests
  // after the caller has considered this batch failed.
  await Promise.allSettled(Array.from({ length: Math.max(1, Math.min(concurrency, items.length)) }, worker));
  if (failure) throw failure.error;
  return results;
}
