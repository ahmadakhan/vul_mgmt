import { types } from 'node:util';

/** Snapshot JSON data without invoking getters, proxies or user-defined toJSON hooks. */
export function boundedJson(raw: unknown): string | null {
  let nodes = 0, budget = 262144;
  const ancestors = new Set<object>();
  const copy = (value: unknown, depth: number): unknown => {
    if (++nodes > 4096 || depth > 32 || (budget -= 8) < 0) throw new Error('JSON_BUDGET');
    if (value === null || typeof value === 'boolean') return value;
    if (typeof value === 'number' && Number.isFinite(value)) return value;
    if (typeof value === 'string') {
      budget -= Buffer.byteLength(value);
      if (budget < 0) throw new Error('JSON_BUDGET');
      return value;
    }
    if (!value || typeof value !== 'object' || types.isProxy(value) || ancestors.has(value))
      throw new Error('NON_JSON_VALUE');
    const array = Array.isArray(value);
    const prototype = Object.getPrototypeOf(value);
    if (!array && prototype !== Object.prototype && prototype !== null) throw new Error('NON_JSON_OBJECT');
    const keys = Object.keys(value);
    if (keys.length > 4096 || (array && value.length > 4096)) throw new Error('JSON_BUDGET');
    const output: Record<string, unknown> | unknown[] = array ? [] : Object.create(null);
    ancestors.add(value);
    for (const key of keys) {
      budget -= Buffer.byteLength(key);
      const descriptor = Object.getOwnPropertyDescriptor(value, key)!;
      if (!('value' in descriptor) || (array && !/^(0|[1-9][0-9]*)$/.test(key))) throw new Error('NON_JSON_PROPERTY');
      if (descriptor.value === undefined && !array) continue;
      Object.defineProperty(output, key, { value: copy(descriptor.value, depth + 1), enumerable: true, writable: true, configurable: true });
    }
    ancestors.delete(value);
    return output;
  };
  try {
    const serialized = JSON.stringify(copy(raw, 0));
    return Buffer.byteLength(serialized) <= 262144 ? serialized : null;
  } catch { return null; }
}
