import { useCallback, useEffect, useRef, useState } from 'react';
import type { CollectionKind } from '../../shared/state';
import { useApp } from '../context/AppContext';

export interface UseCollectionOptions {
  page?: number;
  pageSize?: number;
  search?: string;
  sort?: string;
  order?: 'asc' | 'desc';
  /** Server-side filters. `ALL`, empty strings, and undefined values are ignored. */
  filters?: Record<string, unknown>;
  enabled?: boolean;
}

export interface UseCollectionResult<T> {
  items: T[];
  total: number;
  loading: boolean;
  reload: () => void;
}

/**
 * Reads one page from `/api/collections/:kind`. Filtering, sorting, and paging
 * all happen in PostgreSQL so large collections never have to be shipped to the
 * browser. The hook refetches whenever the app-level state refresh completes so
 * a view stays current with the ten-second poll without duplicating a copy of
 * the full collection in the snapshot.
 */
export function useCollection<T>(
  kind: CollectionKind,
  options: UseCollectionOptions = {},
): UseCollectionResult<T> {
  const { fetchCollection, refreshVersion } = useApp();
  const { page = 1, pageSize = 25, search = '', sort, order, filters, enabled = true } = options;
  const [items, setItems] = useState<T[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(enabled);
  const [localVersion, setLocalVersion] = useState(0);
  const requestId = useRef(0);

  // Debounce free-text search so typing does not issue one query per keystroke.
  const [debouncedSearch, setDebouncedSearch] = useState(search);
  useEffect(() => {
    if (!search) {
      setDebouncedSearch('');
      return;
    }
    const timer = setTimeout(() => setDebouncedSearch(search), 250);
    return () => clearTimeout(timer);
  }, [search]);

  // Filters are a fresh object on every render; compare their serialized shape.
  const filterKey = JSON.stringify(filters ?? {});

  useEffect(() => {
    if (!enabled) {
      setLoading(false);
      return;
    }
    const id = ++requestId.current;
    setLoading(true);
    fetchCollection<T>(kind, {
      page,
      pageSize,
      search: debouncedSearch || undefined,
      sort,
      order,
      filters: JSON.parse(filterKey) as Record<string, unknown>,
    })
      .then((result) => {
        if (requestId.current !== id) return;
        setItems(result.items);
        setTotal(result.total);
      })
      .catch(() => {
        // The app-level error banner is populated by the request helper; keep the
        // last page visible instead of replacing it with a misleading empty table.
        if (requestId.current !== id) return;
      })
      .finally(() => {
        if (requestId.current === id) setLoading(false);
      });
    return () => {
      // Invalidate the in-flight request on unmount or parameter change so a
      // late response cannot update a hook that is no longer current.
      requestId.current++;
    };
  }, [
    fetchCollection,
    kind,
    page,
    pageSize,
    debouncedSearch,
    sort,
    order,
    filterKey,
    enabled,
    refreshVersion,
    localVersion,
  ]);

  const reload = useCallback(() => setLocalVersion((value) => value + 1), []);
  return { items, total, loading, reload };
}
