import {useCallback, useEffect, useRef, useState} from "react";
import type {Page} from "./types";

interface FetchState<T> {
  data: T | null;
  loading: boolean;
  error: string | null;
  reload: () => void;
}

/** Minimal data-fetch hook with reload + dependency-keyed refetch. */
export function useFetch<T>(fn: () => Promise<T>, deps: unknown[] = []): FetchState<T> {
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [tick, setTick] = useState(0);
  const fnRef = useRef(fn);
  fnRef.current = fn;

  useEffect(() => {
    let alive = true;
    setLoading(true);
    setError(null);
    fnRef
      .current()
      .then((d) => {
        if (alive) setData(d);
      })
      .catch((e) => {
        if (alive) setError(e instanceof Error ? e.message : String(e));
      })
      .finally(() => {
        if (alive) setLoading(false);
      });
    return () => {
      alive = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, tick]);

  const reload = useCallback(() => setTick((t) => t + 1), []);
  return {data, loading, error, reload};
}

/** Offset/total pagination hook: returns the current page's items + controls. */
export function usePaginated<T>(
  fetcher: (page: number, limit: number) => Promise<Page<T>>,
  deps: unknown[] = [],
  limit = 50,
) {
  const [page, setPage] = useState(1);
  const [tick, setTick] = useState(0);
  const [items, setItems] = useState<T[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const fetcherRef = useRef(fetcher);
  fetcherRef.current = fetcher;

  // reset to page 1 whenever the inputs change
  useEffect(() => {
    setPage(1);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);

  useEffect(() => {
    let alive = true;
    setLoading(true);
    setError(null);
    fetcherRef
      .current(page, limit)
      .then((p) => {
        if (alive) {
          setItems(p.items);
          setTotal(p.total);
        }
      })
      .catch((e) => {
        if (alive) setError(e instanceof Error ? e.message : String(e));
      })
      .finally(() => {
        if (alive) setLoading(false);
      });
    return () => {
      alive = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, page, limit, tick]);

  const totalPages = Math.max(1, Math.ceil(total / limit));
  return {
    items,
    total,
    page,
    setPage,
    totalPages,
    limit,
    loading,
    error,
    reload: () => setTick((t) => t + 1),
  };
}
