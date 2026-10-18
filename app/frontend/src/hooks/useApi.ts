import { useCallback, useEffect, useRef, useState } from "react";
import { ApiError } from "../api";

export interface ApiState<T> { data: T | null; error: string | null; loading: boolean; reload: () => void }

/** One GET with loading and error state, re-run when `key` changes. `refreshMs` re-polls quietly
 *  (the previous data stays on screen), for views that describe something still moving. */
export function useApi<T>(load: () => Promise<T>, key: string, refreshMs?: number): ApiState<T> {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [tick, setTick] = useState(0);
  const loader = useRef(load);
  loader.current = load;

  useEffect(() => {
    let alive = true;
    setLoading(true);
    loader.current()
      .then((d) => { if (alive) { setData(d); setError(null); } })
      .catch((e) => { if (alive) setError(e instanceof ApiError ? e.message : String(e)); })
      .finally(() => { if (alive) setLoading(false); });
    return () => { alive = false; };
  }, [key, tick]);

  useEffect(() => {
    if (!refreshMs) return;
    const id = setInterval(() => setTick((t) => t + 1), refreshMs);
    return () => clearInterval(id);
  }, [refreshMs]);

  return { data, error, loading, reload: useCallback(() => setTick((t) => t + 1), []) };
}
