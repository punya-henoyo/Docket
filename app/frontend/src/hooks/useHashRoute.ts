import { useCallback, useEffect, useState } from "react";

/** Hash routing, no router dependency. The console is a handful of views behind one
 *  loopback server; react-router would be more code than this and one more thing to
 *  keep current. */
export function useHashRoute<T extends string>(ids: readonly T[], fallback: T) {
  const read = useCallback((): T => {
    const hash = window.location.hash.replace("#/", "") as T;
    return ids.includes(hash) ? hash : fallback;
  }, [ids, fallback]);

  const [view, setView] = useState<T>(read);

  useEffect(() => {
    const onHash = () => setView(read());
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, [read]);

  const go = useCallback((next: T) => {
    setView(next);
    window.location.hash = `#/${next}`;
  }, []);

  return [view, go] as const;
}
