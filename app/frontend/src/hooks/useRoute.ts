import { useCallback, useEffect, useState } from "react";

/** `#/app/ibank%2Fcard-payments` -> { name: "app", param: "ibank/card-payments" }.
 *  Hash routing with one optional parameter segment; no router dependency, same reason as
 *  useHashRoute. */
export interface Route { name: string; param: string | null }

const read = (): Route => {
  const raw = window.location.hash.replace(/^#\/?/, "");
  const [name = "", ...rest] = raw.split("/");
  const param = rest.length ? decodeURIComponent(rest.join("/")) : null;
  return { name: name || "home", param };
};

export function useRoute() {
  const [route, setRoute] = useState<Route>(read);
  useEffect(() => {
    const on = () => setRoute(read());
    window.addEventListener("hashchange", on);
    return () => window.removeEventListener("hashchange", on);
  }, []);
  const go = useCallback((name: string, param?: string | null) => {
    window.location.hash = param ? `#/${name}/${encodeURIComponent(param)}` : `#/${name}`;
  }, []);
  return [route, go] as const;
}
