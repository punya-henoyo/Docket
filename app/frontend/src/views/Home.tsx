import type { Portfolio } from "../portfolio";
import { PageHead } from "../hx/components";

export function Home({ portfolio, error, go }: { portfolio: Portfolio | null; error: string | null; go: (name: string, param?: string | null) => void }) {
  void go;
  return <><PageHead eyebrow="Code Security" title="Posture" sub={error ?? (portfolio ? `${portfolio.applications.length} applications` : "Loading…")} /></>;
}
