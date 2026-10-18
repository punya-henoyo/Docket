import type { Portfolio } from "../portfolio";
import { PageHead } from "../hx/components";

export function Applications({ portfolio, go }: { portfolio: Portfolio | null; go: (name: string, param?: string | null) => void }) {
  void go; void portfolio;
  return <PageHead eyebrow="Code Security" title="Applications" />;
}
