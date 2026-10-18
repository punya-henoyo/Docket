import { PageHead } from "../hx/components";

export function ScanRunPage({ run, go, onOpenDetail }: { run: string; go: (name: string, param?: string | null) => void; onOpenDetail: (run: string) => void }) {
  void go; void onOpenDetail;
  return <PageHead eyebrow="Scan" title={run} />;
}
