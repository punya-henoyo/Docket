import { PageHead } from "../hx/components";

export function FindingsPage({ go }: { go: (name: string, param?: string | null) => void }) {
  void go;
  return <PageHead eyebrow="Code Security" title="Findings" />;
}
