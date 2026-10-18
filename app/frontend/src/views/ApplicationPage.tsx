import { PageHead } from "../hx/components";

export function ApplicationPage({ id, go }: { id: string; go: (name: string, param?: string | null) => void }) {
  void go;
  return <PageHead eyebrow="Application" title={id} />;
}
