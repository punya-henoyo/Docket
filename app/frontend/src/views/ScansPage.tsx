import { useMemo } from "react";
import type { Application, Portfolio, ScanEvent } from "../portfolio";
import { Card, Empty, PageHead, useSort } from "../hx/components";
import { hx } from "../hx/hx";

interface Row { a: Application; e: ScanEvent; at: number }

const COVERAGE = {
  full: ["ok", "All required ran"],
  partial: ["warn", "Partial"],
  failed: ["bad", "Failed"],
} as const;

const ACCESS = {
  scan: (r: Row) => r.e.id,
  app: (r: Row) => r.a.label,
  kind: (r: Row) => r.e.kind,
  when: (r: Row) => r.at,
  coverage: (r: Row) => r.e.coverage,
  result: (r: Row) => r.e.proven,
  candidates: (r: Row) => r.e.candidates,
};

const day = (ms: number) => new Date(ms).toLocaleDateString("en-GB", { day: "numeric", month: "short" });

export function ScansPage({ portfolio, go }: { portfolio: Portfolio | null; go: (name: string, param?: string | null) => void }) {
  const base = useMemo<Row[]>(
    () => (portfolio?.applications ?? [])
      .flatMap((a) => a.events.map((e) => ({ a, e, at: Date.parse(e.at) })))
      .sort((x, y) => y.at - x.at),
    [portfolio],
  );
  const { rows, Th } = useSort(base, ACCESS);
  return (
    <>
      <PageHead eyebrow="Code Security" title="Scans" sub="Every scan across the portfolio, newest first."
                actions={<button className={hx("btn primary")} onClick={() => go("repos")}>Start a scan</button>} />
      <Card title="Recent scans" flush>
        {!portfolio ? <Empty>Loading scans…</Empty> : rows.length === 0 ? <Empty>No scans yet. Start one from a connected repository.</Empty> : (
          <table className={hx("lv")}>
            <thead>
              <tr>
                <Th k="scan">Scan</Th><Th k="app">Application</Th><Th k="kind">Kind</Th><Th k="when">When</Th>
                <Th k="coverage">Coverage</Th><Th k="result">Result</Th><Th k="candidates">Candidates</Th>
              </tr>
            </thead>
            <tbody>
              {rows.map(({ a, e, at }) => {
                const [tone, word] = COVERAGE[e.coverage];
                return (
                  <tr key={`${a.id}/${e.id}`} tabIndex={0} onClick={() => go("scan", e.id)} onKeyDown={(k) => k.key === "Enter" && go("scan", e.id)}>
                    <td><b className={hx("mono")}>{e.id}</b></td>
                    <td><div className={hx("tt")}>{a.label}</div></td>
                    <td>{e.kind === "pr" ? "Pull request" : "Full scan"}{e.label ? <div className={hx("ms")}>{e.label}</div> : null}</td>
                    <td>{day(at)}</td>
                    <td><span className={hx(`chip ${tone}`)}>{word}</span></td>
                    <td>{e.proven ? <span className={hx("proof y")}>◆ {e.proven} proven</span> : <span className={hx("proof n")}>None proven</span>}</td>
                    <td>{e.candidates} {e.candidates === 1 ? "candidate" : "candidates"}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </Card>
    </>
  );
}
