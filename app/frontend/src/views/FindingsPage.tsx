import { useMemo, useState } from "react";
import * as api from "../api";
import type { PortfolioFinding, Proof } from "../portfolio";
import { Card, Empty, OriginChip, PageHead, ProofCell, SevChip, ago, useSort } from "../hx/components";
import { FindingDrawer } from "../hx/Drawers";
import { hx } from "../hx/hx";
import { useApi } from "../hooks/useApi";

interface Row { f: PortfolioFinding; app: string }

const SEV_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const PROOF_RANK: Record<Proof, number> = { reproduced: 0, deterministic: 1, candidate: 2, not_reachable: 3 };

const ACCESS = {
  sev: (r: Row) => SEV_RANK[r.f.sev] ?? 5,
  finding: (r: Row) => r.f.title,
  app: (r: Row) => r.app,
  proof: (r: Row) => PROOF_RANK[r.f.proof],
  by: (r: Row) => r.f.by.name,
  age: (r: Row) => r.f.age_days,
  status: (r: Row) => r.f.status,
};

// a secret in source: the scanners' secret rules, or a title that says so. Looser words ("token",
// "credential") also match insecure-random and auth-over-http findings, which are not secrets.
const SECRET_RULE = /(^|\/)secrets?(\/|$)/i;
const SECRET_TITLE = /hardcoded|secret|api[ _-]?key|private[ _-]?key|cloud key/i;
const VIEWS: { key: string; label: string; test: (f: PortfolioFinding) => boolean }[] = [
  { key: "proven", label: "Proven exploitable", test: (f) => f.proof === "reproduced" },
  { key: "reach", label: "Reachable, unproven", test: (f) => f.proof === "candidate" && f.reach === "Reachable" },
  { key: "secrets", label: "Secrets", test: (f) => f.proof === "deterministic" || SECRET_TITLE.test(f.title) || SECRET_RULE.test(f.rule_id ?? "") },
  { key: "all", label: "All open", test: (f) => f.proof !== "not_reachable" },
];

export function FindingsPage({ go }: { go: (name: string, param?: string | null) => void }) {
  void go;
  const findings = useApi(api.portfolio.getFindings, "findings");
  const portfolio = useApi(api.portfolio.getPortfolio, "portfolio");
  const [view, setView] = useState("proven");
  const [open, setOpen] = useState<PortfolioFinding | null>(null);

  const labels = useMemo(() => new Map((portfolio.data?.applications ?? []).map((a) => [a.id, a.label])), [portfolio.data]);
  const all = findings.data;
  const current = VIEWS.find((v) => v.key === view) ?? VIEWS[0];
  const base = useMemo<Row[]>(
    () => (all ?? []).filter(current.test).map((f) => ({ f, app: labels.get(f.application) ?? f.application })),
    [all, labels, current],
  );
  const { rows, Th } = useSort(base, ACCESS);

  return (
    <>
      <PageHead eyebrow="Code Security" title="Findings"
                sub="A finding that blocks a release has a reproduced proof. Everything else is a lead for a person to judge." />
      <Card flush>
        <div className={hx("views")}>
          {VIEWS.map((v) => (
            <button key={v.key} type="button" className={hx("view")} aria-pressed={view === v.key} onClick={() => setView(v.key)}>
              {v.label}{all ? <b>{all.filter(v.test).length}</b> : null}
            </button>
          ))}
        </div>
        {findings.error && !all ? <div className={hx("notice bad")} role="alert" style={{ margin: 16 }}><b>Could not load findings.</b> {findings.error}</div>
          : !all ? <Empty>Loading findings…</Empty>
          : rows.length === 0 ? <Empty>Nothing here.</Empty> : (
            <table className={hx("lv")}>
              <thead>
                <tr>
                  <Th k="sev">Severity</Th><Th k="finding">Finding</Th><Th k="app">Application</Th><Th k="proof">Proof</Th>
                  <Th k="by">Found by</Th><Th k="age">Age</Th><Th k="status">Status</Th>
                </tr>
              </thead>
              <tbody>
                {rows.map(({ f, app }) => (
                  <tr key={f.id} tabIndex={0} onClick={() => setOpen(f)} onKeyDown={(e) => e.key === "Enter" && setOpen(f)}>
                    <td><SevChip sev={f.sev} /></td>
                    <td><div className={hx("tt")}>{f.title}</div><div className={hx("ms")}>{f.sub}</div></td>
                    <td>{app}</td>
                    <td><ProofCell f={f} /></td>
                    <td><OriginChip origin={f.by.origin} name={f.by.name} /></td>
                    <td>{ago(f.age_days)}</td>
                    <td>{f.status}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
      </Card>
      <FindingDrawer finding={open} appLabel={open ? labels.get(open.application) : undefined} onClose={() => setOpen(null)} />
    </>
  );
}
