import { useMemo, useState } from "react";
import * as api from "../api";
import type { Lane, PipelineDetail, PortfolioFinding } from "../portfolio";
import { Card, PageHead } from "../hx/components";
import { FindingDrawer, LaneDrawer } from "../hx/Drawers";
import { hx } from "../hx/hx";
import { useApi } from "../hooks/useApi";
import { Kit } from "../kit/Kit";
import { FindingTable } from "./ApplicationPage";
import "./ApplicationPage.css";

/** The pipeline payload also carries these; they are in the contract's example runs but not in the
 *  shared type, so name them here rather than touch src/portfolio.ts. */
type ScanDetail = PipelineDetail & { required?: { ran: number; of: number }; coverage?: string; kind?: string };

const when = (iso: string | null) =>
  iso ? new Date(iso).toLocaleString("en-GB", { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" }) : "";

export function ScanRunPage({ run, go, onOpenDetail }: { run: string; go: (name: string, param?: string | null) => void; onOpenDetail: (run: string) => void }) {
  const pipe = useApi(() => api.portfolio.getPipeline(run) as Promise<ScanDetail>, `pipeline:${run}`);
  const all = useApi(api.portfolio.getFindings, "findings:all");
  const portfolio = useApi(api.portfolio.getPortfolio, "portfolio:scan");
  const [finding, setFinding] = useState<PortfolioFinding | null>(null);
  const [lane, setLane] = useState<Lane | null>(null);

  const p = pipe.data;
  const app = useMemo(() => portfolio.data?.applications.find((x) => x.id === p?.application) ?? null, [portfolio.data, p]);
  const mine = useMemo(() => (all.data ?? []).filter((f) => f.run === run), [all.data, run]);

  if (!p) {
    return (
      <div className={hx("notfound")}>
        <Card title={pipe.loading ? "Loading scan" : "Scan not found"}>
          {pipe.loading ? <p>Loading…</p> : (
            <>
              <p>{pipe.error ?? "This scan is not in the portfolio."}</p>
              <button type="button" className={hx("btn")} onClick={() => go("scans")}>Back to Scans</button>
            </>
          )}
        </Card>
      </div>
    );
  }

  const appLabel = app?.label ?? p.application;
  const sub = [
    p.commit ? `Commit ${p.commit}` : null,
    p.started_at ? `started ${when(p.started_at)}` : null,
    p.required ? `${p.required.ran} of ${p.required.of} required scanners ran` : null,
  ].filter(Boolean).join(", ");
  const tiles: [string, string][] = [
    ["Total cost", `$${p.cost_usd.toFixed(2)}`],
    ["Agents spawned", String(p.agents)],
    ["Tokens", `${(p.tokens.input / 1000).toFixed(1)}k in, ${(p.tokens.output / 1000).toFixed(1)}k out`],
    ["Commit", p.commit ?? "none recorded"],
  ];

  return (
    <>
      <PageHead eyebrow="Scan" title={`${run} · ${appLabel}`} sub={sub}
        actions={
          <>
            <button type="button" className={hx("btn")} onClick={() => onOpenDetail(run)}>Open full detail</button>
            <a className={hx("btn primary")} href={api.runs.downloadUrl(run, "sarif")} download>Download SARIF</a>
          </>
        } />
      <div className={hx("stack")}>
        <div className={hx("res")}>
          {tiles.map(([k, v]) => (
            <div key={k} className={hx("count")}><b style={{ fontSize: 20 }}>{v}</b><span>{k}</span></div>
          ))}
        </div>
        <Kit tag="docket-pipeline" on={{ "docket:lane": (d) => { const l = p.lanes.find((x) => x.id === d.id); if (l) setLane(l); } }} props={{
          heading: `Scan ${run} pipeline`, lanes: p.lanes, groups: p.groups, policy: p.policy ?? undefined,
          helpText: "Click a bar for what that stage did. The time axis is minutes and seconds from the start of the scan.",
          source: { label: appLabel, href: `#/app/${encodeURIComponent(p.application)}` }, asOf: p.ended_at ?? p.started_at ?? undefined,
        }} />
        <Card title="Findings from this scan" sub="Click one to see the proof" flush>
          <FindingTable rows={mine} onOpen={setFinding}
            empty={all.loading ? "Loading…" : "No open finding is attached to this scan."} />
        </Card>
      </div>
      <FindingDrawer finding={finding} appLabel={appLabel} onClose={() => setFinding(null)} />
      <LaneDrawer lane={lane} onClose={() => setLane(null)} />
    </>
  );
}
