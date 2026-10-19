import { useMemo, useState } from "react";
import * as api from "../api";
import type { ApplicationDetail, Lane, PortfolioFinding, Proof } from "../portfolio";
import { Card, Empty, LEVELS, Lamp, OriginChip, ProofCell, SevChip, ago, useSort } from "../hx/components";
import { FindingDrawer, LaneDrawer } from "../hx/Drawers";
import { hx } from "../hx/hx";
import { useApi } from "../hooks/useApi";
import { Kit } from "../kit/Kit";
import "./ApplicationPage.css";

type Go = (name: string, param?: string | null) => void;
type Tab = "overview" | "related" | "details";
const TABS: Tab[] = ["overview", "related", "details"];

const SEV_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const PROOF_RANK: Record<Proof, number> = { reproduced: 0, deterministic: 1, candidate: 2, not_reachable: 3 };

const FINDING_SORT = {
  sev: (f: PortfolioFinding) => SEV_RANK[f.sev] ?? 9,
  finding: (f: PortfolioFinding) => f.title,
  proof: (f: PortfolioFinding) => PROOF_RANK[f.proof],
  by: (f: PortfolioFinding) => f.by.name,
  age: (f: PortfolioFinding) => f.age_days,
};

/** Open findings, shared with the scan page. A reproduced exploit and a scanner candidate sit in
 *  the same table but the proof column says which is which, in words (AGENTS.md rules 1 and 10). */
export function FindingTable({ rows, showAge, empty, onOpen }: {
  rows: PortfolioFinding[]; showAge?: boolean; empty: string; onOpen: (f: PortfolioFinding) => void;
}) {
  const { rows: sorted, Th } = useSort(rows, FINDING_SORT);
  if (!rows.length) return <Empty>{empty}</Empty>;
  return (
    <table className={hx("lv")}>
      <thead>
        <tr>
          <Th k="sev">Severity</Th><Th k="finding">Finding</Th><Th k="proof">Proof</Th><Th k="by">Found by</Th>
          {showAge ? <Th k="age">Age</Th> : null}
        </tr>
      </thead>
      <tbody>
        {sorted.map((f) => (
          <tr key={f.id} onClick={() => onOpen(f)}>
            <td><SevChip sev={f.sev} /></td>
            <td><div className={hx("tt")}>{f.title}</div><div className={hx("ms")}>{f.sub}</div></td>
            <td><ProofCell f={f} /></td>
            <td><OriginChip origin={f.by.origin} name={f.by.name} /></td>
            {showAge ? <td className={hx("num")}>{ago(f.age_days)}</td> : null}
          </tr>
        ))}
      </tbody>
    </table>
  );
}

const day = (iso: string | null | undefined) =>
  iso ? new Date(iso).toLocaleDateString("en-GB", { day: "numeric", month: "short" }) : "";

/** Coverage is the server's word for whether every required scanner ran. */
const CoverageChip = ({ c }: { c: "full" | "partial" | "failed" }) =>
  c === "full" ? <span className={hx("chip ok")}>All required ran</span>
    : c === "partial" ? <span className={hx("chip warn")}>Partial</span>
      : <span className={hx("chip bad")}>Failed</span>;

const ProvenCell = ({ n }: { n: number }) =>
  n ? <span className={hx("proof y")}>◆ {n} proven</span> : <span className={hx("proof n")}>None proven</span>;

const STATUS_VALUES = [
  { value: "onboarded", label: "Onboarded" },
  { value: "scanned", label: "Scanned" },
  { value: "proven", label: "Exploit open" },
  { value: "fix_proposed", label: "Fix in review" },
  { value: "fix_merged", label: "Fix merged" },
  { value: "verified", label: "Re-verified" },
];

type ScanRow = ApplicationDetail["scans"][number] & { label?: string | null };
const SCAN_SORT = {
  scan: (s: ScanRow) => Date.parse(s.at),
  coverage: (s: ScanRow) => s.coverage,
  result: (s: ScanRow) => s.proven,
};

function ScanTable({ rows, go }: { rows: ScanRow[]; go: Go }) {
  const { rows: sorted, Th } = useSort(rows, SCAN_SORT);
  if (!rows.length) return <Empty>No scans yet.</Empty>;
  return (
    <div className={hx("scroll")}>
    <table className={hx("lv")}>
      <thead>
        <tr><Th k="scan">Scan</Th><Th k="coverage">Coverage</Th><Th k="result">Result</Th></tr>
      </thead>
      <tbody>
        {sorted.map((s) => (
          <tr key={s.id} onClick={() => go("scan", s.id)}>
            <td className={hx("scanid")}><b>{s.label ?? s.id}</b>
              <div className={hx("ms")}>{s.kind === "pr" ? "Pull request" : "Full scan"} · {day(s.at)}</div></td>
            <td><CoverageChip c={s.coverage} /></td>
            <td><ProvenCell n={s.proven} /><div className={hx("ms")}>{s.candidates} candidates</div></td>
          </tr>
        ))}
      </tbody>
    </table>
    </div>
  );
}

type Fix = ApplicationDetail["fixes"][number];
const FIX_SORT = {
  pr: (x: Fix) => x.title,
  fixes: (x: Fix) => x.fixes,
  status: (x: Fix) => x.status,
  opened: (x: Fix) => Date.parse(x.opened_at),
};
function FixTable({ rows }: { rows: Fix[] }) {
  const { rows: sorted, Th } = useSort(rows, FIX_SORT);
  if (!rows.length) return <Empty>No fix pull request.</Empty>;
  return (
    <table className={hx("lv")}>
      <thead><tr><Th k="pr">Pull request</Th><Th k="fixes">Fixes</Th><Th k="status">Status</Th><Th k="opened">Opened</Th></tr></thead>
      <tbody>
        {sorted.map((x, i) => (
          <tr key={`${x.title}-${i}`} className={x.url ? undefined : hx("static")}
              onClick={x.url ? () => window.open(x.url!, "_blank", "noopener") : undefined}>
            <td className={hx("tt")}>{x.url ? <a href={x.url} target="_blank" rel="noopener noreferrer" onClick={(e) => e.stopPropagation()}>{x.title}</a> : x.title}</td>
            <td>{x.fixes}</td>
            <td><span className={hx("chip neutral")}>{x.status.replace(/_/g, " ")}</span></td>
            <td className={hx("num")}>{day(x.opened_at)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export function ApplicationPage({ id, go }: { id: string; go: Go }) {
  const { data, error, loading } = useApi(() => api.portfolio.getApplication(id), `app:${id}`, 20000);
  const [tab, setTab] = useState<Tab>("overview");
  const [finding, setFinding] = useState<PortfolioFinding | null>(null);
  const [lane, setLane] = useState<Lane | null>(null);

  const scans = useMemo<ScanRow[]>(() => {
    if (!data) return [];
    const labels = new Map(data.application.events.map((e) => [e.id, e.label]));
    return data.scans.map((s) => ({ ...s, label: labels.get(s.id) }));
  }, [data]);

  if (!data) {
    return (
      <div className={hx("notfound")}>
        <Card title={loading ? "Loading application" : "Application not found"}>
          {loading ? <p>Loading…</p> : (
            <>
              <p>{error ?? "This application is not in the portfolio."}</p>
              <button type="button" className={hx("btn")} onClick={() => go("apps")}>Back to Applications</button>
            </>
          )}
        </Card>
      </div>
    );
  }

  const { application: a, health, banner, lifecycle, pipeline, findings, fixes, compliance } = data;
  const unscanned = a.level === "unknown";

  const onLane = (d: Record<string, string | undefined>) => {
    const l = pipeline.lanes.find((x) => x.id === d.id);
    if (l) setLane(l);
  };
  // The banner row names an action but the API gives it a target only sometimes; fall back to the
  // proof the row is about, so "Review the proof" opens a reproduced finding.
  const onBanner = (d: Record<string, string | undefined>) => {
    const row = banner.find((r) => r.id === d.id);
    if (!row) return;
    if (row.href) {
      if (row.href.startsWith("#")) window.location.hash = row.href;
      else window.open(row.href, "_blank", "noopener");
      return;
    }
    const proof: Proof | null = row.word === "Exploit proven" ? "reproduced" : row.word === "Secret in source" ? "deterministic" : null;
    const f = proof ? findings.find((x) => x.proof === proof) : null;
    if (f) setFinding(f);
  };

  return (
    <>
      <div className={hx("rh")}>
        <span className={hx("objicon")} style={{ background: "rgb(var(--h-verdant-100))", color: "rgb(var(--h-verdant-700))" }}>
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
            <path d="m8 7-5 5 5 5M16 7l5 5-5 5M14 4l-4 16" />
          </svg>
        </span>
        <div>
          <div className={hx("eyebrow")}>Application</div>
          <h1>{a.label}</h1>
          <div className={hx("meta")}>
            <Lamp level={a.level} /><b>{LEVELS[a.level].word}</b>
            <span className={hx("dot")}>·</span><span className={hx("mono")}>{a.repo}</span>
            <span className={hx("dot")}>·</span><span>{a.tier}</span>
            <span className={hx("dot")}>·</span><span>Owner {a.owner}</span>
          </div>
        </div>
        <div className={hx("grow")} style={{ flex: 1 }} />
        <button type="button" className={hx("btn")} disabled title="Applications are defined in docket_portfolio.json">Edit</button>
        <button type="button" className={hx("btn primary")} onClick={() => go("repos")}>Run scan</button>
      </div>

      <div className={hx("stack")}>
        <Kit tag="henoyo-record-banner" props={{ rows: banner }} on={{ "henoyo:banner-action": onBanner }} />
        <Kit tag="henoyo-status-path" props={{
          variant: "bar", editable: false, values: STATUS_VALUES, current: lifecycle.current,
          since: lifecycle.since ?? undefined, owner: lifecycle.owner, ownerLabel: "Owner",
        }} />
      </div>

      <div className={hx("rtabs")} role="tablist">
        {TABS.map((t) => (
          <button key={t} type="button" role="tab" aria-selected={tab === t} onClick={() => setTab(t)}>
            {t.charAt(0).toUpperCase() + t.slice(1)}
          </button>
        ))}
      </div>

      {tab === "overview" ? (
        <div className={hx("stack")}>
          <Kit tag="docket-health-card" props={{
            heading: "Health report", subject: a.label, ...health,
            helpText: "The verdict, then what is lit, then every measure against its reference range. Reference ranges come from the security policy that covers this application.",
            source: { label: "Last scan" }, asOf: a.last_scan_at ?? undefined,
          }} />
          <Kit tag="docket-pipeline" on={{ "docket:lane": onLane }} props={{
            heading: "Latest scan pipeline", lanes: pipeline.lanes, groups: pipeline.groups, policy: pipeline.policy ?? undefined,
            helpText: "Each bar is a scanner or agent, from when it started to when it finished. Verdant bars are built by Henoyo; grey bars are third-party tools. A dashed amber bar is a scanner the policy requires that did not run.",
            source: pipeline.run ? { label: `Scan ${pipeline.run}`, href: `#/scan/${encodeURIComponent(pipeline.run)}` } : undefined,
            asOf: pipeline.run ? a.last_scan_at ?? undefined : undefined,
          }} />
          <div className={hx("cols")}>
            <Card title="Open findings" sub="Proven first" flush tip="Findings related to this application. Reproduced exploits sort above candidates.">
              <FindingTable rows={findings} showAge onOpen={setFinding}
                empty={unscanned ? "Nothing to show until the first scan." : "Nothing open. The last scan found no open finding here."} />
            </Card>
            <Card title="Scan history" sub="Newest first" flush>
              <ScanTable rows={scans} go={go} />
            </Card>
          </div>
        </div>
      ) : tab === "related" ? (
        <div className={hx("stack")}>
          <Card title="Findings" flush>
            <FindingTable rows={findings} showAge onOpen={setFinding} empty="No open finding." />
          </Card>
          <Card title="Scans" flush><ScanTable rows={scans} go={go} /></Card>
          <Card title="Fix pull requests" flush><FixTable rows={fixes} /></Card>
          <Card title="Compliance results">
            {compliance.length ? compliance.map((c) => (
              <p key={c.pack_id} style={{ margin: "0 0 6px" }}>
                {c.title}: {c.met} met, {c.not_met} not met, {c.unknown} could not be told from code.{" "}
                <a href={`#/compliance`} onClick={(e) => { e.preventDefault(); go("compliance"); }}>Open the baseline</a>
              </p>
            )) : <Empty>No compliance pack has been read for this application.</Empty>}
          </Card>
        </div>
      ) : (
        <Card title="Details">
          <dl className={hx("kv")}>
            <dt>Repository</dt><dd className={hx("mono")}>{a.repo}</dd>
            <dt>Language</dt><dd>{a.lang}</dd>
            <dt>Tier</dt><dd>{a.tier}</dd>
            <dt>Owner</dt><dd>{a.owner}</dd>
            <dt>Policy</dt><dd>{pipeline.policy ?? "None"}</dd>
            <dt>Last scan</dt><dd>{a.last_scan_at ? new Date(a.last_scan_at).toLocaleString("en-GB", { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" }) : "Never"}</dd>
          </dl>
        </Card>
      )}

      <FindingDrawer finding={finding} appLabel={a.label} onClose={() => setFinding(null)} />
      <LaneDrawer lane={lane} onClose={() => setLane(null)} />
    </>
  );
}
