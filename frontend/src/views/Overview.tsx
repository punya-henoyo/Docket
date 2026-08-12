import { useMemo } from "react";
import type { Finding, RunSummary, ScanState, Severity } from "../types";
import { SEVERITIES } from "../types";
import { cweLabel } from "../cwe";
import { AreaChart, SeverityDonut, StackedRuns } from "../components/charts";
import { Empty, findingLocation, Panel, ruleLeaf, SevTag } from "../components/ui";

const SEV_COLOR: Record<Severity, string> = {
  critical: "var(--crit)",
  high: "var(--high)",
  medium: "var(--med)",
  low: "var(--low)",
  info: "var(--info)",
};

const shortDate = (iso: string | null) =>
  iso ? new Date(iso).toLocaleDateString(undefined, { month: "short", day: "numeric" }) : "";

/** The security dashboard.
 *
 *  The headline number is REACHABLE findings, not raw finding count. A scanner's output
 *  volume says nothing about risk: 48 matches with 24 unreachable is a different morning
 *  than 48 matches all reachable, and only one of those numbers survives being read out
 *  in a meeting.
 *
 *  Every tile here is wired to something docket measured. Where a number is unknown the
 *  tile says so rather than rendering a zero, because on a security dashboard a
 *  confident zero is worse than a blank. */
export function Overview({
  scan,
  runs,
  onGoFindings,
  onGoRepos,
  onSelectFinding,
  onOpenRun,
}: {
  scan: ScanState | null;
  runs: RunSummary[];
  onGoFindings: () => void;
  onGoRepos: () => void;
  onSelectFinding: (f: Finding) => void;
  onOpenRun: (runName: string) => void;
}) {
  const findings = scan?.findings ?? [];
  const triaged = findings.filter((f) => f.triage);
  const reachable = triaged.filter((f) => f.triage!.verdict === "exploitable");
  const ruledOut = triaged.filter((f) => f.triage!.verdict === "not_reachable");
  const unknown = triaged.filter((f) => f.triage!.verdict === "uncertain");
  const untriaged = findings.length - triaged.length;

  const counts = useMemo(() => {
    const acc: Partial<Record<Severity, number>> = {};
    for (const f of findings) acc[f.severity] = (acc[f.severity] ?? 0) + 1;
    return acc;
  }, [findings]);

  // One row per repository, worst first. Runs are per-repo, so the latest run for each
  // repo IS that repo's current state; summing every historical run would count a
  // finding once per scan and inflate a frequently-scanned repo.
  const assets = useMemo(() => {
    const latest = new Map<string, RunSummary>();
    for (const r of runs) {
      const key = (r.target ?? r.run_name).replace(/^github:/, "").split("@")[0];
      if (!latest.has(key)) latest.set(key, r); // runs arrive newest-first
    }
    return [...latest.entries()]
      .map(([repo, r]) => ({ repo, counts: r.severity_counts ?? {}, total: r.finding_count,
                             run: r.run_name }))
      .sort((a, b) =>
        (b.counts.critical ?? 0) - (a.counts.critical ?? 0) ||
        (b.counts.high ?? 0) - (a.counts.high ?? 0) ||
        b.total - a.total)
      .slice(0, 6);
  }, [runs]);

  // Worst reachable first — that IS the work queue. Falls back to raw severity when
  // nothing has been triaged, with the panel title saying which it is showing.
  const top = [...(reachable.length ? reachable : findings)]
    .sort((a, b) => SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity))
    .slice(0, 5);

  const coverage = scan?.coverage?.semgrep;
  const history = [...runs].reverse(); // oldest first, the direction a trend reads
  const spend = runs.reduce((sum, r) => sum + (r.cost_usd ?? 0), 0);

  if (!scan) {
    return (
      <>
        <div className="page-head"><h1>Security dashboard</h1></div>
        <Panel>
          <Empty>
            <div>No scan yet.</div>
            <button className="btn primary" onClick={onGoRepos}>Pick a repository</button>
          </Empty>
        </Panel>
      </>
    );
  }

  return (
    <>
      <div className="page-head">
        <h1>Security dashboard</h1>
        <div className="head-actions">
          <span className="chip">{(scan.repo || "").replace(/^github:/, "")}</span>
          {scan.ref && <span className="chip mono">{scan.ref}</span>}
          <button className="btn primary" onClick={onGoRepos}>New scan</button>
        </div>
      </div>

      <div className="kpis">
        <Kpi label="Reachable" value={triaged.length ? reachable.length : "—"}
             tone="var(--crit)"
             sub={triaged.length ? `of ${findings.length}` : "not triaged"} />
        <Kpi label="Findings" value={findings.length}
             sub={counts.critical ? `${counts.critical} critical` : undefined}
             subTone="var(--crit)" />
        <Kpi label="High severity" value={(counts.critical ?? 0) + (counts.high ?? 0)}
             tone="var(--high)" />
        <Kpi label="Scans" value={runs.length} />
        <Kpi label="AI spend" value={`$${spend.toFixed(2)}`} sub="all runs" />
      </div>

      <div className="trio">
        {/* ── the work queue ──────────────────────────────────────────── */}
        <Panel
          title={reachable.length ? "Fix these first" : "Top issues"}
          action={<button className="btn ghost" onClick={onGoFindings}>View all →</button>}
        >
          {top.length === 0 ? (
            <Empty>Nothing reported.</Empty>
          ) : (
            <div className="rows">
              {top.map((f) => (
                <button key={f.id} onClick={() => onSelectFinding(f)}>
                  <span style={{ minWidth: 0, flex: 1 }}>
                    <span style={{ display: "block", fontSize: 13.5,
                                   overflow: "hidden", textOverflow: "ellipsis",
                                   whiteSpace: "nowrap" }}>
                      {ruleLeaf(f.rule_id)}
                    </span>
                    <span className="path" style={{ display: "block", fontSize: 11.5,
                                   overflow: "hidden", textOverflow: "ellipsis",
                                   whiteSpace: "nowrap", wordBreak: "normal" }}>
                      {findingLocation(f)}{f.cwe ? ` · ${cweLabel(f.cwe)}` : ""}
                    </span>
                  </span>
                  <SevTag severity={f.severity} />
                </button>
              ))}
            </div>
          )}
          {!reachable.length && triaged.length > 0 && (
            <div className="note">
              Nothing was judged reachable, so this is ordered by scanner severity.
            </div>
          )}
        </Panel>

        {/* ── posture across every repo, not just this run ─────────────── */}
        <Panel
          title="Top affected repositories"
          action={<span className="note" style={{ fontSize: 12 }}>latest scan each</span>}
        >
          {assets.length === 0 ? (
            <Empty>No runs yet.</Empty>
          ) : (
            <div className="rows">
              {assets.map((a) => (
                <button key={a.repo} onClick={() => onOpenRun(a.run)}
                        title={`Open the latest scan of ${a.repo}`}>
                  <span style={{ flex: 1, minWidth: 0, overflow: "hidden",
                                 textOverflow: "ellipsis", whiteSpace: "nowrap",
                                 fontSize: 13.5 }}>
                    {a.repo}
                  </span>
                  <span style={{ display: "flex", gap: 10, flex: "none" }}>
                    {SEVERITIES.filter((s) => a.counts[s]).slice(0, 4).map((s) => (
                      <span key={s} title={`${a.counts[s]} ${s}`}
                            style={{ display: "inline-flex", alignItems: "center", gap: 4,
                                     font: "500 12px var(--sans)", color: "var(--ink-2)" }}>
                        <span style={{ width: 7, height: 7, borderRadius: "50%",
                                       background: SEV_COLOR[s] }} />
                        <span className="num">{a.counts[s]}</span>
                      </span>
                    ))}
                  </span>
                </button>
              ))}
            </div>
          )}
        </Panel>

        <Panel title="Severity breakdown">
          <div style={{ padding: "10px 0 4px" }}>
            <SeverityDonut counts={counts} />
          </div>
        </Panel>
      </div>

      <div className="trio">
        {/* ── the funnel: volume in, decisions out ─────────────────────── */}
        <Panel title="Triage outcome">
          {triaged.length === 0 ? (
            <Empty>
              <div style={{ maxWidth: "34ch" }}>
                {findings.length} finding(s), none triaged. Turn on <b>AI triage</b> to
                separate what an attacker can reach from what they cannot.
              </div>
            </Empty>
          ) : (
            <>
              <div style={{ display: "flex", alignItems: "baseline", gap: 10 }}>
                <span className="num" style={{ font: "600 34px/1 var(--sans)",
                                               color: "var(--crit)" }}>
                  {reachable.length}
                </span>
                <span className="note" style={{ maxWidth: "20ch" }}>
                  reachable by untrusted input
                </span>
              </div>
              <div style={{ display: "flex", height: 10, borderRadius: 5,
                            overflow: "hidden", background: "var(--raised)" }}>
                {([
                  [reachable.length, "var(--crit)", "reachable"],
                  [unknown.length, "var(--med)", "uncertain"],
                  [ruledOut.length, "var(--ok)", "ruled out"],
                  [untriaged, "var(--line-2)", "not triaged"],
                ] as const).map(([n, c, label]) =>
                  n > 0 ? <span key={label} title={`${n} ${label}`}
                                style={{ flex: n, background: c }} /> : null,
                )}
              </div>
              <div style={{ display: "flex", flexWrap: "wrap", gap: "4px 14px" }}>
                {([
                  [reachable.length, "var(--crit)", "reachable"],
                  [unknown.length, "var(--med)", "uncertain"],
                  [ruledOut.length, "var(--ok)", "ruled out"],
                  [untriaged, "var(--line-2)", "not triaged"],
                ] as const).map(([n, c, label]) => (
                  <span key={label} style={{ display: "inline-flex", alignItems: "center",
                                             gap: 6, font: "500 12.5px var(--sans)",
                                             color: "var(--ink-2)" }}>
                    <span style={{ width: 8, height: 8, borderRadius: "50%", background: c }} />
                    {label} <span className="num" style={{ color: "var(--ink)" }}>{n}</span>
                  </span>
                ))}
              </div>
              {ruledOut.length > 0 && (
                <div className="note">
                  An agent read the source and ruled out {ruledOut.length} finding(s) that
                  would otherwise sit in someone's queue.
                </div>
              )}
            </>
          )}
        </Panel>

        <Panel
          title="Findings over time"
          action={<span className="note" style={{ fontSize: 12 }}>{runs.length} run(s)</span>}
        >
          <StackedRuns
            runs={history.map((r) => ({
              counts: r.severity_counts ?? {},
              total: r.finding_count,
              label: shortDate(r.generated_at),
            }))}
          />
          <div className="note">
            One column per scan, stacked by severity. Counts move with scanner
            configuration as well as with code, so read the shape, not the exact delta.
          </div>
        </Panel>

        <Panel
          title="Cost per scan"
          action={<span className="num note" style={{ fontSize: 12 }}>${spend.toFixed(2)} total</span>}
        >
          <AreaChart
            values={history.map((r) => r.cost_usd ?? 0)}
            labels={history.map((r) => shortDate(r.generated_at))}
            format={(v) => `$${v.toFixed(2)}`}
          />
          <div className="note">
            Only the AI phases spend: triage and recon. A scanner-only run costs nothing.
          </div>
        </Panel>
      </div>

      {/* Coverage sits on the executive page on purpose: "0 findings" and "nothing was
          analysed" are the same number, and only one is good news. */}
      <div className="cols">
        <Panel title="What was examined" action={<span className="chip">this run</span>}>
          {coverage?.files_scanned != null ? (
            <div style={{ display: "flex", flexWrap: "wrap", gap: "14px 34px" }}>
              <Fact label="Files analysed" value={coverage.files_scanned.toLocaleString()} />
              <Fact label="Languages matched"
                    value={coverage.rules_fired?.join(", ") || "none"} />
              <Fact label="Dependency manifests"
                    value={scan.coverage?.trivy?.manifest_count ?? 0} />
              <Fact label="Entry points mapped"
                    value={scan.surface?.entry_points?.length ?? "—"} />
              <Fact label="Could not be analysed" value={coverage.error_count ?? 0}
                    tone={coverage.error_count ? "var(--high)" : undefined} />
            </div>
          ) : (
            <div className="note">
              Not recorded for this run. Treat the finding count as a lower bound.
            </div>
          )}
          <div className="note">
            No live target was tested, so nothing runtime-only was covered.
            {coverage?.error_count
              ? ` ${coverage.error_count} file(s) could not be analysed — those are coverage holes, not clean passes.`
              : ""}
          </div>
        </Panel>

        <Panel title="Recent scans">
          {runs.length === 0 ? (
            <Empty>No runs yet.</Empty>
          ) : (
            <div className="rows">
              {runs.slice(0, 5).map((r) => (
                <button key={r.run_name} onClick={() => onOpenRun(r.run_name)}
                        aria-selected={scan.id === r.run_name}
                        style={scan.id === r.run_name ? { background: "var(--wash)" } : undefined}>
                  <span style={{ flex: 1, minWidth: 0, overflow: "hidden",
                                 textOverflow: "ellipsis", whiteSpace: "nowrap",
                                 fontSize: 13.5 }}>
                    {(r.target ?? r.run_name).replace(/^github:/, "")}
                  </span>
                  <span className="note" style={{ fontSize: 12, flex: "none" }}>
                    {shortDate(r.generated_at)}
                  </span>
                  <span className="num" style={{ flex: "none", minWidth: 26,
                                                 textAlign: "right", fontSize: 13.5 }}>
                    {r.finding_count}
                  </span>
                </button>
              ))}
            </div>
          )}
        </Panel>
      </div>
    </>
  );
}

function Kpi({ label, value, tone, sub, subTone }: {
  label: string; value: number | string; tone?: string;
  sub?: string; subTone?: string;
}) {
  return (
    <div>
      <div className="eyebrow">{label}</div>
      <div className="v" style={tone && value !== 0 && value !== "—" ? { color: tone } : undefined}>
        {value}
        {sub && <small style={subTone && value !== 0 ? { color: subTone } : undefined}>{sub}</small>}
      </div>
    </div>
  );
}

function Fact({ label, value, tone }: { label: string; value: number | string; tone?: string }) {
  return (
    <div>
      <div className="eyebrow" style={{ fontSize: 11.5 }}>{label}</div>
      <div className="num" style={{ font: "600 17px var(--sans)", marginTop: 3, color: tone }}>
        {value}
      </div>
    </div>
  );
}
