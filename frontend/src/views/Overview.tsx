import { useMemo } from "react";
import type { Finding, RunSummary, ScanState, Severity } from "../types";
import { SEVERITIES } from "../types";
import { cweLabel } from "../cwe";
import { Empty, findingLocation, Panel, ruleLeaf, SevTag } from "../components/ui";

const SEV_COLOR: Record<Severity, string> = {
  critical: "var(--crit)",
  high: "var(--high)",
  medium: "var(--med)",
  low: "var(--low)",
  info: "var(--info)",
};

/** The executive view.
 *
 *  The number a security lead has to act on is NOT "48 findings" — that is a scanner's
 *  output volume, and it says nothing about risk. It is "how many can an attacker
 *  actually reach", and after that "how much of the codebase did we even look at".
 *  Both are here and the raw count is deliberately secondary.
 *
 *  Nothing on this page is invented. Every figure below comes from a real scan, and
 *  where a number is unknown it says so rather than showing a zero that reads as good
 *  news. */
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

  // Worst reachable first — that IS the work queue. Falls back to raw severity when
  // nothing has been triaged, with the page saying so.
  const top = [...(reachable.length ? reachable : findings)]
    .sort((a, b) => SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity))
    .slice(0, 6);

  const coverage = scan?.coverage?.semgrep;
  const trend = [...runs].reverse().map((r) => r.finding_count);

  if (!scan) {
    return (
      <>
        <div className="page-head"><h1>Overview</h1></div>
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
        <h1>Overview</h1>
        <div className="head-actions">
          <span className="chip">{(scan.repo || "").replace(/^github:/, "")}</span>
          {scan.ref && <span className="chip">{scan.ref}</span>}
        </div>
      </div>

      {/* ── the headline: what is actually actionable ─────────────────── */}
      <div className="split">
        <Panel title="Needs attention">
          {triaged.length === 0 ? (
            <Empty>
              <div style={{ maxWidth: "40ch" }}>
                {findings.length} finding(s), none triaged. Turn on <b>AI triage</b> to
                separate what an attacker can reach from what they cannot.
              </div>
            </Empty>
          ) : (
            <>
              <div style={{ display: "flex", alignItems: "baseline", gap: 10 }}>
                <span style={{ font: "600 54px/1 var(--sans)", color: "var(--crit)",
                               fontVariantNumeric: "tabular-nums" }}>
                  {reachable.length}
                </span>
                <span className="note" style={{ maxWidth: "22ch" }}>
                  reachable by untrusted input, of {findings.length} reported
                </span>
              </div>

              {/* The funnel is the story: volume in, decisions out. */}
              <div style={{ display: "flex", height: 10, borderRadius: 2,
                            overflow: "hidden", background: "var(--wash)", marginTop: 12 }}>
                {[
                  [reachable.length, "var(--crit)", "reachable"],
                  [unknown.length, "var(--ink-3)", "uncertain"],
                  [ruledOut.length, "var(--ok)", "ruled out"],
                  [untriaged, "var(--line-2)", "not triaged"],
                ].map(([n, c, label]) =>
                  (n as number) > 0 ? (
                    <span key={label as string} title={`${n} ${label}`}
                          style={{ flex: n as number, background: c as string }} />
                  ) : null,
                )}
              </div>
              <div className="note" style={{ marginTop: 6, lineHeight: 1.9 }}>
                <b style={{ color: "var(--crit)" }}>{reachable.length}</b> reachable ·{" "}
                <b style={{ color: "var(--ink-3)" }}>{unknown.length}</b> uncertain ·{" "}
                <b style={{ color: "var(--ok)" }}>{ruledOut.length}</b> ruled out
                {untriaged > 0 && <> · {untriaged} not triaged</>}
              </div>
              {ruledOut.length > 0 && (
                <div className="note" style={{ color: "var(--ink-2)" }}>
                  An agent read the source and ruled out {ruledOut.length} finding(s) that
                  would otherwise sit in someone's queue.
                </div>
              )}
              <button className="btn primary" style={{ alignSelf: "flex-start" }}
                      onClick={onGoFindings}>
                Review findings
              </button>
            </>
          )}
        </Panel>

        <div className="stack">
          <div className="kpis">
            <Kpi label="Reported" value={findings.length} />
            <Kpi label="Critical" value={counts.critical ?? 0} tone="var(--crit)" />
            <Kpi label="High" value={counts.high ?? 0} tone="var(--high)" />
            <Kpi label="Entry points"
                 value={scan.surface?.entry_points?.length ?? "—"} />
            <Kpi label="AI spend"
                 value={scan.cost_usd != null ? `$${scan.cost_usd.toFixed(2)}` : "—"} />
          </div>

          <div className="cols">
            <Panel title="Severity">
              <div style={{ display: "flex", flexDirection: "column", gap: 7 }}>
                {SEVERITIES.filter((s) => counts[s]).map((s) => (
                  <div key={s}>
                    <div style={{ display: "flex", justifyContent: "space-between",
                                  font: "11px var(--mono)", color: "var(--ink-2)" }}>
                      <SevTag severity={s} />
                      <span>{counts[s]}</span>
                    </div>
                    <div style={{ height: 6, borderRadius: 2, background: "var(--wash)",
                                  marginTop: 4 }}>
                      <div style={{ width: `${(counts[s]! / findings.length) * 100}%`,
                                    height: "100%", borderRadius: 2,
                                    background: SEV_COLOR[s] }} />
                    </div>
                  </div>
                ))}
              </div>
            </Panel>

            {/* Coverage sits on the executive page on purpose: "0 findings" and
                "nothing was analysed" are the same number, and only one is good news. */}
            <Panel title="What was examined">
              {coverage?.files_scanned != null ? (
                <div className="note" style={{ color: "var(--ink-2)", lineHeight: 2 }}>
                  <div><b style={{ color: "var(--ink)" }}>
                    {coverage.files_scanned.toLocaleString()}</b> files analysed</div>
                  {coverage.rules_fired?.length ? (
                    <div>languages: {coverage.rules_fired.join(", ")}</div>
                  ) : null}
                  {scan.coverage?.trivy?.manifest_count ? (
                    <div>{scan.coverage.trivy.manifest_count} dependency manifest(s)</div>
                  ) : null}
                  {coverage.error_count ? (
                    <div className="note bad">
                      {coverage.error_count} file(s) could not be analysed — a gap, not a
                      clean pass.
                    </div>
                  ) : null}
                  <div style={{ color: "var(--ink-3)" }}>
                    No live target was tested, so nothing runtime-only was covered.
                  </div>
                </div>
              ) : (
                <div className="note">
                  Not recorded for this run. Treat the count as a lower bound.
                </div>
              )}
            </Panel>
          </div>
        </div>
      </div>

      <div className="cols">
        <Panel
          title={reachable.length ? "Fix these first" : "Highest severity"}
          action={<button className="btn sm" onClick={onGoFindings}>view all</button>}
        >
          {top.length === 0 ? (
            <Empty>Nothing reported.</Empty>
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
              {top.map((f) => (
                <button key={f.id} onClick={() => onSelectFinding(f)}
                  style={{ display: "flex", justifyContent: "space-between", gap: 10,
                           alignItems: "center", background: "none", border: 0,
                           borderBottom: "1px dashed rgba(255,255,255,.15)",
                           padding: "6px 0", cursor: "pointer", textAlign: "left",
                           font: "11.5px var(--mono)" }}>
                  <span style={{ minWidth: 0 }}>
                    <span style={{ display: "block", color: "var(--ink)" }}>
                      {ruleLeaf(f.rule_id)}
                    </span>
                    <span style={{ color: "var(--ink-3)", fontSize: 10.5,
                                   wordBreak: "break-all" }}>
                      {findingLocation(f)}
                      {f.cwe ? ` · ${cweLabel(f.cwe)}` : ""}
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

        <Panel title="History" action={
          <span className="mono" style={{ fontSize: 11, color: "var(--ink-3)" }}>
            {runs.length} run(s)
          </span>
        }>
          {trend.length < 2 ? (
            <div className="note">Needs at least two runs to show a trend.</div>
          ) : (
            <>
              <div style={{ display: "flex", alignItems: "flex-end", gap: 4, height: 70 }}>
                {trend.slice(-16).map((v, i, arr) => (
                  <div key={i} title={`${v} finding(s)`}
                    style={{ flex: 1, minWidth: 3,
                             height: `${Math.max((v / Math.max(...trend, 1)) * 100, 3)}%`,
                             background: i === arr.length - 1
                               ? "var(--ink)" : "rgba(255,255,255,.25)",
                             borderRadius: 1 }} />
                ))}
              </div>
              <div className="note">
                Findings per run, oldest to newest. Counts move with scanner
                configuration as well as with code, so read the shape, not the exact
                delta.
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: 3,
                            borderTop: "1px dashed rgba(255,255,255,.2)", paddingTop: 8 }}>
                {runs.slice(0, 5).map((r) => (
                  <button key={r.run_name} onClick={() => onOpenRun(r.run_name)}
                    title={`Open ${r.target ?? r.run_name}`}
                    style={{ display: "flex", gap: 8, background:
                               scan?.id === r.run_name ? "var(--wash)" : "none",
                             border: 0, borderRadius: 4, padding: "4px 6px",
                             cursor: "pointer", font: "11px var(--mono)",
                             color: "var(--ink-2)", textAlign: "left" }}>
                    <span style={{ color: "var(--ink-3)" }}>
                      {(r.generated_at ?? "").slice(5, 16).replace("T", " ")}
                    </span>
                    <span style={{ minWidth: 0, overflow: "hidden",
                                   textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                      {(r.target ?? r.run_name).replace(/^github:/, "")}
                    </span>
                    <span style={{ marginLeft: "auto", color: "var(--ink-3)" }}>
                      {r.finding_count}
                    </span>
                  </button>
                ))}
              </div>
            </>
          )}
        </Panel>
      </div>
    </>
  );
}

function Kpi({ label, value, tone }: { label: string; value: number | string; tone?: string }) {
  return (
    <div>
      <div className="eyebrow">{label}</div>
      <div className="v" style={tone && value !== 0 ? { color: tone } : undefined}>
        {value}
      </div>
    </div>
  );
}
