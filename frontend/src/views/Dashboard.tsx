import type { Finding, RunSummary, ScanState, Session, Severity } from "../types";
import { SCANNER_LABEL, SCANNERS } from "../types";
import { Radar } from "../components/Radar";
import { SeverityDonut, TrendBars } from "../components/charts";
import { CweBreakdown } from "../components/CweBreakdown";
import { Empty, findingLocation, Panel, ruleLeaf, SevTag } from "../components/ui";

const STATUS_LABEL: Record<string, string> = {
  queued: "queued",
  fetching: "downloading source",
  scanning: "scanning",
  done: "complete",
  error: "failed",
};

const SKIP_REASON: Record<string, string> = {
  nuclei: "needs a live URL",
  trivy: "needs source",
  semgrep: "needs source",
};

export function Dashboard({
  scan,
  runs,
  counts,
  scanError,
  session,
  onSelectFinding,
  newestId,
  onGoRepos,
  onGoIntegrations,
  cweFilter,
  onCweSelect,
  onOpenRun,
}: {
  scan: ScanState | null;
  runs: RunSummary[];
  counts: Partial<Record<Severity, number>>;
  scanError: string | null;
  session: Session | null;
  onSelectFinding: (f: Finding) => void;
  newestId?: string;
  onGoRepos: () => void;
  onGoIntegrations: () => void;
  cweFilter: string | null;
  onCweSelect: (cwe: string | null) => void;
  onOpenRun: (runName: string) => void;
}) {
  const running =
    !scan?.historical &&
    (scan?.status === "queued" || scan?.status === "fetching" || scan?.status === "scanning");
  const top = [...(scan?.findings ?? [])]
    .sort((a, b) => order(a.severity) - order(b.severity))
    .slice(0, 5);

  return (
    <>
      <div className="page-head">
        <h1>Security Dashboard</h1>
        <div className="head-actions">
          {!session?.connected && (
            <button className="btn" onClick={onGoIntegrations}>
              Connect GitHub
            </button>
          )}
          <button className="btn primary" onClick={onGoRepos}>
            + New scan
          </button>
        </div>
      </div>

      {scanError && <div className="note bad">{scanError}</div>}

      <div className="split">
        {/* ── radar hero ─────────────────────────────────────────────── */}
        <Panel
          title={
            <span className="mono" style={{ fontSize: 11, color: "var(--ink-3)" }}>
              {scan
                ? `${scan.historical ? "LAST RUN" : "SCANNING"} ${scan.repo}${scan.ref ? "@" + scan.ref : ""}`
                : "NO SCAN RUNNING"}
            </span>
          }
          action={
            <span className="mono" style={{ fontSize: 11, color: running ? "var(--ok)" : "var(--ink-3)" }}>
              {scan ? (running ? "● live" : STATUS_LABEL[scan.status]) : "idle"}
            </span>
          }
        >
          <Radar scan={scan} onSelect={onSelectFinding} newestId={newestId} />

          {!scan?.historical && (
          <div className="stages" style={{ borderTop: "1px dashed rgba(255,255,255,.2)", paddingTop: 9 }}>
            {SCANNERS.map((s) => {
              const state = scan?.stages?.[s] ?? "pending";
              return (
                <div key={s} className="stage" data-state={state}>
                  <span className="bulb" />
                  <span>{SCANNER_LABEL[s]}</span>
                  <span className="why">
                    {state === "skipped" ? SKIP_REASON[s] ?? "skipped" : state}
                  </span>
                </div>
              );
            })}
          </div>
          )}

          {scan?.status === "error" && <div className="note bad">{scan.error}</div>}
          {scan?.status === "done" && (
            <div className="note">
              {scan.finding_count} finding(s)
              {scan.elapsed_sec != null ? ` in ${scan.elapsed_sec}s` : ""}. Click a blip to open it.
            </div>
          )}
          {!scan && (
            <div className="note">
              Rings are scanner stages, innermost first. Blips are real findings, placed by
              severity. Start a scan from Repositories.
            </div>
          )}
        </Panel>

        {/* ── right column ───────────────────────────────────────────── */}
        <div className="stack">
          <div className="kpis">
            <Kpi label="Findings" value={scan?.finding_count ?? 0} />
            <Kpi label="Critical" value={counts.critical ?? 0} tone="var(--crit)" />
            <Kpi label="High" value={counts.high ?? 0} tone="var(--high)" />
            <Kpi label="Runs" value={runs.length} />
            <Kpi
              label="LLM cost"
              value={runs.reduce((s, r) => s + (r.cost_usd || 0), 0).toFixed(2)}
              unit="usd"
            />
          </div>

          <div className="cols">
            <Panel title="Top findings" action={<span className="mono" style={{ fontSize: 11, color: "var(--ink-3)" }}>by severity</span>}>
              {top.length === 0 ? (
                <Empty>{running ? "Scanning…" : "No findings yet."}</Empty>
              ) : (
                <div style={{ display: "flex", flexDirection: "column", gap: 7 }}>
                  {top.map((f) => (
                    <button
                      key={f.id}
                      onClick={() => onSelectFinding(f)}
                      style={{
                        display: "flex",
                        justifyContent: "space-between",
                        gap: 10,
                        alignItems: "center",
                        background: "none",
                        border: 0,
                        borderBottom: "1px dashed rgba(255,255,255,.15)",
                        padding: "6px 0",
                        cursor: "pointer",
                        textAlign: "left",
                        font: "11.5px var(--mono)",
                      }}
                    >
                      <span style={{ minWidth: 0 }}>
                        <span style={{ display: "block", color: "var(--ink)" }}>{ruleLeaf(f.rule_id)}</span>
                        <span style={{ color: "var(--ink-3)", fontSize: 10.5, wordBreak: "break-all" }}>
                          {findingLocation(f)}
                        </span>
                      </span>
                      <SevTag severity={f.severity} />
                    </button>
                  ))}
                </div>
              )}
            </Panel>

            <Panel
              title="Weakness classes"
              action={
                cweFilter ? (
                  <button className="btn sm" onClick={() => onCweSelect(null)}>
                    clear filter
                  </button>
                ) : (
                  <span className="mono" style={{ fontSize: 11, color: "var(--ink-3)" }}>
                    by CWE
                  </span>
                )
              }
            >
              <SeverityDonut counts={counts} />
              <div style={{ borderTop: "1px dashed rgba(255,255,255,.2)", paddingTop: 9 }}>
                <CweBreakdown
                  findings={scan?.findings ?? []}
                  selected={cweFilter}
                  onSelect={onCweSelect}
                />
              </div>
            </Panel>
          </div>

          <Panel title="Run history">
            {runs.length === 0 ? (
              <Empty>No completed runs on disk yet.</Empty>
            ) : (
              <>
                <TrendBars values={[...runs].reverse().map((r) => r.finding_count)} />
                <div className="feed">
                  {runs.slice(0, 6).map((r) => (
                    <button
                      key={r.run_name}
                      onClick={() => onOpenRun(r.run_name)}
                      title={`Open ${r.target ?? r.run_name}`}
                      style={{
                        display: "flex",
                        gap: 8,
                        background: scan?.id === r.run_name ? "var(--wash)" : "none",
                        border: 0,
                        borderRadius: 4,
                        padding: "4px 6px",
                        cursor: "pointer",
                        font: "11px var(--mono)",
                        color: "var(--ink-2)",
                        textAlign: "left",
                      }}
                    >
                      <span className="t">{(r.generated_at ?? "").slice(0, 16).replace("T", " ")}</span>
                      <span style={{ minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
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
      </div>
    </>
  );
}

function Kpi({ label, value, tone, unit }: { label: string; value: number | string; tone?: string; unit?: string }) {
  return (
    <div>
      <div className="eyebrow">{label}</div>
      <div className="v" style={tone && value !== 0 ? { color: tone } : undefined}>
        {value} {unit && <small>{unit}</small>}
      </div>
    </div>
  );
}

const order = (s: Severity) => ["critical", "high", "medium", "low", "info"].indexOf(s);
