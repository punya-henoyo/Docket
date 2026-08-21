import { useMemo } from "react";
import type { Finding, RunSummary, ScanState, Severity, WatchState } from "../types";
import { SEVERITIES } from "../types";
import { cweLabel } from "../cwe";
import { AreaChart, SeverityDonut, StackedRuns } from "../components/charts";
import { CvssBadge, Empty, findingLocation, Panel, ruleLeaf, SevTag } from "../components/ui";

const SEV_COLOR: Record<Severity, string> = {
  critical: "var(--crit)",
  high: "var(--high)",
  medium: "var(--med)",
  low: "var(--low)",
  info: "var(--info)",
};

const shortDate = (iso: string | null | undefined) =>
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
  watch,
  onGoFindings,
  onGoRepos,
  onGoPulls,
  onSelectFinding,
  onOpenRun,
}: {
  scan: ScanState | null;
  runs: RunSummary[];
  watch: WatchState | null;
  onGoFindings: () => void;
  onGoRepos: () => void;
  onGoPulls: () => void;
  onSelectFinding: (f: Finding) => void;
  onOpenRun: (runName: string) => void;
}) {
  const findings = scan?.findings ?? [];
  const triaged = findings.filter((f) => f.triage);
  const reachable = triaged.filter((f) => f.triage!.verdict === "exploitable");
  const ruledOut = triaged.filter((f) => f.triage!.verdict === "not_reachable");
  const unknown = triaged.filter((f) => f.triage!.verdict === "uncertain");
  const untriaged = findings.length - triaged.length;

  // The portfolio. The latest scan of each repo IS that repo's current state, so the
  // headline sums across those — not across all history, which would count one finding
  // once per re-scan and inflate a frequently-scanned repo. This is what makes the main
  // dashboard the WHOLE estate rather than whichever single scan happens to be open.
  const latestByRepo = useMemo(() => {
    const m = new Map<string, RunSummary>();
    for (const r of runs) {
      const key = (r.target ?? r.run_name).replace(/^github:/, "").split("@")[0];
      if (!m.has(key)) m.set(key, r); // runs arrive newest-first
    }
    return m;
  }, [runs]);

  const portfolio = useMemo(() => {
    const counts: Partial<Record<Severity, number>> = {};
    let total = 0;
    let reachable = 0;
    let triagedRepos = 0; // repos whose latest run actually ran triage, so a portfolio
    for (const r of latestByRepo.values()) { // "0 reachable" reads as judged-none, not unknown
      total += r.finding_count;
      for (const s of SEVERITIES)
        counts[s] = (counts[s] ?? 0) + (r.severity_counts?.[s] ?? 0);
      if (r.reachable_count != null) {
        reachable += r.reachable_count;
        triagedRepos += 1;
      }
    }
    return { counts, total, reachable, triagedRepos, repos: latestByRepo.size };
  }, [latestByRepo]);

  // One row per repository, worst first — the same rollup, sliced for the panel.
  const assets = useMemo(() =>
    [...latestByRepo.entries()]
      .map(([repo, r]) => ({ repo, counts: r.severity_counts ?? {}, total: r.finding_count,
                             run: r.run_name }))
      .sort((a, b) =>
        (b.counts.critical ?? 0) - (a.counts.critical ?? 0) ||
        (b.counts.high ?? 0) - (a.counts.high ?? 0) ||
        b.total - a.total)
      .slice(0, 6),
    [latestByRepo]);

  // Worst reachable first — that IS the work queue. Falls back to raw severity when
  // nothing has been triaged, with the panel title saying which it is showing.
  const top = [...(reachable.length ? reachable : findings)]
    .sort((a, b) => SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity))
    .slice(0, 5);

  const coverage = scan?.coverage?.semgrep;
  const history = [...runs].reverse(); // oldest first, the direction a trend reads
  const spend = runs.reduce((sum, r) => sum + (r.cost_usd ?? 0), 0);

  // Auto-fix PRs docket opened, newest first. A fix only exists here once it VERIFIED
  // and shipped — an unproven patch is never opened, so this count is fixes that held,
  // not fixes attempted. Sourced from the live PR watch, not the loaded scan.
  const fixPrs = useMemo(
    () => (watch?.results ?? [])
      .filter((r) => r.fix?.number)
      .sort((a, b) => b.at - a.at),
    [watch],
  );
  const filesFixed = (r: (typeof fixPrs)[number]) => r.fix?.files?.length ?? 0;

  const repoLabel = (scan?.repo || "").replace(/^github:/, "");

  if (runs.length === 0 && !scan) {
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
          <span className="chip">
            {portfolio.repos} {portfolio.repos === 1 ? "repository" : "repositories"}
          </span>
          <button className="btn primary" onClick={onGoRepos}>New scan</button>
        </div>
      </div>

      <div className="kpis">
        <Kpi label="Reachable"
             value={portfolio.triagedRepos ? portfolio.reachable : "—"}
             tone="var(--crit)"
             sub={portfolio.triagedRepos ? `of ${portfolio.total} findings` : "not triaged"} />
        <Kpi label="Open findings" value={portfolio.total}
             sub={portfolio.counts.critical
               ? `${portfolio.counts.critical} critical`
               : "across all repos"}
             subTone={portfolio.counts.critical ? "var(--crit)" : undefined} />
        <Kpi label="Critical + High"
             value={(portfolio.counts.critical ?? 0) + (portfolio.counts.high ?? 0)}
             tone="var(--high)" sub="need attention" />
        <Kpi label="Auto-fix PRs" value={fixPrs.length}
             tone="var(--ok)"
             sub={fixPrs.length ? "opened & verified" : watch?.autofix ? "none yet" : "off"} />
        <Kpi label="Scans" value={runs.length} sub="all time" />
        <Kpi label="AI spend" value={`$${spend.toFixed(2)}`} sub="all runs" />
      </div>

      <div className="trio">
        {/* ── the work queue ──────────────────────────────────────────── */}
        <Panel
          title={reachable.length ? "Fix these first" : "Top issues"}
          action={
            <span style={{ display: "flex", alignItems: "center", gap: 8 }}>
              {repoLabel && <span className="chip" title="latest scan">{repoLabel}</span>}
              <button className="btn ghost" onClick={onGoFindings}>View all →</button>
            </span>
          }
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
                  <CvssBadge cvss={f.cvss} size="sm" />
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

        <Panel title="Severity breakdown"
               action={<span className="note" style={{ fontSize: 12 }}>all repos</span>}>
          <div style={{ padding: "10px 0 4px" }}>
            <SeverityDonut counts={portfolio.counts} />
          </div>
        </Panel>
      </div>

      <div className="trio">
        {/* ── the funnel: volume in, decisions out ─────────────────────── */}
        <Panel title="Triage outcome"
               action={repoLabel
                 ? <span className="chip" title="latest scan">{repoLabel}</span>
                 : undefined}>
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
      <div className="trio">
        {/* ── the flagship: fixes docket shipped, not just problems it found ── */}
        <Panel
          title="Auto-fix PRs"
          action={fixPrs.length
            ? <button className="btn ghost" onClick={onGoPulls}>Pull requests →</button>
            : undefined}
        >
          {fixPrs.length === 0 ? (
            <Empty>
              <div style={{ maxWidth: "30ch" }}>
                {watch?.autofix
                  ? "No fix PR opened yet. A blocked PR gets one once a patch verifies."
                  : "Autofix is off. Turn it on so a blocked PR also gets a verified fix PR."}
              </div>
              {!watch?.autofix && (
                <button className="btn primary" onClick={onGoPulls}>Set up autofix</button>
              )}
            </Empty>
          ) : (
            <div className="rows">
              {fixPrs.slice(0, 5).map((r) => (
                <a key={`${r.repo}#${r.number}`} href={r.fix!.url}
                   target="_blank" rel="noreferrer"
                   title={`Fix for ${r.repo} #${r.number} — opens on GitHub`}>
                  <span style={{ minWidth: 0, flex: 1 }}>
                    <span style={{ display: "block", fontSize: 13.5, overflow: "hidden",
                                   textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                      {r.title || `#${r.number}`}
                    </span>
                    <span className="path" style={{ display: "block", fontSize: 11.5 }}>
                      #{r.number} → fix #{r.fix!.number} · {filesFixed(r)} file
                      {filesFixed(r) === 1 ? "" : "s"}
                    </span>
                  </span>
                  <span className="tag" style={{ background: "rgba(18,183,106,0.12)",
                               color: "var(--ok)", font: "600 10px var(--sans)",
                               borderRadius: 5, padding: "2px 7px", flex: "none" }}>
                    OPENED
                  </span>
                </a>
              ))}
            </div>
          )}
        </Panel>

        <Panel title="What was examined"
               action={<span className="chip" title="latest scan">{repoLabel || "this run"}</span>}>
          {coverage?.files_scanned != null ? (
            <div style={{ display: "flex", flexWrap: "wrap", gap: "14px 34px" }}>
              <Fact label="Files analysed" value={coverage.files_scanned.toLocaleString()} />
              <Fact label="Languages matched"
                    value={coverage.rules_fired?.join(", ") || "none"} />
              <Fact label="Dependency manifests"
                    value={scan?.coverage?.trivy?.manifest_count ?? 0} />
              <Fact label="Entry points mapped"
                    value={scan?.surface?.entry_points?.length ?? "—"} />
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
                        aria-selected={scan?.id === r.run_name}
                        style={scan?.id === r.run_name ? { background: "var(--wash)" } : undefined}>
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
