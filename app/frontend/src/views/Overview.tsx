import { useMemo, useState } from "react";
import type { Finding, RunSummary, ScanState, Severity, WatchState } from "../types";
import { SEVERITIES } from "../types";
import { cweLabel } from "../cwe";
import { SeverityDonut, StackedRuns } from "../components/charts";
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

const repoOf = (r: RunSummary) =>
  (r.target ?? r.run_name).replace(/^github:/, "").split("@")[0];

/** The security dashboard, with an explicit scope selector.
 *
 *  A dropdown in the header chooses what the whole page is about: "All repositories" (the
 *  organization rollup) or one repository. Before this, the headline numbers were the
 *  portfolio while a few panels silently showed whichever single scan happened to be
 *  loaded — so "whose numbers am I looking at" had no answer on the page. Now it does.
 *
 *  - All repositories: reachable/findings summed across the latest scan of every repo,
 *    with the repo table as the org work queue (worst-reachable first).
 *  - One repository: every panel scopes to it; picking it loads that repo's latest scan,
 *    so the findings, triage split and coverage are real, not just summary counts.
 *
 *  The headline number is REACHABLE, not raw finding count: a scanner's volume says
 *  nothing about risk, and only the judged number survives being read out in a meeting. */
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
  // The latest scan of each repo IS that repo's current state, so both the org rollup and
  // the per-repo scope read from this map rather than from all history (which would count
  // one finding once per re-scan).
  const latestByRepo = useMemo(() => {
    const m = new Map<string, RunSummary>();
    for (const r of runs) {
      const key = repoOf(r);
      if (!m.has(key)) m.set(key, r); // runs arrive newest-first
    }
    return m;
  }, [runs]);

  const repos = useMemo(() => [...latestByRepo.keys()].sort(), [latestByRepo]);

  const [pickedScope, setPickedScope] = useState<string>("all");
  // A picked repo that has since vanished (all its runs pruned) falls back to the org view
  // rather than rendering an empty scope, without an effect to reset state.
  const scope = pickedScope !== "all" && latestByRepo.has(pickedScope) ? pickedScope : "all";

  const changeScope = (v: string) => {
    setPickedScope(v);
    if (v !== "all") {
      const r = latestByRepo.get(v);
      if (r) onOpenRun(r.run_name); // load its full findings for the detail panels
    }
  };

  // Org rollup, summed across the latest run of each repo.
  const portfolio = useMemo(() => {
    const counts: Partial<Record<Severity, number>> = {};
    let total = 0;
    let reachable = 0;
    let triagedRepos = 0;
    for (const r of latestByRepo.values()) {
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

  // Per-repo rows for the org table, worst-reachable first.
  const assets = useMemo(() =>
    [...latestByRepo.entries()]
      .map(([repo, r]) => ({
        repo,
        counts: r.severity_counts ?? {},
        total: r.finding_count,
        reachable: r.reachable_count ?? null,
        when: r.running ? "scanning" : shortDate(r.generated_at),
        running: !!r.running,
        run: r.run_name,
      }))
      .sort((a, b) =>
        (b.reachable ?? -1) - (a.reachable ?? -1) ||
        (b.counts.critical ?? 0) - (a.counts.critical ?? 0) ||
        (b.counts.high ?? 0) - (a.counts.high ?? 0) ||
        b.total - a.total)
      .slice(0, 8),
    [latestByRepo]);

  const fixPrs = useMemo(
    () => (watch?.results ?? [])
      .filter((r) => r.fix?.number)
      .sort((a, b) => b.at - a.at),
    [watch],
  );
  const filesFixed = (r: (typeof fixPrs)[number]) => r.fix?.files?.length ?? 0;

  // ── the scoped scan: single-repo detail comes from a loaded ScanState ─────────────
  const scopeRun = scope !== "all" ? latestByRepo.get(scope) ?? null : null;
  const scanRepo = (scan?.repo || "").replace(/^github:/, "");
  const scanMatches = scope !== "all" && scanRepo === scope; // the loaded scan IS this repo
  const findings = scanMatches ? scan?.findings ?? [] : [];
  const triaged = findings.filter((f) => f.triage);
  const reachableF = triaged.filter((f) => f.triage!.verdict === "exploitable");
  const ruledOut = triaged.filter((f) => f.triage!.verdict === "not_reachable");
  const unknown = triaged.filter((f) => f.triage!.verdict === "uncertain");
  const untriaged = findings.length - triaged.length;

  // Headline numbers, scoped. Org: from the rollup. Repo: from the run summary (instant,
  // no wait on the scan load), with the triage split filled in once the scan arrives.
  const head = scope === "all"
    ? {
        reachable: portfolio.triagedRepos ? portfolio.reachable : null,
        total: portfolio.total,
        critical: portfolio.counts.critical ?? 0,
        critHigh: (portfolio.counts.critical ?? 0) + (portfolio.counts.high ?? 0),
        counts: portfolio.counts,
      }
    : {
        reachable: scopeRun?.reachable_count ?? null,
        total: scopeRun?.finding_count ?? 0,
        critical: scopeRun?.severity_counts?.critical ?? 0,
        critHigh: (scopeRun?.severity_counts?.critical ?? 0) + (scopeRun?.severity_counts?.high ?? 0),
        counts: (scopeRun?.severity_counts ?? {}) as Partial<Record<Severity, number>>,
      };

  const scopedRuns = scope === "all" ? runs : runs.filter((r) => repoOf(r) === scope);
  const scopedFix = scope === "all" ? fixPrs : fixPrs.filter((r) => r.repo === scope);
  const spend = scopedRuns.reduce((sum, r) => sum + (r.cost_usd ?? 0), 0);
  const history = [...scopedRuns].reverse();
  const lastScan = shortDate(scopedRuns[0]?.generated_at);
  const coverage = scanMatches ? scan?.coverage?.semgrep : undefined;

  const top = [...(reachableF.length ? reachableF : findings)]
    .sort((a, b) => SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity))
    .slice(0, 5);

  const triageSplit = [
    [reachableF.length, "var(--crit)", "reachable"],
    [unknown.length, "var(--med)", "uncertain"],
    [ruledOut.length, "var(--ok)", "ruled out"],
    [untriaged, "var(--line-2)", "not triaged"],
  ] as const;

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

  const shippedPanel = (
    <Panel
      title="Fixes shipped"
      action={scopedFix.length
        ? <button className="btn ghost" onClick={onGoPulls}>Pull requests →</button>
        : undefined}
    >
      {scopedFix.length === 0 ? (
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
        <>
          <div className="rows">
            {scopedFix.slice(0, 4).map((r) => (
              <a key={`${r.repo}#${r.number}`} href={r.fix!.url}
                 target="_blank" rel="noreferrer"
                 title={`Fix for ${r.repo} #${r.number} — opens on GitHub`}>
                <span style={{ minWidth: 0, flex: 1 }}>
                  <span className="clip" style={{ display: "block", fontSize: 13.5 }}>
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
          <div className="note">
            A patch is only opened after it verified, so these are fixes that held.
          </div>
        </>
      )}
    </Panel>
  );

  return (
    <>
      <div className="page-head">
        <div style={{ display: "flex", alignItems: "center", gap: 12, flexWrap: "wrap" }}>
          <h1>Security dashboard</h1>
          <span className="scope-select">
            <select value={scope} onChange={(e) => changeScope(e.target.value)}
                    aria-label="Dashboard scope">
              <option value="all">All repositories</option>
              {repos.map((r) => <option key={r} value={r}>{r}</option>)}
            </select>
          </span>
          {lastScan && (
            <span className="note" style={{ fontSize: 12.5 }}>
              {scope === "all" ? `${portfolio.repos} repositories · ` : ""}last scan {lastScan}
            </span>
          )}
        </div>
        <div className="head-actions">
          <button className="btn primary" onClick={onGoRepos}>New scan</button>
        </div>
      </div>

      <div className="band">
        <h2>{scope === "all" ? "Across the organization" : scope}</h2>
        <span className="rule" />
      </div>

      <div className="kpis lead">
        <div className="kpi-hero">
          <div className="eyebrow" style={{ display: "flex", alignItems: "center", gap: 7 }}>
            Reachable
            <span className="legend"><span className="dot" style={{ background: "var(--crit)" }} /></span>
          </div>
          <div className="v" style={{ color: head.reachable != null ? "var(--crit)" : "var(--ink-3)" }}>
            {head.reachable != null ? head.reachable : "—"}
          </div>
          <div className="sub">
            {head.reachable != null
              ? `of ${head.total} findings · judged by reading source`
              : "not triaged yet — treat the counts below as unjudged"}
          </div>
          {scanMatches && triaged.length > 0 && (
            <>
              <div className="bar" style={{ marginTop: 12 }}>
                {triageSplit.map(([n, c, label]) =>
                  n > 0 ? <span key={label} title={`${n} ${label}`}
                                style={{ flex: n, background: c }} /> : null)}
              </div>
              <div className="legend" style={{ marginTop: 8 }}>
                {triageSplit.map(([n, , label]) => (
                  <span key={label}>{n} {label}</span>
                ))}
              </div>
            </>
          )}
        </div>

        <div>
          <div className="eyebrow">Open findings</div>
          <div className="v">{head.total}</div>
          <div className="foot" style={head.critical ? { color: "var(--crit)" } : undefined}>
            {head.critical ? `${head.critical} critical` : scope === "all" ? "across all repos" : "in this repo"}
          </div>
        </div>

        <div>
          <div className="eyebrow">Critical + High</div>
          <div className="v" style={{ color: "var(--high)" }}>{head.critHigh}</div>
          <div className="foot">need attention</div>
        </div>

        <div>
          <div className="eyebrow">Auto-fix PRs</div>
          <div className="v" style={scopedFix.length ? { color: "var(--ok)" } : undefined}>
            {scopedFix.length}
          </div>
          <div className="foot">
            {scopedFix.length ? "opened & verified" : watch?.autofix ? "none yet" : "autofix off"}
          </div>
        </div>
      </div>

      <div className="meta-strip">
        <span><span className="n">{scopedRuns.length}</span> scans{scope === "all" ? " all time" : " of this repo"}</span>
        <span className="sep" />
        <span>AI spend <span className="n mono">${spend.toFixed(2)}</span></span>
        {scope === "all" && (
          <>
            <span className="sep" />
            <span>{portfolio.triagedRepos} of {portfolio.repos} repos triaged</span>
          </>
        )}
        {watch?.enabled && (
          <>
            <span className="sep" />
            <span>PR watch on{watch.autofix ? " · autofix on" : ""}</span>
          </>
        )}
      </div>

      {scope === "all" ? (
        /* ══════════════════ ORGANIZATION VIEW ══════════════════ */
        <>
          <div className="split" style={{ gridTemplateColumns: "1.7fr 1fr" }}>
            <Panel
              title="Repositories"
              action={<span className="note" style={{ fontSize: 12 }}>worst-reachable first</span>}
            >
              {assets.length === 0 ? (
                <Empty>No runs yet.</Empty>
              ) : (
                <div className="gtable">
                  <div className="head">
                    <span>Repository</span>
                    <span className="r">Reachable</span>
                    <span className="mix">Severity mix</span>
                    <span className="r">Findings</span>
                    <span className="r when">Scanned</span>
                  </div>
                  {assets.map((a) => (
                    <button key={a.repo} onClick={() => changeScope(a.repo)}
                            title={`Focus the dashboard on ${a.repo}`}>
                      <span className="clip">{a.repo}</span>
                      <span className="r" style={a.reachable
                        ? { color: "var(--crit)", fontWeight: 600 }
                        : { color: "var(--ink-3)" }}>
                        {a.reachable ?? "—"}
                      </span>
                      <span className="mix">
                        <span className="bar">
                          {SEVERITIES.filter((s) => a.counts[s]).map((s) => (
                            <span key={s} title={`${a.counts[s]} ${s}`}
                                  style={{ flex: a.counts[s], background: SEV_COLOR[s] }} />
                          ))}
                        </span>
                      </span>
                      <span className="r">{a.total}</span>
                      <span className="r when note"
                            style={{ fontSize: 12, color: a.running ? "var(--ok)" : undefined }}>
                        {a.when}
                      </span>
                    </button>
                  ))}
                </div>
              )}
              <div className="note">
                Click a repository to focus the whole dashboard on it. Reachable leads the
                sort — 40 unreachable findings is not the one to open first.
              </div>
            </Panel>

            {shippedPanel}
          </div>

          <div className="band">
            <h2>Trend &amp; coverage</h2>
            <span className="rule" />
            <span className="aside">
              {runs.length} run{runs.length === 1 ? "" : "s"} · ${spend.toFixed(2)} all time
            </span>
          </div>

          <div className="split" style={{ gridTemplateColumns: "1fr 1fr" }}>
            <Panel title="Severity mix"
                   action={<span className="note" style={{ fontSize: 12 }}>all repos</span>}>
              <div style={{ padding: "10px 0 4px" }}>
                <SeverityDonut counts={portfolio.counts} />
              </div>
              <div className="note">Scanner severity, before triage. The judged number leads above.</div>
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
                One column per scan, stacked by severity. Read the shape, not the exact delta.
              </div>
            </Panel>
          </div>
        </>
      ) : (
        /* ══════════════════ SINGLE-REPOSITORY VIEW ══════════════════ */
        <>
          <div className="split" style={{ gridTemplateColumns: "1.7fr 1fr" }}>
            <Panel
              title={reachableF.length ? "Fix these first" : "Top issues"}
              action={<button className="btn ghost" onClick={onGoFindings}>View all →</button>}
            >
              {!scanMatches ? (
                <Empty>Loading {scope}…</Empty>
              ) : top.length === 0 ? (
                <Empty>Nothing reported in this repo.</Empty>
              ) : (
                <div className="rows">
                  {top.map((f) => (
                    <button key={f.id} onClick={() => onSelectFinding(f)}>
                      <span style={{ minWidth: 0, flex: 1 }}>
                        <span className="clip" style={{ display: "block", fontSize: 13.5 }}>
                          {ruleLeaf(f.rule_id)}
                        </span>
                        <span className="path clip" style={{ display: "block", fontSize: 11.5,
                                                             wordBreak: "normal" }}>
                          {findingLocation(f)}{f.cwe ? ` · ${cweLabel(f.cwe)}` : ""}
                        </span>
                      </span>
                      <CvssBadge cvss={f.cvss} size="sm" />
                      <SevTag severity={f.severity} />
                    </button>
                  ))}
                </div>
              )}
              {scanMatches && !reachableF.length && triaged.length > 0 && (
                <div className="note">
                  Nothing was judged reachable, so this is ordered by scanner severity.
                </div>
              )}
            </Panel>

            {shippedPanel}
          </div>

          <div className="band">
            <h2>Detail</h2>
            <span className="rule" />
            <span className="aside">{scope}</span>
          </div>

          <div className="trio">
            <Panel title="Severity mix">
              <div style={{ padding: "10px 0 4px" }}>
                <SeverityDonut counts={head.counts} />
              </div>
              <div className="note">Scanner severity for this repo, before triage.</div>
            </Panel>

            <Panel title="What was examined"
                   action={<span className="chip" title="latest scan">this scan</span>}>
              {coverage?.files_scanned != null ? (
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "14px 20px" }}>
                  <Fact label="Files analysed" value={coverage.files_scanned.toLocaleString()} />
                  <Fact label="Could not be analysed" value={coverage.error_count ?? 0}
                        tone={coverage.error_count ? "var(--high)" : undefined} />
                  <Fact label="Dependency manifests"
                        value={scan?.coverage?.trivy?.manifest_count ?? 0} />
                  <Fact label="Entry points mapped"
                        value={scan?.surface?.entry_points?.length ?? "—"} />
                </div>
              ) : (
                <div className="note">
                  {scanMatches ? "Coverage not recorded for this run." : `Loading ${scope}…`}
                </div>
              )}
            </Panel>

            <Panel title="Recent scans"
                   action={<span className="note" style={{ fontSize: 12 }}>cost per run</span>}>
              {scopedRuns.length === 0 ? (
                <Empty>No runs yet.</Empty>
              ) : (
                <div className="rows">
                  {scopedRuns.slice(0, 6).map((r) => (
                    <button key={r.run_name} onClick={() => onOpenRun(r.run_name)}
                            aria-current={scan?.id === r.run_name ? "true" : undefined}
                            style={scan?.id === r.run_name ? { background: "var(--wash)" } : undefined}>
                      <span className="note" style={{ flex: 1, minWidth: 0, fontSize: 12.5,
                                                      color: r.running ? "var(--ok)" : "var(--ink-2)" }}>
                        {r.running ? "running" : r.failed ? "failed" : shortDate(r.generated_at)}
                      </span>
                      <span className="num" style={{ flex: "none", fontSize: 13,
                                                     color: "var(--ink)", minWidth: 28,
                                                     textAlign: "right" }}>
                        {r.finding_count}
                      </span>
                      <span className="mono" style={{ flex: "none", fontSize: 12,
                                                      color: "var(--ink-3)", minWidth: 46,
                                                      textAlign: "right" }}>
                        ${(r.cost_usd ?? 0).toFixed(2)}
                      </span>
                    </button>
                  ))}
                </div>
              )}
              <div className="note">Only the AI phases spend: triage and recon.</div>
            </Panel>
          </div>
        </>
      )}
    </>
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
