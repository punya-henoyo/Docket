import { useMemo } from "react";
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

/** The security dashboard.
 *
 *  The headline number is REACHABLE findings, not raw finding count. A scanner's output
 *  volume says nothing about risk: 48 matches with 24 unreachable is a different morning
 *  than 48 matches all reachable, and only one of those numbers survives being read out
 *  in a meeting.
 *
 *  Every tile here is wired to something docket measured. Where a number is unknown the
 *  tile says so rather than rendering a zero, because on a security dashboard a
 *  confident zero is worse than a blank.
 *
 *  Laid out in three bands rather than four equal-weight trios. The previous version gave
 *  twelve panels the same visual claim, so "Fix these first" competed with "Cost per
 *  scan" and the auto-fix PRs — the product's whole pitch — sat last, below the fold.
 *    This morning     what to act on now
 *    Portfolio        where it lives
 *    Trend & coverage what to trust the numbers about
 *  Panels that only restated a number elsewhere on the page are gone: the triage funnel
 *  is now the hero KPI's own bar, and cost per scan is a column in the run list. */
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
      const key = repoOf(r);
      if (!m.has(key)) m.set(key, r); // runs arrive newest-first
    }
    return m;
  }, [runs]);

  const portfolio = useMemo(() => {
    const counts: Partial<Record<Severity, number>> = {};
    let total = 0;
    let reach = 0;
    let triagedRepos = 0; // repos whose latest run actually ran triage, so a portfolio
    for (const r of latestByRepo.values()) { // "0 reachable" reads as judged-none, not unknown
      total += r.finding_count;
      for (const s of SEVERITIES)
        counts[s] = (counts[s] ?? 0) + (r.severity_counts?.[s] ?? 0);
      if (r.reachable_count != null) {
        reach += r.reachable_count;
        triagedRepos += 1;
      }
    }
    return { counts, total, reachable: reach, triagedRepos, repos: latestByRepo.size };
  }, [latestByRepo]);

  // One row per repository, worst first. Carries reachable_count now: the estate view
  // could not previously be read against the metric the page leads with.
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
  const lastScan = shortDate(runs[0]?.generated_at);

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
  const triageSplit = [
    [reachable.length, "var(--crit)", "reachable"],
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

  return (
    <>
      <div className="page-head">
        <div style={{ display: "flex", alignItems: "baseline", gap: 12, flexWrap: "wrap" }}>
          <h1>Security dashboard</h1>
          <span className="note" style={{ fontSize: 13 }}>
            {portfolio.repos} {portfolio.repos === 1 ? "repository" : "repositories"}
            {lastScan ? ` · last scan ${lastScan}` : ""}
          </span>
        </div>
        <div className="head-actions">
          <button className="btn primary" onClick={onGoRepos}>New scan</button>
        </div>
      </div>

      {/* ══ band 1: what to act on now ═══════════════════════════════════════════ */}
      <div className="band">
        <h2>This morning</h2>
        <span className="rule" />
      </div>

      <div className="kpis lead">
        {/* The triage funnel lives inside the headline rather than in its own panel:
            it was answering the same question the number above it already asked. */}
        <div className="kpi-hero">
          <div className="eyebrow" style={{ display: "flex", alignItems: "center", gap: 7 }}>
            Reachable
            <span className="legend"><span className="dot" style={{ background: "var(--crit)" }} /></span>
          </div>
          <div className="v" style={{ color: portfolio.triagedRepos ? "var(--crit)" : "var(--ink-3)" }}>
            {portfolio.triagedRepos ? portfolio.reachable : "—"}
          </div>
          <div className="sub">
            {portfolio.triagedRepos
              ? `of ${portfolio.total} findings · judged by reading source`
              : "no run has been triaged — treat the counts below as unjudged"}
          </div>
          {triaged.length > 0 && (
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
          <div className="v">{portfolio.total}</div>
          <div className="foot" style={portfolio.counts.critical ? { color: "var(--crit)" } : undefined}>
            {portfolio.counts.critical ? `${portfolio.counts.critical} critical` : "across all repos"}
          </div>
        </div>

        <div>
          <div className="eyebrow">Critical + High</div>
          <div className="v" style={{ color: "var(--high)" }}>
            {(portfolio.counts.critical ?? 0) + (portfolio.counts.high ?? 0)}
          </div>
          <div className="foot">need attention</div>
        </div>

        <div>
          <div className="eyebrow">Auto-fix PRs</div>
          <div className="v" style={fixPrs.length ? { color: "var(--ok)" } : undefined}>
            {fixPrs.length}
          </div>
          <div className="foot">
            {fixPrs.length ? "opened & verified" : watch?.autofix ? "none yet" : "autofix off"}
          </div>
        </div>
      </div>

      <div className="meta-strip">
        <span><span className="n">{runs.length}</span> scans all time</span>
        <span className="sep" />
        <span>AI spend <span className="n mono">${spend.toFixed(2)}</span></span>
        <span className="sep" />
        <span>
          {portfolio.triagedRepos} of {portfolio.repos} repos triaged
        </span>
        {watch?.enabled && (
          <>
            <span className="sep" />
            <span>PR watch on{watch.autofix ? " · autofix on" : ""}</span>
          </>
        )}
      </div>

      <div className="split" style={{ gridTemplateColumns: "1.7fr 1fr" }}>
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
          {!reachable.length && triaged.length > 0 && (
            <div className="note">
              Nothing was judged reachable, so this is ordered by scanner severity.
            </div>
          )}
        </Panel>

        {/* Promoted out of the third trio. A tool that opens verified fixes should not
            report that fact below the fold. */}
        <Panel
          title="Fixes shipped"
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
            <>
              <div className="rows">
                {fixPrs.slice(0, 4).map((r) => (
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
      </div>

      {/* ══ band 2: where it lives ═══════════════════════════════════════════════ */}
      <div className="band">
        <h2>Portfolio</h2>
        <span className="rule" />
        <span className="aside">latest scan of each repository</span>
      </div>

      <div className="split" style={{ gridTemplateColumns: "1.7fr 1fr" }}>
        <Panel
          title="Repositories"
          action={<button className="btn ghost" onClick={onGoRepos}>All repositories →</button>}
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
                <button key={a.repo} onClick={() => onOpenRun(a.run)}
                        title={`Open the latest scan of ${a.repo}`}>
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
            Reachable leads the sort — a repo with 40 unreachable findings is not the one
            to open first.
          </div>
        </Panel>

        <Panel title="Severity mix"
               action={<span className="note" style={{ fontSize: 12 }}>all repos</span>}>
          <div style={{ padding: "10px 0 4px" }}>
            <SeverityDonut counts={portfolio.counts} />
          </div>
          <div className="note">Scanner severity, before triage. The judged number is above.</div>
        </Panel>
      </div>

      {/* ══ band 3: what to trust the numbers about ══════════════════════════════ */}
      <div className="band">
        <h2>Trend &amp; coverage</h2>
        <span className="rule" />
        <span className="aside">
          {runs.length} run{runs.length === 1 ? "" : "s"} · ${spend.toFixed(2)} all time
        </span>
      </div>

      <div className="trio">
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

        {/* Coverage stays on the executive page on purpose: "0 findings" and "nothing
            was analysed" are the same number, and only one is good news. */}
        <Panel title="What was examined"
               action={<span className="chip" title="latest scan">{repoLabel || "this run"}</span>}>
          {coverage?.files_scanned != null ? (
            <>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr",
                            gap: "14px 20px" }}>
                <Fact label="Files analysed" value={coverage.files_scanned.toLocaleString()} />
                <Fact label="Could not be analysed" value={coverage.error_count ?? 0}
                      tone={coverage.error_count ? "var(--high)" : undefined} />
                <Fact label="Dependency manifests"
                      value={scan?.coverage?.trivy?.manifest_count ?? 0} />
                <Fact label="Entry points mapped"
                      value={scan?.surface?.entry_points?.length ?? "—"} />
              </div>
              {coverage.rules_fired?.length ? (
                <div className="mono" style={{ fontSize: 12.5, color: "var(--ink-2)",
                                               border: "1px solid var(--line)",
                                               borderRadius: "var(--r-sm)",
                                               padding: "8px 11px" }}>
                  {coverage.rules_fired.join(" · ")}
                </div>
              ) : null}
            </>
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

        {/* Cost per scan folded in here as a column. Eleven near-identical values did
            not earn their own area chart, and cost is only ever read per run anyway. */}
        <Panel title="Recent scans"
               action={<span className="note" style={{ fontSize: 12 }}>cost per run</span>}>
          {runs.length === 0 ? (
            <Empty>No runs yet.</Empty>
          ) : (
            <div className="rows">
              {runs.slice(0, 6).map((r) => (
                <button key={r.run_name} onClick={() => onOpenRun(r.run_name)}
                        aria-current={scan?.id === r.run_name ? "true" : undefined}
                        style={scan?.id === r.run_name ? { background: "var(--wash)" } : undefined}>
                  <span className="clip" style={{ flex: 1, minWidth: 0, fontSize: 13.5 }}>
                    {repoOf(r)}
                  </span>
                  <span className="note" style={{ fontSize: 11.5, flex: "none",
                                                  color: r.running ? "var(--ok)" : undefined }}>
                    {r.running ? "running" : r.failed ? "failed" : shortDate(r.generated_at)}
                  </span>
                  <span className="mono" style={{ flex: "none", fontSize: 12,
                                                  color: "var(--ink-2)", minWidth: 46,
                                                  textAlign: "right" }}>
                    ${(r.cost_usd ?? 0).toFixed(2)}
                  </span>
                </button>
              ))}
            </div>
          )}
          <div className="note">
            Only the AI phases spend: triage and recon. A scanner-only run reads $0.00.
          </div>
        </Panel>
      </div>
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
