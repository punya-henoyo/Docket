import type { Finding, ScanState, Severity, Verdict } from "../types";
import { SCANNER_LABEL, SCANNERS } from "../types";
import { Radar } from "../components/Radar";
import { TriagePanel } from "../components/TriagePanel";
import { CweBreakdown } from "../components/CweBreakdown";
import { Panel } from "../components/ui";
import { downloadUrl } from "../api";

const STATUS_LABEL: Record<string, string> = {
  queued: "queued", fetching: "downloading source", scanning: "scanning",
  done: "complete", error: "failed",
};

const SKIP_REASON: Record<string, string> = {
  nuclei: "needs a live URL",
  recon: "not requested",
  triage: "not requested",
  trivy: "needs source",
  semgrep: "needs source",
};

/** The operational view: what this run is doing right now, and what it cost.
 *
 *  Split out of the old single-column dashboard, which had grown to stack the radar,
 *  five stages, an attack-surface table, a triage funnel, a CWE breakdown and run
 *  history on top of each other. Live progress and executive summary answer different
 *  questions for different people; they do not belong on the same screen. */
export function Scan({
  scan, counts, scanError, onSelectFinding, newestId,
  cweFilter, onCweSelect, verdictFilter, onVerdictSelect, onGoRepos,
}: {
  scan: ScanState | null;
  counts: Partial<Record<Severity, number>>;
  scanError: string | null;
  onSelectFinding: (f: Finding) => void;
  newestId?: string;
  cweFilter: string | null;
  onCweSelect: (c: string | null) => void;
  verdictFilter: Verdict | null;
  onVerdictSelect: (v: Verdict | null) => void;
  onGoRepos: () => void;
}) {
  const running = !scan?.historical &&
    (scan?.status === "queued" || scan?.status === "fetching" || scan?.status === "scanning");
  const finished = scan && (scan.historical || scan.status === "done");

  return (
    <>
      <div className="page-head">
        <h1>{scan?.historical ? "Last run" : "Scan"}</h1>
        <div className="head-actions">
          {finished && (
            <>
              <a className="btn" href={downloadUrl(scan!.id, "md")} download>report .md</a>
              <a className="btn" href={downloadUrl(scan!.id, "json")} download>.json</a>
              <a className="btn" href={downloadUrl(scan!.id, "sarif")} download>.sarif</a>
            </>
          )}
          <button className="btn primary" onClick={onGoRepos}>+ New scan</button>
        </div>
      </div>

      {scanError && <div className="note bad">{scanError}</div>}

      <div className="split">
        <Panel
          title={<span className="mono" style={{ fontSize: 11, color: "var(--ink-3)" }}>
            {scan ? `${scan.repo}${scan.ref ? "@" + scan.ref : ""}` : "NO SCAN RUNNING"}
          </span>}
          action={<span className="mono" style={{ fontSize: 11,
            color: running ? "var(--ok)" : "var(--ink-3)" }}>
            {scan ? (running ? "● live" : STATUS_LABEL[scan.status]) : "idle"}
          </span>}
        >
          <Radar scan={scan} onSelect={onSelectFinding} newestId={newestId} />

          {!scan?.historical && (
            <div className="stages" style={{ borderTop: "1px dashed rgba(255,255,255,.2)",
                                             paddingTop: 9 }}>
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
              {scan.elapsed_sec != null ? ` in ${scan.elapsed_sec}s` : ""}. Click a blip to
              open it.
            </div>
          )}
          {!scan && (
            <div className="note">
              Rings are scanner stages, innermost first. Blips are real findings, placed by
              severity.
            </div>
          )}
        </Panel>

        <div className="stack">
          <TriagePanel scan={scan} findings={scan?.findings ?? []}
                       selectedVerdict={verdictFilter} onSelectVerdict={onVerdictSelect} />
          <Panel title="Weakness classes"
            action={cweFilter
              ? <button className="btn sm" onClick={() => onCweSelect(null)}>clear filter</button>
              : <span className="mono" style={{ fontSize: 11, color: "var(--ink-3)" }}>by CWE</span>}>
            <CweBreakdown findings={scan?.findings ?? []} selected={cweFilter}
                          onSelect={onCweSelect} />
          </Panel>
        </div>
      </div>
      <div style={{ display: "none" }}>{Object.keys(counts).length}</div>
    </>
  );
}
