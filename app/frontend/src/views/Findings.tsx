import { useMemo, useState } from "react";
import type { Finding, ScanState, Severity, Verdict } from "../types";
import { SEVERITIES } from "../types";
import { FindingDetail, FindingsTable } from "../components/FindingsTable";
import { Empty, Panel } from "../components/ui";
import { cweLabel } from "../cwe";

const SEV_COLOR: Record<Severity, string> = {
  critical: "var(--crit)",
  high: "var(--high)",
  medium: "var(--med)",
  low: "var(--low)",
  info: "var(--info)",
};

const titleCase = (s: string) => s[0].toUpperCase() + s.slice(1);

/** Findings.
 *
 *  Severity is a segmented control, not a row of buttons: the active filter used to wear
 *  the primary-CTA fill, so a filter state looked like the page's main action. Selection
 *  here is a raised cell with a brand underline, which leaves exactly one filled button
 *  on any page.
 *
 *  Verdict and CWE filters share one bar with a single "showing n of m" and a single
 *  clear. Previously each rendered its own row, so two active filters printed the same
 *  count twice on two lines with two clears. */
export function Findings({
  findings,
  selected,
  onSelect,
  scan,
  onGoRepos,
  cweFilter,
  onCweSelect,
  verdictFilter,
  onVerdictSelect,
}: {
  findings: Finding[];
  selected: Finding | null;
  onSelect: (f: Finding) => void;
  scan: ScanState | null;
  onGoRepos: () => void;
  cweFilter: string | null;
  onCweSelect: (cwe: string | null) => void;
  verdictFilter: Verdict | null;
  onVerdictSelect: (v: Verdict | null) => void;
}) {
  const [filter, setFilter] = useState<Severity | "all">("all");

  const present = useMemo(
    () => SEVERITIES.filter((s) => findings.some((f) => f.severity === s)),
    [findings],
  );

  const bySeverity = useMemo(() => {
    const acc: Partial<Record<Severity, number>> = {};
    for (const f of findings) acc[f.severity] = (acc[f.severity] ?? 0) + 1;
    return acc;
  }, [findings]);

  const shown = useMemo(
    () =>
      findings
        .filter((f) => filter === "all" || f.severity === filter)
        .filter((f) => !cweFilter || f.cwe === cweFilter)
        .filter((f) => !verdictFilter || f.triage?.verdict === verdictFilter)
        .slice()
        .sort((a, b) => SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity)),
    [findings, filter, cweFilter, verdictFilter],
  );

  const active = selected && shown.some((f) => f.id === selected.id) ? selected : shown[0] ?? null;
  const filtered = shown.length !== findings.length;
  const repoLabel = (scan?.repo || "").replace(/^github:/, "");

  const clearAll = () => {
    setFilter("all");
    onCweSelect(null);
    onVerdictSelect(null);
  };

  return (
    <>
      <div className="page-head">
        <div style={{ display: "flex", alignItems: "baseline", gap: 12, flexWrap: "wrap" }}>
          <h1>Findings</h1>
          {repoLabel && (
            <span className="note" style={{ fontSize: 13 }}>
              {repoLabel}{scan?.ref ? ` @ ${scan.ref}` : ""}
            </span>
          )}
        </div>
        <div className="head-actions">
          <button className="btn primary" onClick={onGoRepos}>New scan</button>
        </div>
      </div>

      {findings.length > 0 && (
        <div className="segmented" role="group" aria-label="Filter by severity">
          <button aria-pressed={filter === "all"} onClick={() => setFilter("all")}>
            All <span className="n">{findings.length}</span>
          </button>
          {present.map((s) => (
            <button key={s} aria-pressed={filter === s} onClick={() => setFilter(s)}>
              <span className="dot" style={{ background: SEV_COLOR[s] }} />
              {titleCase(s)} <span className="n">{bySeverity[s]}</span>
            </button>
          ))}
        </div>
      )}

      {(filtered || verdictFilter || cweFilter) && (
        <div className="filterbar">
          <span className="count">
            Showing <span className="n">{shown.length}</span> of {findings.length}
          </span>
          {(verdictFilter || cweFilter) && <span className="sep" />}
          {verdictFilter && (
            <span className="chip dismiss">
              triage: {verdictFilter.replace("_", " ")}
              <button onClick={() => onVerdictSelect(null)}
                      aria-label="Clear triage filter">×</button>
            </span>
          )}
          {cweFilter && (
            <span className="chip dismiss">
              {cweLabel(cweFilter)}
              <button onClick={() => onCweSelect(null)}
                      aria-label="Clear CWE filter">×</button>
            </span>
          )}
          <button className="clear" onClick={clearAll}>Clear all</button>
        </div>
      )}

      {findings.length === 0 ? (
        <Panel>
          <Empty>
            <div>
              {scan?.status === "done"
                ? `No findings in ${scan.repo}.`
                : scan
                  ? "Scan in progress — findings appear here as each scanner finishes."
                  : "No scan has run in this session."}
            </div>
            {!scan && (
              <button className="btn primary" onClick={onGoRepos}>
                Pick a repository
              </button>
            )}
          </Empty>
        </Panel>
      ) : shown.length === 0 ? (
        <Panel>
          <Empty>
            <div>No finding matches these filters.</div>
            <button className="btn" onClick={clearAll}>Clear all filters</button>
          </Empty>
        </Panel>
      ) : (
        <>
          <Panel>
            <FindingsTable findings={shown} selectedId={active?.id} onSelect={onSelect} />
          </Panel>
          {active && (
            <Panel>
              <FindingDetail finding={active} />
            </Panel>
          )}
        </>
      )}
    </>
  );
}
