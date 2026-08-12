import { useMemo, useState } from "react";
import type { Finding, ScanState, Severity } from "../types";
import { SEVERITIES } from "../types";
import { FindingDetail, FindingsTable } from "../components/FindingsTable";
import { Empty, Panel } from "../components/ui";

export function Findings({
  findings,
  selected,
  onSelect,
  scan,
  onGoRepos,
}: {
  findings: Finding[];
  selected: Finding | null;
  onSelect: (f: Finding) => void;
  scan: ScanState | null;
  onGoRepos: () => void;
}) {
  const [filter, setFilter] = useState<Severity | "all">("all");

  const present = useMemo(
    () => SEVERITIES.filter((s) => findings.some((f) => f.severity === s)),
    [findings],
  );

  const shown = useMemo(
    () =>
      (filter === "all" ? findings : findings.filter((f) => f.severity === filter))
        .slice()
        .sort((a, b) => SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity)),
    [findings, filter],
  );

  const active = selected && shown.some((f) => f.id === selected.id) ? selected : shown[0] ?? null;

  return (
    <>
      <div className="page-head">
        <h1>Findings</h1>
        <div className="head-actions">
          <button
            className={filter === "all" ? "btn primary" : "btn"}
            onClick={() => setFilter("all")}
          >
            all {findings.length}
          </button>
          {present.map((s) => (
            <button
              key={s}
              className={filter === s ? "btn primary" : "btn"}
              onClick={() => setFilter(s)}
            >
              {s} {findings.filter((f) => f.severity === s).length}
            </button>
          ))}
        </div>
      </div>

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
