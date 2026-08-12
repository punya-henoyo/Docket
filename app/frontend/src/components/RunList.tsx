import type { RunSummary } from "../types";

export function RunList({
  runs, selected, onSelect,
}: { runs: RunSummary[]; selected: string | null; onSelect: (name: string) => void }) {
  if (runs.length === 0) return <div className="empty" style={{ padding: 12 }}>No runs yet.</div>;
  return (
    <div className="runs">
      {runs.map((run) => (
        <button className="run" key={run.run_name} aria-current={run.run_name === selected}
                onClick={() => onSelect(run.run_name)}>
          <span className="name">{run.run_name}</span>
          <span className="meta">
            <span className={`dot ${run.running ? "running" : run.failed ? "failed" : run.finished ? "completed" : ""}`}
                  aria-hidden="true" />
            {run.running ? "running" : run.failed ? "failed" : run.finished ? "done" : "incomplete"}
            {typeof run.finding_count === "number" && <> · {run.finding_count} found</>}
          </span>
        </button>
      ))}
    </div>
  );
}
