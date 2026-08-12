import type { RunPayload } from "../types";
import { SEVERITIES } from "../types";

/** Findings per severity are small integers against a known set, so the right form is
 *  a stat-tile row, not a chart. Cost is one measure against a ceiling, so a meter. */
export function StatBar({ run, budget }: { run: RunPayload; budget: number }) {
  const counts = run.severity_counts ?? {};
  const usage = (run.usage ?? {}) as { total_tokens?: number };
  const spent = run.cost_usd ?? 0;
  const pct = budget > 0 ? Math.min(100, (spent / budget) * 100) : 0;
  const level = pct >= 100 ? "over" : pct >= 75 ? "warn" : "";

  return (
    <div className="stats">
      {SEVERITIES.map((severity) => {
        const value = counts[severity] ?? 0;
        return (
          <div className="stat" key={severity}>
            <div className="k">
              <span className={`sev ${severity}`} aria-hidden="true">
                <span className="glyph">{"●"}</span>
              </span>
              {severity}
            </div>
            <div className={`v${value === 0 ? " zero" : ""}`}>{value}</div>
          </div>
        );
      })}
      <div className="stat">
        <div className="k">agents</div>
        <div className={`v${run.agents.length === 0 ? " zero" : ""}`}>{run.agents.length}</div>
      </div>
      <div className="stat">
        <div className="k">tokens</div>
        <div className={`v${usage.total_tokens ? "" : " zero"}`}>
          {(usage.total_tokens ?? 0).toLocaleString()}
        </div>
      </div>
      <div className="stat">
        <div className="k">cost</div>
        <div className={`v${spent === 0 ? " zero" : ""}`}>${spent.toFixed(3)}</div>
        <div className={`meter ${level}`} role="meter" aria-valuenow={spent} aria-valuemax={budget}
             aria-label={`spend against $${budget} budget`}>
          <i style={{ width: `${pct}%` }} />
        </div>
      </div>
    </div>
  );
}
