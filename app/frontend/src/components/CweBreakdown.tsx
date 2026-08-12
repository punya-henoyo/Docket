import { useMemo } from "react";
import type { Finding, Severity } from "../types";
import { SEVERITIES } from "../types";
import { cweLabel, cweUrl } from "../cwe";
import { Empty } from "./ui";

const COLOR: Record<Severity, string> = {
  critical: "var(--crit)",
  high: "var(--high)",
  medium: "var(--med)",
  low: "var(--low)",
  info: "var(--info)",
};

interface Group {
  id: string;
  count: number;
  worst: Severity;
  bySeverity: Partial<Record<Severity, number>>;
}

/** Findings grouped by weakness class rather than by file.
 *
 *  This is the view that changes what you do next: twenty separate SQL-injection hits
 *  across a codebase are one habit to fix, not twenty tickets. The per-file table
 *  cannot show that, because the thing they share is the CWE. */
export function CweBreakdown({
  findings,
  selected,
  onSelect,
}: {
  findings: Finding[];
  selected: string | null;
  onSelect: (cwe: string | null) => void;
}) {
  const groups = useMemo<Group[]>(() => {
    const acc = new Map<string, Group>();
    for (const f of findings) {
      if (!f.cwe) continue;
      const g = acc.get(f.cwe) ?? { id: f.cwe, count: 0, worst: "info", bySeverity: {} };
      g.count += 1;
      g.bySeverity[f.severity] = (g.bySeverity[f.severity] ?? 0) + 1;
      if (SEVERITIES.indexOf(f.severity) < SEVERITIES.indexOf(g.worst)) g.worst = f.severity;
      acc.set(f.cwe, g);
    }
    return [...acc.values()].sort(
      (a, b) =>
        SEVERITIES.indexOf(a.worst) - SEVERITIES.indexOf(b.worst) || b.count - a.count,
    );
  }, [findings]);

  const untagged = findings.filter((f) => !f.cwe).length;
  const max = Math.max(...groups.map((g) => g.count), 1);

  if (groups.length === 0) {
    return <Empty>No findings carry a CWE yet.</Empty>;
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 7 }}>
      {groups.map((g) => {
        const active = selected === g.id;
        return (
          <div key={g.id} style={{ display: "flex", alignItems: "center", gap: 9 }}>
            <button
              onClick={() => onSelect(active ? null : g.id)}
              aria-pressed={active}
              title={active ? "Show all findings" : `Show only ${g.id}`}
              style={{
                flex: 1,
                minWidth: 0,
                textAlign: "left",
                background: active ? "var(--wash)" : "none",
                border: 0,
                borderRadius: 4,
                padding: "5px 7px",
                cursor: "pointer",
                font: "11.5px var(--mono)",
                color: "var(--ink)",
              }}
            >
              <span style={{ display: "flex", justifyContent: "space-between", gap: 8 }}>
                <span
                  style={{
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                    whiteSpace: "nowrap",
                    color: active ? "var(--ink)" : "var(--ink-2)",
                  }}
                >
                  {cweLabel(g.id)}
                </span>
                <span style={{ color: "var(--ink-3)", fontVariantNumeric: "tabular-nums" }}>
                  {g.count}
                </span>
              </span>
              {/* Stacked by severity: one bar shows both how MANY and how BAD, which
                  a count alone hides — 14 lows and 14 criticals look identical. */}
              <span
                style={{
                  display: "flex",
                  height: 6,
                  marginTop: 4,
                  borderRadius: 2,
                  overflow: "hidden",
                  background: "var(--wash)",
                  width: `${(g.count / max) * 100}%`,
                  minWidth: 8,
                }}
              >
                {SEVERITIES.filter((s) => g.bySeverity[s]).map((s) => (
                  <span
                    key={s}
                    style={{
                      flex: g.bySeverity[s],
                      background: COLOR[s],
                    }}
                  />
                ))}
              </span>
            </button>
            <a
              href={cweUrl(g.id)}
              target="_blank"
              rel="noreferrer noopener"
              title={`${g.id} on cwe.mitre.org`}
              style={{ font: "11px var(--mono)", color: "var(--ink-3)", textDecoration: "none" }}
            >
              ↗
            </a>
          </div>
        );
      })}
      {untagged > 0 && (
        <div className="note">{untagged} finding(s) carry no CWE and are not shown here.</div>
      )}
    </div>
  );
}
