import type { Severity } from "../types";
import { SEVERITIES } from "../types";

const COLOR: Record<Severity, string> = {
  critical: "var(--crit)",
  high: "var(--high)",
  medium: "var(--med)",
  low: "var(--low)",
  info: "var(--info)",
};

/** Wireframe 2b's conic-gradient donut. Renders an explicit empty ring at zero rather
 *  than a misleading full circle of one colour. */
export function SeverityDonut({ counts }: { counts: Partial<Record<Severity, number>> }) {
  const present = SEVERITIES.map((s) => [s, counts[s] ?? 0] as const).filter(([, n]) => n > 0);
  const total = present.reduce((sum, [, n]) => sum + n, 0);

  let cursor = 0;
  const stops = present.map(([sev, n]) => {
    const start = (cursor / total) * 100;
    cursor += n;
    return `${COLOR[sev]} ${start}% ${(cursor / total) * 100}%`;
  });

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 9, alignItems: "center" }}>
      <div
        style={{
          width: 118,
          height: 118,
          borderRadius: "50%",
          background: total ? `conic-gradient(${stops.join(",")})` : "transparent",
          border: total ? "none" : "2px dashed var(--line)",
          display: "grid",
          placeItems: "center",
        }}
      >
        <div
          style={{
            width: 72,
            height: 72,
            borderRadius: "50%",
            background: "var(--card)",
            display: "grid",
            placeItems: "center",
            font: "600 18px var(--sans)",
            fontVariantNumeric: "tabular-nums",
          }}
        >
          {total}
        </div>
      </div>
      <div className="mono" style={{ fontSize: 10.5, color: "var(--ink-2)", textAlign: "center" }}>
        {total === 0
          ? "no findings"
          : present.map(([sev, n]) => `${sev} ${n}`).join(" · ")}
      </div>
    </div>
  );
}

/** Findings-per-run trend. One bar per run, newest last, latest emphasised. */
export function TrendBars({ values }: { values: number[] }) {
  if (values.length < 2) {
    return <div className="note">Needs at least two runs to show a trend.</div>;
  }
  const max = Math.max(...values, 1);
  return (
    <div style={{ display: "flex", alignItems: "flex-end", gap: 5, height: 64 }}>
      {values.map((v, i) => (
        <div
          key={i}
          title={`${v} finding(s)`}
          style={{
            flex: 1,
            minWidth: 4,
            height: `${Math.max((v / max) * 100, 3)}%`,
            background: i === values.length - 1 ? "var(--ink)" : "rgba(255,255,255,.255)",
            borderRadius: 1,
          }}
        />
      ))}
    </div>
  );
}
