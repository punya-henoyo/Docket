import type { Severity } from "../types";
import { SEVERITIES } from "../types";

const COLOR: Record<Severity, string> = {
  critical: "var(--crit)",
  high: "var(--high)",
  medium: "var(--med)",
  low: "var(--low)",
  info: "var(--info)",
};

/** Severity ring with the total in the middle and a legend beneath.
 *
 *  Renders an explicit empty ring at zero rather than a full circle of one colour —
 *  a solid green donut for "nothing found" is indistinguishable from a solid green
 *  donut for "all low severity", and only one of those is good news. */
export function SeverityDonut({
  counts,
  size = 150,
}: {
  counts: Partial<Record<Severity, number>>;
  size?: number;
}) {
  const present = SEVERITIES.map((s) => [s, counts[s] ?? 0] as const).filter(([, n]) => n > 0);
  const total = present.reduce((sum, [, n]) => sum + n, 0);

  let cursor = 0;
  const stops = present.map(([sev, n]) => {
    const start = (cursor / total) * 100;
    cursor += n;
    return `${COLOR[sev]} ${start}% ${(cursor / total) * 100}%`;
  });

  const hole = Math.round(size * 0.64);

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16, alignItems: "center" }}>
      <div
        role="img"
        aria-label={total ? present.map(([s, n]) => `${n} ${s}`).join(", ") : "no findings"}
        style={{
          width: size,
          height: size,
          borderRadius: "50%",
          background: total ? `conic-gradient(${stops.join(",")})` : "transparent",
          border: total ? "none" : "2px dashed var(--line-2)",
          display: "grid",
          placeItems: "center",
        }}
      >
        <div
          style={{
            width: hole,
            height: hole,
            borderRadius: "50%",
            background: "var(--card)",
            display: "grid",
            placeItems: "center",
            alignContent: "center",
            gap: 1,
          }}
        >
          <div style={{ font: "500 12px var(--sans)", color: "var(--ink-3)" }}>Total</div>
          <div className="num" style={{ font: "600 26px/1 var(--sans)" }}>{total}</div>
        </div>
      </div>

      <div style={{ display: "flex", flexWrap: "wrap", gap: "6px 14px", justifyContent: "center" }}>
        {total === 0 ? (
          <span className="note">No findings reported.</span>
        ) : (
          present.map(([sev, n]) => (
            <span key={sev} style={{ display: "inline-flex", alignItems: "center", gap: 6,
                                     font: "500 12.5px var(--sans)", color: "var(--ink-2)" }}>
              <span style={{ width: 8, height: 8, borderRadius: "50%", background: COLOR[sev] }} />
              {sev} <span className="num" style={{ color: "var(--ink)" }}>{n}</span>
            </span>
          ))
        )}
      </div>
    </div>
  );
}

/** Smooth area chart with a gradient fill and an emphasised final point.
 *
 *  Deliberately not a library: one polyline and one polygon is the whole thing, and a
 *  charting dependency would be more code than this file. */
export function AreaChart({
  values,
  labels,
  colour = "var(--ok)",
  height = 132,
  format = (v: number) => String(v),
}: {
  values: number[];
  labels?: string[];
  colour?: string;
  height?: number;
  format?: (v: number) => string;
}) {
  if (values.length < 2) {
    return <div className="note">Needs at least two runs to plot a trend.</div>;
  }

  const W = 100;
  const H = 40;
  const max = Math.max(...values, 1);
  const pt = (v: number, i: number) => {
    const x = (i / (values.length - 1)) * W;
    const y = H - (v / max) * (H - 3) - 1.5;
    return [x, y] as const;
  };
  const pts = values.map(pt);
  const line = pts.map(([x, y]) => `${x.toFixed(2)},${y.toFixed(2)}`).join(" ");
  const area = `0,${H} ${line} ${W},${H}`;
  const id = `g${colour.replace(/[^a-z0-9]/gi, "")}`;
  const [lx, ly] = pts[pts.length - 1];

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
      <div style={{ display: "flex", gap: 10 }}>
        {/* Axis outside the SVG so the labels stay at readable size while the plot
            stretches to whatever width the card happens to be. */}
        <div style={{ display: "flex", flexDirection: "column", justifyContent: "space-between",
                      font: "11px var(--sans)", color: "var(--ink-3)", height,
                      textAlign: "right", flex: "none" }}>
          <span>{format(max)}</span>
          <span>{format(max / 2)}</span>
          <span>0</span>
        </div>
        <svg viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none"
             style={{ width: "100%", height, overflow: "visible" }}>
          <defs>
            <linearGradient id={id} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={colour} stopOpacity="0.32" />
              <stop offset="100%" stopColor={colour} stopOpacity="0" />
            </linearGradient>
          </defs>
          {[0.25, 0.5, 0.75].map((f) => (
            <line key={f} x1="0" x2={W} y1={H * f} y2={H * f}
                  stroke="var(--line)" strokeWidth="0.3" vectorEffect="non-scaling-stroke" />
          ))}
          <polygon points={area} fill={`url(#${id})`} />
          <polyline points={line} fill="none" stroke={colour} strokeWidth="2"
                    strokeLinejoin="round" strokeLinecap="round"
                    vectorEffect="non-scaling-stroke" />
          <circle cx={lx} cy={ly} r="3" fill={colour} stroke="var(--card)" strokeWidth="1.5"
                  vectorEffect="non-scaling-stroke" />
        </svg>
      </div>
      {labels && (
        <div style={{ display: "flex", justifyContent: "space-between",
                      font: "11px var(--sans)", color: "var(--ink-3)", paddingLeft: 34 }}>
          <span>{labels[0]}</span>
          <span>{labels[labels.length - 1]}</span>
        </div>
      )}
    </div>
  );
}

/** Severity stacked over time, one column per run.
 *
 *  Columns rather than a stacked area on purpose: runs are discrete events at irregular
 *  intervals, and an area chart would draw a continuous line implying the count was
 *  measured between them, when nothing was scanned at all. */
export function StackedRuns({
  runs,
  height = 132,
}: {
  runs: { counts: Partial<Record<Severity, number>>; label: string; total: number }[];
  height?: number;
}) {
  if (runs.length < 2) {
    return <div className="note">Needs at least two runs to plot a trend.</div>;
  }
  const max = Math.max(...runs.map((r) => r.total), 1);

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
      <div style={{ display: "flex", gap: 10 }}>
        <div style={{ display: "flex", flexDirection: "column", justifyContent: "space-between",
                      font: "11px var(--sans)", color: "var(--ink-3)", height,
                      textAlign: "right", flex: "none" }}>
          <span>{max}</span>
          <span>{Math.round(max / 2)}</span>
          <span>0</span>
        </div>
        <div style={{ display: "flex", alignItems: "flex-end", gap: 6, height, flex: 1,
                      borderBottom: "1px solid var(--line)" }}>
          {runs.map((r, i) => (
            <div key={i} title={`${r.label}: ${r.total} finding(s)`}
                 style={{ flex: 1, minWidth: 6, height: `${(r.total / max) * 100}%`,
                          display: "flex", flexDirection: "column-reverse",
                          borderRadius: "3px 3px 0 0", overflow: "hidden" }}>
              {SEVERITIES.filter((s) => r.counts[s]).map((s) => (
                <div key={s} style={{ flex: r.counts[s], background: COLOR[s] }} />
              ))}
            </div>
          ))}
        </div>
      </div>
      <div style={{ display: "flex", justifyContent: "space-between",
                    font: "11px var(--sans)", color: "var(--ink-3)", paddingLeft: 34 }}>
        <span>{runs[0].label}</span>
        <span>{runs[runs.length - 1].label}</span>
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
            background: i === values.length - 1 ? "var(--ok)" : "var(--line-2)",
            borderRadius: 2,
          }}
        />
      ))}
    </div>
  );
}
