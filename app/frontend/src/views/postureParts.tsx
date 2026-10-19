import { useId, useMemo, useRef } from "react";
import * as api from "../api";
import type { Movement, PostureQuadrant, PosturePoint, QuadCell } from "../portfolio";
import { LEVELS } from "../hx/components";
import { hx } from "../hx/hx";
import { useApi } from "../hooks/useApi";

/** Pieces shared by the Posture home, the application page and the Applications table. The server
 *  decides every cell, note and movement; nothing here derives a position (AGENTS.md rules 10 and 14:
 *  candidates never move a dot, and there is no score or percentage). */

/** "5 Oct" from a date or timestamp. Date-only strings are UTC, so they are read as UTC. */
export const shortDate = (iso: string | null | undefined): string =>
  iso ? new Date(iso).toLocaleDateString("en-GB", { day: "numeric", month: "short", timeZone: "UTC" }) : "";

const AXIS_A: Record<Movement["assurance"], string> = {
  down: "Required checks slipping", up: "Required checks catching up", steady: "Required checks steady",
};
const AXIS_S: Record<Movement["standing"], string> = {
  down: "more problems proven", up: "fewer problems proven", steady: "proven problems steady",
};

/** Movement in words, one per axis and never summed. `new` has no earlier point to compare with, so
 *  it says since when the application has had a position (`firstSeen`, from its own trail). */
export function moveWords(moved: Movement | "new" | null | undefined, since?: string | null, firstSeen?: string | null): string {
  if (!moved) return "";
  if (moved === "new") return firstSeen ? `New since ${shortDate(firstSeen)}` : "New: first assessment";
  const when = since ? ` since ${shortDate(since)}` : "";
  if (moved.assurance === "steady" && moved.standing === "steady") return `Steady${when}`;
  return `${AXIS_A[moved.assurance]}, ${AXIS_S[moved.standing]}${when}`;
}

/** The date of an application's first position, taken from its own trail (null entries skipped). */
export const firstSeenOf = (p: PosturePoint | undefined): string | null =>
  p?.trail?.find((t) => t != null)?.at ?? null;

export const cellTitle = (quadrants: PostureQuadrant[] | undefined, cell: QuadCell | undefined): PostureQuadrant | undefined =>
  cell ? quadrants?.find((q) => q.key === cell) : undefined;

/** Keeps the previous object while the content is unchanged, so a quiet re-poll does not hand the kit
 *  elements new props (the map would otherwise redraw and drop its scrubber and filters). */
export function useStable<T>(value: T): T {
  const ref = useRef<{ json: string; value: T } | null>(null);
  const json = JSON.stringify(value);
  if (!ref.current || ref.current.json !== json) ref.current = { json, value };
  return ref.current.value;
}

/** Policy names by id, for places that only have the id (an unassessed application has no point). */
export function usePolicyNames(): Map<string, string> {
  const { data } = useApi(() => api.portfolio.getPolicies(), "policy-names");
  return useMemo(() => new Map((data?.policies ?? []).map((p) => [p.id, p.name])), [data]);
}

const TONE_FILL: Record<"bad" | "warn" | "ok" | "off", string> = {
  bad: "rgb(var(--h-sev-critical))", warn: "rgb(var(--h-sev-high))", ok: "rgb(var(--h-status-success))", off: "rgb(var(--h-hairline-2))",
};
const TIER_R: Record<string, number> = { "Tier 1": 7, "Tier 2": 6, "Tier 3": 5 };

/** The application's own two-by-two: its dot and its trail, nothing else. Roughly 220 by 180. */
export function MiniQuadrant({ point, quadrants }: { point: PosturePoint; quadrants?: PostureQuadrant[] }) {
  const uid = useId().replace(/:/g, "");
  const W = 220, H = 184, x0 = 30, y0 = 6, pw = 184, ph = 128;
  const X = (a: number) => x0 + (a / 100) * pw;
  const Y = (s: number) => y0 + ((100 - s) / 100) * ph;
  const trail = (point.trail ?? []).filter((t): t is NonNullable<typeof t> => t != null);
  // The newest trail entry is today's position; the dot itself stands for it.
  const last = trail[trail.length - 1];
  const lastIsToday = !!last && Math.abs(last.assurance - point.assurance) < 0.01 && Math.abs(last.standing - point.standing) < 0.01;
  const past = lastIsToday ? trail.slice(0, -1) : trail;
  const pts = [...past.map((t) => [X(t.assurance), Y(t.standing)]), [X(point.assurance), Y(point.standing)]];
  const r = TIER_R[point.tier] ?? 6;
  const fill = TONE_FILL[LEVELS[point.level].tone];
  const mx = x0 + pw / 2, my = y0 + ph / 2;
  const title = cellTitle(quadrants, point.cell)?.title ?? "";
  const label = `${point.label}: ${LEVELS[point.level].word}. ${title}. ${point.assurance_note ?? ""} ${point.standing_note ?? ""}`.trim();
  const rect = (cx: number, cy: number, cell: QuadCell) => (
    <rect x={cx} y={cy} width={pw / 2} height={ph / 2}
          fill={cell === "bl" ? "rgb(var(--h-status-warning-soft))" : "rgb(var(--h-surface-2))"} />
  );
  return (
    <svg className={hx("miniq")} viewBox={`0 0 ${W} ${H}`} width={W} height={H} role="img" aria-label={label}>
      <defs>
        <marker id={`${uid}-ar`} viewBox="0 0 8 8" refX="7" refY="4" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
          <path d="M0 0 8 4 0 8z" fill="rgb(var(--h-text-3))" />
        </marker>
      </defs>
      {rect(x0, y0, "tl")}{rect(mx, y0, "tr")}{rect(x0, my, "bl")}{rect(mx, my, "br")}
      <rect x={x0} y={y0} width={pw} height={ph} fill="none" stroke="rgb(var(--h-hairline-2))" />
      <path d={`M${mx} ${y0}V${y0 + ph}M${x0} ${my}H${x0 + pw}`} stroke="rgb(var(--h-hairline-2))" strokeDasharray="3 3" />
      {pts.length > 1 ? (
        <polyline points={pts.map(([x, y]) => `${x.toFixed(1)},${y.toFixed(1)}`).join(" ")} fill="none"
                  stroke="rgb(var(--h-text-3))" strokeWidth="1.2" markerEnd={`url(#${uid}-ar)`} />
      ) : null}
      {past.map((t) => (
        <circle key={t.at} cx={X(t.assurance)} cy={Y(t.standing)} r="2.6" fill="rgb(var(--h-surface))" stroke="rgb(var(--h-text-3))" strokeWidth="1.2" />
      ))}
      <circle cx={X(point.assurance)} cy={Y(point.standing)} r={r} fill={fill} stroke="rgb(var(--h-surface))" strokeWidth="2" />
      <g fontSize="9.5" fill="rgb(var(--h-text-2))" fontFamily="Inter, sans-serif">
        <text x={x0} y={y0 + ph + 13}>Overdue</text>
        <text x={x0 + pw} y={y0 + ph + 13} textAnchor="end">Current</text>
        <text x={mx} y={y0 + ph + 27} textAnchor="middle" fontWeight="600">Required checks</text>
        <text transform={`translate(10 ${my}) rotate(-90)`} textAnchor="middle" fontWeight="600">Proven problems</text>
        <text transform={`translate(22 ${y0 + ph - 2}) rotate(-90)`} textAnchor="start">Some</text>
        <text transform={`translate(22 ${y0 + 2}) rotate(-90)`} textAnchor="end">None</text>
      </g>
    </svg>
  );
}
