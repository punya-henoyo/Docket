import { useMemo } from "react";
import type { Finding, ScanState, Severity } from "../types";
import { SCANNERS } from "../types";

/* Wireframe 2b's radar, wired to real scan state rather than decoration.
 *
 *   ring     = a scanner stage (innermost fetch -> outermost nuclei), lit as it runs
 *   sweep    = only animates while a scan is actually in flight
 *   blip     = one real finding; radius encodes severity, angle is derived from the
 *              finding's own id so a given finding always lands in the same spot
 *              instead of jittering on every poll
 *
 * Nothing here is generated when no scan has run: the caller renders an idle state. */

const SIZE = 270;
const CENTRE = SIZE / 2;
const CORE = 23;
const MAX_R = CENTRE - 12;

/** Severity -> distance from the core. Critical sits closest: the eye goes to the
 *  middle first, and "near the core" reads as "deep in your system". */
const SEVERITY_RADIUS: Record<Severity, number> = {
  critical: 0.3,
  high: 0.48,
  medium: 0.65,
  low: 0.8,
  info: 0.92,
};

const SEVERITY_COLOR: Record<Severity, string> = {
  critical: "var(--crit)",
  high: "var(--high)",
  medium: "var(--med)",
  low: "var(--low)",
  info: "var(--info)",
};

/** Stable angle from an id. Deterministic so blips never move between polls. */
function angleFor(seed: string): number {
  let hash = 0;
  for (let i = 0; i < seed.length; i++) hash = (hash * 31 + seed.charCodeAt(i)) >>> 0;
  return (hash % 3600) / 10;
}

interface Blip {
  finding: Finding;
  x: number;
  y: number;
  colour: string;
  isNew: boolean;
}

export function Radar({
  scan,
  onSelect,
  newestId,
}: {
  scan: ScanState | null;
  onSelect: (finding: Finding) => void;
  newestId?: string;
}) {
  const running = scan?.status === "fetching" || scan?.status === "scanning" || scan?.status === "queued";

  const blips = useMemo<Blip[]>(() => {
    if (!scan) return [];
    return scan.findings.map((finding) => {
      const angle = (angleFor(finding.id || finding.rule_id) * Math.PI) / 180;
      const radius = CORE + SEVERITY_RADIUS[finding.severity] * (MAX_R - CORE);
      return {
        finding,
        x: CENTRE + Math.cos(angle) * radius,
        y: CENTRE + Math.sin(angle) * radius,
        colour: SEVERITY_COLOR[finding.severity],
        isNew: finding.id === newestId,
      };
    });
  }, [scan, newestId]);

  const ringState = (index: number) => scan?.stages?.[SCANNERS[index]] ?? "pending";

  return (
    <div
      style={{ position: "relative", width: SIZE, height: SIZE, margin: "0 auto" }}
      role="img"
      aria-label={
        scan
          ? `Radar: ${scan.finding_count} findings on ${scan.repo}, status ${scan.status}`
          : "Radar: no scan running"
      }
    >
      {/* rings — one per scanner stage */}
      {SCANNERS.map((scanner, i) => {
        const state = ringState(i);
        const r = CORE + ((i + 1) / SCANNERS.length) * (MAX_R - CORE);
        const lit = state === "done" || state === "running";
        return (
          <div
            key={scanner}
            style={{
              position: "absolute",
              left: CENTRE - r,
              top: CENTRE - r,
              width: r * 2,
              height: r * 2,
              borderRadius: "50%",
              border: `1px ${state === "skipped" ? "dashed" : "solid"} ${
                lit ? "rgba(255,255,255,.34)" : "rgba(255,255,255,.12)"
              }`,
              transition: "border-color .4s ease",
              pointerEvents: "none",
            }}
          />
        );
      })}

      {/* outer bezel */}
      <div
        style={{
          position: "absolute",
          inset: 0,
          borderRadius: "50%",
          border: "2px solid var(--line-2)",
          pointerEvents: "none",
        }}
      />

      {/* crosshairs */}
      <div style={{ position: "absolute", left: "50%", top: 0, bottom: 0, width: 1, background: "var(--line)" }} />
      <div style={{ position: "absolute", top: "50%", left: 0, right: 0, height: 1, background: "var(--line)" }} />

      {/* sweep — present only while something is genuinely running */}
      {running && (
        <div
          style={{
            position: "absolute",
            inset: 0,
            borderRadius: "50%",
            background: `conic-gradient(from 0deg, var(--sweep), rgba(0,0,0,0) 70deg)`,
            animation: "sweep 5s linear infinite",
            pointerEvents: "none",
          }}
        />
      )}

      {/* core */}
      <div
        style={{
          position: "absolute",
          left: "50%",
          top: "50%",
          transform: "translate(-50%,-50%)",
          width: CORE * 2,
          height: CORE * 2,
          border: "2px solid rgba(255,255,255,.4)",
          borderRadius: "50%",
          display: "grid",
          placeItems: "center",
          font: "10px var(--mono)",
          color: "var(--ink-3)",
          textAlign: "center",
          pointerEvents: "none",
        }}
      >
        {scan ? scan.finding_count : "idle"}
      </div>

      {/* blips */}
      {blips.map(({ finding, x, y, colour, isNew }, i) => (
        <button
          key={`${finding.id || finding.rule_id}-${i}`}
          onClick={() => onSelect(finding)}
          title={`${finding.severity.toUpperCase()} · ${finding.title}`}
          style={{
            position: "absolute",
            left: x - 7,
            top: y - 7,
            width: 14,
            height: 14,
            padding: 0,
            borderRadius: "50%",
            background: colour,
            border: "none",
            cursor: "pointer",
          }}
        >
          {isNew && (
            <span
              style={{
                position: "absolute",
                inset: -2,
                borderRadius: "50%",
                border: `2px solid ${colour}`,
                animation: "ping 2.2s ease-out infinite",
                pointerEvents: "none",
              }}
            />
          )}
        </button>
      ))}
    </div>
  );
}
