import { useEffect, useRef } from "react";
import type { TranscriptLine } from "../types";

/** One row per tool call and per tool result. A result's `output` is the tool's raw
 *  repr and can be kilobytes, so it is clipped here — the full text lives in the run's
 *  artifacts/output/ directory, which is the point of spooling it. */
const CLIP = 150;

function summarize(line: TranscriptLine): string {
  const tool = line.tool ?? "?";
  if (line.kind === "result") {
    const out = (line.output ?? "").replace(/\s+/g, " ").trim();
    return `← ${tool}  ${out.length > CLIP ? `${out.slice(0, CLIP)}…` : out}`;
  }
  const args = Object.entries(line.args ?? {})
    .map(([k, v]) => `${k}=${String(v).slice(0, 40)}`)
    .join(" ");
  return `→ ${tool}${args ? `  ${args}` : ""}`;
}

export function Activity({ lines }: { lines: TranscriptLine[] }) {
  const ref = useRef<HTMLDivElement>(null);
  // Follow the tail while a scan streams; otherwise the newest line is off-screen
  // exactly when someone is watching it happen.
  useEffect(() => {
    const node = ref.current;
    if (node) node.scrollTop = node.scrollHeight;
  }, [lines.length]);

  if (lines.length === 0) return <div className="empty">Nothing yet.</div>;
  return (
    <div className="log" ref={ref}>
      {lines.map((line, index) => (
        <div className="line" key={index}>
          <span className="who">{line.role ?? line.agent_id ?? "—"}</span>
          <span>{summarize(line)}</span>
        </div>
      ))}
    </div>
  );
}
