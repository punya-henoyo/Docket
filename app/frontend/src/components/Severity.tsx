import type { Severity } from "../types";

// Icon + label, never colour alone: on the light surface `warning` and `serious`
// (medium/high) sit below 3:1 contrast by design, and a colourblind reader gets
// nothing from hue here either.
const GLYPH: Record<Severity, string> = {
  critical: "◆", // filled diamond
  high: "▲",     // triangle
  medium: "●",   // circle
  low: "▪",      // small square
  info: "◦",     // hollow bullet
};

export function SeverityTag({ severity }: { severity: Severity }) {
  const key = (severity ?? "info") as Severity;
  return (
    <span className={`sev ${key}`}>
      <span className="glyph" aria-hidden="true">{GLYPH[key] ?? GLYPH.info}</span>
      {key}
    </span>
  );
}
