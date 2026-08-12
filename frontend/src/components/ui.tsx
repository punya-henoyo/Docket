import type { ReactNode } from "react";
import type { Cvss, Finding, Severity } from "../types";

export function Panel({
  title,
  action,
  children,
  dashed,
  style,
}: {
  title?: ReactNode;
  action?: ReactNode;
  children: ReactNode;
  dashed?: boolean;
  style?: React.CSSProperties;
}) {
  return (
    <section className={dashed ? "panel dashed" : "panel"} style={style}>
      {title && (
        <header>
          <span>{title}</span>
          {action}
        </header>
      )}
      <div className="body">{children}</div>
    </section>
  );
}

export const SevTag = ({ severity }: { severity: Severity }) => (
  <span className={`sev ${severity}`}>{severity.toUpperCase()}</span>
);

/** A rule_id is `semgrep/python.lang.security.audit.foo.foo` — show the leaf, which is
 *  the part a human actually reads, and keep the full id available on hover. */
export function ruleLeaf(ruleId: string): string {
  const afterScanner = ruleId.includes("/") ? ruleId.slice(ruleId.indexOf("/") + 1) : ruleId;
  const parts = afterScanner.split(".");
  return parts[parts.length - 1] || afterScanner;
}

export function findingLocation(finding: Finding): string {
  const { source_file, method, path, parameter } = finding.location;
  if (source_file) return source_file.replace(/^\/work\/source\//, "");
  return `${method} ${path}${parameter ? ` (${parameter})` : ""}`;
}

const VERDICT_STYLE: Record<string, { label: string; color: string }> = {
  // Colours are deliberately NOT the severity palette: a verdict answers a different
  // question ("can input get here?") and reusing severity colours would blur the two.
  exploitable: { label: "REACHABLE", color: "var(--crit)" },
  not_reachable: { label: "NOT REACHABLE", color: "var(--ok)" },
  uncertain: { label: "UNCERTAIN", color: "var(--ink-3)" },
};

export function VerdictTag({ verdict }: { verdict: string }) {
  const style = VERDICT_STYLE[verdict];
  if (!style) return null;
  return (
    <span
      className="chip"
      title="Judged by reading the source. Not an exploit: nothing was run."
      style={{ color: style.color, borderColor: style.color }}
    >
      {style.label}
    </span>
  );
}

/** CVSS band colours, from the v3.1 spec's qualitative severity ratings (section 5).
 *  Deliberately the same palette as scanner severity: two scales that disagree about
 *  the same finding should look comparable, so the disagreement is visible. */
function cvssTone(score: number): string {
  if (score >= 9) return "var(--crit)";
  if (score >= 7) return "var(--high)";
  if (score >= 4) return "var(--med)";
  return "var(--low)";
}

/** The published CVSS, attributed. Renders nothing when there is no score.
 *
 *  An absent score is left blank rather than shown as 0.0: in CVSS, 0.0 is an
 *  affirmative claim that a vulnerability has no impact, which is the opposite of
 *  "nobody scored this". */
export function CvssBadge({ cvss, size = "md" }: { cvss?: Cvss | null; size?: "sm" | "md" }) {
  if (!cvss) return null;
  const tone = cvssTone(cvss.score);
  return (
    <span
      title={`CVSS v${cvss.version} ${cvss.score.toFixed(1)} per ${cvss.source.toUpperCase()}`
             + (cvss.vector ? `\n${cvss.vector}` : "\nNo vector published.")
             + "\nRates the vulnerability class, not this codebase's exposure to it."}
      className="num"
      style={{
        font: `600 ${size === "sm" ? 11.5 : 12.5}px var(--sans)`,
        color: tone,
        background: "color-mix(in srgb, currentColor 12%, transparent)",
        border: "1px solid color-mix(in srgb, currentColor 28%, transparent)",
        borderRadius: 6,
        padding: size === "sm" ? "1px 6px" : "2px 7px",
        whiteSpace: "nowrap",
        flex: "none",
      }}
    >
      {cvss.score.toFixed(1)}
    </span>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="empty">{children}</div>;
}

export function ErrorNote({ error }: { error: string }) {
  return <div className="note bad">{error}</div>;
}
