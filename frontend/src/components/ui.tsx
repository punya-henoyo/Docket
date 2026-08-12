import type { ReactNode } from "react";
import type { Finding, Severity } from "../types";

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

export function Empty({ children }: { children: ReactNode }) {
  return <div className="empty">{children}</div>;
}

export function ErrorNote({ error }: { error: string }) {
  return <div className="note bad">{error}</div>;
}
