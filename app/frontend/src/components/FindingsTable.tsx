import type { Finding } from "../types";
import { findingLocation, ruleLeaf, SevTag } from "./ui";

export function FindingsTable({
  findings,
  selectedId,
  onSelect,
}: {
  findings: Finding[];
  selectedId?: string;
  onSelect: (finding: Finding) => void;
}) {
  return (
    <div className="tablewrap">
      <table>
        <thead>
          <tr>
            <th>Rule</th>
            <th>Sev</th>
            <th>Location</th>
            <th>Found by</th>
          </tr>
        </thead>
        <tbody>
          {findings.map((finding) => (
            <tr
              key={finding.id}
              tabIndex={0}
              aria-selected={finding.id === selectedId}
              onClick={() => onSelect(finding)}
              onKeyDown={(e) => {
                if (e.key === "Enter" || e.key === " ") {
                  e.preventDefault();
                  onSelect(finding);
                }
              }}
            >
              <td title={finding.rule_id}>{ruleLeaf(finding.rule_id)}</td>
              <td>
                <SevTag severity={finding.severity} />
              </td>
              <td className="path">{findingLocation(finding)}</td>
              <td>
                <span className="chip">{finding.discovered_by}</span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function FindingDetail({ finding }: { finding: Finding }) {
  return (
    <>
      <div style={{ display: "flex", justifyContent: "space-between", gap: 12, flexWrap: "wrap", alignItems: "baseline" }}>
        <h2 style={{ font: "600 15px var(--sans)" }}>{finding.title}</h2>
        <SevTag severity={finding.severity} />
      </div>
      <div className="mono" style={{ fontSize: 11, color: "var(--ink-3)", wordBreak: "break-all" }}>
        {finding.rule_id}
        {finding.cwe ? ` · ${finding.cwe}` : ""} · found by {finding.discovered_by}
      </div>
      <div className="note" style={{ color: "var(--ink-2)", maxWidth: "72ch" }}>
        {finding.description}
      </div>

      <div className="evidence">
        <div className="lbl">{findingLocation(finding)}</div>
        {/* An event-stream finding has no poc at all: the validated request/response
            only exists in report.json. Say so rather than rendering an empty pre, which
            reads as "we found this and there was no evidence". */}
        <pre>{finding.poc?.request || "no reproduced request in this projection"}</pre>
        {finding.poc?.response && (
          <>
            <div className="lbl">OBSERVED</div>
            <pre>{finding.poc.response}</pre>
          </>
        )}
      </div>

      {finding.corroborating_evidence.length > 0 && (
        <div className="note">
          {finding.corroborating_evidence.length} corroborating result(s) collapsed into this
          finding by the dedupe key.
        </div>
      )}
    </>
  );
}
