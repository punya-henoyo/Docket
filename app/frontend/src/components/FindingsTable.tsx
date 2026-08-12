import type { Finding } from "../types";
import { CvssBadge, findingLocation, ruleLeaf, SevTag, VerdictTag } from "./ui";

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
            <th>CVSS</th>
            <th>Location</th>
            <th>Found by</th>
            <th>Triage</th>
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
              {/* Recon findings have no rule — the title IS the finding, so show that
                  rather than a slugified copy of it. Both clamp to one line: a
                  wrapping cell makes every row a different height and the table
                  stops being scannable, which is the whole point of a table. */}
              <td title={finding.discovered_by === "recon" ? finding.title : finding.rule_id}
                  style={{ maxWidth: "26rem", overflow: "hidden",
                           textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                {finding.discovered_by === "recon"
                  ? finding.title
                  : ruleLeaf(finding.rule_id)}
              </td>
              <td>
                <SevTag severity={finding.severity} />
              </td>
              <td><CvssBadge cvss={finding.cvss} size="sm" /></td>
              <td className="path">{findingLocation(finding)}</td>
              <td>
                <span className="chip">{finding.discovered_by}</span>
              </td>
              <td>{finding.triage ? <VerdictTag verdict={finding.triage.verdict} /> : null}</td>
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
        <span style={{ display: "flex", gap: 8, alignItems: "center" }}>
          <CvssBadge cvss={finding.cvss} />
          <SevTag severity={finding.severity} />
        </span>
      </div>

      {finding.merged_cwes && finding.merged_cwes.length > 1 && (
        <div className="note bad" style={{ fontSize: 12 }}>
          Weakness disputed: the {finding.merged_rules?.length ?? finding.merged_cwes.length}{" "}
          rules that matched this line disagree — {finding.merged_cwes.join(", ")}. Docket
          shows none of them rather than picking one, because semgrep's CWE metadata is
          wrong often enough that a confident answer here would be a guess.
          <div className="mono" style={{ fontSize: 11, marginTop: 5, color: "var(--ink-3)" }}>
            {(finding.merged_rules ?? []).map((r) => r.split("/").pop()).join("\n")}
          </div>
        </div>
      )}

      {/* The vector, spelled out. A score with no vector is a number to take on faith;
          with it, anyone can check how it was reached — and see that it rates the
          vulnerability class, not this repository's exposure to it. */}
      {finding.cvss && (
        <div className="note" style={{ fontSize: 12 }}>
          CVSS v{finding.cvss.version} <b style={{ color: "var(--ink-2)" }}>
          {finding.cvss.score.toFixed(1)}</b> per {finding.cvss.source.toUpperCase()}
          {finding.cvss.vector
            ? <> · <span className="mono" style={{ fontSize: 11 }}>{finding.cvss.vector}</span></>
            : " · no vector published"}
          <div>Rates the vulnerability class. Whether this codebase reaches it is the
            triage question below.</div>
        </div>
      )}
      <div className="mono" style={{ fontSize: 11, color: "var(--ink-3)", wordBreak: "break-all" }}>
        {finding.rule_id}
        {finding.cwe ? ` · ${finding.cwe}` : ""} · found by {finding.discovered_by}
        {finding.merged_rules && finding.merged_rules.length > 1 && (
          <> · {finding.merged_rules.length} rules matched this line</>
        )}
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

      {finding.triage && (
        <div
          style={{
            border: "1px solid var(--line)",
            borderRadius: 6,
            padding: "10px 11px",
            display: "flex",
            flexDirection: "column",
            gap: 7,
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: 9 }}>
            <VerdictTag verdict={finding.triage.verdict} />
            <span className="note">agent triage · read the source, ran nothing</span>
          </div>
          <div className="note" style={{ color: "var(--ink-2)", maxWidth: "72ch" }}>
            {finding.triage.reasoning}
          </div>
          <div className="evidence">
            <div className="lbl">CODE IT READ</div>
            <pre>{finding.triage.evidence}</pre>
          </div>
        </div>
      )}

      {finding.corroborating_evidence.length > 0 && (
        <div className="note">
          {finding.corroborating_evidence.length} corroborating result(s) collapsed into this
          finding by the dedupe key.
        </div>
      )}
    </>
  );
}
