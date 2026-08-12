import { useEffect, useRef } from "react";
import type { Finding } from "../types";
import { SeverityTag } from "./Severity";

const ORDER = ["critical", "high", "medium", "low", "info"];

export function FindingsTable({
  findings, onSelect,
}: { findings: Finding[]; onSelect: (f: Finding) => void }) {
  if (findings.length === 0) {
    return <div className="empty">No findings yet. docket only files what it has reproduced.</div>;
  }
  const sorted = [...findings].sort(
    (a, b) => ORDER.indexOf(a.severity ?? "info") - ORDER.indexOf(b.severity ?? "info"),
  );
  return (
    <table>
      <thead>
        <tr>
          <th>Severity</th><th>Rule</th><th>Where</th><th>Param</th><th>By</th>
        </tr>
      </thead>
      <tbody>
        {sorted.map((finding, index) => (
          <tr key={finding.finding_id ?? finding.dedupe_key ?? index}
              onClick={() => onSelect(finding)}
              title="Open the reproduced proof">
            <td><SeverityTag severity={finding.severity} /></td>
            <td>{finding.rule_id ?? finding.rule_type ?? "—"}</td>
            <td className="mono">
              {finding.location?.method} {finding.location?.path ?? finding.location?.url ?? "—"}
            </td>
            <td className="mono">{finding.location?.parameter ?? "—"}</td>
            <td className="mono">{finding.discovered_by ?? "—"}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export function FindingDialog({
  finding, runName, onClose,
}: { finding: Finding | null; runName: string; onClose: () => void }) {
  const ref = useRef<HTMLDialogElement>(null);

  useEffect(() => {
    const node = ref.current;
    if (!node) return;
    // showModal() throws if already open, and native <dialog> is the only way to get
    // focus trapping and Escape-to-close without writing either.
    if (finding && !node.open) node.showModal();
    if (!finding && node.open) node.close();
  }, [finding]);

  return (
    <dialog ref={ref} onClose={onClose} onClick={(e) => { if (e.target === ref.current) onClose(); }}>
      {finding && (
        <>
          <div className="dlg-head">
            <SeverityTag severity={finding.severity} />
            <strong>{finding.rule_id ?? finding.title ?? "Finding"}</strong>
            <span className="spacer" />
            <button className="btn icon" onClick={onClose} aria-label="Close">✕</button>
          </div>
          <div className="dlg-body">
            {finding.description && <><h3>What it is</h3><p>{finding.description}</p></>}
            <h3>Location</h3>
            <pre>{[finding.location?.method, finding.location?.url ?? finding.location?.path]
              .filter(Boolean).join(" ")}
              {finding.location?.parameter ? `\nparameter: ${finding.location.parameter}` : ""}
              {finding.cwe ? `\n${finding.cwe}` : ""}</pre>
            <h3>Request sent</h3>
            <pre>{finding.poc?.request || "—"}</pre>
            <h3>Response observed</h3>
            <pre>{finding.poc?.response || "—"}</pre>
            {finding.poc?.steps?.length ? (
              <><h3>Steps</h3><pre>{finding.poc.steps.join("\n")}</pre></>
            ) : null}
            {finding.poc?.screenshot && (
              <>
                <h3>Screenshot</h3>
                <img alt="proof-of-concept screenshot"
                     src={`/api/runs/${encodeURIComponent(runName)}/artifacts/${finding.poc.screenshot}`} />
              </>
            )}
          </div>
        </>
      )}
    </dialog>
  );
}
