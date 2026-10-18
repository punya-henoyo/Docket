import type { Lane, PortfolioFinding } from "../portfolio";
import { Drawer, OriginChip, ProofCell, SevChip, ago } from "./components";
import { hx } from "./hx";

/** The proof drawer. A reproduced finding shows its captured request and response and the evidence
 *  reference; anything else says plainly that it is a lead, not a verdict (AGENTS.md rules 1, 10). */
export function FindingDrawer({ finding, appLabel, onClose }: { finding: PortfolioFinding | null; appLabel?: string; onClose: () => void }) {
  const f = finding;
  return (
    <Drawer open={f !== null} onClose={onClose}>
      {f ? (
        <>
          <header>
            <button className={hx("x")} aria-label="Close" onClick={onClose}>×</button>
            <div className={hx("eyebrow")}>Finding{appLabel ? ` · ${appLabel}` : ""}</div>
            <h3 style={{ fontSize: "1.3rem", marginTop: 4 }}>{f.title}</h3>
            <div style={{ display: "flex", gap: 8, marginTop: 10, flexWrap: "wrap", alignItems: "center" }}>
              <SevChip sev={f.sev} /><ProofCell f={f} /><OriginChip origin={f.by.origin} name={f.by.name} />
              <span className={hx("chip neutral")}>{f.status}</span>
              {f.age_days != null ? <span className={hx("chip neutral")}>{ago(f.age_days)} old</span> : null}
            </div>
          </header>
          <div className={hx("body")}>
            {f.sub ? <p style={{ marginTop: 14 }}>{f.sub}</p> : null}
            {f.proof === "reproduced" && f.poc ? (
              <>
                <h4>Proof <span className={hx("chip crit")} style={{ marginLeft: 6 }}>Reproduced</span></h4>
                <p className={hx("note")}>
                  Docket only reports an exploit after it reproduces it. This request and response were captured from a live run
                  {f.evidence_ref ? <> and stored as evidence <span className={hx("mono")}>{f.evidence_ref}</span></> : null}.
                </p>
                <div className={hx("eyebrow")} style={{ margin: "12px 0 6px" }}>Request</div>
                <pre className={hx("code")}>{f.poc.request}</pre>
                <div className={hx("eyebrow")} style={{ margin: "12px 0 6px" }}>Response</div>
                <pre className={hx("code")}>{f.poc.response}</pre>
                {f.poc.notes ? <p>{f.poc.notes}</p> : null}
              </>
            ) : (
              <>
                <h4>{f.proof === "deterministic" ? "Why this blocks without an exploit" : "Why this is not a proven finding"}</h4>
                <p className={hx("note")}>
                  {f.proof === "deterministic"
                    ? "A secret in source is a deterministic rule: it blocks without an exploit."
                    : f.proof === "not_reachable"
                      ? "Triage read the source and found no path from untrusted input to this code."
                      : "A scanner matched a pattern. No exploit has been reproduced, so this is a lead for a person to judge, not a verdict."}
                </p>
                {f.reach ? <dl className={hx("kv")}><dt>Reachability</dt><dd>{f.reach}</dd></dl> : null}
              </>
            )}
            {f.triage ? (
              <>
                <h4>Triage</h4>
                <p><b>{f.triage.verdict}</b>: {f.triage.reasoning}</p>
                {f.triage.evidence ? <p className={hx("mono")}>{f.triage.evidence}</p> : null}
              </>
            ) : null}
            {f.fix ? (
              <>
                <h4>Proposed fix</h4>
                <p>{f.fix.summary}</p>
                {f.fix.diff ? <pre className={hx("code")}>{f.fix.diff}</pre> : null}
              </>
            ) : null}
            <dl className={hx("kv")} style={{ marginTop: 18 }}>
              {f.rule_id ? <><dt>Rule</dt><dd className={hx("mono")}>{f.rule_id}</dd></> : null}
              {f.cwe ? <><dt>CWE</dt><dd>{f.cwe}</dd></> : null}
              {f.location ? <><dt>Location</dt><dd className={hx("mono")}>{f.location}</dd></> : null}
            </dl>
          </div>
        </>
      ) : null}
    </Drawer>
  );
}

export function LaneDrawer({ lane, onClose }: { lane: Lane | null; onClose: () => void }) {
  const l = lane;
  return (
    <Drawer open={l !== null} onClose={onClose}>
      {l ? (
        <>
          <header>
            <button className={hx("x")} aria-label="Close" onClick={onClose}>×</button>
            <div className={hx("eyebrow")}>Pipeline stage</div>
            <h3 style={{ fontSize: "1.3rem", marginTop: 4 }}>{l.label}</h3>
            <div style={{ marginTop: 10, display: "flex", gap: 8 }}>
              <OriginChip origin={l.origin} name={l.tool} />
              {l.required ? <span className={hx("chip sec")}>Required by policy</span> : null}
            </div>
          </header>
          <div className={hx("body")}>
            <dl className={hx("kv")} style={{ marginTop: 14 }}>
              <dt>State</dt><dd>{l.state.replace("_", " ")}</dd>
              <dt>Result</dt><dd>{l.summary || "Nothing to report"}</dd>
              {l.requiredBy?.length ? <><dt>Required by</dt><dd>{l.requiredBy.map((r) => <div key={r}>{r}</div>)}</dd></> : null}
              {l.cost ? <><dt>Cost</dt><dd>${l.cost.toFixed(2)}</dd></> : null}
            </dl>
            {l.state === "not_run" ? (
              <p className={hx("note")}>The policy requires this stage, but it did not run in this scan.</p>
            ) : null}
          </div>
        </>
      ) : null}
    </Drawer>
  );
}
