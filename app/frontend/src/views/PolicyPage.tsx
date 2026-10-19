import { useEffect, useMemo, useState } from "react";
import { getPolicy } from "../api/portfolio";
import { useApi } from "../hooks/useApi";
import type { Policy, PolicyPayload, PolicyStep, PolicyWhy } from "../portfolio";
import { Card, Empty, OriginChip, PageHead } from "../hx/components";
import { hx } from "../hx/hx";

const chip = (mod: string) => hx(`chip ${mod}`);
import { Kit } from "../kit/Kit";
import "./PolicyPage.css";

type Go = (name: string, param?: string | null) => void;
/** The contract sends `required` on every step; the shared type predates it. */
type Step = PolicyStep & { required?: boolean };

const NO_CLAUSE = "Clause reference not yet mapped. The pack cites the section, not a numbered clause.";

/** One "Required because" line. A regulatory reason carries the authority, the text and an
 *  obligation link; a security reason is just the rule. The clause is never invented. */
function Why({ w, go }: { w: PolicyWhy; go: Go }) {
  if (w.kind !== "regulatory") {
    return <div className={hx("whyrow")}><span className={hx("chip sec")}>Security</span><span>{w.text}</span></div>;
  }
  return (
    <div className={hx("whyrow")}>
      {w.authority ? <span className={hx("chip reg")}>{w.authority}</span> : null}
      <span>{w.text}</span>
      {w.clause ? <span className={hx("mono")}>Clause: {w.clause}</span> : null}
      {w.obligation_ref ? (
        <a className={hx("mono")} href="#/compliance" title="Resolves to a Henoyo obligation record"
           onClick={(e) => { e.preventDefault(); go("compliance"); }}>↗ {w.obligation_ref}</a>
      ) : null}
    </div>
  );
}

function Sequence({ steps, go }: { steps: Step[]; go: Go }) {
  const grid = { gridTemplateColumns: "36px minmax(0,1.1fr) minmax(0,1.6fr) 150px 170px" };
  return (
    <div className={hx("seq")}>
      <div className={hx("step head")} style={grid}>
        <span>#</span><span>Scanner</span><span>Required because</span><span>Cadence</span><span>If it fails</span>
      </div>
      {steps.map((s) => {
        const req = s.required !== false;
        return (
          <div key={s.id} className={hx(`step${req ? "" : " optional"}`)} style={grid}>
            <span className={hx("n")}>{s.n}</span>
            <div>
              <div className={hx("nm")}>{s.label}</div>
              <div className={hx("tags")}>
                <OriginChip origin={s.origin} name={s.tool ?? undefined} />
                <span className={chip(req ? "sec" : "neutral")}>{req ? "Required" : "Optional"}</span>
              </div>
            </div>
            <div style={{ display: "grid", gap: 7 }}>
              {s.why.map((w, i) => <Why key={i} w={w} go={go} />)}
            </div>
            <div className={hx("cad")}>{s.cadence}</div>
            <div className={hx("cad")}>{s.on_fail}</div>
          </div>
        );
      })}
    </div>
  );
}

const cap = (s: string) => s.charAt(0).toUpperCase() + s.slice(1);
const GATE_CLASS = { blocks: "bad", flags: "warn", advises: "neutral" } as const;

function PolicyBody({ policy, data, go }: { policy: Policy; data: PolicyPayload; go: Go }) {
  const steps = policy.steps as Step[];
  const required = steps.filter((s) => s.required !== false);
  const optional = steps.length - required.length;
  const hen = required.filter((s) => s.origin === "henoyo").length;
  const cov = data.coverage.policy === policy.id ? data.coverage : null;

  const matrixProps = useMemo(() => cov ? ({
    heading: "Policy against reality",
    windowDays: cov.window_days,
    scanners: cov.scanners,
    rows: cov.rows,
    helpText: "Each cell asks: did this required scanner finish inside its window for this application? The last column says what that adds up to: a stale scanner flags, a reproduced exploit blocks.",
    source: { label: "Docket scans" },
  }) : null, [cov]);
  const matrixOn = useMemo(() => ({
    "docket:open-app": (d: Record<string, string | undefined>) => { if (d.id) go("app", d.id); },
  }), [go]);

  const sub = [
    policy.applies ? `Applies to ${policy.applies.charAt(0).toLowerCase()}${policy.applies.slice(1)}` : null,
    `version ${policy.version}`,
    policy.approved ? (/approv/i.test(policy.approved) ? policy.approved : `approved ${policy.approved}`) : null,
    optional ? `${optional} optional step${optional === 1 ? "" : "s"}` : null,
  ].filter(Boolean).join(" · ");

  return (
    <>
      <div className={hx("res")} style={{ marginBottom: 16 }}>
        <div className={hx("count")}><b>{required.length}</b><span>Required scanners, of {steps.length} steps</span></div>
        <div className={hx("count")}><b>{required.length - hen} + {hen}</b><span>Third-party + Henoyo-built, required</span></div>
        <div className={hx("count")}><b>{policy.cadence_days} days</b><span>Longest gap between scans</span></div>
        <div className={hx("count")}><b>{policy.applies_count}</b><span>Applications under this policy</span></div>
      </div>
      <div className={hx("stack")}>
        <Card title={`${policy.name}: the sequence that runs`} flush sub={sub}
              tip="Scanners run in this order. Required steps count toward 'did it run?'; optional steps run when they can. Each names the security rule or regulatory source behind it.">
          <Sequence steps={steps} go={go} />
        </Card>
        <div className={hx("cols2")}>
          <Card title="Regulatory requirements" sub="Each resolves to an obligation in Henoyo"
                tip="These are the regulations the policy answers to. The clause reference is filled in where the source gives one; otherwise the section is cited.">
            {policy.regulatory.length === 0 ? <Empty>This policy cites no regulation.</Empty> : (
              <div className={hx("req")}>
                {policy.regulatory.map((r) => (
                  <div className={hx("it")} key={`${r.authority}:${r.obligation_ref}`}>
                    <span className={hx("chip reg")}>{r.authority}</span>
                    <div>
                      <div className={hx("t")}>{r.text}</div>
                      <div className={hx("c")}>
                        {r.clause ? `Clause: ${r.clause}` : NO_CLAUSE}
                        {r.obligation_ref ? <> · <a href="#/compliance" onClick={(e) => { e.preventDefault(); go("compliance"); }}>{r.obligation_ref}</a></> : null}
                        {r.source_url ? <> · <a href={r.source_url} target="_blank" rel="noopener noreferrer">Source</a></> : null}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </Card>
          <Card title="Security requirements" sub="What the engineering rule is">
            {policy.security.length === 0 ? <Empty>This policy states no security rule.</Empty> : (
              <div className={hx("req")}>
                {policy.security.map((r) => (
                  <div className={hx("it")} key={r.text}>
                    <span className={hx("chip sec")}>Security</span>
                    <div><div className={hx("t")}>{r.text}</div><div className={hx("c")}>{r.detail}</div></div>
                  </div>
                ))}
              </div>
            )}
          </Card>
        </div>
        <Card title="What the policy does about it">
          <div className={hx("gate")}>
            {policy.gate.map((g) => (
              <div key={g.effect}><span className={chip(GATE_CLASS[g.effect])}>{cap(g.effect)}</span> {g.text}</div>
            ))}
          </div>
        </Card>
        {matrixProps ? <Kit tag="docket-policy-matrix" props={matrixProps} on={matrixOn} /> : null}
      </div>
    </>
  );
}

export function PolicyPage({ go }: { go: Go }) {
  const { data, error, loading } = useApi(getPolicy, "policy");
  const [pick, setPick] = useState<string | null>(null);
  const policies = data?.policies ?? [];
  const policy = policies.find((p) => p.id === pick) ?? policies[0];
  useEffect(() => { if (pick && !policies.some((p) => p.id === pick)) setPick(null); }, [pick, policies]);

  return (
    <>
      <PageHead eyebrow="Code Security" title="Policy"
        sub="What every application must run, in what order, and why. A requirement without a source is a preference, so each step names the security rule or regulation behind it." />
      {policies.length > 1 ? (
        <div className={hx("polsel")} role="tablist" aria-label="Policy">
          {policies.map((p) => (
            <button key={p.id} className={hx("view")} aria-pressed={p.id === policy?.id} onClick={() => setPick(p.id)}>
              {p.name}<b>{p.applies_count}</b>
            </button>
          ))}
        </div>
      ) : null}
      {error && !data ? <Empty>The policy could not be loaded: {error}</Empty>
        : loading && !data ? <Empty>Loading the policy.</Empty>
        : !policy || !data ? <Empty>No policy is defined yet, so the built-in default applies to every application.</Empty>
        : <PolicyBody key={policy.id} policy={policy} data={data} go={go} />}
    </>
  );
}
