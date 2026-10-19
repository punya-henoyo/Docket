import { useMemo, useState } from "react";
import { getApplication, getPipeline } from "../../api/portfolio";
import { useApi } from "../../hooks/useApi";
import { Kit } from "../../kit/Kit";
import { Card, Empty, OriginChip, useSort } from "../../hx/components";
import { LaneDrawer } from "../../hx/Drawers";
import { hx } from "../../hx/hx";
import type { Catalog, Lane, PipelineDetail } from "../../portfolio";
import { AvailChip, ReqChip } from "./bits";
import { hydratePacks, hydrateSteps, appliesText, toolOf, slotOf, type Draft } from "./model";

export interface RunApp { id: string; label: string; tier: string; repo: string }
type Gate = { effect: "blocks" | "flags" | "advises"; text: string }[];
export type RunTab = "plan" | "last";

const PLAN_ACCESS = {
  step: (r: { i: number }) => r.i, how: (r: { how: string }) => r.how, what: (r: { what: string }) => r.what,
  produces: (r: { produces: string }) => r.produces, by: (r: { by: string }) => r.by,
};

/** A plan from the catalog: what each step will do and produce. It never shows an outcome. */
function Plan({ draft, catalog, app }: { draft: Draft; catalog: Catalog; app: RunApp }) {
  const base = useMemo(() => hydrateSteps(draft, catalog).map((s, i) => {
    const slot = slotOf(catalog, s.id)!;
    const t = toolOf(slot, draft.steps.find((x) => x.id === s.id)?.tool ?? null);
    const how = t.availability === "imports" ? `Run ${t.name} in your own pipeline, then pass its results: docket scan --sarif ./${t.id}.sarif`
      : t.availability === "planned" ? "Planned: Docket cannot run this yet"
      : slot.command || "A Docket agent, in the sandbox";
    return { i, s, how, what: slot.what, produces: slot.produces, by: t.origin === "henoyo" ? "Henoyo" : t.name, imports: t.availability === "imports" };
  }), [draft, catalog]);
  const { rows, Th } = useSort(base, PLAN_ACCESS);
  return (
    <>
      <div className={hx("eyebrow")} style={{ marginBottom: 8 }}>Plan for {app.label}. Nothing has run.</div>
      <table className={`${hx("lv")} pol-table`}>
        <thead><tr><Th k="step">Step</Th><Th k="how">How it runs</Th><Th k="what">What it does</Th><Th k="produces">What it produces</Th><Th k="by">Detection written by</Th></tr></thead>
        <tbody>
          {rows.map(({ s, how, what, produces, by, imports }) => (
            <tr key={s.id}>
              <td><b>{s.label}</b>
                <div className="pol-tags"><OriginChip origin={s.origin} name={s.tool} /><AvailChip a={s.availability} /><ReqChip required={s.required} /></div></td>
              <td>{imports || !s.command || s.availability === "planned" ? how : <code>{how}</code>}</td>
              <td>{what}</td><td>{produces}</td><td>{by}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <p className={hx("note")}>This is a plan, not a result. A step marked Imports SARIF is run by your own pipeline: Docket reads its file and records that the step ran.</p>
    </>
  );
}

interface LastRunData { detail: PipelineDetail | null; label: string }
const day = (iso?: string | null) => (iso ? new Date(iso).toLocaleDateString("en-GB", { day: "numeric", month: "short" }) : "");

function LastRun({ app, draft, catalog, gate, gateResult, dirty }: {
  app: RunApp; draft: Draft; catalog: Catalog; gate: Gate; gateResult: { effect: "blocks" | "flags" | "advises"; text: string } | null; dirty: boolean;
}) {
  const [lane, setLane] = useState<Lane | null>(null);
  const { data, error, loading } = useApi<LastRunData>(async () => {
    const a = await getApplication(app.id);
    const run = a.pipeline.run;
    if (!run) return { detail: null, label: app.label };
    const detail = await getPipeline(run);
    return { detail, label: app.label };
  }, `lastrun:${app.id}`);
  const detail = data?.detail ?? null;
  const flow = useMemo(() => ({
    mode: "run", gate, starts: catalog.starts,
    policy: { id: draft.key, name: draft.name || "Untitled policy", applies: appliesText(draft.applies_when), cadence_days: draft.cadence_days, steps: hydrateSteps(draft, catalog), guidelines: draft.guidelines },
    guidelines: hydratePacks(draft, catalog),
    runLanes: detail?.lanes ?? [], gateResult: gateResult ?? null,
    runLabel: detail ? [app.label, day(detail.ended_at ?? detail.started_at), `${(detail as PipelineDetail & { coverage?: string }).coverage ?? "full"} scan`, detail.commit ? `commit ${detail.commit}` : ""].filter(Boolean).join(", ") : undefined,
    helpText: "The same flow, drawn from the recorded evidence of one real run. A dashed slot is a step the policy requires that did not run. Nothing here is projected.",
    source: detail ? { label: `Scan ${detail.run}`, href: `#/scan/${encodeURIComponent(detail.run)}` } : undefined,
  }), [draft, catalog, gate, detail, gateResult, app.label]);
  const on = useMemo(() => ({
    "docket:lane": (d: Record<string, string | undefined>) => setLane(detail?.lanes.find((l) => l.id === d.id && !l.parentId) ?? null),
  }), [detail]);

  if (error && !data) return <Empty>The last run could not be loaded: {error}</Empty>;
  if (loading && !data) return <Empty>Loading the last run.</Empty>;
  if (!detail) {
    return <Empty><b>No run is recorded for {app.label}.</b><br />Use Run now. Docket never shows an outcome that did not happen.</Empty>;
  }
  return (
    <>
      {dirty ? <p className={hx("note")} style={{ marginTop: 0 }}>Drawn against your unsaved draft. A required step in the draft that this run did not run shows as a gap.</p> : null}
      <Kit tag="docket-policy-flow" props={flow} on={on} />
      <LaneDrawer lane={lane} onClose={() => setLane(null)} />
    </>
  );
}

export function RunIt({ draft, catalog, gate, apps, underPolicy, dirty, isNew, gateFor, connected, onRunNow, tab, setTab, appId, setAppId }: {
  draft: Draft; catalog: Catalog; gate: Gate; apps: RunApp[]; underPolicy: string[]; dirty: boolean; isNew: boolean;
  gateFor: (appId: string) => { effect: "blocks" | "flags" | "advises"; text: string } | null;
  connected: boolean; onRunNow: () => void; tab: RunTab; setTab: (t: RunTab) => void; appId: string | null; setAppId: (id: string) => void;
}) {
  const mine = apps.filter((a) => underPolicy.includes(a.id));
  const rest = apps.filter((a) => !underPolicy.includes(a.id));
  const app = apps.find((a) => a.id === appId) ?? mine[0] ?? rest[0] ?? null;
  const repoName = app?.repo.split("/").pop() ?? ".";
  return (
    <Card title="Run it" sub="Pick an application. Preview the plan, or read the evidence of its last run."
          tip="See what this policy would do for one application, then what the last real run did. A preview is a plan: it never shows results. Results come only from a recorded run.">
      {!app ? <Empty>No application is connected yet, so there is nothing to run this policy against.</Empty> : (
        <>
          <div className="pol-runbar">
            <label className="pol-sub2" htmlFor="pol-app">Application
              <select id="pol-app" className="pol-select" value={app.id} onChange={(e) => setAppId(e.target.value)}>
                {mine.length ? <optgroup label={isNew || dirty ? "Would be under this policy" : "Under this policy"}>{mine.map((a) => <option key={a.id} value={a.id}>{a.label} ({a.tier})</option>)}</optgroup> : null}
                {rest.length ? <optgroup label="Other applications">{rest.map((a) => <option key={a.id} value={a.id}>{a.label} ({a.tier})</option>)}</optgroup> : null}
              </select>
            </label>
            <div className="pol-seg" role="group" aria-label="What to show">
              <button type="button" aria-pressed={tab === "plan"} onClick={() => setTab("plan")}>Preview a run</button>
              <button type="button" aria-pressed={tab === "last"} onClick={() => setTab("last")}>Last run</button>
            </div>
            <span style={{ flex: 1 }} />
            <button type="button" className={hx("btn primary")} onClick={onRunNow} disabled={!connected}
                    title={connected ? "Opens the scan launcher in Connections" : "Connect a repository first"}>Run now</button>
          </div>
          <p className="pol-sub2 pol-runnote">
            {connected
              ? "Run now opens the scan launcher in Connections, where you choose the repository and start the scan."
              : <>No repository is connected, so Run now cannot start. From the command line: <code className={hx("mono")}>docket scan --source ./{repoName}</code></>}
          </p>
          {tab === "plan" ? <Plan draft={draft} catalog={catalog} app={app} />
            : <LastRun key={app.id} app={app} draft={draft} catalog={catalog} gate={gate} gateResult={dirty || isNew ? null : gateFor(app.id)} dirty={dirty || isNew} />}
        </>
      )}
    </Card>
  );
}
