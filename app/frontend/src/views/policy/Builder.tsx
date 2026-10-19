import type { Catalog, CatalogSlot, PolicyPreview } from "../../portfolio";
import { Card, Help } from "../../hx/components";
import { hx } from "../../hx/hx";
import type { RefObject } from "react";
import { Authority, AvailChip, StepIcon, Switch } from "./bits";
import {
  PROFILE_FIELDS, REQUIRED_BY_DEFAULT, defaultToolOf, inCatalogOrder, selectable, slotOf, stepIsPlanned, toolOf,
  type Draft, type DraftStep,
} from "./model";

export type Edit = (fn: (d: Draft) => void) => void;

/* ── Who and when ──────────────────────────────────────────────────────────────────────────────── */

export interface FitsElsewhere { id: string; label: string; policyName: string }

export function WhoWhen({ draft, catalog, edit, matches, previewing, savedId, fitsElsewhere }: {
  draft: Draft; catalog: Catalog; edit: Edit; matches: PolicyPreview["matches"] | null; previewing: boolean;
  /** The id a new policy will be saved under. */
  savedId: string; fitsElsewhere: FitsElsewhere[];
}) {
  const w = draft.applies_when;
  return (
    <Card title="Who and when" sub="Which applications this policy covers, and how fresh a required check must be.">
      <div className="pol-fld">
        <label className="pol-lbl" htmlFor="pol-name">Name<span className={hx("chip sec")}>Required</span></label>
        <input id="pol-name" className="pol-input" value={draft.name} onChange={(e) => edit((d) => { d.name = e.target.value; })} />
        <div className="pol-sub2" style={{ marginTop: 5 }}>
          {draft.savedId ? <>Id <span className={hx("mono")}>{draft.savedId}</span></> : <>Will be saved as <span className={hx("mono")}>{savedId}</span></>}
        </div>
      </div>

      <div className="pol-fld">
        <div className="pol-lbl" id="pol-when">
          Applies when
          <Help text="An application gets this policy when its profile matches every field you choose. A field you leave empty does not constrain it. The most specific matching policy wins; an application with no match gets the built-in baseline." />
          <span className={hx("chip neutral")} style={{ marginLeft: "auto" }}>Matching</span>
        </div>
        {PROFILE_FIELDS.map(([f, label]) => (
          <div className="pol-pf" key={f} role="group" aria-label={label}>
            <span>{label}</span>
            <div className="pol-toggles">
              {catalog.profile[f].map((v) => (
                <button key={v} type="button" className="pol-tg" aria-pressed={w[f].includes(v)}
                        onClick={() => edit((d) => { const a = d.applies_when[f]; const i = a.indexOf(v); if (i < 0) a.push(v); else a.splice(i, 1); })}>{v}</button>
              ))}
            </div>
          </div>
        ))}
        <div className="pol-matchline" aria-live="polite" aria-busy={previewing}>
          {matches == null ? <b>Checking which applications match…</b> : (
            <>
              <b>Matches {matches.length} application{matches.length === 1 ? "" : "s"}</b>
              <div className="pol-chips">
                {matches.length ? matches.map((m) => (
                  <span key={m.id} className={hx("chip neutral")} title={[m.category, m.exposure].filter(Boolean).join(" · ")}>{m.label} · {m.tier}</span>
                )) : <span className="pol-sub2">No application has this profile.</span>}
              </div>
            </>
          )}
          {fitsElsewhere.length ? (
            <div className="pol-sub2" style={{ marginTop: 7 }}>
              {fitsElsewhere.length} more fit{fitsElsewhere.length === 1 ? "s" : ""} the profile but {fitsElsewhere.length === 1 ? "uses" : "use"} another policy:{" "}
              {fitsElsewhere.map((o) => `${o.label} (${o.policyName})`).join(", ")}.
            </div>
          ) : null}
        </div>
      </div>

      <div className="pol-fld">
        <label className="pol-lbl" htmlFor="pol-cad">
          Cadence
          <Help text="The window a required check is judged against: it counts as current if it finished within this many days. Docket does not start scans on a schedule yet; it judges how recent the last one was." />
          <span className={hx("chip sec")}>Required</span>
        </label>
        <div className="pol-inline">
          <input id="pol-cad" className="pol-num" type="number" min={1} max={365} value={Number.isFinite(draft.cadence_days) ? draft.cadence_days : ""}
                 onChange={(e) => edit((d) => { d.cadence_days = e.target.value === "" ? NaN : Math.round(Number(e.target.value)); })} />
          <span className="pol-sub2">days. Judged, not started.</span>
        </div>
      </div>
    </Card>
  );
}

/* ── Steps ─────────────────────────────────────────────────────────────────────────────────────── */

function StepRow({ step, slot, draft, selected, locked, cantRemove, edit, onSelect }: {
  step: DraftStep; slot: CatalogSlot; draft: Draft; selected: boolean; locked: boolean; cantRemove: boolean; edit: Edit; onSelect: () => void;
}) {
  const t = toolOf(slot, step.tool);
  const planned = stepIsPlanned(slot, step);
  const setStep = (fn: (s: DraftStep) => void) => edit((d) => { const s = d.steps.find((x) => x.id === step.id); if (s) fn(s); });
  const isLocked = locked && slot.id === "compliance";
  return (
    <div className={`pol-row${step.required ? "" : " opt"}${selected ? " sel" : ""}`} data-step={step.id}>
      <div className="pol-nm">
        <StepIcon name={slot.icon} origin={t.origin} />
        <button type="button" className="pol-pick" aria-expanded={selected} onClick={onSelect}>{slot.label}</button>
      </div>
      <div className="pol-tool">
        {slot.tools.length > 1 ? (
          <select className="pol-select" aria-label={`Tool for ${slot.label}`} value={t.id}
                  onChange={(e) => setStep((s) => { s.tool = e.target.value === defaultToolOf(slot).id ? null : e.target.value; })}>
            {slot.tools.map((x) => (
              <option key={x.id} value={x.id} disabled={!selectable(x)}>
                {x.name}{x.availability === "planned" ? " (Planned, not available yet)" : x.availability === "imports" ? " (imports SARIF)" : ""}
              </option>
            ))}
          </select>
        ) : <span>{t.name}</span>}
        {t.origin === "henoyo" ? <span className={hx("origin h")}>Henoyo</span> : null}
        <AvailChip a={t.availability} />
      </div>
      <div>
        {isLocked
          ? <Switch on={false} label="Optional, locked" disabled title="Guidelines advise only, so the reader is always optional" onToggle={() => undefined} />
          : <Switch on={step.required} label={step.required ? "Required" : "Optional"} onToggle={() => setStep((s) => { s.required = !s.required; })} />}
      </div>
      <button type="button" className="pol-x" aria-label={`Remove ${slot.label}`} aria-disabled={cantRemove || undefined}
              title={cantRemove ? "Needed while a guideline is selected" : "Remove from the policy"}
              onClick={() => { if (cantRemove) return; edit((d) => { d.steps = d.steps.filter((x) => x.id !== step.id); }); }}>
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" aria-hidden="true"><path d="M6 6l12 12M18 6 6 18" /></svg>
      </button>
      {selected ? (
        <div className="pol-detail">
          <div>{slot.what}</div>
          <div><b>Produces:</b> {slot.produces}.</div>
          <div>{slot.command ? <code>{slot.command}</code> : "Runs as a Docket agent, inside the sandbox."}</div>
          <div><b>Detection written by:</b> {t.origin === "henoyo" ? "Henoyo" : t.name}</div>
          {planned ? <div className={hx("chip warn")} style={{ whiteSpace: "normal", height: "auto", padding: "3px 9px" }}>Planned: Docket cannot run this yet, so every run will show it as not run.</div> : null}
          {slot.tools.some((x) => x.availability === "planned") && slot.tools.length > 1
            ? <div className="pol-sub2">Planned tools are listed so you can see what is coming. They cannot be chosen or saved.</div> : null}
          {slot.id !== "compliance" && step.required ? (
            <div className="pol-inline">
              <label htmlFor={`pol-sd-${slot.id}`}><b>Cadence for this step</b></label>
              <input id={`pol-sd-${slot.id}`} className="pol-num" type="number" min={1} max={365} placeholder={String(draft.cadence_days)}
                     value={step.cadence_days ?? ""} aria-describedby={`pol-sd-h-${slot.id}`}
                     onChange={(e) => setStep((s) => { s.cadence_days = e.target.value === "" ? null : Math.round(Number(e.target.value)); })} />
              <span id={`pol-sd-h-${slot.id}`} className="pol-sub2">days. Empty uses the policy window ({draft.cadence_days}).</span>
            </div>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}

export function StepsCard({ draft, catalog, edit, selStep, setSelStep, flashGroup, paletteRef }: {
  draft: Draft; catalog: Catalog; edit: Edit; selStep: string | null; setSelStep: (id: string | null) => void;
  flashGroup: "pre" | "agents" | null; paletteRef: RefObject<HTMLDivElement | null>;
}) {
  const steps = inCatalogOrder(draft.steps, catalog);
  const readerLocked = draft.guidelines.length > 0;
  const add = (slot: CatalogSlot, toolId: string) => edit((d) => {
    if (d.steps.some((s) => s.id === slot.id)) return;
    d.steps.push({ id: slot.id, required: REQUIRED_BY_DEFAULT.has(slot.id), tool: toolId === defaultToolOf(slot).id ? null : toolId, cadence_days: null });
  });
  const group = (ph: "pre" | "agents", title: string) => (
    <>
      <div className="pol-palh">{title}</div>
      <div className="pol-pal">
        {catalog.slots.filter((sl) => sl.phase === ph).map((sl) => {
          const inPolicy = draft.steps.some((s) => s.id === sl.id);
          return (
            <div key={sl.id} className={`pol-slot${inPolicy ? " in" : ""}${flashGroup === ph ? " flash" : ""}`}>
              <b>{sl.label}</b>
              <p>{sl.what}</p>
              {sl.id === "compliance" ? <p>Added when you choose a guideline below.</p>
                : inPolicy ? <p>In this policy.</p>
                : (
                  <div className="pol-opts">
                    {sl.tools.map((t) => selectable(t)
                      ? <button key={t.id} type="button" className="pol-vend" aria-label={`Add ${sl.label} using ${t.name}`} onClick={() => add(sl, t.id)}>{t.name}<AvailChip a={t.availability} /></button>
                      : <button key={t.id} type="button" className="pol-vend" aria-disabled="true" aria-label={`${t.name}, planned and not available`}
                                title={`Planned: ${t.name} is not available yet, so a policy cannot use it.`}>{t.name}<AvailChip a="planned" /></button>)}
                  </div>
                )}
            </div>
          );
        })}
      </div>
    </>
  );
  return (
    <Card title="Steps" sub="What must have run. Required steps decide whether an application has every required check current."
          tip="A required step that has not finished inside the window means the application lacks a check, and the gate flags it. An optional step is judged only when it runs.">
      <p className="pol-hint">Steps sit in the order Docket runs them. There is nothing to reorder: the policy decides what must have run, not the order.</p>
      <div className="pol-rows">
        {steps.map((s) => {
          const slot = slotOf(catalog, s.id);
          if (!slot) return null;
          return <StepRow key={s.id} step={s} slot={slot} draft={draft} selected={selStep === s.id} locked={readerLocked}
                          cantRemove={s.id === "compliance" && readerLocked} edit={edit} onSelect={() => setSelStep(selStep === s.id ? null : s.id)} />;
        })}
        {steps.length === 0 ? <div className="pol-row"><span className="pol-sub2">No steps yet. Add one below.</span></div> : null}
      </div>
      <div ref={paletteRef} tabIndex={-1} style={{ outline: "none" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 6, marginTop: 18 }}>
          <b style={{ fontSize: 13 }}>Add a step</b>
          <Help text="Pick a vendor to fill a capability. Docket runs the tools marked Runs in Docket. Tools marked Imports SARIF are run by you; Docket reads their SARIF file and records that the step ran. Planned tools are shown so you can see what is coming, but cannot be chosen." />
        </div>
        {group("pre", "Before the agents")}
        {group("agents", "Docket agents")}
      </div>
    </Card>
  );
}

/* ── Guidelines ────────────────────────────────────────────────────────────────────────────────── */

export function GuidelinesCard({ draft, catalog, edit, flash, sectionRef }: {
  draft: Draft; catalog: Catalog; edit: Edit; flash: boolean; sectionRef: RefObject<HTMLDivElement | null>;
}) {
  const toggle = (id: string) => edit((d) => {
    const i = d.guidelines.indexOf(id);
    if (i >= 0) { d.guidelines.splice(i, 1); return; }
    d.guidelines.push(id);
    if (!d.steps.some((s) => s.id === "compliance")) d.steps.push({ id: "compliance", required: false, tool: null, cadence_days: null });
  });
  return (
    <Card title="Guidelines" sub="Regulatory and framework packs the Compliance reader checks the code against. They advise only."
          tip="Selecting a guideline adds the Compliance reader as an optional step. It annotates a pull request at notice level and never blocks, and it is never counted in whether the required checks are current.">
      <div ref={sectionRef} tabIndex={-1} style={{ outline: "none" }} className="pol-packs" role="group" aria-label="Guidelines">
        {catalog.guidelines.map((g) => {
          const on = draft.guidelines.includes(g.id);
          return (
            <button key={g.id} type="button" role="checkbox" aria-checked={on} className={`pol-pack${flash ? " flash" : ""}`} onClick={() => toggle(g.id)}>
              <span className="pol-bx" aria-hidden="true"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3.2" strokeLinecap="round"><path d="m5 12 5 5 9-10" /></svg></span>
              <span>
                <span className="pol-t"><Authority a={g.authority} />{g.title}</span>
                <span className="pol-c">{g.controls} controls, {g.observable} readable from code. The others need a person to answer.</span>
              </span>
            </button>
          );
        })}
      </div>
      <p className={hx("note")}>Guidelines advise only. Selecting one adds the Compliance reader as an optional step. It annotates a pull request at notice level and never blocks.</p>
    </Card>
  );
}

