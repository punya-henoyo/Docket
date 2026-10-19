import { useEffect, useMemo, useRef } from "react";
import type { PolicyPreview } from "../../portfolio";
import { Card, Help, useSort } from "../../hx/components";
import { hx } from "../../hx/hx";
import { OUTCOME_WORD } from "./model";

export interface AppLite { id: string; label: string; tier: string }

type Change = PolicyPreview["changes"][number] & { tier: string };
const STATE_ORDER = { meets: 0, breaches: 1, none: 2 } as const;
const ACCESS = {
  app: (c: Change) => c.label, tier: (c: Change) => c.tier,
  now: (c: Change) => STATE_ORDER[c.before], after: (c: Change) => STATE_ORDER[c.after], why: (c: Change) => c.why,
};

/** Outcome as a word, never colour alone: "Current" / "Lacks a check" / "Baseline only". */
function State({ s, why }: { s: Change["before"]; why?: string }) {
  if (s === "meets") return <span className={hx("chip ok")}>{OUTCOME_WORD.meets}</span>;
  if (s === "breaches") return <span className={hx("chip warn")} title={why}>{OUTCOME_WORD.breaches}</span>;
  return <span className={hx("chip neutral")} title="Under the built-in baseline, not judged by a saved policy">{OUTCOME_WORD.none}</span>;
}

export interface SaveState {
  dirty: boolean; isNew: boolean; saving: boolean; builtin: boolean;
  /** Reasons the draft cannot be saved: ours, the preview's, ties, and the last refused save. */
  errors: string[]; warnings: string[]; notice: string | null; canDelete: boolean;
}

export function SavePanel({ preview, previewing, apps, state, onSave, onDiscard, onDelete }: {
  preview: PolicyPreview | null; previewing: boolean; apps: AppLite[]; state: SaveState;
  onSave: () => void; onDiscard: () => void; onDelete: () => void;
}) {
  const base = useMemo(() => {
    const tier = new Map(apps.map((a) => [a.id, a.tier]));
    return (preview?.changes ?? []).map((c) => ({ ...c, tier: tier.get(c.id) ?? "" }));
  }, [preview, apps]);
  const changes = base;
  const { rows, Th } = useSort(base, ACCESS);
  const unchanged = Math.max(0, apps.length - changes.length);
  const blocked = state.errors.length > 0;
  return (
    <section className={hx("hc")} aria-label="If you save">
      <header>
        <div className={hx("grow")}>
          <h3>
            If you save
            <Help text="Computed from the latest runs of every application, with nothing sent anywhere. It compares what each application gets today with what it would get if this draft were saved." />
            {state.dirty ? <span className={hx("chip warn")} style={{ marginLeft: 8 }}>Unsaved changes</span> : null}
          </h3>
          <p>{state.dirty || state.isNew ? "The effect of this draft on every application." : "No unsaved changes. This is the saved policy."}</p>
        </div>
      </header>
      <div className={`${hx("pad")} pol-sv`} aria-busy={previewing}>
        <div className="pol-big">
          <div><b>{preview ? preview.matches.length : "…"}</b><span>Matches</span></div>
          <div><b>{preview ? preview.would_meet : "…"}</b><span>Would be current</span></div>
          <div className="pol-lack"><b>{preview ? preview.would_breach : "…"}</b><span>Would lack a check</span></div>
        </div>
        {state.warnings.length ? (
          <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
            {state.warnings.map((w) => <span key={w} className={hx("chip warn")}>{w}</span>)}
          </div>
        ) : null}
        {state.errors.map((e) => <div key={e} className="pol-err" role="alert">{e}</div>)}
        {state.notice ? <div className="pol-ok" role="status">{state.notice}</div> : null}
        {preview == null ? <p className="pol-sub2" style={{ margin: 0 }}>{previewing ? "Working out who is affected…" : "Fix the points above to see who is affected."}</p>
          : changes.length === 0 ? <p className="pol-sub2" style={{ margin: 0 }}>Nothing changes for any application.</p> : (
            <div style={{ overflowX: "auto" }}>
              <table className={`${hx("lv")} pol-table`}>
                <thead>
                  <tr><Th k="app">Application</Th><Th k="now">Now</Th><Th k="after">If you save</Th></tr>
                </thead>
                <tbody>
                  {rows.map((c) => (
                    <tr key={c.id}>
                      <td><b>{c.label}</b>{c.tier ? <span className="pol-sub2"> · {c.tier}</span> : null}<div className="pol-sub2">{c.why}</div></td>
                      <td><State s={c.before} /></td><td><State s={c.after} why={c.why} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <p className="pol-sub2" style={{ margin: "8px 0 0" }}>{unchanged} other application{unchanged === 1 ? "" : "s"} would not change.</p>
            </div>
          )}
        <div className="pol-btns">
          <button type="button" className={hx("btn primary")} disabled={!state.dirty && !state.isNew || blocked || state.saving} onClick={onSave}>{state.saving ? "Saving…" : "Save"}</button>
          <button type="button" className={hx("btn")} disabled={!state.dirty && !state.isNew || state.saving} onClick={onDiscard}>Discard</button>
          <span className="pol-grow" />
          <button type="button" className={`${hx("btn")} pol-danger`} disabled={!state.canDelete || state.saving} onClick={onDelete}
                  title={state.builtin ? "The built-in baseline cannot be deleted" : state.canDelete ? "Remove this policy" : "Not saved yet"}>Delete</button>
        </div>
        <p className="pol-sub2" style={{ margin: 0 }}>Save only writes the policy file. It does not start a scan. Approval is not editable until an audit trail exists.</p>
      </div>
    </section>
  );
}

export function GateCard({ gate }: { gate: { effect: "blocks" | "flags" | "advises"; text: string }[] }) {
  const cls = { blocks: ["bad", "Blocks"], flags: ["warn", "Flags"], advises: ["neutral", "Advises"] } as const;
  return (
    <Card title="The gate" sub="Fixed for every policy."
          tip="What a run concludes is fixed by Docket. A policy cannot change it: it only decides which checks must have run.">
      <div className={hx("gate")}>
        {gate.map((g) => <div key={g.effect}><span className={hx(`chip ${cls[g.effect][0]}`)}>{cls[g.effect][1]}</span> {g.text}</div>)}
      </div>
      <p className="pol-sub2" style={{ margin: "10px 0 0" }}><span className={hx("chip neutral")}>Read-only</span> The policy cannot change this wording.</p>
    </Card>
  );
}

/** In-page confirmation (no window.confirm: it blocks browser tooling and cannot list applications). */
export function DeleteDialog({ name, applications, busy, error, onCancel, onConfirm }: {
  name: string; applications: AppLite[]; busy: boolean; error: string | null; onCancel: () => void; onConfirm: () => void;
}) {
  const keep = useRef<HTMLButtonElement>(null);
  useEffect(() => { keep.current?.focus(); }, []);
  return (
    <div className="pol-dlg-scrim" onMouseDown={(e) => { if (e.target === e.currentTarget) onCancel(); }}
         onKeyDown={(e) => {
           if (e.key === "Escape") onCancel();
           if (e.key === "Tab") {
             const f = [...e.currentTarget.querySelectorAll<HTMLElement>("button:not([disabled])")];
             if (!f.length) return;
             const first = f[0]!, last = f[f.length - 1]!;
             if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
             else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
           }
         }}>
      <div className="pol-dlg" role="dialog" aria-modal="true" aria-labelledby="pol-del-t">
        <h3 id="pol-del-t">Delete “{name}”?</h3>
        <p style={{ margin: 0 }}>
          {applications.length
            ? `${applications.length} application${applications.length === 1 ? "" : "s"} would fall to another matching policy, or to the built-in baseline, and may start to lack checks.`
            : "No application uses this policy."}
        </p>
        {applications.length ? <ul>{applications.map((a) => <li key={a.id}><b>{a.label}</b> <span className="pol-sub2">{a.tier}</span></li>)}</ul> : null}
        {error ? <div className="pol-err" role="alert">{error}</div> : null}
        <div className="pol-btns" style={{ justifyContent: "flex-end", marginTop: 12 }}>
          <button type="button" ref={keep} className={hx("btn")} onClick={onCancel} disabled={busy}>Keep it</button>
          <button type="button" className={`${hx("btn")} pol-danger`} onClick={onConfirm} disabled={busy}>{busy ? "Deleting…" : "Delete policy"}</button>
        </div>
      </div>
    </div>
  );
}
