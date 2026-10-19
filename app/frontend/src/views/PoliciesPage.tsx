import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { deletePolicy, getCatalog, getPolicies, previewPolicy, savePolicy, type Written } from "../api/portfolio";
import { useApi } from "../hooks/useApi";
import { Kit } from "../kit/Kit";
import { Empty, PageHead } from "../hx/components";
import { hx } from "../hx/hx";
import type { Application, AppProfile, Portfolio, PolicyListPayload, PolicyPreview, PolicyRec } from "../portfolio";
import { GuidelinesCard, StepsCard, WhoWhen, type Edit, type FitsElsewhere } from "./policy/Builder";
import { PolicyCard, TemplateMenu, type LibItem } from "./policy/Library";
import { RunIt, type RunTab } from "./policy/RunIt";
import { DeleteDialog, GateCard, SavePanel, type AppLite } from "./policy/SavePanel";
import {
  PROFILE_FIELDS, appliesText, blankDraft, draftFromPolicy, fingerprint, fitsProfile, hydratePacks, hydrateSteps, inCatalogOrder,
  localErrors, slotOf, templateDraft, toBody, uniqueId, type Draft,
} from "./policy/model";
import "./PoliciesPage.css";

type Go = (name: string, param?: string | null) => void;
type PApp = Application & AppProfile;

/** The gate wording is fixed by Docket and arrives with every policy. This is only for the moment
 *  before any policy has loaded, so the banner is never empty. */
const GATE_FALLBACK: PolicyRec["gate"] = [
  { effect: "blocks", text: "A reproduced exploit, a secret in source or another deterministic rule, or a triage verdict of confirmed." },
  { effect: "flags", text: "A required scanner that did not run inside its window." },
  { effect: "advises", text: "Compliance results. They annotate the pull request and never block it." },
];

/** `#/policy/banking-customer?step=triage&run=last&app=ibank%2Fdisputes&new=blank` — a deep link for
 *  review. Only the policy id is needed in normal use. */
function parseParam(param: string | null) {
  const [id = "", q = ""] = (param ?? "").split("?");
  const p = new URLSearchParams(q);
  return { policy: id || null, step: p.get("step"), run: p.get("run"), app: p.get("app"), fresh: p.get("new") };
}

const msg = (e: unknown) => (e instanceof Error ? e.message : String(e));
const reduced = () => window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
const bring = (el: HTMLElement | null | undefined, focus = false) => {
  if (!el) return;
  el.scrollIntoView({ behavior: reduced() ? "auto" : "smooth", block: "center" });
  if (focus) el.focus({ preventScroll: true });
};

export function PoliciesPage({ go, portfolio, onPortfolioChanged, connected, param }: {
  go: Go; portfolio: Portfolio | null; onPortfolioChanged: () => void; connected: boolean; param: string | null;
}) {
  const catalogApi = useApi(getCatalog, "catalog");
  const catalog = catalogApi.data;
  const initial = useMemo(() => parseParam(param), []); // eslint-disable-line react-hooks/exhaustive-deps

  // ── the policies on disk (own loader: a save must wait for the refetch before moving the selection)
  const [list, setList] = useState<{ data: PolicyListPayload | null; error: string | null }>({ data: null, error: null });
  const [epoch, setEpoch] = useState(0);
  const refresh = useCallback(async () => {
    try {
      const data = await getPolicies();
      setList({ data, error: null });
      setEpoch((n) => n + 1);
      return data;
    } catch (e) {
      setList((l) => ({ ...l, error: msg(e) }));
      return null;
    }
  }, []);
  useEffect(() => { void refresh(); }, [refresh]);
  const policies = useMemo(() => list.data?.policies ?? [], [list.data]);

  // ── selection and working copies (unsaved edits survive switching cards)
  const [sel, setSel] = useState<string | null>(initial.policy);
  const [work, setWork] = useState<Record<string, Draft>>({});
  const [selStep, setSelStep] = useState<string | null>(initial.step);
  const [newN, setNewN] = useState(0);
  const [runTab, setRunTab] = useState<RunTab>(initial.run === "last" ? "last" : "plan");
  const [appId, setAppId] = useState<string | null>(initial.app);
  const [flash, setFlash] = useState<"pre" | "agents" | "guidelines" | null>(null);
  const paletteRef = useRef<HTMLDivElement>(null);
  const guidelinesRef = useRef<HTMLDivElement>(null);
  const flowRef = useRef<HTMLDivElement>(null);

  const draftKeys = Object.keys(work).filter((k) => work[k]!.savedId == null);
  const selKey = (sel && (policies.some((p) => p.id === sel) || work[sel]) ? sel : policies[0]?.id) ?? draftKeys[0] ?? null;
  const saved = policies.find((p) => p.id === selKey) ?? null;
  const savedDraft = useMemo(() => (saved && catalog ? draftFromPolicy(saved, catalog) : null), [saved, catalog]);
  const draft: Draft | null = selKey ? work[selKey] ?? savedDraft : null;
  const isNew = draft ? draft.savedId == null : false;
  const dirty = Boolean(draft && catalog && (isNew || (savedDraft && fingerprint(draft, catalog) !== fingerprint(savedDraft, catalog))));
  const takenIds = policies.map((p) => p.id);
  const draftId = draft ? draft.savedId ?? uniqueId(draft.name, takenIds) : "";
  const builtin = saved?.id === "default";

  const [notice, setNotice] = useState<string | null>(null);
  const [saveErrors, setSaveErrors] = useState<string[]>([]);
  const [saving, setSaving] = useState(false);
  const [saveWarnings, setSaveWarnings] = useState<string[]>([]);

  const selRef = useRef({ selKey, savedDraft, catalog });
  selRef.current = { selKey, savedDraft, catalog };
  const edit: Edit = useCallback((fn) => {
    const { selKey: key, savedDraft: base, catalog: cat } = selRef.current;
    if (!key || !cat) return;
    setWork((w) => {
      const cur = w[key] ?? base;
      if (!cur) return w;
      const next = JSON.parse(JSON.stringify(cur)) as Draft;
      fn(next);
      next.steps = inCatalogOrder(next.steps, cat);
      return { ...w, [key]: next };
    });
    setNotice(null); setSaveErrors([]); setSaveWarnings([]);
  }, []);

  // ── debounced preview of the draft (300 ms): matches, who would be current, what changes
  const body = draft && catalog ? toBody(draft, draftId, catalog) : null;
  const bodyKey = body ? JSON.stringify(body) : "";
  const local = draft ? localErrors(draft) : [];
  const [pv, setPv] = useState<{ forKey: string | null; res: Written<PolicyPreview> } | null>(null);
  const [pvBusy, setPvBusy] = useState(false);
  const skipPreview = !body || (draft?.steps.length ?? 0) === 0 || !draft?.name.trim();
  useEffect(() => {
    if (!body || skipPreview) { setPv(null); setPvBusy(false); return; }
    let alive = true;
    setPvBusy(true);
    const h = setTimeout(async () => {
      const res = await previewPolicy(body);
      if (alive) { setPv({ forKey: selKey, res }); setPvBusy(false); }
    }, 300);
    return () => { alive = false; clearTimeout(h); };
    // body is derived from bodyKey; epoch re-runs it after a save or delete changed the file
  }, [bodyKey, epoch]); // eslint-disable-line react-hooks/exhaustive-deps
  const pvHere = pv && pv.forKey === selKey ? pv.res : null;
  const preview = pvHere?.ok ? pvHere.body : null;
  const previewErrors = pvHere && !pvHere.ok ? pvHere.errors : [];

  // A link to #/policy/<id> from elsewhere (an application page) moves the selection.
  const firstParam = useRef(true);
  useEffect(() => {
    if (firstParam.current) { firstParam.current = false; return; }
    const next = parseParam(param);
    if (next.policy) { setSel(next.policy); setSelStep(next.step); }
    if (next.run) setRunTab(next.run === "last" ? "last" : "plan");
    if (next.app) setAppId(next.app);
  }, [param]);

  // ── applications
  const apps = useMemo(() => (portfolio?.applications ?? []) as PApp[], [portfolio]);
  const assignedTo = (a: PApp) => a.assignment?.policy ?? a.policy ?? null;
  const underSaved = saved ? apps.filter((a) => assignedTo(a) === saved.id).map((a) => a.id) : [];
  const underDraft = preview && (dirty || isNew) ? preview.matches.map((m) => m.id) : underSaved;
  const fitsElsewhere: FitsElsewhere[] = useMemo(() => {
    if (!draft || !preview) return [];
    const mine = new Set(preview.matches.map((m) => m.id));
    return apps.filter((a) => !mine.has(a.id) && assignedTo(a) !== draft.savedId && fitsProfile(draft.applies_when, a))
      .map((a) => ({ id: a.id, label: a.label, policyName: policies.find((p) => p.id === assignedTo(a))?.name ?? "the built-in baseline" }));
  }, [draft, preview, apps, policies]); // eslint-disable-line react-hooks/exhaustive-deps
  const appLite: AppLite[] = useMemo(() => apps.map((a) => ({ id: a.id, label: a.label, tier: a.tier })), [apps]);

  // ── coverage of the SAVED policy (the matrix and the gate result of a real run)
  const savedId = saved?.id ?? null;
  const cov = useApi<PolicyListPayload | null>(() => (savedId ? getPolicies(savedId) : Promise.resolve(null)), `cov:${savedId}:${epoch}`);
  const coverage = cov.data && cov.data.coverage.policy === savedId ? cov.data.coverage : null;

  // ── the flow (hero)
  const gate = policies.find((p) => p.gate?.length)?.gate ?? GATE_FALLBACK;
  const flowProps = useMemo(() => (draft && catalog ? {
    mode: "design", starts: catalog.starts, gate,
    policy: { id: draft.key, name: draft.name || "Untitled policy", applies: appliesText(draft.applies_when), cadence_days: draft.cadence_days, steps: hydrateSteps(draft, catalog), guidelines: draft.guidelines },
    guidelines: hydratePacks(draft, catalog),
    warnings: preview?.warnings ?? (dirty ? [] : saved?.warnings ?? []),
    selected: selStep ?? undefined,
    helpText: "The whole policy as one picture, left to right: how a run begins, the scanners from any vendor, the Docket agents, the guidelines that advise, the gate, and what people get. Select a station to edit it.",
    source: { label: "docket_policy.json" },
  } : null), [draft, catalog, gate, preview, dirty, saved, selStep]);
  const flowOn = useMemo(() => ({
    "docket:station": (d: Record<string, string | undefined>) => {
      const id = d.id ?? null;
      setSelStep((s) => (s === id ? null : id));
      window.setTimeout(() => bring(document.querySelector<HTMLElement>(`[data-step="${id}"]`)), 30);
    },
    "docket:add-station": (d: Record<string, string | undefined>) => {
      setFlash(d.group === "agents" ? "agents" : "pre");
      bring(paletteRef.current, true);
      window.setTimeout(() => setFlash(null), 1800);
    },
    "docket:add-guideline": () => {
      setFlash("guidelines");
      bring(guidelinesRef.current, true);
      window.setTimeout(() => setFlash(null), 1500);
    },
  }), []);

  // ── library
  const libKeys = [...policies.map((p) => p.id), ...draftKeys];
  const items: LibItem[] = catalog ? libKeys.map((key) => {
    const p = policies.find((x) => x.id === key) ?? null;
    const d = work[key] ?? (p ? draftFromPolicy(p, catalog) : null);
    if (!d) return null;
    const dots = d.steps.flatMap((s) => { const sl = slotOf(catalog, s.id); return sl ? [{ id: s.id, label: sl.label, required: s.required, group: sl.phase }] : []; });
    const warning = key === selKey ? (preview?.warnings[0] ?? (dirty ? null : p?.warnings[0] ?? null)) : p?.warnings[0] ?? null;
    return {
      key, name: d.name, when: PROFILE_FIELDS.flatMap(([f]) => d.applies_when[f]), dots,
      required: dots.filter((x) => x.required).length, optional: dots.filter((x) => !x.required).length,
      applies: p ? p.applies_count : null, meets: p ? p.meets_count : null,
      draft: !p, dirty: Boolean(work[key] && p && fingerprint(work[key]!, catalog) !== fingerprint(draftFromPolicy(p, catalog), catalog)),
      warning, builtin: key === "default",
    } satisfies LibItem;
  }).filter((x): x is LibItem => x !== null) : [];

  const choose = (key: string) => { setSel(key); setSelStep(null); setNotice(null); setSaveErrors([]); setSaveWarnings([]); };
  const startNew = useCallback((templateId: string | null) => {
    if (!catalog) return;
    const key = `new-${newN + 1}`;
    const tpl = templateId ? policies.find((p) => p.id === templateId) : null;
    setNewN((n) => n + 1);
    setWork((w) => ({ ...w, [key]: tpl ? templateDraft(tpl, key, catalog) : blankDraft(key, catalog) }));
    choose(key);
    window.setTimeout(() => bring(flowRef.current), 30);
  }, [catalog, newN, policies]);
  const startedFresh = useRef(false);
  useEffect(() => {
    if (!initial.fresh || startedFresh.current || !catalog || !list.data) return;
    startedFresh.current = true;
    startNew(initial.fresh === "blank" ? null : initial.fresh);
  }, [initial.fresh, catalog, list.data, startNew]);

  // ── save, discard, delete
  const save = async () => {
    if (!draft || !catalog) return;
    setSaving(true); setSaveErrors([]); setNotice(null);
    const res = await savePolicy(toBody(draft, draftId, catalog));
    if (!res.ok) { setSaveErrors(res.errors); setSaving(false); return; }
    const key = draft.key, name = draft.name.trim();
    await refresh();
    setWork((w) => { const n = { ...w }; delete n[key]; return n; });
    setSel(draftId);
    setNotice(`Saved “${name}”. Only the policy file was written; no scan was started.`);
    setSaveWarnings(res.body?.warnings ?? []);
    onPortfolioChanged();
    setSaving(false);
  };
  const discard = () => {
    if (!selKey) return;
    setWork((w) => { const n = { ...w }; delete n[selKey]; return n; });
    if (isNew) setSel(policies[0]?.id ?? null);
    setSelStep(null); setSaveErrors([]); setNotice(null); setSaveWarnings([]);
  };
  const [confirmDel, setConfirmDel] = useState(false);
  const [delBusy, setDelBusy] = useState(false);
  const [delError, setDelError] = useState<string | null>(null);
  const confirmDelete = async () => {
    if (!saved) return;
    setDelBusy(true); setDelError(null);
    const res = await deletePolicy(saved.id);
    if (!res.ok) { setDelError(res.errors.join(" ")); setDelBusy(false); return; }
    await refresh();
    setWork((w) => { const n = { ...w }; delete n[saved.id]; return n; });
    setSel(null); setSelStep(null); setConfirmDel(false); setDelBusy(false);
    setNotice(`Deleted “${saved.name}”.`);
    onPortfolioChanged();
  };

  const errors = [...local, ...previewErrors.filter((e) => !local.includes(e)), ...(preview?.conflicts ?? []), ...saveErrors];
  const warnings = [...(preview?.warnings ?? (dirty ? [] : saved?.warnings ?? [])), ...saveWarnings.filter((w) => !(preview?.warnings ?? []).includes(w))];

  const runApps = apps.map((a) => ({ id: a.id, label: a.label, tier: a.tier, repo: a.repo }));
  const gateFor = useCallback((id: string) => coverage?.rows.find((r) => r.id === id)?.consequence ?? null, [coverage]);

  const head = (
    <PageHead eyebrow="Code Security" title="Policies"
      sub="A policy says which checks an application must have had, from any vendor, how recently, and what a gap means. Docket runs one fixed pipeline; the policy judges it."
      actions={catalog ? (
        <div className="pol-libhead">
          <TemplateMenu templates={policies.map((p) => ({ id: p.id, name: p.name, sub: appliesText(p.applies_when) }))} onPick={startNew} />
          <button type="button" className={hx("btn primary")} onClick={() => startNew(null)}>New policy</button>
        </div>
      ) : null} />
  );

  if (list.error && !list.data) return <>{head}<Empty>The policies could not be loaded: {list.error}</Empty></>;
  if (catalogApi.error && !catalog) return <>{head}<Empty>The catalog could not be loaded: {catalogApi.error}</Empty></>;
  if (!catalog || !list.data) return <>{head}<Empty>Loading the policies.</Empty></>;

  return (
    <>
      {head}
      {list.data.conflicts.length ? (
        <div className="pol-conflict" role="status">
          <b>Two policies are equally specific for the same applications</b>
          {list.data.conflicts.map((c) => <div key={c.ids.join("|")}>{c.message}.</div>)}
        </div>
      ) : null}
      <div className="pol-lib" role="group" aria-label="Policy library">
        {items.map((it) => <PolicyCard key={it.key} item={it} selected={it.key === selKey} onSelect={() => choose(it.key)} />)}
      </div>

      {!draft ? <Empty>No policy is defined yet, so the built-in baseline applies to every application. Start one with New policy.</Empty> : (
        <div className="pol-stack">
          <div ref={flowRef} className="pol-flowhost" style={{ marginBottom: 0 }}>
            {flowProps ? <Kit tag="docket-policy-flow" props={flowProps} on={flowOn} /> : null}
          </div>
          <div className="pol-grid">
            <div className="pol-stack">
              <WhoWhen draft={draft} catalog={catalog} edit={edit} matches={preview?.matches ?? null} previewing={pvBusy} savedId={draftId} fitsElsewhere={fitsElsewhere} />
              <StepsCard draft={draft} catalog={catalog} edit={edit} selStep={selStep} setSelStep={setSelStep}
                         flashGroup={flash === "pre" || flash === "agents" ? flash : null} paletteRef={paletteRef} />
              <GuidelinesCard draft={draft} catalog={catalog} edit={edit} flash={flash === "guidelines"} sectionRef={guidelinesRef} />
            </div>
            <div className="pol-side">
              <SavePanel preview={preview} previewing={pvBusy} apps={appLite}
                         state={{ dirty, isNew, saving, builtin, errors, warnings, notice, canDelete: Boolean(saved) && !builtin }}
                         onSave={save} onDiscard={discard} onDelete={() => { setDelError(null); setConfirmDel(true); }} />
              <GateCard gate={gate} />
            </div>
          </div>
          <RunIt draft={draft} catalog={catalog} gate={gate} apps={runApps} underPolicy={underDraft} dirty={dirty} isNew={isNew}
                 gateFor={gateFor} connected={connected} onRunNow={() => go("repos")} tab={runTab} setTab={setRunTab}
                 appId={appId} setAppId={setAppId} />
          <Reality go={go} saved={saved} dirty={dirty} isNew={isNew} coverage={coverage} loading={cov.loading && !coverage} error={cov.error} />
        </div>
      )}
      {confirmDel && saved ? (
        <DeleteDialog name={saved.name} applications={appLite.filter((a) => underSaved.includes(a.id))} busy={delBusy} error={delError}
                      onCancel={() => setConfirmDel(false)} onConfirm={confirmDelete} />
      ) : null}
    </>
  );
}

/** Policy against reality: the v1 matrix for the saved policy, as before, under the new wording. */
function Reality({ go, saved, dirty, isNew, coverage, loading, error }: {
  go: Go; saved: PolicyRec | null; dirty: boolean; isNew: boolean; coverage: PolicyListPayload["coverage"] | null; loading: boolean; error: string | null;
}) {
  const props = useMemo(() => (coverage && saved ? {
    heading: `Policy against reality: ${saved.name}`,
    windowDays: coverage.window_days, scanners: coverage.scanners, rows: coverage.rows,
    helpText: "Each cell asks: did this required check finish inside the policy window for this application? The last column says what that adds up to: a stale check flags, a reproduced exploit blocks.",
    source: { label: "Docket scans" },
  } : null), [coverage, saved]);
  const on = useMemo(() => ({
    "docket:open-app": (d: Record<string, string | undefined>) => { if (d.id) go("app", d.id); },
  }), [go]);
  if (isNew || !saved) {
    return <section className={hx("hc")}><header><div className={hx("grow")}><h3>Policy against reality</h3></div></header>
      <div className={hx("pad")}><Empty>Save this policy to see it against the latest runs of the applications it covers.</Empty></div></section>;
  }
  return (
    <div>
      <p className="pol-lead" aria-live="polite">
        <b>{saved.meets_count ?? 0} of {saved.applies_count}</b> application{saved.applies_count === 1 ? "" : "s"} have every required check current
        {dirty ? <span className="pol-sub2"> · showing the saved policy, not your unsaved changes</span> : null}
      </p>
      {error && !coverage ? <Empty>The matrix could not be loaded: {error}</Empty>
        : loading || !props ? <Empty>Loading the matrix.</Empty>
        : <Kit tag="docket-policy-matrix" props={props} on={on} />}
    </div>
  );
}
