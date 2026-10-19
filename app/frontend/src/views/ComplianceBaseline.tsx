import { useMemo, useRef, useState } from "react";
import { ApiError } from "../api/client";
import { deletePack, getPack, listPacks, uploadPack, type UploadResult } from "../api/compliance";
import { getRun } from "../api/github";
import { useApi } from "../hooks/useApi";
import type { Application, Level, Portfolio } from "../portfolio";
import type { ControlDefinition, ControlResult, PackResult, PackSummary } from "../types";
import { Card, Empty, Help, PageHead, ago, useSort } from "../hx/components";
import { hx } from "../hx/hx";
import "./ComplianceBaseline.css";

type Go = (name: string, param?: string | null) => void;

/** Pack controls as the API sends them: the shared type predates the citation fields
 *  (api-contract.md, "Compliance citations"). */
type Def = ControlDefinition & {
  clause?: string | null;
  obligation_ref?: string | null;
  citation_parts?: { authority?: string | null; instrument?: string | null; section?: string | null; clause?: string | null; source_url?: string | null } | null;
};

/** A control's standing for this application. "assessed" is absent when the pack was never run:
 *  that is not the same as unknown, and it is never counted as met. */
type Key = "pass" | "fail" | "unknown" | "not_observable" | "not_applicable" | "not_assessed";
const STATUS: Record<Key, { cls: string; word: string }> = {
  pass: { cls: "ok", word: "Met" },
  fail: { cls: "bad", word: "Not met" },
  unknown: { cls: "warn", word: "Unknown" },
  not_observable: { cls: "neutral", word: "Not answerable from code" },
  not_applicable: { cls: "neutral", word: "Not applicable" },
  not_assessed: { cls: "neutral", word: "Not assessed" },
};
// Tiles: the four the mockup shows always; the other two only when something is in them.
const TILES: { key: Key; tone: string; always: boolean }[] = [
  { key: "pass", tone: "ok", always: true },
  { key: "fail", tone: "bad", always: true },
  { key: "unknown", tone: "un", always: true },
  { key: "not_observable", tone: "na", always: true },
  { key: "not_applicable", tone: "na", always: false },
  { key: "not_assessed", tone: "na", always: false },
];
const LIVES: Record<string, string> = { source: "In code", process: "Process", runtime: "Runtime" };
const LEVEL_RANK: Record<Level, number> = { action: 0, attention: 1, clear: 2, unknown: 3 };

interface Row { def: Def; res?: ControlResult; key: Key; linked: string[] }

const ACCESS: Record<string, (r: Row) => string | number | null> = {
  control: (r) => r.def.title,
  citation: (r) => `${r.def.citation_parts?.instrument ?? r.def.citation} ${r.def.citation_parts?.section ?? ""}`,
  lives: (r) => LIVES[r.def.observability] ?? r.def.observability,
  result: (r) => STATUS[r.key].word,
  read: (r) => r.res?.rationale ?? "",
};

const errText = (e: unknown) => (e instanceof ApiError ? e.message : String(e));

/** Authority chip, instrument, section, clause (never invented: "not mapped" unless the pack
 *  supplies one), the source and the obligation. Shared by the baseline table and the library. */
function Cite({ def, authority, go }: { def: Def; authority?: string; go: Go }) {
  const p = def.citation_parts;
  const auth = p?.authority ?? authority;
  const clause = p?.clause ?? def.clause;
  return (
    <div className={hx("cite")}>
      <div className={hx("a")}>
        {auth ? <span className={hx("chip reg")}>{auth}</span> : null}
        <span>{p?.instrument ?? def.citation}</span>
      </div>
      {p?.section ? <div className={hx("t")}>{p.section}</div> : null}
      <div className={hx("ob")}>
        {clause ? `Clause: ${clause}` : "Clause: not mapped"}
        {p?.source_url ? <> · <a href={p.source_url} target="_blank" rel="noopener noreferrer">↗ source</a></> : null}
        {def.obligation_ref ? <> · <a href="#/compliance" title="Resolves to a Henoyo control requirement" onClick={(e) => { e.preventDefault(); go("compliance"); }}>↗ {def.obligation_ref}</a></> : null}
      </div>
    </div>
  );
}

function ControlsTable({ rows, go, authority }: { rows: Row[]; go: Go; authority?: string }) {
  const { rows: sorted, Th } = useSort(rows, ACCESS);
  return (
    <table className={hx("lv ctable")}>
      <thead>
        <tr>
          <Th k="control">Control</Th><Th k="citation">Regulatory citation</Th><Th k="lives">Where it lives</Th>
          <Th k="result">Result</Th><Th k="read">What was read</Th>
        </tr>
      </thead>
      <tbody>
        {sorted.length === 0 ? <tr><td colSpan={5} className={hx("empty")}>No control matches this filter.</td></tr> : sorted.map((r) => {
          const s = STATUS[r.key];
          const res = r.res;
          const reproduced = !!res && (res.escalated || res.proven_findings.length > 0 || res.contradicted_by.length > 0);
          return (
            <tr key={r.def.id}>
              <td style={{ minWidth: 230 }}><div className={hx("tt")}>{r.def.title}</div><div className={hx("ms mono")}>{r.def.id}</div></td>
              <td><Cite def={r.def} authority={authority} go={go} /></td>
              <td>{LIVES[r.def.observability] ?? r.def.observability}</td>
              <td>
                <span className={hx(`chip ${s.cls}`)}>{s.word}</span>
                {reproduced ? <div className={hx("also")}>◆ Also reproduced</div> : null}
              </td>
              <td className={hx("rd")}>
                {res ? (
                  <>
                    {res.rationale}
                    {res.downgraded_from ? <div className={hx("ms")}>Claimed {STATUS[res.downgraded_from]?.word ?? res.downgraded_from}, downgraded: the citation could not be confirmed in the scanned code.</div> : null}
                    {res.status === "unknown" && res.looked_at ? <div className={hx("ms")}>Looked at: {res.looked_at}</div> : null}
                    {res.citations.map((c, i) => (
                      <div key={i}>
                        <div className={hx("ms mono")}>{c.file}{c.line != null ? `:${c.line}` : ""}</div>
                        {c.quote ? <pre className={`code ${hx("quote")}`}>{c.quote}</pre> : null}
                      </div>
                    ))}
                    {r.linked.length ? <div className={hx("ms")}>Linked: {r.linked.join("; ")} (reproduced)</div> : null}
                  </>
                ) : <span className={hx("ms")}>This pack has not been run against this application.</span>}
              </td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}

/** Results for one application's latest run, one pack at a time. Keyed by run so a switch of
 *  application starts from that application's own packs. */
function Results({ app, eventId, packs, go }: { app: Application; eventId: string; packs: PackSummary[]; go: Go }) {
  const run = useApi(() => getRun(eventId), `run:${eventId}`);
  const [pick, setPick] = useState<string | null>(null);
  const [filter, setFilter] = useState<Key | "all">("all");

  const results: PackResult[] = run.data?.compliance ?? [];
  const usable = packs.filter((p) => p.usable);
  const active = usable.find((p) => p.id === pick)
    ?? usable.find((p) => results.some((r) => r.pack_id === p.id))
    ?? usable[0];
  const result = results.find((r) => r.pack_id === active?.id);

  const pack = useApi(() => (active ? getPack(active.id) : Promise.reject(new Error("no pack"))), `pack:${active?.id ?? ""}`);
  const rows = useMemo<Row[]>(() => {
    if (!pack.data) return [];
    const byId = new Map((result?.results ?? []).map((r) => [r.control_id, r]));
    const titles = new Map((run.data?.findings ?? []).map((f) => [f.dedupe_key, f.title]));
    const out: Row[] = (pack.data.pack.controls as Def[]).map((def) => {
      const res = byId.get(def.id);
      const linked = res ? [...res.proven_findings, ...res.contradicted_by].map((k) => titles.get(k)).filter((t): t is string => !!t) : [];
      return { def, res, key: res ? res.status : "not_assessed", linked };
    });
    return out;
  }, [pack.data, result, run.data]);

  const count = (k: Key) => rows.filter((r) => r.key === k).length;
  const shown = filter === "all" ? rows : rows.filter((r) => r.key === filter);
  const readable = active?.source_controls;

  if (usable.length === 0) return <Empty>No control pack is available yet. Upload a policy below to create one.</Empty>;
  return (
    <div className={hx("stack")}>
      <div className={hx("views")} style={{ padding: 0, border: 0 }}>
        {usable.map((p) => (
          <button key={p.id} className={hx("view")} aria-pressed={p.id === active?.id}
                  onClick={() => { setPick(p.id); setFilter("all"); }}>
            {p.title ?? p.id}<b>{p.total_controls ?? ""}</b>
          </button>
        ))}
      </div>
      {run.error && !run.data ? <Empty>The latest run of {app.label} could not be read: {run.error}</Empty>
        : pack.error && !pack.data ? <Empty>This pack could not be read: {pack.error}</Empty>
        : !pack.data || (run.loading && !run.data) ? <Empty>Loading the controls.</Empty> : (
          <>
            <div className={hx("res")}>
              <button className={hx("count")} aria-pressed={filter === "all"} onClick={() => setFilter("all")}>
                <b>{rows.length}</b><span>All controls</span>
              </button>
              {TILES.filter((t) => t.always || count(t.key) > 0).map((t) => (
                <button key={t.key} className={hx(`count ${t.tone}`)} aria-pressed={filter === t.key}
                        onClick={() => setFilter(filter === t.key ? "all" : t.key)}>
                  <b>{count(t.key)}</b><span>{STATUS[t.key].word}</span>
                </button>
              ))}
            </div>
            <p className={hx("note")} style={{ margin: 0 }}>
              {app.label}{app.age_days != null ? `, scanned ${ago(app.age_days) === "today" ? "today" : `${ago(app.age_days)} ago`}` : ""}.
              {result ? <> {readable != null && active?.total_controls != null ? `${readable} of ${active.total_controls} controls are readable from source. ` : ""}</> : " This pack has not been run against this application, so every control is shown as not assessed. "}
              There is no score: a percentage rewards giving up on the hard controls.
            </p>
            <Card title="Controls" flush
                  tip="Citation shows the authority, the instrument and the section the control is drawn from, with a link to the obligation record in Henoyo so the clause can be filled in once, for every application.">
              <ControlsTable rows={shown} go={go} authority={active?.authority} />
            </Card>
          </>
        )}
    </div>
  );
}

/** The packs that exist, how many of each a repository can answer, and the per-pack control
 *  list with its citations. Upload and delete are the same calls the earlier console made. */
function Library({ packs, error, onChanged, upload }: {
  packs: PackSummary[] | null; error: string | null; onChanged: () => void;
  upload: { busy: boolean; result: UploadResult | null; error: string | null; choose: () => void };
}) {
  const [open, setOpen] = useState<string | null>(null);
  const [delError, setDelError] = useState<string | null>(null);
  const remove = async (id: string) => {
    setDelError(null);
    try { await deletePack(id); if (open === id) setOpen(null); onChanged(); } catch (e) { setDelError(errText(e)); }
  };
  const r = upload.result;
  return (
    <div className={hx("cols2")} id="hx-control-library">
      <Card title="Control library" sub="Checkable from source"
            tip="Which packs exist, and how many of each a repository can answer. Controls that are organisational or deployment properties are reported as not answerable from code, never as met.">
        {error && !packs ? <Empty>The packs could not be listed: {error}</Empty>
          : packs === null ? <Empty>Loading the packs.</Empty>
          : packs.length === 0 ? <Empty>No pack is installed.</Empty> : (
            <div className={hx("lib")}>
              {delError ? <div className={hx("note")}>{delError}</div> : null}
              {packs.map((p) => (
                <div className={hx("pk")} key={p.id}>
                  <div className={hx("top")}>
                    <div className={hx("pkwho")}>
                      <div className={hx("tt")}>{p.title ?? p.id}{p.usable === false ? " · unreadable" : ""}</div>
                      <div className={hx("ms mono")}>{p.id}{p.authority ? ` · ${p.authority}` : ""}{p.origin === "uploaded" ? " · uploaded" : ""}</div>
                    </div>
                    <span className={hx("pknum")}
                          title={p.total_controls != null && p.source_controls != null && p.source_controls < p.total_controls
                            ? `${p.total_controls - p.source_controls} control(s) are organisational or deployment properties and cannot be answered by reading a repository. They are reported as not answerable from code, never as met.` : undefined}>
                      {p.source_controls ?? "—"} of {p.total_controls ?? "—"}
                    </span>
                    {p.usable ? <button className={hx("linkbtn")} aria-expanded={open === p.id} onClick={() => setOpen(open === p.id ? null : p.id)}>{open === p.id ? "Hide controls" : "Controls"}</button> : null}
                    {p.origin === "uploaded" ? <button className={hx("linkbtn")} title="Delete this uploaded pack" onClick={() => remove(p.id)}>Delete</button> : null}
                  </div>
                  {open === p.id ? <PackDefs id={p.id} /> : null}
                </div>
              ))}
            </div>
          )}
      </Card>
      <Card title="Upload a policy"
            tip="Upload your own compliance policy as .md, .txt, .docx or .pdf. An agent reads it and extracts the requirements into a reviewable pack, citing where each one came from. Clauses it cannot locate are dropped rather than invented; organisational ones are recorded as not answerable from code.">
        <div className={hx("upl")}>
          <div><button className={hx("btn primary")} disabled={upload.busy} onClick={upload.choose}>Choose a file</button> <span className={hx("ms")}>.md, .txt, .docx or .pdf</span></div>
          {upload.busy ? <div className={hx("note")}>Reading the document and extracting controls. This takes a few seconds.</div> : null}
          {upload.error ? <div className={hx("note")}>{upload.error}</div> : null}
          {r ? (
            <div style={{ display: "grid", gap: 8 }}>
              <div className={hx("note")}>{r.summary}</div>
              {r.truncated ? <div className={hx("note")}>The document was truncated, so its later sections were not read.</div> : null}
              {r.dropped.length > 0 ? (
                <div>
                  <div className={hx("eyebrow")}>Dropped clauses</div>
                  {r.dropped.map((d, i) => <div key={`${d.title}-${i}`} className={hx("dropped")}>{d.title}: {d.reason}</div>)}
                </div>
              ) : null}
            </div>
          ) : null}
        </div>
      </Card>
    </div>
  );
}

function PackDefs({ id }: { id: string }) {
  const { data, error } = useApi(() => getPack(id), `lib:${id}`);
  if (error && !data) return <div className={hx("note")}>This pack could not be read: {error}</div>;
  if (!data) return <div className={hx("note")}>Loading the controls.</div>;
  const noop = () => undefined;
  return (
    <div className={hx("defs")}>
      {(data.pack.controls as Def[]).map((c) => (
        <div className={hx("def")} key={c.id}>
          <div><div className={hx("tt")}>{c.title}</div><div className={hx("ms mono")}>{c.id}</div></div>
          <Cite def={c} authority={data.pack.authority} go={noop} />
          <div>{LIVES[c.observability] ?? c.observability}</div>
        </div>
      ))}
    </div>
  );
}

export function ComplianceBaseline({ portfolio, go }: { portfolio: Portfolio | null; go: Go }) {
  const packs = useApi(listPacks, "packs");
  const [appId, setAppId] = useState<string | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);
  const [busy, setBusy] = useState(false);
  const [uploaded, setUploaded] = useState<UploadResult | null>(null);
  const [upError, setUpError] = useState<string | null>(null);

  // Only an application with a scan can have results; action-first, as on the other pages.
  const apps = useMemo(() => (portfolio?.applications ?? [])
    .filter((a) => a.events.length > 0)
    .map((a, i) => ({ a, i }))
    .sort((x, y) => LEVEL_RANK[x.a.level] - LEVEL_RANK[y.a.level] || x.i - y.i)
    .map((x) => x.a), [portfolio]);
  const app = apps.find((a) => a.id === appId) ?? apps[0];
  const latest = app?.events.reduce((best, e) => (Date.parse(e.at) > Date.parse(best.at) ? e : best), app.events[0]);

  async function onFile(file: File) {
    setBusy(true); setUpError(null); setUploaded(null);
    try { setUploaded(await uploadPack(file)); packs.reload(); } catch (e) { setUpError(errText(e)); } finally {
      setBusy(false);
      if (fileRef.current) fileRef.current.value = "";
    }
  }
  const choose = () => {
    fileRef.current?.click();
    document.getElementById("hx-control-library")?.scrollIntoView({ behavior: "smooth", block: "start" });
  };

  return (
    <>
      <PageHead eyebrow="Code Security" title="Compliance baseline"
        sub="What the code says about each written requirement. A control result is a reading, not a reproduction, and it never blocks a pull request. Process controls are shown as not answerable from code, never guessed."
        actions={<button className={hx("btn")} onClick={choose}>Upload a policy</button>} />
      <input ref={fileRef} type="file" accept=".md,.markdown,.txt,.text,.docx,.pdf" hidden disabled={busy}
             onChange={(e) => { const f = e.target.files?.[0]; if (f) void onFile(f); }} />
      <div className={hx("stack")}>
        {apps.length > 0 ? (
          <div className={hx("cmpbar")}>
            <label className={hx("csel")}>
              Application
              <select value={app?.id} onChange={(e) => setAppId(e.target.value)}>
                {apps.map((a) => <option key={a.id} value={a.id}>{a.label}</option>)}
              </select>
              <Help text="Results come from the latest scan of the application you pick. Applications that have never been scanned are not listed." />
            </label>
          </div>
        ) : null}
        {!portfolio ? <Empty>Loading the applications.</Empty>
          : !app || !latest ? <Empty>No application has been scanned yet, so there are no control results to read. The control library below still shows what each pack covers.</Empty>
          : packs.error && !packs.data ? <Empty>The control packs could not be listed: {packs.error}</Empty>
          : !packs.data ? <Empty>Loading the control packs.</Empty>
          : <Results key={latest.id} app={app} eventId={latest.id} packs={packs.data.packs} go={go} />}
        <Library packs={packs.data?.packs ?? null} error={packs.error} onChanged={packs.reload}
                 upload={{ busy, result: uploaded, error: upError, choose }} />
      </div>
    </>
  );
}
