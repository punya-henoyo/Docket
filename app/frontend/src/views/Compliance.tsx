import { useEffect, useMemo, useRef, useState } from "react";
import * as api from "../api";
import { ApiError } from "../api";
import type {
  ControlDefinition,
  ControlPack,
  ControlResult,
  ControlStatus,
  PackResult,
  PackSummary,
  ScanState,
} from "../types";
import { ControlDetail, ControlsTable, PackRollup } from "../components/ControlsTable";
import { Drawer, Empty, ErrorNote, Panel } from "../components/ui";

/** Compliance: what a control pack said about this repository, and why.
 *
 *  Two halves. The top is the RESULT of the last scan's packs — nothing here is
 *  invented, and a pack that assessed nothing says so rather than rendering a clean
 *  sheet. The bottom is the LIBRARY: which packs exist, how much of each a repository
 *  can actually answer, and the upload that turns a customer's own policy into one.
 *
 *  The number this page refuses to show is a percentage of the pack. See PackRollup.
 */
export function Compliance({
  scan,
  error,
}: {
  scan: ScanState | null;
  error?: string | null;
}) {
  const packs = useMemo(() => scan?.compliance ?? [], [scan]);
  const [activePack, setActivePack] = useState<string | null>(null);
  const [statusFilter, setStatusFilter] = useState<ControlStatus | null>(null);
  const [selected, setSelected] = useState<ControlResult | null>(null);

  const current: PackResult | null =
    packs.find((p) => p.pack_id === activePack) ?? packs[0] ?? null;

  // Definitions carry the requirement text and the clause reference; the RESULTS carry
  // only a control_id. Fetched per pack rather than inlined into every result, because
  // the requirement is identical for every repository that runs the pack.
  const [definitions, setDefinitions] = useState<Record<string, ControlDefinition>>({});
  useEffect(() => {
    if (!current) return;
    let alive = true;
    api.compliance
      .getPack(current.pack_id)
      .then(({ pack }) => {
        if (!alive) return;
        setDefinitions(Object.fromEntries(pack.controls.map((c) => [c.id, c])));
      })
      .catch(() => {
        // A missing definition degrades to showing the id and the rationale, which is
        // still the useful half. It is not worth an error banner over the results.
        if (alive) setDefinitions({});
      });
    return () => {
      alive = false;
    };
  }, [current?.pack_id]);

  const rows = useMemo(() => {
    const all = current?.results ?? [];
    return statusFilter ? all.filter((r) => r.status === statusFilter) : all;
  }, [current, statusFilter]);

  const titles = useMemo(
    () =>
      Object.fromEntries(
        Object.entries(definitions).map(([id, c]) => [id, c.title]),
      ) as Record<string, string>,
    [definitions],
  );

  return (
    <>
      <div className="page-head">
        <h1>Compliance</h1>
      </div>

      {error && <ErrorNote error={error} />}

      {packs.length === 0 ? (
        <Panel dashed>
          <Empty>
            <div>No control pack has been run against this repository.</div>
            <div className="note">
              Pick one or more packs when you start a scan. An agent reads the source and
              answers each control with a file and line you can open.
            </div>
          </Empty>
        </Panel>
      ) : (
        <>
          {packs.length > 1 && (
            <div className="segmented" style={{ marginBottom: 16 }}>
              {packs.map((p) => (
                <button
                  key={p.pack_id}
                  aria-pressed={current?.pack_id === p.pack_id}
                  onClick={() => {
                    setActivePack(p.pack_id);
                    setStatusFilter(null);
                  }}
                >
                  {p.pack_title}
                  <span className="n">{p.total_controls}</span>
                </button>
              ))}
            </div>
          )}

          {current && (
            <div className="split">
              <div className="stack">
                <Panel title="Coverage">
                  <PackRollup
                    pack={current}
                    selected={statusFilter}
                    onSelect={setStatusFilter}
                  />
                </Panel>
              </div>
              <Panel
                title={current.pack_title}
                action={
                  statusFilter && (
                    <button className="btn sm ghost" onClick={() => setStatusFilter(null)}>
                      Clear filter
                    </button>
                  )
                }
              >
                <ControlsTable
                  results={rows}
                  titles={titles}
                  selectedId={selected?.control_id}
                  onSelect={setSelected}
                />
              </Panel>
            </div>
          )}
        </>
      )}

      <div className="band" style={{ marginTop: 32 }}>
        <h2>Control library</h2>
        <span className="rule" />
      </div>
      <PackLibrary />

      {selected && (
        <Drawer
          title={definitions[selected.control_id]?.title ?? selected.control_id}
          subtitle={selected.control_id}
          onClose={() => setSelected(null)}
        >
          <ControlDetail
            result={selected}
            title={definitions[selected.control_id]?.title}
            requirement={definitions[selected.control_id]?.requirement}
            citation={definitions[selected.control_id]?.citation}
          />
        </Drawer>
      )}
    </>
  );
}

/** Which packs exist, and the one number that matters before you choose: how many of a
 *  pack's controls a repository can actually answer. Shown BEFORE the choice, because
 *  "SEBI CSCRF, 43 controls" and "SEBI CSCRF, 14 of 43 checkable from source" set very
 *  different expectations and only one of them is true. */
function PackLibrary() {
  const [packs, setPacks] = useState<PackSummary[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [uploaded, setUploaded] = useState<{
    pack: ControlPack;
    dropped: { title: string; reason: string }[];
    truncated: boolean;
    summary: string;
  } | null>(null);
  const fileInput = useRef<HTMLInputElement>(null);

  const load = () =>
    api.compliance
      .listPacks()
      .then((r) => setPacks(r.packs))
      .catch((e) => setError(e instanceof ApiError ? e.message : String(e)));

  useEffect(() => {
    load();
  }, []);

  async function upload(file: File) {
    setBusy(true);
    setError(null);
    setUploaded(null);
    try {
      const result = await api.compliance.uploadPack(file);
      setUploaded(result);
      await load();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : String(e));
    } finally {
      setBusy(false);
      if (fileInput.current) fileInput.current.value = "";
    }
  }

  async function remove(id: string) {
    setError(null);
    try {
      await api.compliance.deletePack(id);
      await load();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : String(e));
    }
  }

  return (
    <>
      {error && <ErrorNote error={error} />}
      <div className="split">
        <Panel
          title="Packs"
          action={<span className="note" style={{ fontSize: 12 }}>checkable from source</span>}
        >
          {packs === null ? (
            <div className="note">Loading…</div>
          ) : (
            /* A flex list, not .ctable. This panel sits in the narrow half of a .split,
               and a grid with 150px + 132px fixed tracks has ~58px left for the title —
               the cells collide. A list has nothing to collide. */
            <div className="rows">
              {packs.map((p) => (
                <div
                  key={p.id}
                  style={{ display: "flex", alignItems: "baseline", gap: 12 }}
                >
                  <span style={{ minWidth: 0, flex: 1 }}>
                    <span
                      className="clip"
                      style={{ display: "block", font: "13.5px var(--sans)" }}
                    >
                      {p.title ?? p.id}
                      {p.usable === false && (
                        <span style={{ color: "var(--crit)" }}> · unreadable</span>
                      )}
                    </span>
                    <span
                      className="clip"
                      style={{ display: "block", font: "11.5px var(--mono)", color: "var(--ink-3)" }}
                    >
                      {p.id}
                      {p.authority && ` · ${p.authority}`}
                    </span>
                  </span>
                  <span
                    style={{
                      font: "13px var(--sans)",
                      color: "var(--ink-2)",
                      fontVariantNumeric: "tabular-nums",
                      whiteSpace: "nowrap",
                      flex: "none",
                    }}
                    title={
                      p.total_controls !== undefined &&
                      p.source_controls !== undefined &&
                      p.source_controls < p.total_controls
                        ? `${p.total_controls - (p.source_controls ?? 0)} control(s) are ` +
                          "organisational or deployment properties and cannot be answered " +
                          "by reading a repository. They are reported as unassessed, never " +
                          "as satisfied."
                        : undefined
                    }
                  >
                    {p.source_controls ?? "—"} of {p.total_controls ?? "—"}
                  </span>
                  {p.origin === "uploaded" && (
                    <button
                      className="btn sm ghost"
                      style={{ flex: "none" }}
                      onClick={() => remove(p.id)}
                      title="Delete this uploaded pack"
                    >
                      Delete
                    </button>
                  )}
                </div>
              ))}
            </div>
          )}
        </Panel>

        <div className="stack">
          <Panel title="Upload a policy">
            <p className="note">
              Upload your own compliance policy as .md, .txt, .docx or .pdf. An agent reads
              it and extracts the requirements into a reviewable pack, citing where each one
              came from in the document.
            </p>
            <p className="note">
              Clauses it cannot locate in your document are dropped rather than invented,
              and anything organisational — a board review, an audit cadence, a reporting
              timeline — is recorded as not answerable from code.
            </p>
            <input
              ref={fileInput}
              type="file"
              accept=".md,.markdown,.txt,.text,.docx,.pdf"
              disabled={busy}
              onChange={(e) => {
                const file = e.target.files?.[0];
                if (file) upload(file);
              }}
              style={{ font: "13px var(--sans)", color: "var(--ink-2)" }}
            />
            {busy && (
              <div className="note">
                Reading the document and extracting controls. This takes a few seconds.
              </div>
            )}
            {uploaded && (
              <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                <div className="note good">{uploaded.summary}</div>
                {uploaded.truncated && (
                  <div className="note bad">
                    The document was truncated, so its later sections were not read.
                  </div>
                )}
                {uploaded.dropped.length > 0 && (
                  <div>
                    <div className="eyebrow">Dropped clauses</div>
                    <div style={{ display: "flex", flexDirection: "column", gap: 4, marginTop: 6 }}>
                      {uploaded.dropped.map((d, i) => (
                        <div className="note" key={`${d.title}-${i}`} style={{ fontSize: 12 }}>
                          {d.title} — {d.reason}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}
          </Panel>
        </div>
      </div>
    </>
  );
}
