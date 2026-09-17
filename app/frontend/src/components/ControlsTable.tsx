import { useMemo } from "react";
import type { ControlResult, ControlStatus, Finding, PackResult } from "../types";
import { CONTROL_STATUSES, CONTROL_STATUS_LABEL } from "../types";
import { Empty } from "./ui";

const COLOR: Record<ControlStatus, string> = {
  fail: "var(--crit)",
  pass: "var(--ok)",
  unknown: "var(--med)",
  not_applicable: "var(--ink-3)",
  not_observable: "var(--line-2)",
};

export function StatusTag({ status }: { status: ControlStatus }) {
  return (
    <span className={`cstat ${status}`}>
      <span className="dot" />
      {CONTROL_STATUS_LABEL[status]}
    </span>
  );
}

function counts(results: ControlResult[]): Record<ControlStatus, number> {
  const out = {
    fail: 0,
    pass: 0,
    unknown: 0,
    not_applicable: 0,
    not_observable: 0,
  } as Record<ControlStatus, number>;
  for (const r of results) out[r.status] = (out[r.status] ?? 0) + 1;
  return out;
}

/** The headline for one pack, and the only place the numbers are stated.
 *
 *  TWO numbers, never one, and never a percentage of the pack. Pass-rate and coverage
 *  move in opposite directions: an agent that gives up on every hard control scores
 *  100% on what is left. "11 of 13 satisfied, of 43 in the pack" is the honest shape,
 *  and the disclaimer under it is not decoration — this is an evidence report, not an
 *  attestation, and a customer may repeat whatever this tile says to a regulator. */
export function PackRollup({
  pack,
  selected,
  onSelect,
}: {
  pack: PackResult;
  selected: ControlStatus | null;
  onSelect: (status: ControlStatus | null) => void;
}) {
  const c = useMemo(() => counts(pack.results), [pack.results]);
  const assessed = c.pass + c.fail;
  const present = CONTROL_STATUSES.filter((s) => c[s] > 0);

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
      <div>
        <div className="eyebrow">{pack.authority}</div>
        <div style={{ font: "500 15px var(--sans)", color: "var(--ink)", marginTop: 4 }}>
          {assessed > 0 ? (
            /* "decided", not "checkable". They are different numbers: `requested` is how
               many a repository could answer, `assessed` is how many got a yes or a no.
               Not-applicable sits between the two and belongs in neither. */
            <>
              {c.pass} of {assessed} decided controls satisfied
            </>
          ) : (
            <>No control could be assessed from source</>
          )}
        </div>
        <div className="note" style={{ marginTop: 2 }}>
          {pack.total_controls} control{pack.total_controls === 1 ? "" : "s"} in this pack
          {c.not_observable > 0 && <> · {c.not_observable} not answerable from code</>}
        </div>
      </div>

      {pack.unjudged > 0 && (
        /* The loudest thing on this panel when it fires, because it is the one state a
           reader would otherwise misread. These controls are not inconclusive — nobody
           looked at them. Almost always the run hit its budget ceiling partway through,
           and a quiet grey "unknown" would let a truncated audit pass for a finished one. */
        <div className="note bad">
          {pack.unjudged} control{pack.unjudged === 1 ? " was" : "s were"} never reached —
          the run stopped before getting to {pack.unjudged === 1 ? "it" : "them"}, usually
          because the spend ceiling was hit. This audit is incomplete, not clean. Raise the
          budget or run fewer packs.
        </div>
      )}

      {/* Proportion bar over the WHOLE pack, so the unassessed remainder is visible
          rather than being normalised away. A pack that answered 2 of 43 must not
          paint the same bar as one that answered 2 of 2. */}
      <div
        style={{
          display: "flex",
          height: 8,
          borderRadius: 3,
          overflow: "hidden",
          background: "var(--wash)",
        }}
      >
        {CONTROL_STATUSES.filter((s) => c[s] > 0).map((s) => (
          <span key={s} style={{ flex: c[s], background: COLOR[s] }} title={CONTROL_STATUS_LABEL[s]} />
        ))}
      </div>

      <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
        {present.map((s) => {
          const active = selected === s;
          return (
            <button
              key={s}
              onClick={() => onSelect(active ? null : s)}
              aria-pressed={active}
              title={active ? "Show all controls" : `Show only: ${CONTROL_STATUS_LABEL[s]}`}
              style={{
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                gap: 10,
                background: active ? "var(--wash)" : "none",
                border: 0,
                borderRadius: 4,
                padding: "5px 7px",
                cursor: "pointer",
                width: "100%",
                textAlign: "left",
              }}
            >
              <StatusTag status={s} />
              <span
                style={{
                  font: "13px var(--sans)",
                  color: "var(--ink-3)",
                  fontVariantNumeric: "tabular-nums",
                }}
              >
                {c[s]}
              </span>
            </button>
          );
        })}
      </div>

      <div className="note" style={{ fontSize: 12 }}>
        Evidence-based review of source code. Not an attestation of compliance.
      </div>
    </div>
  );
}

export function ControlsTable({
  results,
  titles,
  selectedId,
  onSelect,
}: {
  results: ControlResult[];
  /** control_id -> human title, from the pack definition. Falls back to the id. */
  titles: Record<string, string>;
  selectedId?: string;
  onSelect: (result: ControlResult) => void;
}) {
  if (results.length === 0) return <Empty>No control matches this filter.</Empty>;
  return (
    <div className="ctable">
      <div className="head">
        <span>Control</span>
        <span>Status</span>
      </div>
      {results.map((r) => (
        <button
          key={r.control_id}
          onClick={() => onSelect(r)}
          style={{ background: selectedId === r.control_id ? "var(--wash)" : undefined }}
        >
          <span style={{ minWidth: 0, paddingRight: 12 }}>
            <span className="clip" style={{ display: "block" }}>
            {titles[r.control_id] ?? r.control_id}
            {/* A failed control that a reproduced finding corroborates is the one case
                where it is more than an opinion. Say so on the row, not only inside. */}
            {r.proven_findings.length > 0 && (
              <span style={{ color: "var(--crit)", font: "500 12px var(--sans)" }}>
                {" "}
                · proven
              </span>
            )}
            {r.contradicted_by.length > 0 && (
              <span style={{ color: "var(--high)", font: "500 12px var(--sans)" }}>
                {" "}
                · contradicted
              </span>
            )}
            </span>
            <span className="cid clip" style={{ display: "block" }}>
              {r.control_id}
            </span>
          </span>
          <StatusTag status={r.status} />
        </button>
      ))}
    </div>
  );
}

/** Drawer body for one control: what was required, what was decided, and the lines the
 *  decision was read from. The citations are the point — a control marked satisfied with
 *  nothing to open is exactly what this feature exists not to produce. */
/** The findings a control links to, as rows you can open.
 *
 *  `proven_findings` holds dedupe_keys, not ids, because a link has to survive a rescan.
 *  Anything that no longer exists in this scan is simply not rendered — a dangling row
 *  labelled with a hash helps nobody. */
function LinkedFindings({
  keys,
  findings,
  onSelect,
}: {
  keys: string[];
  findings: Finding[];
  onSelect?: (finding: Finding) => void;
}) {
  const matched = findings.filter((f) => f.dedupe_key && keys.includes(f.dedupe_key));
  if (matched.length === 0) return null;
  return (
    <div className="rows" style={{ marginTop: 6 }}>
      {matched.map((f) => (
        <button
          key={f.id}
          onClick={() => onSelect?.(f)}
          disabled={!onSelect}
          style={{
            display: "flex",
            alignItems: "baseline",
            justifyContent: "space-between",
            gap: 10,
            background: "none",
            border: 0,
            width: "100%",
            textAlign: "left",
            cursor: onSelect ? "pointer" : "default",
            font: "13px var(--sans)",
            color: "var(--ink-2)",
          }}
        >
          <span className="clip" style={{ minWidth: 0 }}>{f.title}</span>
          <span style={{ font: "11.5px var(--mono)", color: "var(--ink-3)", flex: "none" }}>
            {f.severity} ↗
          </span>
        </button>
      ))}
    </div>
  );
}

export function ControlDetail({
  result,
  title,
  requirement,
  citation,
  findings = [],
  onSelectFinding,
}: {
  result: ControlResult;
  title?: string;
  requirement?: string;
  citation?: string;
  /** This scan's findings, so a link can be resolved to something openable. */
  findings?: Finding[];
  onSelectFinding?: (finding: Finding) => void;
}) {
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      <div>
        <StatusTag status={result.status} />
        {result.escalated && (
          <span className="chip" style={{ marginLeft: 8 }}>
            second look
          </span>
        )}
      </div>

      {title && <div style={{ font: "500 15px var(--sans)", color: "var(--ink)" }}>{title}</div>}

      {requirement && (
        <div>
          <div className="eyebrow">Requirement</div>
          <p style={{ font: "14px/1.65 var(--serif)", color: "var(--ink-2)", margin: "6px 0 0" }}>
            {requirement}
          </p>
          {citation && (
            <div className="note" style={{ marginTop: 6, fontSize: 12 }}>
              {citation}
            </div>
          )}
        </div>
      )}

      <div>
        <div className="eyebrow">What docket found</div>
        <p style={{ font: "14px/1.65 var(--sans)", color: "var(--ink-2)", margin: "6px 0 0" }}>
          {result.rationale}
        </p>
      </div>

      {result.downgraded_from && (
        /* The audit trail that matters most. The agent asserted something it could not
           point at in this repository, and the claim was refused rather than recorded. */
        <div className="note bad">
          The agent originally answered “{CONTROL_STATUS_LABEL[result.downgraded_from]}”. That
          claim was not accepted, because it did not cite a line in this repository.
        </div>
      )}

      {result.citations.length > 0 && (
        <div>
          <div className="eyebrow">Read from</div>
          <div style={{ display: "flex", flexDirection: "column", gap: 8, marginTop: 6 }}>
            {result.citations.map((c, i) => (
              <div className="evidence" key={`${c.file}:${c.line}:${i}`}>
                <div className="lbl">
                  {c.file}
                  {c.line !== null && `:${c.line}`}
                </div>
                {c.quote && <pre>{c.quote}</pre>}
              </div>
            ))}
          </div>
        </div>
      )}

      {result.status === "unknown" && result.looked_at && (
        <div>
          <div className="eyebrow">Looked at</div>
          <p style={{ font: "13px/1.6 var(--sans)", color: "var(--ink-3)", margin: "6px 0 0" }}>
            {result.looked_at}
          </p>
        </div>
      )}

      {result.proven_findings.length > 0 && (
        <div>
          <div className="note bad">
            {result.proven_findings.length} reproduced finding
            {result.proven_findings.length === 1 ? "" : "s"} of this weakness class exist in
            this scan. This is not only a review opinion.
          </div>
          <LinkedFindings
            keys={result.proven_findings}
            findings={findings}
            onSelect={onSelectFinding}
          />
        </div>
      )}
      {result.contradicted_by.length > 0 && (
        <div>
          <div className="note bad">
            Contradiction: this control was marked satisfied, but{" "}
            {result.contradicted_by.length} reproduced finding
            {result.contradicted_by.length === 1 ? "" : "s"} of the same weakness class exist
            in this scan. Treat the pass with suspicion.
          </div>
          <LinkedFindings
            keys={result.contradicted_by}
            findings={findings}
            onSelect={onSelectFinding}
          />
        </div>
      )}
    </div>
  );
}
