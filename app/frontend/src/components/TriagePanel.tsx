import type { Finding, ScanState, Verdict } from "../types";
import { Panel } from "./ui";

const VERDICTS: { id: Verdict; label: string; colour: string; blurb: string }[] = [
  { id: "exploitable", label: "reachable", colour: "var(--crit)", blurb: "input can get here" },
  { id: "not_reachable", label: "not reachable", colour: "var(--ok)", blurb: "input cannot" },
  { id: "uncertain", label: "uncertain", colour: "var(--ink-3)", blurb: "source was not enough" },
];

/** Triage outcome and what it cost, together.
 *
 *  These share a panel because they are the same decision: triage is the only thing in
 *  a source scan that spends money, so "how much did I learn" and "what did it cost"
 *  are read as one question. Splitting them would put the price on a KPI tile far from
 *  the thing being priced.
 *
 *  Renders nothing when no triage ran — an empty funnel is noise on a scan that never
 *  asked for one. */
export function TriagePanel({
  scan,
  findings,
  onSelectVerdict,
  selectedVerdict,
}: {
  scan: ScanState | null;
  findings: Finding[];
  onSelectVerdict: (v: Verdict | null) => void;
  selectedVerdict: Verdict | null;
}) {
  const triaged = findings.filter((f) => f.triage);
  const requested = scan?.triage_max ?? 0;
  if (!triaged.length && !requested) return null;

  const counts = VERDICTS.map((v) => ({
    ...v,
    n: triaged.filter((f) => f.triage?.verdict === v.id).length,
  }));

  const spend = scan?.cost_usd ?? 0;
  const budget = scan?.budget_usd ?? 0;
  const inTok = scan?.input_tokens ?? 0;
  const outTok = scan?.output_tokens ?? 0;
  // Capped for the bar only; the number beside it still shows the true figure, so an
  // overrun reads as "full bar, $2.14 of $2.00" rather than being silently clipped.
  const pct = budget > 0 ? Math.min((spend / budget) * 100, 100) : 0;
  const tight = budget > 0 && spend / budget >= 0.8;

  // The gap that matters: asked for N, got fewer. Usually the budget stopping mid-run.
  const shortfall = requested > 0 && triaged.length < Math.min(requested, findings.length);

  return (
    <Panel
      title="Triage"
      action={
        <span className="note" style={{ fontSize: 12 }}>
          {triaged.length} of {findings.length} judged
        </span>
      }
    >
      {triaged.length > 0 ? (
        <>
          <div style={{ display: "flex", height: 8, borderRadius: 2, overflow: "hidden", background: "var(--wash)" }}>
            {counts.filter((c) => c.n).map((c) => (
              <span key={c.id} style={{ flex: c.n, background: c.colour }} title={`${c.n} ${c.label}`} />
            ))}
            {/* The unjudged remainder is part of the picture. Without it, 2-of-13 all
                reachable paints a solid red bar that reads as "everything is reachable". */}
            {findings.length > triaged.length && (
              <span style={{ flex: findings.length - triaged.length, background: "var(--line-2)" }}
                    title={`${findings.length - triaged.length} not judged`} />
            )}
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
            {counts.map((c) => (
              <button
                key={c.id}
                disabled={!c.n}
                aria-pressed={selectedVerdict === c.id}
                onClick={() => onSelectVerdict(selectedVerdict === c.id ? null : c.id)}
                title={c.n ? `Show only ${c.label}` : "none in this run"}
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 8,
                  background: selectedVerdict === c.id ? "var(--wash)" : "none",
                  border: 0,
                  borderRadius: 4,
                  padding: "4px 6px",
                  font: "500 12.5px var(--sans)",
                  color: c.n ? "var(--ink-2)" : "var(--ink-3)",
                  cursor: c.n ? "pointer" : "default",
                  textAlign: "left",
                }}
              >
                <span style={{ width: 8, height: 8, borderRadius: "50%", background: c.colour, flex: "none", opacity: c.n ? 1 : 0.3 }} />
                <span>{c.label}</span>
                <span style={{ color: "var(--ink-3)" }}>{c.blurb}</span>
                <span style={{ marginLeft: "auto", fontVariantNumeric: "tabular-nums", color: "var(--ink)" }}>
                  {c.n}
                </span>
              </button>
            ))}
          </div>
        </>
      ) : (
        <div className="note">
          {scan?.stages?.triage === "running" ? "Reading source…" : "No verdicts yet."}
        </div>
      )}

      {shortfall && (
        <div className="note bad">
          Asked for {requested}, judged {triaged.length}. The budget stops a run mid-way rather
          than refusing it up front.
        </div>
      )}

      {/* Spend sits with triage because triage is the only thing here that spends. */}
      <div style={{ borderTop: "1px dashed rgba(255,255,255,.2)", paddingTop: 9, display: "flex", flexDirection: "column", gap: 6 }}>
        <div style={{ display: "flex", justifyContent: "space-between", font: "500 12.5px var(--sans)" }}>
          <span className="eyebrow">Spend</span>
          <span style={{ color: tight ? "var(--high)" : "var(--ink-2)", fontVariantNumeric: "tabular-nums" }}>
            ${spend.toFixed(4)}
            {budget > 0 && <span style={{ color: "var(--ink-3)" }}> of ${budget.toFixed(2)}</span>}
          </span>
        </div>
        {budget > 0 && (
          <div style={{ height: 6, borderRadius: 2, background: "var(--wash)" }}>
            <div
              style={{
                width: `${pct}%`,
                height: "100%",
                borderRadius: 2,
                background: tight ? "var(--high)" : "var(--ok)",
                transition: "width .4s ease",
              }}
            />
          </div>
        )}
        <div className="note" style={{ fontSize: 10.5 }}>
          {inTok.toLocaleString()} in · {outTok.toLocaleString()} out
          {inTok > 0 && outTok > 0 && ` · ${Math.round(inTok / outTok)}:1`}
        </div>
      </div>
    </Panel>
  );
}
