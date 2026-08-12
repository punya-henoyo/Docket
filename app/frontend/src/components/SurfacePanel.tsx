import type { ScanState } from "../types";
import { Empty, Panel } from "./ui";

/** What the recon agent mapped, which is a different kind of thing from a finding.
 *
 *  A finding says "this line matches a dangerous pattern". This says "here is what the
 *  application IS": where input enters, how it decides who you are, and which entry
 *  points nobody guarded. Kept in its own panel rather than mixed into the findings
 *  table for that reason — an unguarded route is not a match, it is an absence, and
 *  absences do not belong in a list of matches.
 *
 *  Renders nothing when recon did not run, so a plain scan stays uncluttered. */
export function SurfacePanel({ scan, title = "Attack surface" }:
  { scan: ScanState | null; title?: string }) {
  const requested = scan?.recon;
  const surface = scan?.surface;
  if (!requested && !surface) return null;

  if (!surface) {
    const state = scan?.stages?.recon;
    return (
      <Panel title={title} action={<span className="chip">recon</span>}>
        <Empty>
          {state === "running"
            ? "Reading the repository…"
            : state === "error"
              ? "The agent produced no map. Nothing is claimed about this repository's surface."
              : "Not mapped."}
        </Empty>
      </Panel>
    );
  }

  const entries = surface.entry_points ?? [];
  // record_surface uses kind='none' for a repository that genuinely exposes nothing —
  // a library or CLI. That is an answer, not an empty result, and reads differently.
  const noSurface = entries.length === 1 && entries[0]?.kind === "none";

  return (
    <Panel
      title={title}
      action={
        <span className="mono" style={{ fontSize: 11, color: "var(--ink-3)" }}>
          mapped by agent
        </span>
      }
    >
      {surface.partial && (
        <div className="note bad">
          Incomplete. The agent ran out of turns and recorded what it had. Everything
          below was read from source; anything missing was never looked at, so treat
          this as a floor rather than the whole surface.
        </div>
      )}

      {noSurface ? (
        <div className="note">No HTTP surface — this repository exposes no routes.</div>
      ) : (
        <>
          <div className="eyebrow">Entry points ({entries.length})</div>
          <div className="tablewrap">
            <table style={{ minWidth: 420 }}>
              <thead>
                <tr>
                  <th>Method</th>
                  <th>Path</th>
                  <th>Params</th>
                  <th>Auth</th>
                  <th>Source</th>
                </tr>
              </thead>
              <tbody>
                {entries.slice(0, 25).map((e, i) => {
                  const unguarded = /none|no auth|not found/i.test(e.auth ?? "");
                  return (
                    <tr key={`${e.path}-${i}`} style={{ cursor: "default" }}>
                      <td>{e.method ?? "-"}</td>
                      <td className="path">{e.path ?? "-"}</td>
                      <td className="path">{(e.params ?? []).join(", ") || "-"}</td>
                      <td style={unguarded ? { color: "var(--crit)" } : undefined}>
                        {e.auth ?? "-"}
                      </td>
                      <td className="path">{e.file ?? "-"}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
          {entries.length > 25 && (
            <div className="note">Showing 25 of {entries.length}.</div>
          )}
        </>
      )}

      {surface.auth_model && (
        <div style={{ borderTop: "1px dashed rgba(255,255,255,.2)", paddingTop: 9 }}>
          <div className="eyebrow">Auth model</div>
          <div className="note" style={{ color: "var(--ink-2)", marginTop: 4, maxWidth: "72ch" }}>
            {surface.auth_model}
          </div>
        </div>
      )}

      {surface.candidates?.length > 0 && (
        <div style={{ borderTop: "1px dashed rgba(255,255,255,.2)", paddingTop: 9 }}>
          <div className="eyebrow">
            Candidates ({surface.candidates.length}) — no scanner rule matches these
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 8, marginTop: 6 }}>
            {surface.candidates.map((c, i) => (
              <div key={i} style={{ font: "11.5px/1.6 var(--mono)" }}>
                <div style={{ color: "var(--ink)" }}>{c.title}</div>
                {c.file && (
                  <div className="path" style={{ fontSize: 10.5 }}>
                    {c.file}
                  </div>
                )}
                <div style={{ color: "var(--ink-3)" }}>{c.why}</div>
              </div>
            ))}
          </div>
          <div className="note" style={{ marginTop: 6 }}>
            Suspected, not proven. These are reasoning about code, with nothing executed.
          </div>
        </div>
      )}

      {surface.notes && (
        <div style={{ borderTop: "1px dashed rgba(255,255,255,.2)", paddingTop: 9 }}>
          <div className="eyebrow">Could not determine</div>
          <div className="note" style={{ marginTop: 4, maxWidth: "72ch" }}>
            {surface.notes}
          </div>
        </div>
      )}
    </Panel>
  );
}
