import { useState } from "react";
import type { Candidate, EntryPoint, Surface } from "../types";
import { Drawer, Panel } from "./ui";

/** Attack paths — the recon candidates drawn as reachable-input → dangerous-sink, each a
 *  button that opens the full flow and the agent's reasoning in a drawer.
 *
 *  Built from data the Surface tab already has: each candidate carries a sink (file:line)
 *  and a prose `why`; the source is the entry point whose route the candidate names. When
 *  no entry point matches, the source reads "attacker input" rather than inventing one.
 *  This is a visual layer over the candidate list below, not a replacement for it. */

type Risk = { label: string; cls: "crit" | "high" | "med" };

function riskOf(title: string): Risk {
  const t = title.toLowerCase();
  if (/\brce\b|remote code|deserial|pickle|command inj|\bshell\b|forgery|secret key|hardcoded|\bssrf\b/.test(t))
    return { label: "Critical", cls: "crit" };
  if (/idor|authoriz|authz|privileg|priv[ -]?esc|escalat|sql inj|injection|no org|cross[ -]?tenant|bypass|\bcsrf\b/.test(t))
    return { label: "High", cls: "high" };
  return { label: "Medium", cls: "med" };
}
const rank = (r: Risk) => (r.cls === "crit" ? 0 : r.cls === "high" ? 1 : 2);

/** The route the candidate is about, matched to a mapped entry point. */
function matchEntry(cand: Candidate, entries: EntryPoint[]): EntryPoint | null {
  const paths = (cand.title ?? "").match(/\/[A-Za-z0-9_<>:./-]+/g) ?? [];
  for (const p of paths) {
    const hit = entries.find(
      (e) => e.path && (e.path === p || e.path.startsWith(p) || p.startsWith(e.path)));
    if (hit) return hit;
  }
  const f = (cand.file ?? "").split(":")[0];
  if (f) {
    const hit = entries.find((e) => (e.file ?? "").split(":")[0] === f);
    if (hit) return hit;
  }
  return null;
}

const splitTitle = (title: string) => {
  const m = title.match(/\s*\(([A-Z0-9-]+)\)\s*$/);
  return { name: m ? title.slice(0, m.index).trim() : title.trim(), id: m?.[1] ?? null };
};
const sourceLabel = (e: EntryPoint | null) =>
  e ? `${e.method ? e.method + " " : ""}${e.path ?? e.file ?? "route"}` : "attacker input";

export function AttackPaths({ surface }: { surface: Surface }) {
  const [open, setOpen] = useState<number | null>(null);
  const entries = surface.entry_points ?? [];
  const rows = (surface.candidates ?? [])
    .map((c, i) => ({ c, i, entry: matchEntry(c, entries), risk: riskOf(c.title ?? "") }))
    .sort((a, b) => rank(a.risk) - rank(b.risk));

  if (rows.length === 0) return null;
  const active = open != null ? rows.find((r) => r.i === open) ?? null : null;

  return (
    <Panel
      title="Attack paths"
      action={<span className="note" style={{ fontSize: 12 }}>reachable input → sink · click to visualize</span>}
    >
      <div className="apaths">
        {rows.map(({ c, i, entry, risk }) => {
          const { name, id } = splitTitle(c.title ?? "");
          return (
            <button className="apath" key={i} onClick={() => setOpen(i)}>
              <span className={`asev ${risk.cls}`}>{risk.label}</span>
              <span className="apath-main">
                <span className="apath-name clip">{name}{id && <span className="apath-id"> {id}</span>}</span>
                <span className="apath-chain">
                  <span className="anode source clip">{sourceLabel(entry)}</span>
                  <span className="aarrow">→</span>
                  <span className="anode sink clip">{c.file ?? "sink"}</span>
                </span>
              </span>
              <span className="apath-go">visualize →</span>
            </button>
          );
        })}
      </div>

      {active && (
        <Drawer
          onClose={() => setOpen(null)}
          title={
            <span style={{ display: "inline-flex", alignItems: "center", gap: 9 }}>
              <span className={`asev ${active.risk.cls}`}>{active.risk.label}</span>
              {splitTitle(active.c.title ?? "").name}
            </span>
          }
          subtitle={splitTitle(active.c.title ?? "").id ?? active.c.file}
        >
          <div className="apath-flow">
            <div className="anode source big">
              <span className="t">Entry · attacker-reachable</span>
              <span className="loc">{sourceLabel(active.entry)}</span>
              {active.entry?.auth && <span className="d">auth: {active.entry.auth}</span>}
              {active.entry?.file && <span className="d">{active.entry.file}</span>}
            </div>
            <div className="aarrow big">↓</div>
            <div className="anode sink big">
              <span className="t">Sink · dangerous operation</span>
              <span className="loc">{active.c.file ?? "—"}</span>
            </div>
          </div>

          <div className="apath-why">
            <div className="eyebrow" style={{ marginBottom: 6 }}>Why this is reachable</div>
            <p style={{ margin: 0, color: "var(--ink-2)", fontSize: 14, lineHeight: 1.65 }}>
              {active.c.why || "The agent flagged this route but recorded no reasoning."}
            </p>
          </div>

          {!active.entry && (
            <div className="note" style={{ marginTop: 14 }}>
              No mapped entry point matched this candidate's route, so the source is shown
              generically. The sink and reasoning are from recon.
            </div>
          )}
        </Drawer>
      )}
    </Panel>
  );
}
