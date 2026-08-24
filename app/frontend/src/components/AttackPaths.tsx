import { useState } from "react";
import type { Candidate, EntryPoint, Surface } from "../types";
import { Drawer, Panel } from "./ui";

/** Attack paths — the recon candidates drawn as reachable-input → dangerous-sink, each a
 *  button that opens the full flow and the agent's reasoning in a drawer.
 *
 *  Built from data the Surface tab already has (entry_points + candidates), so it is a
 *  visual layer over the candidate list below, not a replacement. A candidate that names
 *  a route becomes a path (entry → sink); a config/source weakness with no route (a
 *  hardcoded secret, debug mode) becomes a single node, not a fake "GET /" source. */

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

/** The SPECIFIC route a candidate names, matched to a mapped entry point — longest match
 *  wins and the bare "/" is never a match, so a candidate about /admin/logs no longer
 *  resolves to the root route. Returns null for candidates that name no route. */
function matchEntry(cand: Candidate, entries: EntryPoint[]): EntryPoint | null {
  const tokens = (cand.title ?? "").match(/\/[A-Za-z0-9_<>:./-]+/g) ?? [];
  let best: EntryPoint | null = null;
  let bestLen = 0;
  for (const p of tokens) {
    for (const e of entries) {
      const ep = e.path;
      if (!ep || ep.length <= 1) continue; // never let "/" match everything
      if ((ep === p || p.startsWith(ep) || ep.startsWith(p)) && ep.length > bestLen) {
        best = e;
        bestLen = ep.length;
      }
    }
  }
  return best;
}

const splitTitle = (title: string) => {
  const m = title.match(/\s*\(([A-Z0-9-]+)\)\s*$/);
  return { name: m ? title.slice(0, m.index).trim() : title.trim(), id: m?.[1] ?? null };
};
const sourceLabel = (e: EntryPoint) => `${e.method ? e.method + " " : ""}${e.path ?? e.file ?? "route"}`;
const hasRoute = (title: string) => /\/[A-Za-z]/.test(title);

export function AttackPaths({ surface }: { surface: Surface }) {
  const [open, setOpen] = useState<number | null>(null);
  const entries = surface.entry_points ?? [];
  const rows = (surface.candidates ?? [])
    .map((c, i) => {
      const entry = matchEntry(c, entries);
      const routed = !!entry || hasRoute(c.title ?? "");
      return { c, i, entry, routed, risk: riskOf(c.title ?? ""), ...splitTitle(c.title ?? "") };
    })
    .sort((a, b) => rank(a.risk) - rank(b.risk));

  if (rows.length === 0) return null;
  const active = open != null ? rows.find((r) => r.i === open) ?? null : null;

  return (
    <Panel
      title="Attack paths"
      action={<span className="note" style={{ fontSize: 12 }}>reachable input → sink · click any to visualize</span>}
    >
      <div className="apaths">
        {rows.map((r) => (
          <button className="apath" key={r.i} onClick={() => setOpen(r.i)}>
            <span className={`asev ${r.risk.cls}`}><span className="d" />{r.risk.label}</span>
            <span className="apath-main">
              <span className="apath-name clip">
                {r.name}{r.id && <span className="apath-id">{r.id}</span>}
              </span>
              <span className="apath-flow">
                {r.routed ? (
                  <>
                    <span className="anode source clip">{r.entry ? sourceLabel(r.entry) : "attacker input"}</span>
                    <span className="aconn"><span className="aline" /><span className="ahead">▸</span></span>
                    <span className="anode sink clip">{r.c.file ?? "sink"}</span>
                  </>
                ) : (
                  <span className="anode weak clip">{r.c.file ?? "—"}</span>
                )}
              </span>
            </span>
            <span className="apath-chev" aria-hidden="true">›</span>
          </button>
        ))}
      </div>

      {active && (
        <Drawer
          onClose={() => setOpen(null)}
          title={
            <span style={{ display: "inline-flex", alignItems: "center", gap: 9 }}>
              <span className={`asev ${active.risk.cls}`}><span className="d" />{active.risk.label}</span>
              {active.name}
            </span>
          }
          subtitle={active.id ?? active.c.file}
        >
          <div className="apath-flow-v">
            <div className="anode source big">
              <span className="t">{active.routed ? "Entry · attacker-reachable" : "Weakness · source"}</span>
              <span className="loc">{active.entry ? sourceLabel(active.entry) : active.routed ? "attacker input" : active.c.file}</span>
              {active.entry?.auth && <span className="d">auth: {active.entry.auth}</span>}
              {active.entry?.file && <span className="d">{active.entry.file}</span>}
            </div>
            {active.routed && (
              <>
                <div className="aarrow-v">↓</div>
                <div className="anode sink big">
                  <span className="t">Sink · dangerous operation</span>
                  <span className="loc">{active.c.file ?? "—"}</span>
                </div>
              </>
            )}
          </div>

          <div className="apath-why">
            <div className="eyebrow" style={{ marginBottom: 6 }}>Why this is reachable</div>
            <p style={{ margin: 0, color: "var(--ink-2)", fontSize: 14, lineHeight: 1.65 }}>
              {active.c.why || "The agent flagged this but recorded no reasoning."}
            </p>
          </div>
        </Drawer>
      )}
    </Panel>
  );
}
