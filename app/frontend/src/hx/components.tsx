import { useMemo, useRef, useState, type ReactNode } from "react";
import type { Level, Origin, Proof, PortfolioFinding } from "../portfolio";
import { hx } from "./hx";

/** Shared Henoyo chrome for the Code Security views. One implementation of each piece so the
 *  nine pages cannot drift: the mockup (docs/ui/mockup) is the visual reference. */

export function PageHead({ eyebrow, title, sub, actions }: { eyebrow: string; title: string; sub?: ReactNode; actions?: ReactNode }) {
  return (
    <div className={hx("pagehead")}>
      <div className={hx("grow")}>
        <div className={hx("eyebrow")}>{eyebrow}</div>
        <h1>{title}</h1>
        {sub ? <p className={hx("sub")}>{sub}</p> : null}
      </div>
      {actions}
    </div>
  );
}

/** The "i": help text lives behind it, never in a paragraph (design-system.md, UI conventions). */
export function Help({ text }: { text: string }) {
  return <button type="button" className={hx("help")} aria-label="About this section" data-tip={text}>i</button>;
}

export function Card({ title, sub, tip, actions, flush, children }: { title?: string; sub?: ReactNode; tip?: string; actions?: ReactNode; flush?: boolean; children: ReactNode }) {
  return (
    <section className={hx("hc")}>
      {title ? (
        <header>
          <div className={hx("grow")}>
            <h3>{title}{tip ? <Help text={tip} /> : null}</h3>
            {sub ? <p>{sub}</p> : null}
          </div>
          {actions}
        </header>
      ) : null}
      <div className={hx(flush ? "flush" : "pad")}>{children}</div>
    </section>
  );
}

const SEV_CLASS: Record<string, string> = { critical: "crit", high: "high", medium: "med", low: "low", info: "info" };
export const SevChip = ({ sev }: { sev: string }) => (
  <span className={hx(`chip ${SEV_CLASS[sev] ?? "info"}`)}>{sev.charAt(0).toUpperCase() + sev.slice(1)}</span>
);

export const OriginChip = ({ origin, name }: { origin: Origin; name?: string }) =>
  origin === "henoyo"
    ? <span className={hx("origin h")} title="Built and run by Henoyo">Henoyo</span>
    : <span className={hx("origin t")} title="Third-party tool, run by Docket">{name ?? "Third-party"}</span>;

export const LEVELS: Record<Level, { word: string; tone: "bad" | "warn" | "ok" | "off" }> = {
  action: { word: "Act today", tone: "bad" },
  attention: { word: "Watch", tone: "warn" },
  clear: { word: "Clear", tone: "ok" },
  unknown: { word: "Not scanned", tone: "off" },
};
export const Lamp = ({ level }: { level: Level }) => <span className={hx(`lamp ${LEVELS[level].tone}`)} aria-hidden="true" />;
export const LevelLabel = ({ level }: { level: Level }) => (
  <span><Lamp level={level} /> <b style={{ marginLeft: 8 }}>{LEVELS[level].word}</b></span>
);

/** Proof is the product: a reproduced exploit is a different kind of thing from a scanner hit, and
 *  the cell says which, in words (AGENTS.md rules 1 and 10). */
export function ProofCell({ f }: { f: Pick<PortfolioFinding, "proof" | "reach"> }) {
  const map: Record<Proof, [string, string]> = {
    reproduced: ["y", "◆ Reproduced"],
    deterministic: ["y", "● Deterministic"],
    candidate: ["m", `◇ Candidate${f.reach ? ` · ${f.reach}` : ""}`],
    not_reachable: ["n", "○ Not reachable"],
  };
  const [cls, text] = map[f.proof];
  return <span className={hx(`proof ${cls}`)}>{text}</span>;
}

export const ago = (days: number | null | undefined): string =>
  days == null ? "" : days < 1 ? "today" : `${Math.round(days)} d`;

export const Empty = ({ children }: { children: ReactNode }) => <div className={hx("empty")}>{children}</div>;

/** Drawer: right-hand panel over a scrim; Escape and the scrim close it. */
export function Drawer({ open, onClose, children }: { open: boolean; onClose: () => void; children: ReactNode }) {
  return (
    <>
      <div className={hx(`scrim${open ? " open" : ""}`)} onClick={onClose} />
      <aside className={hx(`drawer${open ? " open" : ""}`)} aria-hidden={!open} role="dialog" aria-label="Detail"
             onKeyDown={(e) => e.key === "Escape" && onClose()}>
        {open ? children : null}
      </aside>
    </>
  );
}

/* ── sorting ───────────────────────────────────────────────────────────────
 * Every Henoyo table sorts, and the third click clears it (design-system.md: "Every
 * table's columns sort"). Rows are held in memory, so this sorts client-side. */
type Dir = "asc" | "desc";
export function useSort<T>(rows: T[], accessors: Record<string, (r: T) => string | number | null>) {
  const [sort, setSort] = useState<{ key: string; dir: Dir } | null>(null);
  const sorted = useMemo(() => {
    if (!sort) return rows;
    const get = accessors[sort.key];
    if (!get) return rows;
    const m = sort.dir === "asc" ? 1 : -1;
    return [...rows].sort((a, b) => {
      const x = get(a), y = get(b);
      if (x == null && y == null) return 0;
      if (x == null) return 1;
      if (y == null) return -1;
      return (typeof x === "number" && typeof y === "number" ? x - y : String(x).localeCompare(String(y))) * m;
    });
    // accessors are stable per table (declared at module scope or memoised by the caller)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [rows, sort]);
  const next = (key: string) =>
    setSort((s) => (!s || s.key !== key ? { key, dir: "asc" } : s.dir === "asc" ? { key, dir: "desc" } : null));
  // Th must keep one identity across renders: a component recreated per render remounts its DOM, and a
  // keyboard user loses focus on the header they just pressed. It reads the latest sort through a ref.
  const latest = useRef({ sort, next });
  latest.current = { sort, next };
  const Th = useMemo(
    () =>
      function Th({ k, children }: { k: string; children: ReactNode }) {
        const { sort: cur, next: go } = latest.current;
        const active = cur?.key === k ? cur.dir : null;
        return (
          <th aria-sort={active === "asc" ? "ascending" : active === "desc" ? "descending" : "none"}>
            <button type="button" className={hx("sort")} onClick={() => go(k)}>
              {children}<span aria-hidden="true">{active === "asc" ? " ▲" : active === "desc" ? " ▼" : ""}</span>
            </button>
          </th>
        );
      },
    [],
  );
  return { rows: sorted, Th };
}
