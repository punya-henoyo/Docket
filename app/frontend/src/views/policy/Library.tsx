import { useEffect, useRef, useState } from "react";
import { hx } from "../../hx/hx";

export interface LibItem {
  key: string; name: string; when: string[];
  /** One dot per step, grouped into "before the agents" and "agents". */
  dots: { id: string; label: string; required: boolean; group: "pre" | "agents" }[];
  required: number; optional: number;
  /** null until the policy is saved: the server counts applications only for saved policies. */
  applies: number | null; meets: number | null;
  draft: boolean; dirty: boolean; warning: string | null; builtin: boolean;
}

export function PolicyCard({ item, selected, onSelect }: { item: LibItem; selected: boolean; onSelect: () => void }) {
  const groups = (["pre", "agents"] as const).map((g) => item.dots.filter((d) => d.group === g)).filter((g) => g.length);
  return (
    <button type="button" className="pol-card" aria-pressed={selected} onClick={onSelect}>
      <div className="pol-top">
        <h3>{item.name || "Untitled policy"}</h3>
        <span className="pol-tags">
          {item.builtin ? <span className={hx("chip neutral")}>Built-in</span> : null}
          {item.draft ? <span className={hx("chip neutral")}>Draft</span> : null}
          {item.dirty && !item.draft ? <span className={hx("chip reg")}>Unsaved changes</span> : null}
        </span>
      </div>
      <div className="pol-when">
        {item.when.length ? item.when.map((w) => <span key={w} className={hx("chip neutral")}>{w}</span>) : <span className={hx("chip neutral")}>Every other application</span>}
      </div>
      <div className="pol-mini" role="img" aria-label={`${item.required} required steps, ${item.optional} optional`}>
        {groups.map((g, gi) => (
          <span key={gi} style={{ display: "contents" }}>
            {gi > 0 ? <span className="pol-sep" /> : null}
            {g.map((d) => <i key={d.id} className={d.required ? "" : "o"} title={`${d.label}: ${d.required ? "Required" : "Optional"}`} />)}
          </span>
        ))}
        <small>{item.required} required, {item.optional} optional</small>
      </div>
      <div className="pol-cnt">
        {item.applies == null ? <span>Not saved yet</span> : (
          <>
            <span><b>{item.applies}</b> application{item.applies === 1 ? "" : "s"}</span>
            <span>{item.meets == null ? "" : `${item.meets} of ${item.applies} have every required check current`}</span>
          </>
        )}
      </div>
      {item.warning ? <div><span className={hx("chip warn")} style={{ whiteSpace: "normal", height: "auto", padding: "2px 9px" }} title={item.warning}>Thinner than the baseline</span></div> : null}
    </button>
  );
}

/** "Start from a template": a menu, keyboard operable, closed by Escape or a click outside. */
export function TemplateMenu({ templates, onPick }: { templates: { id: string; name: string; sub: string }[]; onPick: (id: string | null) => void }) {
  const [open, setOpen] = useState(false);
  const wrap = useRef<HTMLDivElement>(null);
  const btn = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    if (!open) return;
    const away = (e: MouseEvent) => { if (!wrap.current?.contains(e.target as Node)) setOpen(false); };
    document.addEventListener("mousedown", away);
    wrap.current?.querySelector<HTMLButtonElement>("[role=menuitem]")?.focus();
    return () => document.removeEventListener("mousedown", away);
  }, [open]);
  const close = () => { setOpen(false); btn.current?.focus(); };
  return (
    <div className="pol-menuwrap" ref={wrap} onKeyDown={(e) => {
      if (e.key === "Escape") { e.stopPropagation(); close(); }
      if (open && (e.key === "ArrowDown" || e.key === "ArrowUp")) {
        e.preventDefault();
        const items = [...wrap.current!.querySelectorAll<HTMLButtonElement>("[role=menuitem]")];
        const i = items.indexOf(document.activeElement as HTMLButtonElement);
        items[(i + (e.key === "ArrowDown" ? 1 : items.length - 1)) % items.length]?.focus();
      }
    }}>
      <button type="button" ref={btn} className={hx("btn")} aria-haspopup="menu" aria-expanded={open} onClick={() => setOpen((o) => !o)}>Start from a template</button>
      {open ? (
        <div className="pol-menu" role="menu" aria-label="Templates">
          {templates.map((t) => (
            <button key={t.id} type="button" role="menuitem" onClick={() => { setOpen(false); onPick(t.id); }}>{t.name}<small>{t.sub}</small></button>
          ))}
          <button type="button" role="menuitem" onClick={() => { setOpen(false); onPick(null); }}>Blank policy<small>Dependencies and secrets, and static analysis, required</small></button>
        </div>
      ) : null}
    </div>
  );
}
