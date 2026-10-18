import type { ReactNode } from "react";
import { hx } from "../hx/hx";

export interface Tab { id: string; label: string; badge?: string | null; matches?: string[] }

/** The Henoyo shell: dark masthead (wordmark, app switcher, search, user) over the app's section
 *  tabs, as every Henoyo application is framed (henoyo-core shell/AppShell, SectionBar). */
export function Shell({
  tabs, active, onGo, user, sample, children,
}: { tabs: Tab[]; active: string; onGo: (id: string) => void; user: string | null; sample: boolean; children: ReactNode }) {
  return (
    <>
      <div className={hx("shell")}>
        <span className={hx("mark")}>henoyo<i>.</i></span>
        <button className={hx("launcher")} aria-label="Switch application" type="button">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" aria-hidden="true">
            <rect x="3" y="3" width="7" height="7" rx="1.5" /><rect x="14" y="3" width="7" height="7" rx="1.5" />
            <rect x="3" y="14" width="7" height="7" rx="1.5" /><rect x="14" y="14" width="7" height="7" rx="1.5" />
          </svg>
          Code Security
        </button>
        <div className={hx("search")}>
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" aria-hidden="true"><circle cx="11" cy="11" r="7" /><path d="m20 20-3.5-3.5" /></svg>
          Search applications, findings, controls<kbd>⌘K</kbd>
        </div>
        <div className={hx("who")}>
          <span>{user ?? "Local"}</span>
          <span className={hx("av")}>{(user ?? "L").slice(0, 2).toUpperCase()}</span>
        </div>
      </div>
      <nav className={hx("tabs")} aria-label="Code Security sections">
        <span className={hx("app")}>Code Security</span>
        {tabs.map((t) => (
          <a key={t.id} href={`#/${t.id}`} aria-current={active === t.id ? "page" : undefined}
             onClick={(e) => { e.preventDefault(); onGo(t.id); }}>
            {t.label}{t.badge ? <span className={hx("tabbadge")}>{t.badge}</span> : null}
          </a>
        ))}
      </nav>
      {children}
      {sample ? <div className={hx("sample")}>Sample data. Nothing here is a real scan.</div> : null}
    </>
  );
}
