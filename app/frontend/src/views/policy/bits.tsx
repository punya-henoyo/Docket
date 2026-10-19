import type { ReactNode } from "react";
import type { Availability, Origin } from "../../portfolio";
import { hx } from "../../hx/hx";
import { AVAILABILITY_WORD } from "./model";

/** Small pieces shared by the Policies page. */

const ICONS: Record<string, string> = {
  package: "M12 3l8 4.5v9L12 21l-8-4.5v-9zM12 12L4 7.5M12 12l8-4.5M12 12v9",
  "file-code": "M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8zM14 3v5h5M10 13l-2 2 2 2M14 13l2 2-2 2",
  radar: "M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18zM12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8zM12 12l6-6",
  "shield-alert": "M12 3L4 6v6c0 4.5 3.2 7.6 8 9 4.8-1.4 8-4.5 8-9V6zM12 8v4M12 15.5h.01",
  crosshair: "M12 4a8 8 0 1 0 0 16 8 8 0 0 0 0-16zM12 2v5M12 17v5M2 12h5M17 12h5",
  brain: "M9 4a3 3 0 0 0-3 3 3 3 0 0 0-2 5 3 3 0 0 0 2 5 3 3 0 0 0 6 1V4a3 3 0 0 0-3 0zM15 4a3 3 0 0 1 3 3 3 3 0 0 1 2 5 3 3 0 0 1-2 5 3 3 0 0 1-6 1",
  "scroll-text": "M8 21h10a2 2 0 0 0 2-2v-1H10v1a2 2 0 0 1-2 2zm0 0a2 2 0 0 1-2-2V5a2 2 0 0 0-2-2h14a2 2 0 0 1 2 2v13M10 8h6M10 12h6",
  wrench: "M14.7 6.3a4 4 0 0 0-5.4 5.4L3 18l3 3 6.3-6.3a4 4 0 0 0 5.4-5.4l-2.6 2.6-2.4-.6-.6-2.4z",
};

export function StepIcon({ name, origin }: { name: string; origin: Origin }) {
  return (
    <span className={`pol-ic${origin === "henoyo" ? " h" : ""}`} aria-hidden="true">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d={ICONS[name] ?? ICONS.package} />
      </svg>
    </span>
  );
}

export const AvailChip = ({ a }: { a: Availability }) => <span className={`pol-avl ${a}`}>{AVAILABILITY_WORD[a]}</span>;

/** "Required" / "Optional" as a chip, never "(optional)" in a label (design-system.md). */
export const ReqChip = ({ required }: { required: boolean }) =>
  <span className={hx(`chip ${required ? "sec" : "neutral"}`)}>{required ? "Required" : "Optional"}</span>;

/** An on/off switch that is a real button with role=switch. */
export function Switch({ on, label, disabled, title, onToggle }: { on: boolean; label: string; disabled?: boolean; title?: string; onToggle: () => void }) {
  return (
    <button type="button" role="switch" aria-checked={on} aria-disabled={disabled || undefined} className="pol-sw" title={title}
            onClick={() => { if (!disabled) onToggle(); }}>
      <span className="pol-track" />{label}
    </button>
  );
}

export const Authority = ({ a }: { a: string }) => <span className={hx("chip reg")}>{a === a.toLowerCase() ? a.charAt(0).toUpperCase() + a.slice(1) : a}</span>;

export const Section = ({ children }: { children: ReactNode }) => <div className="pol-fld">{children}</div>;
