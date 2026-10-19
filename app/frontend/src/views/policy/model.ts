/** Pure helpers for the Policies page: the draft, how it maps to and from the server's policy, and
 *  how it is shaped for `<docket-policy-flow>`. No React and no DOM, so it can be compiled and
 *  asserted on its own (see the self-check at the bottom). Nothing here ranks or scores anything. */
import type {
  Availability, Catalog, CatalogGuideline, CatalogSlot, CatalogTool, Origin, PolicyBody, PolicyRec, ProfileFields, ProfileKey,
} from "../../portfolio";

export const PROFILE_FIELDS: [ProfileKey, string][] = [
  ["category", "Category"], ["exposure", "Exposure"], ["stack", "Stack"], ["tier", "Tier"],
];

export interface DraftStep { id: string; required: boolean; tool: string | null; cadence_days: number | null }
export interface Draft {
  /** The library key: the saved id, or `new-N` for a policy that is not saved yet. */
  key: string;
  /** The id the server knows this policy by; null until the first save. */
  savedId: string | null;
  name: string;
  applies_when: ProfileFields;
  cadence_days: number;
  steps: DraftStep[];
  guidelines: string[];
}

export const emptyWhen = (): ProfileFields => ({ category: [], exposure: [], stack: [], tier: [] });
const clone = <T>(o: T): T => JSON.parse(JSON.stringify(o)) as T;

/** Steps always sit in the order Docket runs them: catalog order. There is no reordering. */
export function inCatalogOrder(steps: DraftStep[], catalog: Catalog): DraftStep[] {
  const rank = new Map(catalog.slots.map((s, i) => [s.id, i]));
  return [...steps].sort((a, b) => (rank.get(a.id) ?? 99) - (rank.get(b.id) ?? 99));
}

export function draftFromPolicy(p: PolicyRec, catalog: Catalog): Draft {
  return {
    key: p.id, savedId: p.id, name: p.name, cadence_days: p.cadence_days,
    applies_when: { ...emptyWhen(), ...clone(p.applies_when ?? emptyWhen()) },
    guidelines: [...(p.guidelines ?? [])],
    steps: inCatalogOrder(p.steps.map((s) => ({
      id: s.id, required: s.id === "compliance" ? false : s.required !== false, tool: s.tool_id ?? null, cadence_days: s.cadence_days ?? null,
    })), catalog),
  };
}

export const blankDraft = (key: string, catalog: Catalog): Draft => ({
  key, savedId: null, name: "New policy", cadence_days: 7, applies_when: emptyWhen(), guidelines: [],
  steps: inCatalogOrder(["trivy", "semgrep"].map((id) => ({ id, required: true, tool: null, cadence_days: null })), catalog),
});

export function templateDraft(p: PolicyRec, key: string, catalog: Catalog): Draft {
  return { ...draftFromPolicy(p, catalog), key, savedId: null, name: `Copy of ${p.name}` };
}

/** The id a new policy is saved under: the name, slugged, and made unique among the ids in use. */
export function slugify(name: string): string {
  return name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 56).replace(/-+$/g, "");
}
export function uniqueId(name: string, taken: string[]): string {
  const base = slugify(name) || "policy";
  if (!taken.includes(base)) return base;
  for (let n = 2; n < 1000; n++) if (!taken.includes(`${base}-${n}`)) return `${base}-${n}`;
  return `${base}-${Date.now()}`;
}

/** The body PUT and POST /preview take. Steps in catalog order; the compliance reader is never required. */
export function toBody(d: Draft, id: string, catalog: Catalog): PolicyBody {
  return {
    id, name: d.name.trim(), cadence_days: d.cadence_days, guidelines: [...d.guidelines],
    applies_when: clone(d.applies_when),
    steps: inCatalogOrder(d.steps, catalog).map((s) => ({
      id: s.id, required: s.id === "compliance" ? false : s.required, tool: s.tool, cadence_days: s.cadence_days,
    })),
  };
}
/** A stable string for "is this draft different from what is saved". */
export const fingerprint = (d: Draft, catalog: Catalog): string => JSON.stringify(toBody(d, d.savedId ?? "-", catalog));

/** Mistakes the page can state before it asks the server (the server remains the judge). */
export function localErrors(d: Draft): string[] {
  const out: string[] = [];
  if (!d.name.trim()) out.push("Give the policy a name.");
  if (!d.steps.some((s) => s.required)) out.push("Require at least one step. A policy with nothing required would put every application in the 'checks current' half.");
  if (!Number.isInteger(d.cadence_days) || d.cadence_days < 1 || d.cadence_days > 365) out.push("The cadence must be a whole number of days from 1 to 365.");
  return out;
}

// ── catalog lookups ────────────────────────────────────────────────────────────────────────────
export const slotOf = (catalog: Catalog, id: string): CatalogSlot | undefined => catalog.slots.find((s) => s.id === id);
export const defaultToolOf = (slot: CatalogSlot): CatalogTool => slot.tools.find((t) => t.default) ?? slot.tools[0]!;
export const toolOf = (slot: CatalogSlot, toolId: string | null): CatalogTool =>
  slot.tools.find((t) => t.id === toolId) ?? defaultToolOf(slot);
/** Only a tool Docket runs or imports can be chosen; `planned` is shown, never selectable or saved. */
export const selectable = (t: CatalogTool): boolean => t.availability !== "planned";
/** A step the policy cannot honestly require today: its chosen tool is planned. */
export const stepIsPlanned = (slot: CatalogSlot, s: DraftStep): boolean => toolOf(slot, s.tool).availability === "planned";

export const REQUIRED_BY_DEFAULT = new Set(["trivy", "semgrep", "triage", "swarm"]);
export const AVAILABILITY_WORD: Record<Availability, string> = { runs: "Runs in Docket", imports: "Imports SARIF", planned: "Planned" };

// ── what `<docket-policy-flow>` is given ───────────────────────────────────────────────────────
export interface FlowStepIn {
  id: string; label: string; tool: string; origin: Origin; availability: Availability; required: boolean;
  cadence: string; what: string; produces: string; command: string; icon: string; group?: "pre" | "agents" | "guidelines";
}
export const appliesText = (w: ProfileFields): string => {
  const bits = PROFILE_FIELDS.map(([f]) => w[f].join(" or ")).filter(Boolean);
  return bits.length ? `${bits.join(", ")} applications` : "Every application not covered by a more specific policy";
};

/** The cadence line on a station. A required step is judged against a window; an optional one only
 *  when it ran. Neither says the policy starts anything. */
export function cadenceText(s: DraftStep, policyDays: number): string {
  if (s.id === "compliance") return "Advises only. Never blocks.";
  if (!s.required) return "Judged only when it runs";
  return `At least every ${s.cadence_days ?? policyDays} days`;
}

export function hydrateSteps(d: Draft, catalog: Catalog): FlowStepIn[] {
  const out: FlowStepIn[] = [];
  for (const s of inCatalogOrder(d.steps, catalog)) {
    const slot = slotOf(catalog, s.id);
    if (!slot) continue;
    const t = toolOf(slot, s.tool);
    out.push({
      id: slot.id, label: slot.label, tool: t.name, origin: t.origin, availability: t.availability,
      required: s.id === "compliance" ? false : s.required, cadence: cadenceText(s, d.cadence_days),
      what: slot.what, produces: slot.produces, command: slot.command, icon: slot.icon,
    });
  }
  return out;
}

export const hydratePacks = (d: Draft, catalog: Catalog): CatalogGuideline[] =>
  d.guidelines.map((id) => catalog.guidelines.find((g) => g.id === id)).filter((g): g is CatalogGuideline => Boolean(g));

// ── profile matching (display only: the server decides assignment) ─────────────────────────────
/** True when the application's profile satisfies every constrained field. Used only to name the
 *  applications that fit a profile but sit under a more specific policy; the count and list of
 *  "matches" always come from the server's preview. */
export function fitsProfile(w: ProfileFields, a: { category?: string | null; exposure?: string | null; stack?: string | null; tier?: string | null }): boolean {
  return PROFILE_FIELDS.every(([f]) => !w[f].length || (a[f] != null && w[f].includes(a[f] as string)));
}

/** Server wording for a preview outcome, in the page's words. */
export const OUTCOME_WORD = { meets: "Current", breaches: "Lacks a check", none: "No policy" } as const;

// ── self-check (run by `npm run check:policy-model` style compile; see report) ─────────────────
export function selfCheck(catalog: Catalog): string[] {
  const bad: string[] = [];
  const t = (ok: boolean, msg: string) => { if (!ok) bad.push(msg); };
  t(slugify("Banking, customer-facing!") === "banking-customer-facing", "slugify punctuation");
  t(slugify("  --  ") === "", "slugify empty");
  t(uniqueId("Banking", ["banking", "banking-2"]) === "banking-3", "uniqueId suffix");
  t(uniqueId("???", []) === "policy", "uniqueId fallback");
  t(/^[a-z0-9][a-z0-9._-]{0,63}$/.test(uniqueId("A".repeat(200), [])), "id fits the server's pattern");
  const d = blankDraft("new-1", catalog);
  d.steps.push({ id: "triage", required: true, tool: null, cadence_days: null }, { id: "compliance", required: true, tool: null, cadence_days: null });
  d.steps.unshift({ id: "swarm", required: true, tool: null, cadence_days: null });
  const body = toBody(d, "x", catalog);
  t(body.steps.map((s) => s.id).join() === catalog.slots.map((s) => s.id).filter((i) => ["trivy", "semgrep", "triage", "compliance", "swarm"].includes(i)).join(), "catalog order");
  t(body.steps.find((s) => s.id === "compliance")!.required === false, "compliance never required");
  t(localErrors({ ...d, steps: d.steps.map((s) => ({ ...s, required: false })) }).length === 1, "zero required refused");
  t(localErrors({ ...d, name: " " }).length === 1, "blank name refused");
  t(fitsProfile({ ...emptyWhen(), tier: ["Tier 1"] }, { tier: "Tier 1" }) && !fitsProfile({ ...emptyWhen(), tier: ["Tier 1"] }, { tier: null }), "fitsProfile");
  return bad;
}
