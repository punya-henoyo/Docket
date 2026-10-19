/** Types for the Code Security views. Mirror docs/ui/api-contract.md; the server computes every
 *  value and the UI never derives, ranks or sums anything the server did not send. */

export type Level = "action" | "attention" | "clear" | "unknown";
export type Origin = "henoyo" | "third_party";
export type Coverage = "full" | "partial" | "failed";
export type Proof = "reproduced" | "deterministic" | "candidate" | "not_reachable";
export type Tone = "ok" | "warn" | "bad";

export interface ScanEvent {
  id: string;
  at: string;
  coverage: Coverage;
  proven: number;
  candidates: number;
  kind: "scan" | "pr";
  label?: string | null;
}

export interface Application {
  id: string;
  label: string;
  repo: string;
  tier: string;
  owner: string;
  lang: string;
  level: Level;
  reason: string;
  age_days: number | null;
  last_scan_at: string | null;
  events: ScanEvent[];
}

export interface Portfolio {
  generated_at: string;
  sample?: boolean;
  window_days: number;
  cadence_days: number;
  organization: string;
  counts: Record<Level, number>;
  applications: Application[];
  scanner_coverage: { id: string; label: string; tool?: string | null; origin: Origin; required: boolean; current: number; of: number }[];
  trend: { periods: { key: string; label: string }[]; series: { key: string; label: string; values: number[] }[] };
  /** Absent on a server older than the posture map. */
  posture?: Posture;
  severity_age: {
    old_critical: number;
    old_age: string;
    rows: string[];
    columns: string[];
    cells: { row: string; col: string; value: number }[];
  };
}

export interface Annunciator { key: string; label: string; state: Tone | "off"; value: string; hint?: string }
export interface Analyte {
  key: string; label: string; hint?: string; value: number; display: string; scaleMax: number;
  bands: { from: number; to: number; tone: Tone }[]; ref: string; flag: Tone | "unknown"; flagWord: string;
  trend?: number[]; previous?: string; higherIsBetter?: boolean;
}
export interface Health { level: Level; verdict: string; reasons: string[]; annunciators: Annunciator[]; analytes: Analyte[] }
export interface BannerRow {
  id: string; level: "danger" | "warning" | "info" | "success"; word?: string; message: string; reason?: string;
  actionLabel?: string | null; href?: string | null;
}

export interface Lane {
  id: string; label: string; tool?: string; origin: Origin; group: string;
  state: "done" | "running" | "queued" | "error" | "skipped" | "not_run"; icon?: string;
  start?: number; end?: number; required?: boolean; requiredBy?: string[]; candidates?: number; proven?: number;
  summary?: string; cost?: number; parentId?: string;
}
export interface LaneGroup { key: string; label: string; sub?: string }

export interface PortfolioFinding {
  id: string; run: string; application: string; sev: "critical" | "high" | "medium" | "low" | "info";
  title: string; sub: string; proof: Proof; reach?: string | null; by: { origin: Origin; name: string };
  age_days: number | null; status: string; rule_id?: string; cwe?: string | null; location?: string | null;
  poc?: { request: string; response: string; notes?: string | null } | null;
  triage?: { verdict: string; reasoning: string; evidence?: string | null } | null;
  fix?: { summary: string; diff?: string | null } | null;
  evidence_ref?: string | null;
}

export interface ApplicationDetail {
  application: Application;
  health: Health;
  banner: BannerRow[];
  lifecycle: { current: string; since: string | null; owner: string };
  pipeline: { run: string | null; lanes: Lane[]; groups: LaneGroup[]; policy: string | null };
  findings: PortfolioFinding[];
  scans: { id: string; at: string; kind: "scan" | "pr"; coverage: Coverage; proven: number; candidates: number }[];
  fixes: { title: string; fixes: string; status: string; url?: string | null; opened_at: string }[];
  compliance: { pack_id: string; title: string; met: number; not_met: number; unknown: number; not_observable: number }[];
}

export interface PipelineDetail {
  run: string; application: string; started_at: string | null; ended_at: string | null; elapsed: number;
  commit: string | null; cost_usd: number; agents: number; tokens: { input: number; output: number };
  policy: string | null; lanes: Lane[]; groups: LaneGroup[];
  required?: { ran: number; of: number };
}

export interface PolicyWhy {
  kind: "security" | "regulatory"; text: string; authority?: string | null; obligation_ref?: string | null;
  clause?: string | null; source_url?: string | null;
}
export interface PolicyStep {
  n: number; id: string; label: string; tool?: string | null; origin: Origin; phase: string; required: boolean; cadence: string; on_fail: string; why: PolicyWhy[];
}
export interface Policy {
  id: string; name: string; applies: string; applies_count: number; version: number; approved?: string | null; cadence_days: number;
  steps: PolicyStep[];
  regulatory: { authority: string; text: string; obligation_ref: string; clause?: string | null; source_url?: string | null }[];
  security: { text: string; detail: string }[];
  gate: { effect: "blocks" | "flags" | "advises"; text: string }[];
}
export interface PolicyPayload {
  policies: Policy[];
  coverage: {
    policy: string; window_days: number;
    scanners: { id: string; label: string; tool?: string | null; origin: Origin; icon?: string }[];
    rows: { id: string; label: string; tier: string; cells: Record<string, { state: "ok" | "stale" | "missing" | "na"; ago?: string }> }[];
  };
}

/* ── Policies builder (docs/ui/policy-and-posture.md, sections 3 and 5.3) ─────────────────────────
 * Kept in one block, additive only, so it cannot collide with the posture types. Shapes are what
 * the server really sends (GET /api/catalog, /api/policy, POST /api/policy/preview), which differ
 * from the spec in places: the preview says `would_breach` and `meets`/`breaches`/`none`. */

export type Availability = "runs" | "imports" | "planned";
export type StepGroup = "pre" | "agents" | "guidelines";
export interface ProfileFields { category: string[]; exposure: string[]; stack: string[]; tier: string[] }
export type ProfileKey = keyof ProfileFields;

export interface CatalogTool { id: string; name: string; origin: Origin; availability: Availability; default?: boolean }
export interface CatalogSlot {
  id: string; label: string; capability: string; phase: "pre" | "agents"; icon: string; origin: Origin;
  what: string; produces: string; command: string; tools: CatalogTool[];
}
export interface CatalogStart { kind: string; label: string; availability: "works" | "planned"; note?: string }
export interface CatalogGuideline {
  id: string; authority: string; title: string; version?: string; controls: number; observable: number;
  source_url?: string | null; origin?: string;
}
export interface Catalog {
  slots: CatalogSlot[]; starts: CatalogStart[]; profile: ProfileFields; guidelines: CatalogGuideline[];
}

/** One step as GET /api/policy sends it (PolicyStep plus the fields the builder needs). */
export type PolicyStepRec = PolicyStep & { tool_id?: string | null; availability?: Availability; cadence_days?: number | null };
/** Two policies equally specific for the same applications (refused on save, shown if the file already has one). */
export interface PolicyConflict { ids: string[]; message: string }
/** A policy as GET /api/policy sends it. `Policy` predates profiles, guidelines and warnings. */
export type PolicyRec = Omit<Policy, "steps"> & {
  steps: PolicyStepRec[];
  applies_when: ProfileFields;
  meets_count: number | null;
  default: boolean;
  status: string;
  guidelines: string[];
  starts: CatalogStart[];
  warnings: string[];
  conflicts: PolicyConflict[];
};
export interface PolicyListPayload {
  policies: PolicyRec[];
  conflicts: PolicyConflict[];
  coverage: Omit<PolicyPayload["coverage"], "rows"> & {
    rows: (PolicyPayload["coverage"]["rows"][number] & { consequence?: { effect: "blocks" | "flags"; text: string } | null })[];
  };
  sample?: boolean;
}

/** What PUT /api/policy/<id> and POST /api/policy/preview accept. */
export interface PolicyBody {
  id: string; name: string; applies_when: ProfileFields; cadence_days: number; guidelines: string[];
  steps: { id: string; required: boolean; tool: string | null; cadence_days: number | null }[];
}
export interface PreviewChange { id: string; label: string; before: "meets" | "breaches" | "none"; after: "meets" | "breaches" | "none"; why: string }
export interface PolicyPreview {
  matches: { id: string; label: string; tier: string; category: string | null; exposure: string | null }[];
  would_meet: number; would_breach: number;
  changes: PreviewChange[];
  plan: { id: string; n: number; label: string; tool: string; tool_id: string | null; origin: Origin; availability: Availability | null; required: boolean; command: string; what: string; produces: string }[];
  warnings: string[]; conflicts: string[]; generated_at: string;
}
/** The fields the policy views read from an application (the server sends them; `Application` predates them). */
export interface AppProfile {
  category?: string | null; exposure?: string | null; stack?: string | null; policy?: string | null;
  assignment?: { policy: string; via: "pinned" | "matched" | "default"; incomplete: string[]; overrides: string | null };
}

/* ── Posture (docs/ui/policy-and-posture.md, sections 4 and 5) ────────────────────────────────────
 * What GET /api/portfolio sends under `posture`. The server decides every cell, note, movement and
 * leader; these types only describe it. Kept in one block, additive only. Differences from the spec:
 * categories send `checks_current` (the spec says `meet_policy`), leaders carry `cell`, `assurance`,
 * `standing`, `days_in_cell` and `moved_since`, points carry `policy_name`, `assurance_detail` and
 * `proven_as_of`, and there is no `strip` object. */

export type QuadCell = "tl" | "tr" | "bl" | "br";
export type Direction = "up" | "down" | "steady";
export interface Movement { assurance: Direction; standing: Direction }
export interface PostureTrailPoint {
  at: string; assurance: number; standing: number; cell?: QuadCell; level?: Level; assurance_note?: string; standing_note?: string;
}
export interface PosturePoint {
  id: string; label: string; tier: string; category?: string | null; exposure?: string | null;
  policy?: string | null; policy_name?: string | null; level: Level; reason?: string;
  /** 0..100 places the dot inside its half. Never shown. */
  assurance: number; standing: number; cell: QuadCell; days_in_cell?: number | null;
  assignment?: NonNullable<AppProfile["assignment"]>;
  assurance_note?: string; assurance_detail?: string; standing_note?: string; proven_as_of?: string | null;
  trail?: (PostureTrailPoint | null)[];
  moved?: Movement | "new" | null; moved_since?: string;
}
export interface PostureLeader {
  id: string; label: string; tier: string; level: Level; reason: string; cell?: QuadCell;
  days_in_cell?: number | null; moved?: Movement | "new" | null; moved_since?: string;
}
export interface PostureUnassessed { id: string; label: string; tier?: string; category?: string | null; exposure?: string | null; reason?: string }
export interface PostureQuadrant { key: QuadCell; title: string; note: string }
export interface PostureSnapshotCount { at: string; tl: number; tr: number; bl: number; br: number; unassessed?: number }
export interface PostureAssessments {
  days: number; total: number; scan: number; pr: number;
  outcomes: { proven: number; candidates: number; clean: number; incomplete: number };
  weekly: { label: string; from?: string; at?: string; proven: number; candidates: number; clean: number; incomplete: number }[];
}
export interface PostureCategory {
  key: string; category?: string; exposure?: string; apps: number; checks_current: number;
  levels: Record<Level, number>;
}
export interface Posture {
  as_of: string; history_days: number; snapshots: string[];
  points: PosturePoint[]; by_snapshot: PostureSnapshotCount[]; unassessed: PostureUnassessed[];
  quadrants: PostureQuadrant[];
  leaders: { worst: PostureLeader[]; best: PostureLeader[] };
  assessments: PostureAssessments; categories: PostureCategory[];
}
