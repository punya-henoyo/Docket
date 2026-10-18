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
  by_origin: { label: string; origin: Origin; count: number; proven?: boolean }[];
  trend: { periods: { key: string; label: string }[]; series: { key: string; label: string; values: number[] }[] };
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
}

export interface PolicyWhy {
  kind: "security" | "regulatory"; text: string; authority?: string | null; obligation_ref?: string | null;
  clause?: string | null; source_url?: string | null;
}
export interface PolicyStep {
  n: number; id: string; label: string; tool?: string | null; origin: Origin; phase: string; cadence: string; on_fail: string; why: PolicyWhy[];
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
