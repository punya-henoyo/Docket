/** Mirrors docket's own report model (engine/docket/report/models.py). Kept in the
 *  same field names so what the console shows and what report.json contains cannot
 *  drift into two different vocabularies. */

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

export interface Location {
  method: string;
  path: string;
  parameter: string | null;
  source_file: string | null;
}

export interface PoC {
  request: string;
  response: string;
  notes: string | null;
}

export type Verdict = "exploitable" | "not_reachable" | "uncertain";

/** An agent's judgement on whether a static finding is reachable. Weaker than a PoC
 *  by design: it is reasoning over source, with nothing exploited. */
export interface Triage {
  verdict: Verdict;
  reasoning: string;
  evidence: string;
}

/** A CVSS score docket RECEIVED, never one it computed.
 *
 *  Present only for trivy (CVE advisories) and nuclei (template classification).
 *  semgrep matches carry none, and are shown with no score rather than an invented
 *  one — on screen a guessed 9.8 is indistinguishable from a measured one. */
export interface Cvss {
  score: number;
  vector: string | null;
  version: string;
  source: string;
}

export interface Finding {
  id: string;
  /* Optional because a run with no report.json is projected from events.jsonl, where a
     finding carries rule_type but not rule_id. Anything rendering these must tolerate
     both — see ui.ruleLeaf. */
  rule_id?: string;
  rule_type?: string;
  cwe: string | null;
  title: string;
  severity: Severity;
  location?: Location;
  description?: string;
  poc?: PoC;
  discovered_by: string;
  discovered_at: string;
  status: string;
  corroborating_evidence: PoC[];
  /** null means nobody looked, which differs from looked-and-unsure. */
  triage: Triage | null;
  /** null means no scoring body published one, NOT a score of zero. */
  cvss?: Cvss | null;
  /** Rule ids folded into this finding when several matched the same line. Empty on
   *  an unmerged finding. */
  merged_rules?: string[];
  /** Only populated when those rules DISAGREED about the weakness, in which case
   *  `cwe` is null — docket will not pick one arbitrarily. */
  merged_cwes?: string[];
}

/** `partial` means recon ran out of turns and recorded what it had on a salvage turn.
 *  Everything present is real; what is absent was never looked at. */
export interface EntryPoint {
  method?: string;
  path?: string;
  handler?: string;
  /** Required by record_surface: a route nobody can point at in source is not a route. */
  file?: string;
  params?: string[];
  auth?: string;
  kind?: string;
}

export interface Candidate {
  title?: string;
  file?: string;
  why?: string;
}

/** What the recon agent mapped. Null until recon runs, which is opt-in. */
export interface Surface {
  partial?: boolean;
  entry_points: EntryPoint[];
  auth_model: string;
  candidates: Candidate[];
  notes: string;
}

export type StageState = "pending" | "running" | "done" | "skipped" | "error";
/** "cancelled" is deliberately distinct from "error": the operator stopped it, the
 *  findings already produced are real and were saved, and the rest was never looked
 *  at. Calling a deliberate stop a failure trains people to ignore failures. */
export type ScanStatus =
  | "queued" | "fetching" | "scanning" | "done" | "error" | "cancelled";

/** One agent's lifecycle within a scan.
 *
 *  `turns` and `cost_usd` are joined server-side from the usage ledger the budget hook
 *  writes on every model turn, so they are the provider's numbers, not an estimate. */
export interface AgentRecord {
  id: string;
  role: string;
  status: "running" | "done" | "error";
  label?: string;
  detail?: string;
  outcome?: string;
  turns?: number;
  cost_usd?: number;
}

export interface ScanState {
  id: string;
  repo: string;
  /** null = whatever GitHub calls the repo's default branch. */
  ref: string | null;
  status: ScanStatus;
  stages: Record<string, StageState>;
  agents?: AgentRecord[];
  findings: Finding[];
  finding_count: number;
  error: string | null;
  summary?: string;
  elapsed_sec?: number;
  /** True when loaded from disk rather than observed live: the radar has no stages to
   *  light and the sweep must not animate. */
  historical?: boolean;
  triage_max?: number;
  recon?: boolean;
  surface?: Surface | null;
  coverage?: {
    semgrep?: {
      files_scanned?: number;
      file_types?: Record<string, number>;
      rules_fired?: string[];
      error_count?: number;
      errors?: string[];
    };
    trivy?: { manifests?: string[]; manifest_count?: number };
    nuclei?: { ran?: boolean };
  };
  cost_usd?: number;
  input_tokens?: number;
  output_tokens?: number;
  budget_usd?: number;
}

export interface Session {
  connected: boolean;
  login: string | null;
  configured: boolean;
  /** The OAuth scope granted. Surfaced so the console can state on screen that the
   *  token carries write access, which GitHub gives no way to avoid for private code. */
  scope: string;
}

export interface Repo {
  full_name: string;
  private: boolean;
  language: string | null;
  updated_at: string | null;
}

export interface RunSummary {
  run_name: string;
  target: string | null;
  generated_at?: string | null;
  finding_count: number;
  severity_counts: Partial<Record<Severity, number>>;
  cost_usd: number;
  /* app/backend adds these so the run list can show in-flight and failed runs, not
     just finished ones. A scan that died before its first event has only a log. */
  modified?: number;
  finished?: boolean;
  running?: boolean;
  failed?: boolean;
}

export const SCANNERS = ["fetch", "trivy", "semgrep", "nuclei", "recon", "triage"] as const;
export type Scanner = (typeof SCANNERS)[number];

export const SCANNER_LABEL: Record<Scanner, string> = {
  fetch: "fetch source",
  trivy: "trivy · dependencies",
  semgrep: "semgrep · source",
  nuclei: "nuclei · live target",
  recon: "recon · AI attack surface",
  triage: "triage · AI reachability",
};


/* ---------------------------------------------------------------------------------
 * Local agent runs. The types above cover a repo scan (deterministic scanners over
 * GitHub source); these cover a full agent run against a live target, which is the
 * other half of what docket does and what app/backend serves.
 * --------------------------------------------------------------------------------- */

export interface AgentNode {
  agent_id: string;
  name?: string;
  role?: string;
  status: string;
  parent_id?: string | null;
  tool_calls: number;
  findings: number;
  summary?: string;
  depth: number;
}

/** One row per tool call and per tool result, from
 *  engine/docket/interface/tui/backend/projection.py. NOT a free-text log. */
export interface TranscriptLine {
  ts?: number;
  agent_id?: string;
  role?: string;
  kind?: "call" | "result" | string;
  tool?: string;
  args?: Record<string, unknown>;
  output?: string;
}

/** A static-analysis candidate. Deliberately NOT a Finding: it carries no reproduced
 *  request/response and never will, so it lives in its own list and never touches
 *  finding_count or the exit code. See engine/docket/report/writer.py. */
export interface FlaggedCandidate {
  rule_id: string;
  engine: string;
  severity: Severity;
  cwe: string | null;
  message: string;
  file: string;
  line: number;
  snippet: string | null;
  status: "flagged_not_proven";
  endpoint: string | null;
  reachable: boolean;
  correlation_confidence: string;
  correlation_reason: string;
  cwe_proven_dynamically: boolean;
}

export interface RunPayload {
  run_name: string;
  target?: string;
  finished: boolean;
  running?: boolean;
  exit_code?: number | null;
  summary?: string;
  severity_counts: Partial<Record<Severity, number>>;
  finding_count: number;
  flagged_count?: number;
  flagged_not_proven?: FlaggedCandidate[];
  cost_usd: number;
  usage: { totals?: { total_tokens?: number } } & Record<string, unknown>;
  agents: AgentNode[];
  findings: Finding[];
  transcript: TranscriptLine[];
  notes: unknown[];
  todos: unknown[];
  has_sarif: boolean;
}

export interface Health {
  ok: boolean;
  llm?: string | null;
  docker: boolean;
  docker_error?: string | null;
  search?: string | null;
  warnings: string[];
  loopback_only: boolean;
  active_scan?: string | null;
}


/* ---------------------------------------------------------------------------------
 * The CONTROL PLANE. The types above describe scans an operator started; these
 * describe the ones that happen on their own — a pull request opens, the poller
 * notices, docket scans the diff, the gate decides. Served by
 * app/backend/routers/service.py over engine/docket/service/store.py's schema.
 * --------------------------------------------------------------------------------- */

export type AutofixMode = "off" | "suggest" | "open_pr";

/** Per-repo policy. TRI-STATE: `null` on any member means INHERIT the org default,
 *  which is a different answer from "off". `autofix_mode: null` inherits;
 *  `autofix_mode: "off"` is an operator saying no. Every key is always present — the
 *  backend fills the absent ones with null rather than omitting them, because an
 *  `undefined` read in a form control is what silently loses a setting. */
export interface Policy {
  autofix_mode: AutofixMode | null;
  max_files_changed: number | null;
  require_verified_validation: boolean | null;
  enabled_classes: string[] | null;
  /** 0 is a real setting (judge nothing); null inherits. */
  triage_max: number | null;
  /** null inherits. 0 is rejected by the backend: a $0 ceiling makes every triage
   *  agent trip its budget before its first turn and record `uncertain`, which is a
   *  fail-open wearing a green check. */
  budget_usd: number | null;
  label: string | null;
}

export const EMPTY_POLICY: Policy = {
  autofix_mode: null,
  max_files_changed: null,
  require_verified_validation: null,
  enabled_classes: null,
  triage_max: null,
  budget_usd: null,
  label: null,
};

export interface WatchedRepo {
  full_name: string;
  enabled: boolean;
  policy: Policy;
  added_at: string | null;
}

/** store.py's state machine. Named PrScanState because `ScanState` above is the
 *  repo-scan payload and the two must not be confused. */
export type PrScanState = "queued" | "scanning" | "delivered" | "failed" | "abandoned";

/** GitHub check-run vocabulary, from service/gate.py. `action_required` means a human
 *  must look: the scan did not fail, it did not finish being trustworthy. */
export type GateConclusion = "success" | "failure" | "action_required";

export interface PrScan {
  id: number | string;
  repo: string;
  pr: number | null;
  /** Not in store.py's documented schema yet, so read as optional. */
  title?: string | null;
  head_sha: string;
  base_sha: string;
  state: PrScanState;
  run_name: string | null;
  /** null = the gate has not reported yet. Widened to string because the column is
   *  free text and a value this console has never heard of must render, not crash. */
  conclusion: GateConclusion | string | null;
  /** ISO string or epoch seconds — store.py's column type is its own choice. */
  created_at: string | number | null;
  updated_at: string | number | null;
  lease_owner: string | null;
  lease_expires_at: string | number | null;
  /** Joined from the run's report.json. Always present, always a number. */
  finding_count?: number;
  cost_usd?: number;
  severity_counts?: Partial<Record<Severity, number>>;
  /** Columns store.py grows that this console has not been taught. */
  extra?: Record<string, unknown>;
}

/** The gate's verdict, re-evaluated from report.json. `reasons` is the argument for the
 *  conclusion, which the stored column does not keep. */
export interface GateVerdict {
  conclusion: GateConclusion | string;
  exit_code: number;
  reasons: string[];
  annotation_count: number;
}

/** A proposed fix. `verified` false covers "proof failed" AND "nobody tried" — the
 *  backend collapses unknown into false on purpose, so the UI can only ever err
 *  towards calling a patch unproven. */
export interface Patch {
  name: string;
  diff: string;
  truncated: boolean;
  verified: boolean;
  source: string;
  /** delivery.py's vocabulary. Only "verified_fixed" earns a branch and a fix PR. */
  status?: string | null;
  title?: string | null;
  summary?: string | null;
  /** Paths this patch rewrites. Compared against the policy's max_files_changed. */
  files?: string[];
}

export interface PrScanDetail extends PrScan {
  /** False means the run produced no report.json. "No findings" and "never scanned"
   *  look identical without this, and only one of them is good news. */
  report_found: boolean;
  findings: Finding[];
  triaged: unknown[];
  summary?: string | null;
  gate: GateVerdict | null;
  patches: Patch[];
}

/** What one poll pass found. poll.tick() records per-repo failures in `errors` and
 *  keeps going, so a pass can report success while a repo is not being watched at all —
 *  which is why this is surfaced rather than reduced to a boolean. */
export interface PollSummary {
  repos?: number;
  pull_requests?: number;
  enqueued?: unknown[];
  errors?: { repo?: string; error?: string }[];
}

export interface ServiceStatus {
  running: boolean;
  /** Epoch seconds, or null when the poller has never completed a pass. */
  last_tick: number | null;
  ticks: number;
  /** The last tick's failure. A poller that keeps running while every tick fails looks
   *  identical to a healthy one without this. */
  error: string | null;
  interval_sec: number | null;
  last_summary: PollSummary | null;
  watched: number;
  enabled: number;
  queue_depth: number;
  scanning: number;
  states: Partial<Record<PrScanState, number>>;
}
