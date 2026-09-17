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
  /** Stable across runs, unlike `id` (a per-run uuid4). Compliance results reference
   *  findings by this, so it is what a control links through on. */
  dedupe_key?: string;
  merged_rules?: string[];
  /** Only populated when those rules DISAGREED about the weakness, in which case
   *  `cwe` is null — docket will not pick one arbitrarily. */
  merged_cwes?: string[];
}

/** `partial` means recon ran out of turns and recorded what it had on a salvage turn.
 *  Everything present is real; what is absent was never looked at. */
/** One pull-request verdict from the watcher. `exit_code` follows the CI convention:
 *  0 clean, 1 could not tell, 2 something blocks the merge. */
export interface PrResult {
  repo: string;
  number: number;
  title: string;
  head_sha: string;
  base_ref: string;
  at: number;
  /** True while the scan is still running. A PR appears the moment it is picked up,
   *  not minutes later when the verdict lands. */
  scanning?: boolean;
  error: string | null;
  exit_code: number | null;
  reason: string;
  new: number;
  reachable: number;
  fixed: number;
  trustworthy: boolean;
  posted: Record<string, string>;
  findings: {
    rule_id?: string; title?: string; severity?: string;
    discovered_by?: string; where?: string; verdict?: string;
    /** Where the problem actually lives, when that is not where it was anchored. The
     *  anchor has to stay inside the diff for scoping; this may point anywhere. */
    root_cause?: string | null;
    /** The agent's reading of whether THIS change caused it. Absent on scanner
     *  findings, which are diffed against a baseline and need no opinion. */
    origin?: string | null;
  }[];
  /** True when a fix can still be attempted: the verdict blocked, this process holds
   *  the inputs a patch needs, and no fix PR has been opened yet. Goes false after a
   *  restart, because the full head sha and each finding's PoC live in memory only. */
  fixable?: boolean;
  /** The fix docket opened for this PR, with its unified diff per file — the same
   *  "files changed" a reviewer would open on GitHub, rendered inline in the drawer. */
  fix?: {
    number?: number;
    url?: string;
    files: { path: string; lines: string[] }[];
  };
  /** Live timeline, present ONLY while the scan is in flight. It is dropped the moment
   *  the verdict lands, because the verdict is the durable record and a timeline left
   *  behind would show a scan that is no longer running. */
  progress?: PrProgress;
}

export interface PrStep {
  name: string;
  label: string;
  state: "pending" | "running" | "done" | "error" | "skipped";
  started: number | null;
  ended: number | null;
  /** What it is working on right now — a file, a finding, a refusal reason. */
  detail: string;
}

export interface PrProgress {
  /** Which side is being scanned: "head", "base", or "" before either starts. */
  phase: string;
  started: number;
  /** Findings collected so far. Rises while the scanners run. */
  findings: number;
  steps: PrStep[];
  agents: {
    id: string; role: string; label: string; detail: string;
    status: string; at: number; outcome?: string | null;
  }[];
}

export interface WatchState {
  enabled: boolean;
  /** Opt-in. When on, a BLOCKED pull request also gets a fix PR — but only if the
   *  fix verifies by re-scanning. An unproven patch is never opened. */
  autofix?: boolean;
  repos: string[];
  interval_sec: number;
  last_poll: number | null;
  next_poll: number | null;
  error: string | null;
  results: PrResult[];
}

/** A fix PR docket opened, read live from GitHub (`/api/fixes`) so the dashboard's
 *  "Fixes shipped" survives a console restart, unlike the watcher's in-memory results. */
export interface FixPr {
  repo: string;
  /** The original PR the fix targets, parsed from the `docket/fix/<n>-<sha>` branch. */
  number: number | null;
  title: string;
  fix: { number: number; url: string };
  at: number;
}

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
  /** One row per requested control pack. ALWAYS an array — [] means no pack was asked
   *  for, which is a different statement from a pack that ran and assessed nothing. */
  compliance?: PackResult[];
}

/* ---------------------------------------------------------------------------
 * Compliance. Mirrors engine/docket/compliance/models.py field-for-field.
 *
 * Note what is NOT here: no `score`, no `percent`. There is no honest single number —
 * pass-rate and coverage move in opposite directions, so an agent that gives up on
 * every hard control would score 100% on what is left. Render `counts` and `assessed`,
 * or the backend's `label`. Never divide by `total_controls` to get a pass rate.
 * ------------------------------------------------------------------------- */

export type ControlStatus =
  | "pass"
  | "fail"
  | "not_applicable"
  /** Looked, could not settle it. The safe landing for anything unrecognised. */
  | "unknown"
  /** No repository can answer this one — it is organisational or a deployment property.
   *  Written by the backend, never by a model, and never counted as satisfied. */
  | "not_observable";

/** Display order: what was decided first, what could not be answered last. */
export const CONTROL_STATUSES: ControlStatus[] = [
  "fail",
  "pass",
  "unknown",
  "not_applicable",
  "not_observable",
];

export const CONTROL_STATUS_LABEL: Record<ControlStatus, string> = {
  fail: "Not satisfied",
  pass: "Satisfied",
  unknown: "Inconclusive",
  not_applicable: "Not applicable",
  not_observable: "Not answerable from code",
};

/** The compliance analogue of PoC, and deliberately weaker. A PoC is request/response:
 *  something that happened. This is file/line/quote: something that was read. */
export interface Citation {
  file: string;
  line: number | null;
  quote: string;
}

export interface ControlResult {
  control_id: string;
  status: ControlStatus;
  rationale: string;
  citations: Citation[];
  /** What was searched before giving up. Only meaningful on `unknown`. */
  looked_at: string;
  judged_by: string;
  judged_at: string;
  /** dedupe_keys of findings that independently PROVED this control's weakness class.
   *  Non-empty on a `fail` means it is more than an LLM's opinion. */
  proven_findings: string[];
  /** A `pass` sitting next to a reproduced exploit of the same class. The count of these
   *  is the honest measure of how far to trust a pack run. */
  contradicted_by: string[];
  /** Set when the finish tool refused to take a claim at face value — an uncited pass
   *  becomes an unknown, and this records what it was. */
  downgraded_from: ControlStatus | null;
  escalated: boolean;
}

export interface PackResult {
  pack_id: string;
  pack_title: string;
  authority: string;
  version: string;
  origin: "builtin" | "uploaded";
  /** Every control in the pack, including the ones no repository can answer. */
  total_controls: number;
  results: ControlResult[];
  requested: number;
  judged: number;
  /** Controls the runner wrote as unknown because no agent reached them. Distinct from
   *  a control that was judged inconclusive — this one was never looked at. */
  unjudged: number;
}

/** A row from GET /api/compliance/packs — what a picker needs, without the controls. */
export interface PackSummary {
  id: string;
  title?: string;
  authority?: string;
  version?: string;
  origin?: "builtin" | "uploaded";
  source_url?: string;
  total_controls?: number;
  /** The number a picker must show BEFORE the choice: 14 of 43, not 43. */
  source_controls?: number;
  usable: boolean;
  error?: string;
}

export interface ControlDefinition {
  id: string;
  title: string;
  requirement: string;
  observability: "source" | "runtime" | "process";
  severity: Severity;
  citation: string;
  evidence_hint: string;
  cwe: string[];
  rule_ids: string[];
}

export interface ControlPack {
  id: string;
  title: string;
  authority: string;
  version: string;
  origin: "builtin" | "uploaded";
  source_url: string;
  notes: string;
  controls: ControlDefinition[];
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
  /** Findings triaged reachable-by-untrusted-input (triage_counts.CONFIRMED). Absent on
   *  runs where triage never ran — treat as unknown, not zero. */
  reachable_count?: number;
  cost_usd: number;
  /* app/backend adds these so the run list can show in-flight and failed runs, not
     just finished ones. A scan that died before its first event has only a log. */
  modified?: number;
  finished?: boolean;
  running?: boolean;
  failed?: boolean;
}

// Order matters: these are the radar's rings and the stage list, outermost last, and
// they must match the order run_scan actually executes them in. `compliance` sits
// between recon and triage because that is where the runner puts it.
export const SCANNERS = ["fetch", "trivy", "semgrep", "nuclei", "recon", "compliance",
                         "triage"] as const;
export type Scanner = (typeof SCANNERS)[number];

export const SCANNER_LABEL: Record<Scanner, string> = {
  fetch: "fetch source",
  trivy: "trivy · dependencies",
  semgrep: "semgrep · source",
  nuclei: "nuclei · live target",
  recon: "recon · AI attack surface",
  compliance: "compliance · AI control audit",
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
