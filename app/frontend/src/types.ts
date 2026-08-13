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
/** One pull-request verdict from the watcher. `exit_code` follows the CI convention:
 *  0 clean, 1 could not tell, 2 something blocks the merge. */
export interface PrResult {
  repo: string;
  number: number;
  title: string;
  head_sha: string;
  base_ref: string;
  at: number;
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
  }[];
}

export interface WatchState {
  enabled: boolean;
  repos: string[];
  interval_sec: number;
  last_poll: number | null;
  next_poll: number | null;
  error: string | null;
  results: PrResult[];
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
