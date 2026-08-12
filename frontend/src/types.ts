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

export interface Finding {
  id: string;
  rule_id: string;
  cwe: string | null;
  title: string;
  severity: Severity;
  location: Location;
  description: string;
  poc: PoC;
  discovered_by: string;
  discovered_at: string;
  status: string;
  corroborating_evidence: PoC[];
  /** null means nobody looked, which differs from looked-and-unsure. */
  triage: Triage | null;
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
  entry_points: EntryPoint[];
  auth_model: string;
  candidates: Candidate[];
  notes: string;
}

export type StageState = "pending" | "running" | "done" | "skipped" | "error";
export type ScanStatus = "queued" | "fetching" | "scanning" | "done" | "error";

export interface ScanState {
  id: string;
  repo: string;
  /** null = whatever GitHub calls the repo's default branch. */
  ref: string | null;
  status: ScanStatus;
  stages: Record<string, StageState>;
  findings: Finding[];
  finding_count: number;
  error: string | null;
  summary?: string;
  elapsed_sec?: number;
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
  /** True when loaded from disk rather than observed live: the radar has no stages to
   *  light and the sweep must not animate. */
  historical?: boolean;
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
  generated_at: string | null;
  finding_count: number;
  severity_counts: Partial<Record<Severity, number>>;
  cost_usd: number;
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
