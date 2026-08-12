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
}

export type StageState = "pending" | "running" | "done" | "skipped" | "error";
export type ScanStatus = "queued" | "fetching" | "scanning" | "done" | "error";

export interface ScanState {
  id: string;
  repo: string;
  status: ScanStatus;
  stages: Record<string, StageState>;
  findings: Finding[];
  finding_count: number;
  error: string | null;
  summary?: string;
  elapsed_sec?: number;
}

export interface Session {
  connected: boolean;
  login: string | null;
  configured: boolean;
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

export const SCANNERS = ["fetch", "trivy", "semgrep", "nuclei"] as const;
export type Scanner = (typeof SCANNERS)[number];

export const SCANNER_LABEL: Record<Scanner, string> = {
  fetch: "fetch source",
  trivy: "trivy · dependencies",
  semgrep: "semgrep · source",
  nuclei: "nuclei · live target",
};
