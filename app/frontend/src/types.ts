export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface Location {
  url?: string;
  method?: string;
  path?: string;
  parameter?: string;
  line?: number;
}

export interface PoC {
  request?: string;
  response?: string;
  steps?: string[];
  screenshot?: string;
}

export interface Finding {
  finding_id?: string;
  rule_id?: string;
  rule_type?: string;
  title?: string;
  severity: Severity;
  cwe?: string;
  description?: string;
  location?: Location;
  poc?: PoC;
  discovered_by?: string;
  dedupe_key?: string;
}

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

/** Emitted by interface/tui/backend/projection.py — one row per tool call and per
 *  tool result, not a free-text log. */
export interface TranscriptLine {
  ts?: number;
  agent_id?: string;
  role?: string;
  kind?: "call" | "result" | string;
  tool?: string;
  args?: Record<string, unknown>;
  output?: string;
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
  cost_usd: number;
  usage: Record<string, unknown>;
  agents: AgentNode[];
  findings: Finding[];
  transcript: TranscriptLine[];
  notes: unknown[];
  todos: unknown[];
  has_sarif: boolean;
}

export interface RunSummary {
  run_name: string;
  modified: number;
  finished: boolean;
  running: boolean;
  failed?: boolean;
  target?: string;
  finding_count?: number;
  severity_counts?: Partial<Record<Severity, number>>;
  cost_usd?: number;
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

export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];
