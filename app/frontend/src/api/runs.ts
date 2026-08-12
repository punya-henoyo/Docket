/** Local runs: history, full payloads, artifacts, and live streaming.
 *  Served by app/backend. This is the half that shows what the AGENTS did — the repo
 *  scan surface above only covers the deterministic scanners. */
import type { Health, RunPayload, RunSummary } from "../types";
import { postJson, req } from "./client";

export const getHealth = () => req<Health>("/api/health");

export const getRuns = () => req<{ runs: RunSummary[] }>("/api/runs").then((r) => r.runs);

export const getRun = (name: string) =>
  req<RunPayload>(`/api/runs/${encodeURIComponent(name)}`);

export const getRunLog = (name: string) =>
  fetch(`/api/runs/${encodeURIComponent(name)}/log`).then((r) => r.text());

export const sarifUrl = (name: string) => `/api/runs/${encodeURIComponent(name)}/sarif`;

export const artifactUrl = (name: string, path: string) =>
  `/api/runs/${encodeURIComponent(name)}/artifacts/${path}`;

export interface StartScanBody {
  target: string;
  run_name?: string;
  instruction?: string;
  source?: string;
  max_steps?: number;
}

export const startLocalScan = (body: StartScanBody) =>
  postJson<{ run_name: string; target: string; running: boolean }>("/api/scans", body);

export const stopLocalScan = (name: string) =>
  req<{ stopped: boolean }>(`/api/scans/${encodeURIComponent(name)}`, { method: "DELETE" });
