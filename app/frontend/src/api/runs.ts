/** Local runs: history, full payloads, artifacts, and live streaming.
 *  Served by app/backend. This is the half that shows what the AGENTS did — the repo
 *  scan surface above only covers the deterministic scanners. */
import type { Health, RunPayload, RunSummary } from "../types";
import { req } from "./client";

export const getHealth = () => req<Health>("/api/health");

export const getRuns = () => req<{ runs: RunSummary[] }>("/api/runs").then((r) => r.runs);

export const getRun = (name: string) =>
  req<RunPayload>(`/api/runs/${encodeURIComponent(name)}`);

export const getRunLog = (name: string) =>
  fetch(`/api/runs/${encodeURIComponent(name)}/log`).then((r) => r.text());

export const sarifUrl = (name: string) => `/api/runs/${encodeURIComponent(name)}/sarif`;

export const artifactUrl = (name: string, path: string) =>
  `/api/runs/${encodeURIComponent(name)}/artifacts/${path}`;

/* startLocalScan / stopLocalScan removed with the Live run view. The console scans GitHub
   repositories: SAST plus agent triage. Launching a live agent run against a target URL is
   the DAST path, which stays available on the CLI (`docket scan --target ...`) and is
   deliberately not exposed here — a console button that fires exploit payloads is not what
   this product is. The backend routes still exist and still refuse non-loopback targets. */
