/** Local runs: history, full payloads, artifacts, and live streaming.
 *  Served by app/backend. This is the half that shows what the AGENTS did — the repo
 *  scan surface above only covers the deterministic scanners. */
import type { RunPayload, RunSummary } from "../types";
import { req } from "./client";

export const getRuns = () => req<{ runs: RunSummary[] }>("/api/runs").then((r) => r.runs);

export const getRun = (name: string) =>
  req<RunPayload>(`/api/runs/${encodeURIComponent(name)}`);

/** Download URL for a finished run. The server sets Content-Disposition, so a plain
 *  link saves the file rather than rendering it in a tab. */
export const downloadUrl = (runName: string,
                            fmt: "json" | "sarif" | "md" | "brief") =>
  `/api/download/${encodeURIComponent(runName)}.${fmt}`;

/* startLocalScan / stopLocalScan removed with the Live run view. The console scans GitHub
   repositories: SAST plus agent triage. Launching a live agent run against a target URL is
   the DAST path, which stays available on the CLI (`docket scan --target ...`) and is
   deliberately not exposed here — a console button that fires exploit payloads is not what
   this product is. The backend routes still exist and still refuse non-loopback targets. */
