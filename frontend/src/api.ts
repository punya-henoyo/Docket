import type { Repo, RunSummary, ScanState, Session } from "./types";

/** Every call hits the docket connect server (engine/docket/interface/connect.py).
 *  There is no mock layer and no fixture data: if the backend is not running, calls
 *  reject and the UI says so rather than inventing a dashboard. */

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response;
  try {
    response = await fetch(path, { cache: "no-store", ...init });
  } catch {
    throw new ApiError("Cannot reach the docket server. Is `docket connect` running?", 0);
  }
  const text = await response.text();
  let payload: unknown = null;
  try {
    payload = text ? JSON.parse(text) : null;
  } catch {
    throw new ApiError(`Unexpected non-JSON response from ${path}`, response.status);
  }
  if (!response.ok) {
    const detail =
      payload && typeof payload === "object" && "error" in payload
        ? String((payload as { error: unknown }).error)
        : `Request failed (${response.status})`;
    throw new ApiError(detail, response.status);
  }
  return payload as T;
}

export const getSession = () => req<Session>("/api/session");

export const getRepos = () => req<{ repos: Repo[] }>("/api/repos").then((r) => r.repos);

export const getRuns = () => req<{ runs: RunSummary[] }>("/api/runs").then((r) => r.runs);

export const getScan = (id: string) => req<ScanState>(`/api/scan/${id}`);

/** Rehydrate a finished run from disk. The live scan lives in memory only, so this is
 *  what survives a reload. */
export const getRun = (runName: string) =>
  req<ScanState>(`/api/run/${encodeURIComponent(runName)}`);

/** Ask the running scan to stop. 202 means "asked", not "stopped": the scan halts at
 *  its next checkpoint, which is between scanners or between triage agents. */
export const cancelScan = (id?: string) =>
  req<{ id: string; status: string }>("/api/scan/cancel", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(id ? { id } : {}),
  });

/** Scans still running on the server. The console's only reference to a live scan
 *  used to be React state, so opening a historical run lost it and a reload lost it. */
export const activeScans = () =>
  req<{ scans: { id: string; repo: string; ref: string | null; status: string }[] }>(
    "/api/scans/active",
  );

export const startScan = (repo: string, ref?: string, triageMax = 0, recon = false,
                          budgetUsd = 0) =>
  req<{ id: string; status: string }>("/api/scan", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      repo,
      ...(ref ? { ref } : {}),
      ...(triageMax ? { triage_max: triageMax } : {}),
      ...(recon ? { recon: true } : {}),
      ...(budgetUsd > 0 ? { budget_usd: budgetUsd } : {}),
    }),
  });

export const AUTH_START = "/auth/start";

/** Download URL for a finished run. The server sets Content-Disposition, so a plain
 *  link saves the file rather than rendering it in a tab. */
export const downloadUrl = (runName: string, fmt: "json" | "sarif" | "md" | "brief") =>
  `/api/download/${encodeURIComponent(runName)}.${fmt}`;
