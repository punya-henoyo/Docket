/** GitHub connect: session, repo picking, repo-scan lifecycle.
 *  Served by engine/docket/interface/connect.py. */
import type { Repo, ScanState, Session, WatchState } from "../types";
import { postJson, req } from "./client";

export const getSession = () => req<Session>("/api/session");

export const getRepos = () => req<{ repos: Repo[] }>("/api/repos").then((r) => r.repos);

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

export const startRepoScan = (repo: string, ref?: string, triageMax = 0,
                              recon = false, budgetUsd = 0) =>
  postJson<{ id: string; status: string }>("/api/scan", {
    repo,
    ...(ref ? { ref } : {}),
    // Omitted when 0 so the backend keeps its own default. Every AI phase costs
    // model spend, so each stays opt-in per scan.
    ...(triageMax ? { triage_max: triageMax } : {}),
    ...(recon ? { recon: true } : {}),
    ...(budgetUsd > 0 ? { budget_usd: budgetUsd } : {}),
  });

/** The pull-request watcher: which repositories it polls and what it has found. */
export const getWatch = () => req<WatchState>("/api/watch");

export const setWatch = (body: {
  enabled: boolean; repos?: string[]; interval_sec?: number; triage_max?: number;
}) => postJson<WatchState>("/api/watch", body);

export const AUTH_START = "/auth/start";
