/** GitHub connect: session, repo picking, repo-scan lifecycle.
 *  Served by engine/docket/interface/connect.py. */
import type { FixPr, Repo, ScanState, Session, WatchState } from "../types";
import { postJson, req } from "./client";

export const getSession = () => req<Session>("/api/session");

/** Fix PRs read live from GitHub — durable across restarts, unlike the watcher's memory. */
export const getFixes = () => req<{ fixes: FixPr[] }>("/api/fixes").then((r) => r.fixes);

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
                              recon = false, budgetUsd = 0,
                              compliance: string[] = []) =>
  postJson<{ id: string; status: string }>("/api/scan", {
    repo,
    ...(ref ? { ref } : {}),
    // Omitted when 0 so the backend keeps its own default. Every AI phase costs
    // model spend, so each stays opt-in per scan.
    ...(triageMax ? { triage_max: triageMax } : {}),
    ...(recon ? { recon: true } : {}),
    ...(budgetUsd > 0 ? { budget_usd: budgetUsd } : {}),
    // Control packs to audit against, by id. Omitted when none is chosen: an empty list
    // and an absent key mean the same thing to the backend, but sending nothing keeps
    // the request identical to what it was before this feature existed.
    ...(compliance.length ? { compliance } : {}),
  });

/** The pull-request watcher: which repositories it polls and what it has found. */
export const getWatch = () => req<WatchState>("/api/watch");

export const setWatch = (body: {
  enabled: boolean; repos?: string[]; interval_sec?: number; triage_max?: number;
  autofix?: boolean;
  /** Control packs applied to every pull request the watcher scans. A standing choice,
   *  like triage_max and autofix, not a per-pull-request one. */
  compliance?: string[];
  compliance_deep?: number;
}) => postJson<WatchState>("/api/watch", body);

export const AUTH_START = "/auth/start";
