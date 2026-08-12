/** GitHub connect: session, repo picking, repo-scan lifecycle.
 *  Served by engine/docket/interface/connect.py. */
import type { Repo, ScanState, Session } from "../types";
import { postJson, req } from "./client";

export const getSession = () => req<Session>("/api/session");

export const getRepos = () => req<{ repos: Repo[] }>("/api/repos").then((r) => r.repos);

export const getScan = (id: string) => req<ScanState>(`/api/scan/${id}`);

/** Rehydrate a finished run from disk. The live scan lives in memory only, so this is
 *  what survives a reload. */
export const getRun = (runName: string) =>
  req<ScanState>(`/api/run/${encodeURIComponent(runName)}`);

export const startRepoScan = (repo: string, ref?: string, triageMax = 0) =>
  postJson<{ id: string; status: string }>("/api/scan", {
    repo,
    ...(ref ? { ref } : {}),
    // Omitted when 0 so the backend keeps its own default. Triage costs model spend,
    // so it stays opt-in per scan.
    ...(triageMax ? { triage_max: triageMax } : {}),
  });

export const AUTH_START = "/auth/start";
