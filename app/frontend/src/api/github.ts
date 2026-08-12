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

export const startRepoScan = (repo: string, ref?: string) =>
  postJson<{ id: string; status: string }>("/api/scan", ref ? { repo, ref } : { repo });

export const AUTH_START = "/auth/start";
