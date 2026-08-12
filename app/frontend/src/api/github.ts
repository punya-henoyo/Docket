/** GitHub connect: session, repo picking, repo-scan lifecycle.
 *  Served by engine/docket/interface/connect.py. */
import type { Repo, ScanState, Session } from "../types";
import { postJson, req } from "./client";

export const getSession = () => req<Session>("/api/session");

export const getRepos = () => req<{ repos: Repo[] }>("/api/repos").then((r) => r.repos);

export const getScan = (id: string) => req<ScanState>(`/api/scan/${id}`);

export const startRepoScan = (repo: string) =>
  postJson<{ id: string; status: string }>("/api/scan", { repo });

export const AUTH_START = "/auth/start";
