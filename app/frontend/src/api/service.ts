/** The control plane: the poller, watched repos and their policy, and the PR-scan inbox.
 *  Served by app/backend/routers/service.py.
 *
 *  Every call here can answer 503 — the service half lives in a SQLite store that may not
 *  be built on this machine yet. That is a normal state, not a crash, and callers are
 *  expected to show `ApiError.message` rather than an empty page. */
import type {
  Policy,
  PrScan,
  PrScanDetail,
  PrScanState,
  ServiceStatus,
  WatchedRepo,
} from "../types";
import { postJson, req } from "./client";

export const getStatus = () => req<ServiceStatus>("/api/service/status");

/** 202 means asked, not started: the loop's first tick has not run when this returns. */
export const startPoller = (intervalSec = 30) =>
  postJson<ServiceStatus>("/api/service/poll/start", { interval_sec: intervalSec });

export const stopPoller = () => postJson<ServiceStatus>("/api/service/poll/stop", {});

export const getWatched = () =>
  req<{ repos: WatchedRepo[] }>("/api/service/repos").then((r) => r.repos ?? []);

/** Enable/disable a repo and set its policy. PUT creates the row if it is new.
 *
 *  The whole policy object goes every time, including its nulls: dropping a null would
 *  lose the difference between "inherit the org default" and "never set". */
export const setWatched = (fullName: string, enabled: boolean, policy: Policy) => {
  const [owner, name] = fullName.split("/");
  return req<WatchedRepo>(
    `/api/service/repos/${encodeURIComponent(owner ?? "")}/${encodeURIComponent(name ?? "")}`,
    {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ enabled, policy }),
    },
  );
};

export const getScans = (filter?: { repo?: string; state?: PrScanState; limit?: number }) => {
  const params = new URLSearchParams();
  if (filter?.repo) params.set("repo", filter.repo);
  if (filter?.state) params.set("state", filter.state);
  if (filter?.limit) params.set("limit", String(filter.limit));
  const query = params.toString();
  return req<{ scans: PrScan[] }>(`/api/service/scans${query ? `?${query}` : ""}`).then(
    (r) => r.scans ?? [],
  );
};

export const getScan = (id: string | number) =>
  req<PrScanDetail>(`/api/service/scans/${encodeURIComponent(String(id))}`);

/** Re-queue the SAME head_sha. `force` overrides a live lease, which is only correct when
 *  the worker holding it is gone — otherwise the same commit gets scanned twice and two
 *  check runs are posted. */
export const rescan = (id: string | number, force = false) =>
  postJson<{ id: string | number; state: string; was: string }>(
    `/api/service/scans/${encodeURIComponent(String(id))}/rescan${force ? "?force=true" : ""}`,
    {},
  );
