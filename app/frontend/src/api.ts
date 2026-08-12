import type { Health, RunPayload, RunSummary } from "./types";

async function json<T>(response: Response): Promise<T> {
  if (!response.ok) {
    // FastAPI puts the human-readable reason in `detail`; surfacing it is the
    // difference between "refused" and "refused because the target is not loopback".
    let detail = `${response.status} ${response.statusText}`;
    try {
      const body = await response.json();
      if (body?.detail) detail = body.detail;
    } catch {
      /* non-JSON error body — keep the status line */
    }
    throw new Error(detail);
  }
  return response.json() as Promise<T>;
}

export const getHealth = () => fetch("/api/health").then(json<Health>);

export const getRuns = () =>
  fetch("/api/runs").then(json<{ runs: RunSummary[] }>).then((d) => d.runs);

export const getRun = (name: string) =>
  fetch(`/api/runs/${encodeURIComponent(name)}`).then(json<RunPayload>);

export interface StartScanBody {
  target: string;
  run_name?: string;
  instruction?: string;
  max_steps?: number;
  use_sandbox?: boolean;
}

export const startScan = (body: StartScanBody) =>
  fetch("/api/scans", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  }).then(json<{ run_name: string; target: string; running: boolean }>);

export const getLog = (name: string) =>
  fetch(`/api/runs/${encodeURIComponent(name)}/log`).then((r) => r.text());

export const stopScan = (name: string) =>
  fetch(`/api/scans/${encodeURIComponent(name)}`, { method: "DELETE" }).then(
    json<{ stopped: boolean }>,
  );

/** Live payload stream for one run. Returns a closer. */
export function streamRun(name: string, onPayload: (p: RunPayload) => void): () => void {
  const scheme = location.protocol === "https:" ? "wss" : "ws";
  const socket = new WebSocket(
    `${scheme}://${location.host}/ws/runs/${encodeURIComponent(name)}`,
  );
  socket.onmessage = (event) => {
    const data = JSON.parse(event.data);
    if (!data.error) onPayload(data as RunPayload);
  };
  return () => socket.close();
}
