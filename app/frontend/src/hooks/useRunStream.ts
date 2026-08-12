import { useEffect, useState } from "react";
import type { RunPayload } from "../types";

/** Live payload stream for one local run, over a WebSocket.
 *
 *  A socket rather than the 1.5s poll the repo-scan view uses: an agent run emits bursts
 *  (three specialists firing tools at once) and then goes quiet for a whole model turn.
 *  Polling that is either laggy during the burst or wasteful during the quiet. The
 *  backend only pushes when the event log actually grows, so an idle run costs nothing.
 */
export function useRunStream(runName: string | null): {
  payload: RunPayload | null;
  connected: boolean;
} {
  const [payload, setPayload] = useState<RunPayload | null>(null);
  const [connected, setConnected] = useState(false);

  useEffect(() => {
    if (!runName) {
      setPayload(null);
      setConnected(false);
      return;
    }
    const scheme = location.protocol === "https:" ? "wss" : "ws";
    const socket = new WebSocket(
      `${scheme}://${location.host}/ws/runs/${encodeURIComponent(runName)}`,
    );
    socket.onopen = () => setConnected(true);
    socket.onclose = () => setConnected(false);
    socket.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        if (!data.error) setPayload(data as RunPayload);
      } catch {
        /* a half-written frame is not worth tearing the view down for */
      }
    };
    return () => socket.close();
  }, [runName]);

  return { payload, connected };
}
