import { useState } from "react";
import { startScan } from "../api";
import type { Health } from "../types";

export function StartPanel({
  health, onStarted,
}: { health: Health | null; onStarted: (runName: string) => void }) {
  const [target, setTarget] = useState("http://127.0.0.1:8000");
  const [instruction, setInstruction] = useState("Seeded login is admin/admin123.");
  const [runName, setRunName] = useState("");
  const [maxSteps, setMaxSteps] = useState(20);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const blocked = health !== null && !health.ok;

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const scan = await startScan({
        target,
        run_name: runName || undefined,
        instruction: instruction || undefined,
        max_steps: maxSteps,
      });
      onStarted(scan.run_name);
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : String(exc));
    } finally {
      setBusy(false);
    }
  }

  return (
    <form className="card" onSubmit={submit}>
      <h2>New scan</h2>
      {error && <div className="error">{error}</div>}
      {blocked && (
        <div className="error">
          {health?.llm ? "" : "DOCKET_LLM is not set. "}
          {health?.docker ? "" : `Docker unavailable: ${health?.docker_error ?? "unknown"}. `}
          Fix this in .env, then reload.
        </div>
      )}
      <div className="field">
        <label htmlFor="target">Target</label>
        <input id="target" value={target} onChange={(e) => setTarget(e.target.value)} required
               placeholder="http://127.0.0.1:8000" />
        <span className="hint">
          {health?.loopback_only
            ? "Loopback targets only. docket sends real exploit payloads."
            : "Unrestricted targets enabled. Only scan what you are authorised to test."}
        </span>
      </div>
      <div className="field">
        <label htmlFor="instruction">Context for the agents (optional)</label>
        <textarea id="instruction" rows={2} value={instruction}
                  onChange={(e) => setInstruction(e.target.value)}
                  placeholder="Credentials, routes, anything they cannot discover alone" />
        <span className="hint">
          Routes are hardcoded to the test fixture today, so pass real ones here for any other target.
        </span>
      </div>
      <div className="row">
        <div className="field" style={{ flex: "2 1 180px", marginBottom: 0 }}>
          <label htmlFor="run-name">Run name (optional)</label>
          <input id="run-name" value={runName} onChange={(e) => setRunName(e.target.value)}
                 placeholder="auto-generated" />
        </div>
        <div className="field" style={{ flex: "1 1 96px", marginBottom: 0 }}>
          <label htmlFor="steps">Max turns</label>
          <input id="steps" type="number" min={1} max={200} value={maxSteps}
                 onChange={(e) => setMaxSteps(Number(e.target.value))} />
        </div>
        <button className="btn primary" type="submit" disabled={busy || blocked}>
          {busy ? "Starting…" : "Start scan"}
        </button>
      </div>
    </form>
  );
}
