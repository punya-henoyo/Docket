import { useEffect, useState } from "react";
import * as api from "../api";
import { useRunStream } from "../hooks/useRunStream";
import type { Finding, RunSummary } from "../types";
import { Activity } from "../components/Activity";
import { AgentTree } from "../components/AgentTree";
import { StatBar } from "../components/StatBar";
import { FindingsTable } from "../components/FindingsTable";
import { Empty, ErrorNote, Panel } from "../components/ui";

const BUDGET_USD = 2.0; // DOCKET_MAX_COST_USD default, shown as the meter's ceiling

/** Live agent runs against a target.
 *
 *  The repo-scan views cover the deterministic scanners. This covers the half a pattern
 *  matcher cannot do: agents choosing payloads and proving what they find. It is also the
 *  only view with a WebSocket — a repo scan has four ordered stages and polls fine, while
 *  an agent run bursts and stalls unpredictably.
 */
export function LiveRun({
  runs,
  selected,
  onSelectRun,
  onReloadRuns,
  onSelectFinding,
}: {
  runs: RunSummary[];
  selected: string | null;
  onSelectRun: (name: string) => void;
  onReloadRuns: () => void;
  onSelectFinding: (f: Finding) => void;
}) {
  const { payload, connected } = useRunStream(selected);
  const [failure, setFailure] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [health, setHealth] = useState<Awaited<ReturnType<typeof api.runs.getHealth>> | null>(null);
  const [form, setForm] = useState({
    target: "http://127.0.0.1:8000",
    instruction: "Seeded login is admin/admin123.",
    source: "",
    max_steps: 20,
  });

  useEffect(() => {
    api.runs.getHealth().then(setHealth).catch(() => setHealth(null));
  }, []);

  // Seed from the last payload the socket has not delivered yet, so switching runs does
  // not blank the pane while the connection opens.
  useEffect(() => {
    setFailure(null);
    if (selected) api.runs.getRun(selected).catch(() => {});
  }, [selected]);

  // Exit 2 means "findings present", which is success for a security tool. Only 1 (and
  // anything unexpected) is a failure — and without this the UI shows an empty run with
  // no hint that the scan never actually started.
  useEffect(() => {
    const code = payload?.exit_code;
    if (!selected || code === null || code === undefined || code === 0 || code === 2) return;
    api.runs
      .getRunLog(selected)
      .then((text) => setFailure(text.trim() || `exited ${code}`))
      .catch(() => {});
    onReloadRuns();
  }, [payload?.exit_code, selected, onReloadRuns]);

  async function start(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const scan = await api.runs.startLocalScan({
        target: form.target,
        instruction: form.instruction || undefined,
        source: form.source || undefined,
        max_steps: form.max_steps,
      });
      onSelectRun(scan.run_name);
      onReloadRuns();
    } catch (exc) {
      setError(exc instanceof api.ApiError ? exc.message : String(exc));
    } finally {
      setBusy(false);
    }
  }

  const running = payload?.running ?? false;
  const blocked = health !== null && !health.ok;

  return (
    <>
      <div className="page-head">
        <h1>Live run</h1>
        <div className="head-actions">
          {payload && (
            <span className={`live-pill ${running ? "on" : ""}`}>
              {running ? (connected ? "● streaming" : "● running") : "idle"}
            </span>
          )}
          {running && selected && (
            <button className="btn danger" onClick={() => api.runs.stopLocalScan(selected)}>
              Stop
            </button>
          )}
          {payload?.has_sarif && selected && (
            <a className="btn" href={api.runs.sarifUrl(selected)}>
              SARIF
            </a>
          )}
        </div>
      </div>

      <div className="grid two">
        <Panel title="Start a scan">
          {error && <ErrorNote error={error} />}
          {blocked && (
            <ErrorNote
              error={`${health?.llm ? "" : "DOCKET_LLM is not set. "}${
                health?.docker ? "" : `Docker unavailable: ${health?.docker_error ?? "unknown"}. `
              }Fix this in .env — the health check re-reads it, so no restart needed.`}
            />
          )}
          <form onSubmit={start}>
            <label className="field">
              <span>Target</span>
              <input
                value={form.target}
                required
                onChange={(e) => setForm({ ...form, target: e.target.value })}
              />
              <em>
                {health?.loopback_only
                  ? "Loopback targets only. docket sends real exploit payloads."
                  : "Unrestricted targets enabled — only scan what you are authorised to test."}
              </em>
            </label>
            <label className="field">
              <span>Context for the agents</span>
              <textarea
                rows={2}
                value={form.instruction}
                onChange={(e) => setForm({ ...form, instruction: e.target.value })}
              />
              <em>Credentials, or routes discovery cannot reach.</em>
            </label>
            <label className="field">
              <span>Source tree (optional)</span>
              <input
                value={form.source}
                placeholder="../my-app"
                onChange={(e) => setForm({ ...form, source: e.target.value })}
              />
              <em>Runs Semgrep and correlates each candidate to a discovered endpoint.</em>
            </label>
            <div className="row">
              <label className="field narrow">
                <span>Max turns</span>
                <input
                  type="number"
                  min={1}
                  max={200}
                  value={form.max_steps}
                  onChange={(e) => setForm({ ...form, max_steps: Number(e.target.value) })}
                />
              </label>
              <button className="btn primary" type="submit" disabled={busy || blocked}>
                {busy ? "Starting…" : "Start scan"}
              </button>
            </div>
          </form>
        </Panel>

        <Panel title="Runs" action={<button className="btn ghost" onClick={onReloadRuns}>Reload</button>}>
          {runs.length === 0 ? (
            <Empty>No runs yet.</Empty>
          ) : (
            <div className="runlist">
              {runs.map((run) => (
                <button
                  key={run.run_name}
                  className="runrow"
                  aria-current={run.run_name === selected}
                  onClick={() => onSelectRun(run.run_name)}
                >
                  <span className="name">{run.run_name}</span>
                  <span className="meta">
                    <i
                      className={`dot ${
                        run.running ? "running" : run.failed ? "failed" : run.finished ? "done" : ""
                      }`}
                    />
                    {run.running ? "running" : run.failed ? "failed" : run.finished ? "done" : "incomplete"}
                    {typeof run.finding_count === "number" && <> · {run.finding_count} found</>}
                  </span>
                </button>
              ))}
            </div>
          )}
        </Panel>
      </div>

      {failure && (
        <Panel title="Scan did not complete">
          <div className="evidence">
            <pre>{failure}</pre>
          </div>
        </Panel>
      )}

      {payload && (
        <>
          <Panel title="Summary">
            <StatBar run={payload} budget={BUDGET_USD} />
            {payload.summary && <p className="summary">{payload.summary}</p>}
          </Panel>

          <Panel title="Findings — reproduced, with evidence">
            <FindingsTable findings={payload.findings ?? []} onSelect={onSelectFinding} />
          </Panel>

          {!!payload.flagged_count && (
            <Panel title={`Static candidates — ${payload.flagged_count} flagged, NOT proven`}>
              <table className="flagged">
                <thead>
                  <tr>
                    <th>Where</th>
                    <th>CWE</th>
                    <th>Endpoint</th>
                    <th>Confidence</th>
                    <th>Class proven?</th>
                  </tr>
                </thead>
                <tbody>
                  {(payload.flagged_not_proven ?? []).map((f, i) => (
                    <tr key={`${f.file}:${f.line}:${i}`}>
                      <td className="mono">
                        {f.file}:{f.line}
                      </td>
                      <td className="mono">{f.cwe ?? "—"}</td>
                      <td className="mono">{f.endpoint ?? "unmapped"}</td>
                      <td>{f.correlation_confidence}</td>
                      <td>{f.cwe_proven_dynamically ? "yes, elsewhere" : "no"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </Panel>
          )}

          <div className="grid two">
            <Panel title="Agents">
              <AgentTree agents={payload.agents ?? []} />
            </Panel>
            <Panel title="Activity">
              <Activity lines={payload.transcript ?? []} />
            </Panel>
          </div>
        </>
      )}
    </>
  );
}
