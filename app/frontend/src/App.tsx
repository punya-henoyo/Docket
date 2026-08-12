import { useCallback, useEffect, useState } from "react";
import { getHealth, getLog, getRun, getRuns, startScan, stopScan, streamRun } from "./api";
import type { Finding, Health, RunPayload, RunSummary } from "./types";
import { Activity } from "./components/Activity";
import { AgentTree } from "./components/AgentTree";
import { FindingDialog, FindingsTable } from "./components/Findings";
import { RunList } from "./components/RunList";
import { StartPanel } from "./components/StartPanel";
import { StatBar } from "./components/StatBar";

const BUDGET_USD = 2.0; // DOCKET_MAX_COST_USD default, shown as the meter's ceiling

function useTheme() {
  const [theme, setTheme] = useState<string | null>(() => localStorage.getItem("docket-theme"));
  useEffect(() => {
    if (theme) {
      document.documentElement.setAttribute("data-theme", theme);
      localStorage.setItem("docket-theme", theme);
    } else {
      document.documentElement.removeAttribute("data-theme");
    }
  }, [theme]);
  return [theme, setTheme] as const;
}

export function App() {
  const [health, setHealth] = useState<Health | null>(null);
  const [runs, setRuns] = useState<RunSummary[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [run, setRun] = useState<RunPayload | null>(null);
  const [finding, setFinding] = useState<Finding | null>(null);
  const [failure, setFailure] = useState<string | null>(null);
  const [theme, setTheme] = useTheme();

  const refreshRuns = useCallback(async () => {
    try {
      const rows = await getRuns();
      setRuns(rows);
      // Land on something useful instead of an empty pane on first load.
      setSelected((current) => current ?? rows.find((r) => r.running)?.run_name ?? rows[0]?.run_name ?? null);
    } catch { /* backend not up yet; the interval retries */ }
  }, []);

  useEffect(() => {
    getHealth().then(setHealth).catch(() => setHealth(null));
    refreshRuns();
  }, [refreshRuns]);

  // One socket per selected run. It pushes only when the event log actually grows,
  // so an idle run costs nothing here.
  useEffect(() => {
    if (!selected) { setRun(null); return; }
    let live = true;
    getRun(selected).then((payload) => { if (live) setRun(payload); }).catch(() => {});
    setFailure(null);
    const close = streamRun(selected, (payload) => {
      if (!live) return;
      setRun(payload);
      // A run flipping to finished changes its row in the sidebar too.
      if (!payload.running) refreshRuns();
      // Exit 2 is "findings present", which is success here. Only 1 (and anything
      // unexpected) is a failure, and without this the UI shows an empty run with no
      // hint that the scan never actually started.
      const code = payload.exit_code;
      if (code !== null && code !== undefined && code !== 0 && code !== 2) {
        getLog(selected).then((text) => { if (live) setFailure(text.trim() || `exited ${code}`); });
      }
    });
    return () => { live = false; close(); };
  }, [selected, refreshRuns]);

  // The sidebar needs to notice runs this tab did not start.
  useEffect(() => {
    const timer = setInterval(refreshRuns, 5000);
    return () => clearInterval(timer);
  }, [refreshRuns]);

  const running = run?.running ?? false;

  async function onStarted(runName: string) {
    setSelected(runName);
    await refreshRuns();
  }

  async function rerun() {
    if (!run?.target) return;
    const scan = await startScan({ target: run.target, max_steps: 20 });
    onStarted(scan.run_name);
  }

  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand">
          <strong><h1>docket</h1></strong>
          <span className="tag">proof, not maybes</span>
        </div>
        <RunList runs={runs} selected={selected} onSelect={setSelected} />
      </aside>

      <div className="main">
        <div className="topbar">
          {run ? (
            <>
              <strong>{run.run_name}</strong>
              <span className="target">{run.target}</span>
              <span className={`pill ${running ? "live" : run.finished ? "done" : ""}`}>
                <span className={`dot ${running ? "running" : run.finished ? "completed" : ""}`}
                      aria-hidden="true" />
                {running ? "scanning" : run.finished ? "finished" : "idle"}
              </span>
            </>
          ) : (
            <strong>No run selected</strong>
          )}
          <span className="spacer" />
          {running && selected && (
            <button className="btn danger" onClick={() => stopScan(selected)}>Stop</button>
          )}
          {!running && run?.target && (
            <button className="btn" onClick={rerun}>Re-run</button>
          )}
          {run?.has_sarif && selected && (
            <a className="btn" href={`/api/runs/${encodeURIComponent(selected)}/sarif`}>SARIF</a>
          )}
          <button className="btn icon" title="Toggle theme"
                  onClick={() => setTheme(theme === "dark" ? "light" : "dark")}>◐</button>
        </div>

        {health?.loopback_only === false && (
          <div className="banner">
            <span aria-hidden="true">⚠</span>
            Unrestricted targets are enabled. docket sends real exploit payloads — only
            point it at systems you own or are authorised to test.
          </div>
        )}

        <div className="content">
          <StartPanel health={health} onStarted={onStarted} />

          {failure && (
            <div className="card">
              <h2>Scan did not complete</h2>
              <pre>{failure}</pre>
            </div>
          )}

          {run && (
            <>
              <div className="card">
                <h2>Summary</h2>
                <StatBar run={run} budget={BUDGET_USD} />
                {run.summary && <p style={{ marginBottom: 0 }}>{run.summary}</p>}
              </div>

              <div className="card">
                <h2>Findings — reproduced, with evidence</h2>
                <FindingsTable findings={run.findings ?? []} onSelect={setFinding} />
              </div>

              <div className="cols">
                <div className="card">
                  <h2>Agents</h2>
                  <AgentTree agents={run.agents ?? []} />
                </div>
                <div className="card">
                  <h2>Activity</h2>
                  <Activity lines={run.transcript ?? []} />
                </div>
              </div>
            </>
          )}
        </div>
      </div>

      <FindingDialog finding={finding} runName={selected ?? ""} onClose={() => setFinding(null)} />
    </div>
  );
}
