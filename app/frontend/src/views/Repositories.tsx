import { useMemo, useState } from "react";
import type { Repo, Session, WatchState } from "../types";
import { Empty, Panel } from "../components/ui";

export function Repositories({
  session,
  repos,
  error,
  onReload,
  onScan,
  watch,
  onWatch,
  watchBusy,
  scanning,
  activeRepo,
  onGoIntegrations,
}: {
  session: Session | null;
  repos: Repo[] | null;
  error: string | null;
  onReload: () => void;
  onScan: (repo: string, ref?: string, triageMax?: number, recon?: boolean,
           budgetUsd?: number) => void;
  watch: WatchState | null;
  onWatch: (repos: string[]) => void;
  watchBusy: boolean;
  scanning: boolean;
  activeRepo?: string;
  onGoIntegrations: () => void;
}) {
  const [query, setQuery] = useState("");
  // Per-repo, so typing a branch for one does not follow you to another.
  const [refs, setRefs] = useState<Record<string, string>>({});
  // Off by default: each triaged finding is one LLM agent run, billed per token.
  // The backend does not cap this — DOCKET_MAX_COST_USD is what actually stops a run,
  // so the number chosen here is the only place the count is decided.
  const [triage, setTriage] = useState(0);
  // Off by default like triage: one agent per repo, but still real money.
  const [recon, setRecon] = useState(false);
  // A dollar ceiling for the whole scan. 0 means "use the server's
  // DOCKET_MAX_COST_USD", so an operator who does not care is not forced to pick.
  const [budget, setBudget] = useState(0);
  // Repositories queued for the pull-request watcher. Separate from the scan
  // controls above because watching is a standing arrangement, not one action.
  const [toWatch, setToWatch] = useState<string[]>([]);

const APPROX_USD_PER_FINDING = 0.033;

  const shown = useMemo(() => {
    const list = repos ?? [];
    const q = query.trim().toLowerCase();
    return q ? list.filter((r) => r.full_name.toLowerCase().includes(q)) : list;
  }, [repos, query]);

  if (!session?.connected) {
    return (
      <>
        <div className="page-head">
          <h1>Repositories</h1>
        </div>
        <Panel>
          <Empty>
            <div>GitHub is not connected, so there are no repositories to list.</div>
            <button className="btn primary" onClick={onGoIntegrations}>
              Connect GitHub
            </button>
          </Empty>
        </Panel>
      </>
    );
  }

  return (
    <>
      <div className="page-head">
        <h1>Repositories</h1>
        <div className="head-actions">
          <input
            className="btn"
            style={{ width: 200, color: "var(--ink)" }}
            placeholder="filter…"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
          <button className="btn" onClick={onReload}>
            reload
          </button>
          <button
            className={recon ? "btn primary" : "btn"}
            onClick={() => setRecon(!recon)}
            title="Before triage, an agent reads the repository and maps its attack surface: entry points, auth model, and issues no scanner rule matches. One agent per repo, ~$0.06."
          >
            AI recon {recon ? "on" : "off"}
          </button>
          {/* The dollar cap sits NEXT TO the two controls that spend, because it is
              the only one that bounds what they actually cost. triage_max caps how
              many findings get judged and says nothing about the price of each. */}
          <label
            className="btn"
            style={{ display: "flex", alignItems: "center", gap: 7, cursor: "text" }}
            title="Hard ceiling for this scan in US dollars, checked before every model turn. The run stops mid-way when it is reached rather than being refused up front, so you keep whatever was finished. Leave 0 to use the server default."
          >
            Budget $
            <input
              type="number"
              min={0}
              step={0.25}
              value={budget || ""}
              placeholder="default"
              onChange={(e) => setBudget(Math.max(0, Number(e.target.value) || 0))}
              style={{
                width: 62,
                background: "none",
                border: 0,
                color: "var(--ink)",
                font: "inherit",
                padding: 0,
                outline: "none",
              }}
            />
          </label>
          <label
            className="btn"
            style={{ display: "flex", alignItems: "center", gap: 7, cursor: "text" }}
            title="After scanning, an agent reads the source and judges whether each finding is reachable. One LLM run per finding; 0 turns it off."
          >
            AI triage
            <input
              type="number"
              min={0}
              value={triage}
              onChange={(e) => setTriage(Math.max(0, Number(e.target.value) || 0))}
              style={{
                width: 58,
                background: "none",
                border: 0,
                color: triage ? "var(--ok)" : "var(--ink-3)",
                font: "inherit",
                textAlign: "right",
              }}
            />
          </label>
        </div>
      </div>

      <div className="note" style={{ maxWidth: "70ch" }}>
        Every repository your GitHub account can reach, including ones you only collaborate
        on. Leave the branch box empty to scan the default branch, or name a branch, tag or commit. Each is downloaded as a tarball (never cloned, so there is no remote to push back
        to), scanned with trivy and semgrep in the sandbox, then deleted.
      </div>

      {error && <div className="note bad">{error}</div>}

      <Panel>
        {repos === null ? (
          <Empty>Loading repositories…</Empty>
        ) : shown.length === 0 ? (
          query ? (
            <Empty>Nothing matches that filter.</Empty>
          ) : (
            <Empty>This account can reach no repositories on GitHub.</Empty>
          )
        ) : (
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            {(toWatch.length > 0 || watch?.enabled) && (
              <div
                style={{
                  display: "flex", alignItems: "center", gap: 12, flexWrap: "wrap",
                  padding: "11px 13px", borderRadius: "var(--r-sm)",
                  border: "1px solid var(--ok)",
                  background: "color-mix(in srgb, var(--ok) 8%, transparent)",
                }}
              >
                <span style={{ font: "500 13px var(--sans)" }}>
                  {watch?.enabled
                    ? `Watching ${watch.repos.length} repository(s) — every pull request is checked as it is pushed.`
                    : `${toWatch.length} selected. Watching checks every pull request and posts a commit status.`}
                </span>
                <button
                  className="btn primary"
                  style={{ marginLeft: "auto" }}
                  disabled={watchBusy || (!watch?.enabled && toWatch.length === 0)}
                  onClick={() => onWatch(watch?.enabled ? [] : toWatch)}
                >
                  {watchBusy
                    ? "…"
                    : watch?.enabled ? "Stop watching" : "Start watching"}
                </button>
              </div>
            )}
            {shown.map((repo) => (
              <div className="repo-row" key={repo.full_name}>
                <span style={{ minWidth: 0, wordBreak: "break-all" }}>{repo.full_name}</span>
                <span className="meta">
                  {repo.private ? "private" : "public"}
                  {repo.language ? ` · ${repo.language}` : ""}
                </span>
                <input
                  className="btn sm"
                  style={{ width: 130, color: "var(--ink)", marginLeft: 10 }}
                  placeholder="default branch"
                  aria-label={`branch, tag or commit to scan in ${repo.full_name}`}
                  value={refs[repo.full_name] ?? ""}
                  onChange={(e) => setRefs({ ...refs, [repo.full_name]: e.target.value })}
                />
                <button
                  className="btn sm"
                  disabled={scanning}
                  onClick={() =>
                    onScan(repo.full_name, refs[repo.full_name]?.trim() || undefined,
                           triage, recon, budget)
                  }
                >
                  {scanning && activeRepo === repo.full_name ? "scanning…" : "scan"}
                </button>
                <label
                  className="btn sm"
                  title="Check every pull request on this repository as it is pushed, and post a commit status you can require in branch protection."
                  style={{ display: "flex", alignItems: "center", gap: 6,
                           cursor: "pointer",
                           color: toWatch.includes(repo.full_name)
                             ? "var(--ok)" : undefined,
                           borderColor: toWatch.includes(repo.full_name)
                             ? "var(--ok)" : undefined }}
                >
                  <input
                    type="checkbox"
                    checked={toWatch.includes(repo.full_name)}
                    onChange={(e) =>
                      setToWatch((prev) =>
                        e.target.checked
                          ? [...prev, repo.full_name]
                          : prev.filter((r) => r !== repo.full_name))
                    }
                    style={{ margin: 0, accentColor: "var(--ok)" }}
                  />
                  watch
                </label>
              </div>
            ))}
          </div>
        )}
      </Panel>

      {recon && (
        <div className="note">
          AI recon on: one agent reads the repository and maps where input enters, how auth
          works, and what no scanner rule would flag. Roughly <b>$0.06</b> per repo regardless
          of finding count, and its candidates give triage something better to judge than
          pattern matches alone.
        </div>
      )}

      {triage > 0 && (
        <div className="note">
          AI triage on: after the scanners finish, an agent reads the source for the{" "}
          <b>{triage}</b> worst-severity findings and judges whether untrusted input can reach
          them. It reads code and runs nothing — a verdict is reasoning, not an exploit.
          <br />
          Roughly <b>${(triage * APPROX_USD_PER_FINDING).toFixed(2)}</b> at ~$
          {APPROX_USD_PER_FINDING.toFixed(3)}/finding. Nothing caps the count but{" "}
          <span className="mono">DOCKET_MAX_COST_USD</span>, which halts a run mid-way when the
          spend is reached.
        </div>
      )}

      {scanning && (
        <div className="note">
          One scan at a time in this build — scans run on a thread, not a job queue.
        </div>
      )}
    </>
  );
}
