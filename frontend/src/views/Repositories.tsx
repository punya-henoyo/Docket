import { useMemo, useState } from "react";
import type { Repo, Session } from "../types";
import { Empty, Panel } from "../components/ui";

export function Repositories({
  session,
  repos,
  error,
  onReload,
  onScan,
  scanning,
  activeRepo,
  onGoIntegrations,
}: {
  session: Session | null;
  repos: Repo[] | null;
  error: string | null;
  onReload: () => void;
  onScan: (repo: string, ref?: string, triageMax?: number) => void;
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
                    onScan(repo.full_name, refs[repo.full_name]?.trim() || undefined, triage)
                  }
                >
                  {scanning && activeRepo === repo.full_name ? "scanning…" : "scan"}
                </button>
              </div>
            ))}
          </div>
        )}
      </Panel>

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
