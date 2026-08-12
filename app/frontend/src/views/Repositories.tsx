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
  onScan: (repo: string) => void;
  scanning: boolean;
  activeRepo?: string;
  onGoIntegrations: () => void;
}) {
  const [query, setQuery] = useState("");

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
        </div>
      </div>

      <div className="note" style={{ maxWidth: "70ch" }}>
        Exactly the repositories this authorization can see. Each is downloaded read-only as a
        tarball (never cloned, so there is no remote to push back to), scanned with trivy and
        semgrep in the sandbox, then deleted.
      </div>

      {error && <div className="note bad">{error}</div>}

      <Panel>
        {repos === null ? (
          <Empty>Loading repositories…</Empty>
        ) : shown.length === 0 ? (
          <Empty>{query ? "Nothing matches that filter." : "No repositories available."}</Empty>
        ) : (
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            {shown.map((repo) => (
              <div className="repo-row" key={repo.full_name}>
                <span style={{ minWidth: 0, wordBreak: "break-all" }}>{repo.full_name}</span>
                <span className="meta">
                  {repo.private ? "private" : "public"}
                  {repo.language ? ` · ${repo.language}` : ""}
                </span>
                <button
                  className="btn sm"
                  disabled={scanning}
                  onClick={() => onScan(repo.full_name)}
                >
                  {scanning && activeRepo === repo.full_name ? "scanning…" : "scan"}
                </button>
              </div>
            ))}
          </div>
        )}
      </Panel>

      {scanning && (
        <div className="note">
          One scan at a time in this build — scans run on a thread, not a job queue.
        </div>
      )}
    </>
  );
}
