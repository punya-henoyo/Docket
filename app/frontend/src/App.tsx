import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import * as api from "./api";
import { ApiError } from "./api";
import type { Finding, Repo, RunSummary, ScanState, Session, Severity, Verdict } from "./types";
import { useHashRoute } from "./hooks/useHashRoute";
import { Dashboard } from "./views/Dashboard";
import { Findings } from "./views/Findings";
import { Repositories } from "./views/Repositories";
import { Integrations } from "./views/Integrations";

type View = "dashboard" | "findings" | "repos" | "integrations";

const VIEWS: { id: View; label: string }[] = [
  { id: "dashboard", label: "Dashboard" },
  { id: "findings", label: "Findings" },
  { id: "repos", label: "Repositories" },
  { id: "integrations", label: "Integrations" },
];

const VIEW_IDS = VIEWS.map((v) => v.id);

export default function App() {
  const [view, go] = useHashRoute<View>(VIEW_IDS, "dashboard");
  const [session, setSession] = useState<Session | null>(null);
  const [bootError, setBootError] = useState<string | null>(null);
  const [repos, setRepos] = useState<Repo[] | null>(null);
  const [reposError, setReposError] = useState<string | null>(null);
  const [runs, setRuns] = useState<RunSummary[]>([]);
  const [scan, setScan] = useState<ScanState | null>(null);
  const [scanError, setScanError] = useState<string | null>(null);
  const [selected, setSelected] = useState<Finding | null>(null);
  const [newestId, setNewestId] = useState<string | undefined>();
  // Bumped to re-arm polling after a failed tick. Without it a dropped request
  // ends polling for good: the catch never calls setScan, so the effect below
  // never re-runs, and the UI freezes while the scan carries on server-side.
  const [pollTick, setPollTick] = useState(0);
  const [cweFilter, setCweFilter] = useState<string | null>(null);
  const [verdictFilter, setVerdictFilter] = useState<Verdict | null>(null);
  const prevIds = useRef<Set<string>>(new Set());

  // Boot: session + run history. A failure here means the backend is not running,
  // which every view needs to know before it renders anything.
  useEffect(() => {
    let alive = true;
    (async () => {
      // Retried: a single failed request at page load used to condemn the whole
      // session to the "cannot reach docket" screen with no way back but a refresh,
      // even though the server was up a second later.
      for (let attempt = 0; attempt < 3 && alive; attempt++) {
        try {
          const s = await api.github.getSession();
          if (!alive) return;
          setSession(s);
          setBootError(null);
          if (s.connected) loadRepos();
          break;
        } catch (err) {
          if (!alive) return;
          if (attempt === 2) {
            setBootError(err instanceof ApiError ? err.message : String(err));
          } else {
            await new Promise((r) => setTimeout(r, 600 * (attempt + 1)));
          }
        }
      }
      try {
        const r = await api.runs.getRuns();
        if (!alive) return;
        setRuns(r);
        // Reload used to land on an empty dashboard even though report.json was on
        // disk the whole time. Restore the newest run so refreshing is not
        // indistinguishable from never having scanned.
        if (r.length) {
          try {
            setScan(await api.github.getRun(r[0].run_name));
          } catch {
            /* a corrupt or half-written report must not blank the console */
          }
        }
      } catch {
        /* run history is optional context, not a blocker */
      }
    })();
    return () => {
      alive = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Landed back from GitHub: jump to the repo picker.
  useEffect(() => {
    if (new URLSearchParams(window.location.search).get("connected")) {
      window.history.replaceState({}, "", window.location.pathname);
      go("repos");
    }
  }, [go]);

  const loadRepos = useCallback(async () => {
    setReposError(null);
    try {
      setRepos(await api.github.getRepos());
    } catch (err) {
      setRepos([]);
      setReposError(err instanceof ApiError ? err.message : String(err));
    }
  }, []);

  // Poll an in-flight scan. Stops as soon as it reaches a terminal state, so a
  // finished scan is not still being polled in the background.
  useEffect(() => {
    if (!scan || scan.status === "done" || scan.status === "error") return;
    const timer = setTimeout(async () => {
      try {
        const next = await api.github.getScan(scan.id);
        const fresh = next.findings.find((f) => !prevIds.current.has(f.id));
        if (fresh) setNewestId(fresh.id);
        prevIds.current = new Set(next.findings.map((f) => f.id));
        setScan(next);
        // Recovered: polling is a repeated action, so a stale failure banner from an
        // earlier tick is now a lie about the current state.
        setScanError(null);
        if (next.status === "done") api.runs.getRuns().then(setRuns).catch(() => {});
      } catch (err) {
        setScanError(err instanceof ApiError ? err.message : String(err));
        setPollTick((t) => t + 1);  // keep polling; the run is still going
      }
    }, 1500);
    return () => clearTimeout(timer);
  }, [scan, pollTick]);

  const runScan = useCallback(
    async (repo: string, ref?: string, triageMax = 0) => {
      setScanError(null);
      setSelected(null);
      setCweFilter(null);
      setVerdictFilter(null);
      prevIds.current = new Set();
      setNewestId(undefined);
      try {
        const { id } = await api.github.startRepoScan(repo, ref, triageMax);
        setScan({
          id,
          repo,
          ref: ref ?? null,
          status: "queued",
          stages: {
            fetch: "pending", trivy: "pending", semgrep: "pending",
            nuclei: "pending", triage: "pending",
          },
          findings: [],
          finding_count: 0,
          error: null,
        });
        go("dashboard");
      } catch (err) {
        setScanError(err instanceof ApiError ? err.message : String(err));
      }
    },
    [go],
  );

  const findings = scan?.findings ?? [];

  const counts = useMemo(() => {
    const acc: Partial<Record<Severity, number>> = {};
    for (const f of findings) acc[f.severity] = (acc[f.severity] ?? 0) + 1;
    return acc;
  }, [findings]);

  const openRun = useCallback(
    async (runName: string) => {
      setScanError(null);
      setSelected(null);
      setCweFilter(null);
      setVerdictFilter(null);
      try {
        setScan(await api.github.getRun(runName));
      } catch (err) {
        setScanError(err instanceof ApiError ? err.message : String(err));
      }
    },
    [],
  );

  const openFinding = useCallback(
    (finding: Finding) => {
      setSelected(finding);
      go("findings");
    },
    [go],
  );

  const scanning = scan?.status === "queued" || scan?.status === "fetching" || scan?.status === "scanning";

  return (
    <div className="shell">
      <nav className="rail">
        <div className="org">
          <span className="dot" />
          <span>{session?.login ?? "docket"}</span>
          {session?.connected && <span className="tag">GITHUB</span>}
        </div>

        {VIEWS.map((v) => (
          <button
            key={v.id}
            className="nav"
            aria-current={view === v.id ? "page" : undefined}
            onClick={() => go(v.id)}
          >
            {v.label}
            {(v.id === "dashboard" && scanning) && <span className="live">● live</span>}
            {v.id === "findings" && findings.length > 0 && (
              <span className="count">{findings.length}</span>
            )}
          </button>
        ))}

        <div className="rail-sep" />
        <div className="rail-foot">$ docket connect</div>
      </nav>

      <main className="main">
        {bootError ? (
          <>
            <div className="page-head">
              <h1>Cannot reach docket</h1>
            </div>
            <div className="panel">
              <div className="body">
                <div className="note bad">{bootError}</div>
                <div className="note">
                  Start the backend from the repo root, then reload:
                </div>
                <div className="evidence">
                  <pre>docket connect</pre>
                </div>
              </div>
            </div>
          </>
        ) : view === "dashboard" ? (
          <Dashboard
            scan={scan}
            runs={runs}
            counts={counts}
            scanError={scanError}
            session={session}
            onSelectFinding={openFinding}
            newestId={newestId}
            onGoRepos={() => go("repos")}
            onGoIntegrations={() => go("integrations")}
            cweFilter={cweFilter}
            onCweSelect={setCweFilter}
            onOpenRun={openRun}
            verdictFilter={verdictFilter}
            onVerdictSelect={setVerdictFilter}
          />
        ) : view === "findings" ? (
          <Findings
            findings={findings}
            selected={selected}
            onSelect={setSelected}
            scan={scan}
            onGoRepos={() => go("repos")}
            cweFilter={cweFilter}
            onCweSelect={setCweFilter}
            verdictFilter={verdictFilter}
            onVerdictSelect={setVerdictFilter}
          />
        ) : view === "repos" ? (
          <Repositories
            session={session}
            repos={repos}
            error={reposError}
            onReload={loadRepos}
            onScan={runScan}
            scanning={scanning}
            activeRepo={scan?.repo}
            onGoIntegrations={() => go("integrations")}
          />
        ) : (
          <Integrations session={session} />
        )}
      </main>
    </div>
  );
}
