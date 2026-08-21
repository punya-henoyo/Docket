import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import * as api from "./api";
import { ApiError } from "./api";
import type {
  Finding, Repo, RunSummary, ScanState, Session, Severity, Verdict, WatchState,
} from "./types";
import { Overview } from "./views/Overview";
import { Scan } from "./views/Scan";
import { Surface } from "./views/Surface";
import { Findings } from "./views/Findings";
import { Repositories } from "./views/Repositories";
import { Integrations } from "./views/Integrations";
import { PullRequests } from "./views/PullRequests";
import { useHashRoute } from "./hooks/useHashRoute";

type View =
  | "overview" | "scan" | "pulls" | "surface" | "findings" | "repos" | "integrations";

// Ordered by who asks the question: posture first (a security lead), then the live
// run, then the map, then the detail an engineer works from.
const VIEWS: { id: View; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "scan", label: "Scan" },
  { id: "pulls", label: "Pull requests" },
  { id: "surface", label: "Attack surface" },
  { id: "findings", label: "Findings" },
  { id: "repos", label: "Repositories" },
  { id: "integrations", label: "Integrations" },
];

// Derived, not a second hand-maintained list: the router and the sidebar cannot drift.
const VIEW_IDS = VIEWS.map((v) => v.id);

export default function App() {
  const [view, go] = useHashRoute<View>(VIEW_IDS, "overview");
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
  // The id of a scan that is RUNNING, independent of whatever is being displayed.
  // Kept in sessionStorage so it survives a reload and a second tab, because losing
  // it means a scan keeps running and spending with no way back to it.
  const [watch, setWatch] = useState<WatchState | null>(null);
  const [watchBusy, setWatchBusy] = useState(false);
  const [watchError, setWatchError] = useState<string | null>(null);
  const [liveId, setLiveId] = useState<string | null>(
    () => sessionStorage.getItem("docket.liveId"),
  );

  const rememberLive = useCallback((id: string | null) => {
    setLiveId(id);
    if (id) sessionStorage.setItem("docket.liveId", id);
    else sessionStorage.removeItem("docket.liveId");
  }, []);
  const [cweFilter, setCweFilter] = useState<string | null>(null);
  const [verdictFilter, setVerdictFilter] = useState<Verdict | null>(null);
  const prevIds = useRef<Set<string>>(new Set());

  // A scan may be running that this browser has never seen: after a reload, in a
  // second tab, or because the previous view replaced it with history. Ask the server
  // rather than trusting local state, which is what went missing in the first place.
  useEffect(() => {
    let alive = true;
    api.github.activeScans()
      .then(({ scans }) => {
        if (!alive) return;
        if (scans.length) rememberLive(scans[0].id);
        else if (sessionStorage.getItem("docket.liveId")) rememberLive(null);
      })
      .catch(() => {});
    return () => {
      alive = false;
    };
  }, [rememberLive]);

  // The watcher runs on the server, so the console asks rather than assumes. Polled
  // faster than the watcher itself polls GitHub: the countdown and "checked 8s ago"
  // are only honest if this is more frequent than what it is reporting on.
  useEffect(() => {
    let alive = true;
    const pull = () =>
      api.github.getWatch()
        .then((w) => { if (alive) setWatch(w); })
        .catch(() => {});
    pull();
    const id = setInterval(pull, 5000);
    return () => { alive = false; clearInterval(id); };
  }, []);

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
    // "cancelled" is terminal too. Without it the console polls a stopped scan
    // forever, and the tab keeps showing "live" over a run that ended.
    if (!scan || scan.status === "done" || scan.status === "error" ||
        scan.status === "cancelled") return;
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
        // A cancelled scan writes a partial report too, so the run list needs
        // refreshing either way.
        if (next.status === "done" || next.status === "cancelled" ||
            next.status === "error") {
          if (next.id === liveId) rememberLive(null);
          if (next.status !== "error") api.runs.getRuns().then(setRuns).catch(() => {});
        }
      } catch (err) {
        setScanError(err instanceof ApiError ? err.message : String(err));
        setPollTick((t) => t + 1);  // keep polling; the run is still going
      }
    }, 1500);
    return () => clearTimeout(timer);
  }, [scan, pollTick, liveId, rememberLive]);

  const runScan = useCallback(
    async (repo: string, ref?: string, triageMax = 0, recon = false,
           budgetUsd = 0) => {
      setScanError(null);
      setSelected(null);
      setCweFilter(null);
      setVerdictFilter(null);
      prevIds.current = new Set();
      setNewestId(undefined);
      try {
        const { id } = await api.github.startRepoScan(repo, ref, triageMax, recon, budgetUsd);
        rememberLive(id);
        setScan({
          id,
          repo,
          ref: ref ?? null,
          status: "queued",
          stages: {
            fetch: "pending", trivy: "pending", semgrep: "pending",
            nuclei: "pending", recon: "pending", triage: "pending",
          },
          recon,
          surface: null,
          findings: [],
          finding_count: 0,
          error: null,
        });
        go("scan");
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

  /** Return to the running scan. Separate from openRun on purpose: openRun replaces
   *  the displayed scan with history, which is exactly what used to strand this one. */
  const resumeLive = useCallback(async () => {
    if (!liveId) return;
    setScanError(null);
    setSelected(null);
    try {
      setScan(await api.github.getScan(liveId));
      go("scan");
    } catch {
      // The server no longer knows this scan — it finished and was evicted, or the
      // console restarted. Forget it rather than leaving a button that does nothing.
      rememberLive(null);
    }
  }, [liveId, go, rememberLive]);

  const applyWatch = useCallback(async (repos: string[], autofix = false) => {
    setWatchBusy(true);
    setWatchError(null);
    try {
      setWatch(await api.github.setWatch(
        repos.length
          ? { enabled: true, repos, interval_sec: 30, triage_max: 5, autofix }
          : { enabled: false },
      ));
    } catch (err) {
      setWatchError(err instanceof Error ? err.message : String(err));
    } finally {
      setWatchBusy(false);
    }
  }, []);

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
        <div className="brand">
          <div className="brand-mark">
            Henoyo<span className="brand-dot">.</span>
          </div>
          <div className="brand-product">docket</div>
        </div>

        {session?.login && (
          <div className="org">
            <span className="dot" />
            <span>{session.login}</span>
            {session.connected && <span className="tag">GITHUB</span>}
          </div>
        )}

        {VIEWS.map((v) => (
          <button
            key={v.id}
            className="nav"
            aria-current={view === v.id ? "page" : undefined}
            onClick={() => {
              // Clicking Scan while a run is live returns to THAT run, not to
              // whatever historical scan happens to be loaded. Losing your way back
              // to a running scan is how one ends up spending unwatched.
              if (v.id === "scan" && liveId && scan?.id !== liveId) resumeLive();
              else go(v.id);
            }}
          >
            {v.label}
            {v.id === "scan" && (scanning || liveId) && (
              <span className="live">● live</span>
            )}
            {v.id === "pulls" && watch?.enabled && (
              <span className="live">● on</span>
            )}
            {v.id === "findings" && findings.length > 0 && (
              <span className="count">{findings.length}</span>
            )}
          </button>
        ))}

        <div className="rail-sep" />
        <div className="rail-foot">$ docket connect</div>
      </nav>

      <main className="main">
        {liveId && scan?.id !== liveId && (
          <div
            className="note"
            style={{
              display: "flex", alignItems: "center", gap: 12, flexWrap: "wrap",
              border: "1px solid var(--ok)", borderRadius: "var(--r)",
              padding: "10px 14px", color: "var(--ink-2)",
              background: "color-mix(in srgb, var(--ok) 8%, transparent)",
            }}
          >
            <span className="live">●</span>
            A scan is still running. You are looking at a different run.
            <button className="btn primary" style={{ marginLeft: "auto" }}
                    onClick={resumeLive}>
              Back to the live scan
            </button>
          </div>
        )}
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
        ) : view === "overview" ? (
          <Overview
            scan={scan}
            runs={runs}
            watch={watch}
            onGoFindings={() => go("findings")}
            onGoRepos={() => go("repos")}
            onGoPulls={() => go("pulls")}
            onSelectFinding={openFinding}
            onOpenRun={openRun}
          />
        ) : view === "scan" ? (
          <Scan
            scan={scan}
            counts={counts}
            scanError={scanError}
            onSelectFinding={openFinding}
            newestId={newestId}
            cweFilter={cweFilter}
            onCweSelect={setCweFilter}
            verdictFilter={verdictFilter}
            onVerdictSelect={setVerdictFilter}
            onGoRepos={() => go("repos")}
          />
        ) : view === "pulls" ? (
          <PullRequests
            watch={watch}
            onStop={() => applyWatch([])}
            onGoRepos={() => go("repos")}
            busy={watchBusy}
            error={watchError}
          />
        ) : view === "surface" ? (
          <Surface scan={scan} onGoRepos={() => go("repos")} />
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
            watch={watch}
            onWatch={applyWatch}
            watchBusy={watchBusy}
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
