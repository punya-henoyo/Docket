import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import * as api from "./api";
import { ApiError } from "./api";
import type { Finding, Repo, RunSummary, ScanState, Session, Severity, Verdict } from "./types";
import { Overview } from "./views/Overview";
import { Scan } from "./views/Scan";
import { Surface } from "./views/Surface";
import { Findings } from "./views/Findings";
import { Repositories } from "./views/Repositories";
import { Integrations } from "./views/Integrations";

type View = "overview" | "scan" | "surface" | "findings" | "repos" | "integrations";

// Ordered by who asks the question: posture first (a security lead), then the live
// run, then the map, then the detail an engineer works from.
const VIEWS: { id: View; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "scan", label: "Scan" },
  { id: "surface", label: "Attack surface" },
  { id: "findings", label: "Findings" },
  { id: "repos", label: "Repositories" },
  { id: "integrations", label: "Integrations" },
];

const routeOf = (): View => {
  const hash = window.location.hash.replace("#/", "") as View;
  return VIEWS.some((v) => v.id === hash) ? hash : "overview";
};

export default function App() {
  const [view, setView] = useState<View>(routeOf);
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

  const go = useCallback((next: View) => {
    setView(next);
    window.location.hash = `#/${next}`;
  }, []);

  useEffect(() => {
    const onHash = () => setView(routeOf());
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
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
          const s = await api.getSession();
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
        const r = await api.getRuns();
        if (!alive) return;
        setRuns(r);
        // Reload used to land on an empty dashboard even though report.json was on
        // disk the whole time. Restore the newest run so refreshing is not
        // indistinguishable from never having scanned.
        if (r.length) {
          try {
            setScan(await api.getRun(r[0].run_name));
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
      setRepos(await api.getRepos());
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
        const next = await api.getScan(scan.id);
        const fresh = next.findings.find((f) => !prevIds.current.has(f.id));
        if (fresh) setNewestId(fresh.id);
        prevIds.current = new Set(next.findings.map((f) => f.id));
        setScan(next);
        // Recovered: polling is a repeated action, so a stale failure banner from an
        // earlier tick is now a lie about the current state.
        setScanError(null);
        // A cancelled scan writes a partial report too, so the run list needs
        // refreshing either way.
        if (next.status === "done" || next.status === "cancelled") {
          api.getRuns().then(setRuns).catch(() => {});
        }
      } catch (err) {
        setScanError(err instanceof ApiError ? err.message : String(err));
        setPollTick((t) => t + 1);  // keep polling; the run is still going
      }
    }, 1500);
    return () => clearTimeout(timer);
  }, [scan, pollTick]);

  const runScan = useCallback(
    async (repo: string, ref?: string, triageMax = 0, recon = false) => {
      setScanError(null);
      setSelected(null);
      setCweFilter(null);
      setVerdictFilter(null);
      prevIds.current = new Set();
      setNewestId(undefined);
      try {
        const { id } = await api.startScan(repo, ref, triageMax, recon);
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

  const openRun = useCallback(
    async (runName: string) => {
      setScanError(null);
      setSelected(null);
      setCweFilter(null);
      setVerdictFilter(null);
      try {
        setScan(await api.getRun(runName));
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
            {v.id === "scan" && scanning && <span className="live">● live</span>}
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
        ) : view === "overview" ? (
          <Overview
            scan={scan}
            runs={runs}
            onGoFindings={() => go("findings")}
            onGoRepos={() => go("repos")}
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
