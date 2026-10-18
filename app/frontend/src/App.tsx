import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import * as api from "./api";
import { ApiError } from "./api";
import type {
  Finding, Repo, RunSummary, ScanState, Session, Severity, Verdict, WatchState,
} from "./types";
import { Scan } from "./views/Scan";
import { Surface } from "./views/Surface";
import { Findings } from "./views/Findings";
import { Repositories } from "./views/Repositories";
import { Integrations } from "./views/Integrations";
import { PullRequests } from "./views/PullRequests";
import { Compliance } from "./views/Compliance";
import { useRoute } from "./hooks/useRoute";
import { useApi } from "./hooks/useApi";
import { Shell, type Tab } from "./shell/Shell";
import { hx } from "./hx/hx";
import { Home } from "./views/Home";
import { Applications } from "./views/Applications";
import { ApplicationPage } from "./views/ApplicationPage";
import { ScansPage } from "./views/ScansPage";
import { ScanRunPage } from "./views/ScanRunPage";
import { FindingsPage } from "./views/FindingsPage";
import { PolicyPage } from "./views/PolicyPage";
import { ComplianceBaseline } from "./views/ComplianceBaseline";

// The console is the "Code Security" application inside Henoyo. Tabs follow the question a person
// asks, posture first (a security lead), then the work an engineer does:
//   Home (who needs me), Applications (one record each), Scans, Pull requests, Findings,
//   Compliance (what the code says about written requirements), Policy (what must run).
// The older single-scan views keep working under scandetail / scanfindings / scancompliance, reached
// from a scan record, so nothing the previous console did is lost.
const TABS: Tab[] = [
  { id: "home", label: "Home" },
  { id: "apps", label: "Applications" },
  { id: "scans", label: "Scans" },
  { id: "pulls", label: "Pull requests" },
  { id: "findings", label: "Findings" },
  { id: "compliance", label: "Compliance" },
  { id: "policy", label: "Policy" },
  { id: "repos", label: "Connections" },
];

/** Which tab lights up for a route that is not itself a tab. */
const TAB_OF: Record<string, string> = {
  app: "apps", scan: "scans", scandetail: "scans", surface: "scans", scanfindings: "findings",
  scancompliance: "compliance", integrations: "repos",
};

/** Routes drawn by the older, single-scan views. They own their own padding and layout. */
const LEGACY = new Set(["scandetail", "scanfindings", "scancompliance", "surface", "pulls", "repos", "integrations"]);

export default function App() {
  const [route, goRoute] = useRoute();
  const view = route.name;
  const go = useCallback((name: string, param?: string | null) => goRoute(name, param), [goRoute]);
  const portfolio = useApi(api.portfolio.getPortfolio, "portfolio", 20000);
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
           budgetUsd = 0, compliance: string[] = []) => {
      setScanError(null);
      setSelected(null);
      setCweFilter(null);
      setVerdictFilter(null);
      prevIds.current = new Set();
      setNewestId(undefined);
      try {
        const { id } = await api.github.startRepoScan(repo, ref, triageMax, recon,
                                                     budgetUsd, compliance);
        rememberLive(id);
        setScan({
          id,
          repo,
          ref: ref ?? null,
          status: "queued",
          stages: {
            fetch: "pending", trivy: "pending", semgrep: "pending",
            nuclei: "pending", recon: "pending", compliance: "pending",
            triage: "pending",
          },
          recon,
          surface: null,
          // [] not undefined, from the first render: the Compliance view tells "no pack
          // was requested" from "a pack ran and assessed nothing", and an absent key
          // would collapse the two while the scan is still queued.
          compliance: [],
          findings: [],
          finding_count: 0,
          error: null,
        });
        go("scandetail");
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
      go("scandetail");
    } catch {
      // The server no longer knows this scan — it finished and was evicted, or the
      // console restarted. Forget it rather than leaving a button that does nothing.
      rememberLive(null);
    }
  }, [liveId, go, rememberLive]);

  const applyWatch = useCallback(async (repos: string[], autofix = false,
                                        compliance: string[] = []) => {
    setWatchBusy(true);
    setWatchError(null);
    try {
      setWatch(await api.github.setWatch(
        repos.length
          ? { enabled: true, repos, interval_sec: 30, triage_max: 5, autofix,
              // Omitted when empty, so a watch started without packs sends exactly the
              // request it did before this feature existed.
              ...(compliance.length ? { compliance } : {}) }
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
      go("scanfindings");
    },
    [go],
  );

  const scanning = scan?.status === "queued" || scan?.status === "fetching" || scan?.status === "scanning";

  // The repo of the RUNNING scan, which is not necessarily the displayed one.
  const liveRepo = (runs.find((r) => r.run_name === liveId)?.target ?? "")
    .replace(/^github:/, "")
    .split("@")[0] || null;

  const active = TAB_OF[view] ?? view;
  const tabs = TABS.map((t) => (t.id === "pulls" && watch?.enabled ? { ...t, badge: "on" } : t));
  const legacy = LEGACY.has(view);

  const liveBanner =
    liveId && scan?.id !== liveId ? (
      <div className={hx("notice")} style={{ marginBottom: 16, display: "flex", gap: 12, alignItems: "center" }}>
        <span className="live">●</span>
        <span style={{ flex: 1 }}>
          A scan is still running{liveRepo ? <> on <b>{liveRepo}</b></> : null}. You are looking at a different run.
        </span>
        <button className="btn primary" onClick={resumeLive}>Go to the live scan</button>
      </div>
    ) : null;

  const legacyView =
    view === "scandetail" ? (
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
    ) : view === "scanfindings" ? (
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
    ) : view === "scancompliance" ? (
      <Compliance scan={scan} error={scanError} onSelectFinding={openFinding} />
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
    );

  const portfolioView =
    view === "apps" ? (
      <Applications portfolio={portfolio.data} go={go} />
    ) : view === "app" && route.param ? (
      <ApplicationPage id={route.param} go={go} />
    ) : view === "scans" ? (
      <ScansPage portfolio={portfolio.data} go={go} />
    ) : view === "scan" && route.param ? (
      <ScanRunPage
        run={route.param}
        go={go}
        onOpenDetail={async (run) => { await openRun(run); go("scandetail"); }}
      />
    ) : view === "findings" ? (
      <FindingsPage go={go} />
    ) : view === "compliance" ? (
      <ComplianceBaseline portfolio={portfolio.data} go={go} />
    ) : view === "policy" ? (
      <PolicyPage go={go} />
    ) : (
      <Home portfolio={portfolio.data} error={portfolio.error} go={go} />
    );

  return (
    <Shell tabs={tabs} active={active} onGo={(id) => go(id)} user={session?.login ?? null} sample={Boolean(portfolio.data?.sample)}>
      {bootError ? (
        <main className="hx-main">
          <h1>Cannot reach docket</h1>
          <div className={hx("notice bad")} style={{ marginTop: 12 }}>{bootError}</div>
          <p>Start the backend from the repo root, then reload:</p>
          <pre className="mono">docket connect</pre>
        </main>
      ) : legacy ? (
        <main className="main legacy">{liveBanner}{legacyView}</main>
      ) : (
        <main className="hx-main">{liveBanner}{portfolioView}</main>
      )}
    </Shell>
  );
}
