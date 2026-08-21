import { useEffect, useState } from "react";
import type { PrProgress, PrResult, WatchState } from "../types";
import { Empty, Panel } from "../components/ui";

/** The continuous half of the product.
 *
 *  A scan is something you run; this is something that runs. That difference is why
 *  it gets its own tab rather than living under Repositories — a pull-request verdict
 *  is not a scan run, it has its own stream, and the question it answers ("is anything
 *  getting worse?") is asked over time rather than once.
 *
 *  The screen is built around one claim: docket is quiet unless a change made things
 *  worse. So a passing verdict is a single muted line, and a blocked one is the only
 *  thing on the page with colour. If every row shouted, none of them would mean
 *  anything.
 */

const VERDICT = {
  0: { label: "passed", tone: "var(--ok)", mark: "✓" },
  1: { label: "inconclusive", tone: "var(--med)", mark: "!" },
  2: { label: "blocked", tone: "var(--crit)", mark: "✕" },
} as const;

const SEV_TONE: Record<string, string> = {
  critical: "var(--crit)", high: "var(--high)", medium: "var(--med)",
  low: "var(--low)", info: "var(--info)",
};

function verdictOf(result: PrResult) {
  if (result.scanning) return { label: "scanning…", tone: "var(--ok)", mark: "•" };
  if (result.error) return { label: "failed", tone: "var(--crit)", mark: "✕" };
  return VERDICT[(result.exit_code ?? 1) as 0 | 1 | 2] ?? VERDICT[1];
}

function ago(seconds: number | null): string {
  if (!seconds) return "never";
  const delta = Math.max(0, Math.floor(Date.now() / 1000 - seconds));
  if (delta < 60) return `${delta}s ago`;
  if (delta < 3600) return `${Math.floor(delta / 60)}m ago`;
  return `${Math.floor(delta / 3600)}h ago`;
}

export function PullRequests({
  watch,
  onStop,
  onGoRepos,
  busy,
  error,
}: {
  watch: WatchState | null;
  onStop: () => void;
  onGoRepos: () => void;
  busy: boolean;
  error: string | null;
}) {
  // Re-render on a timer so "8s ago" and the countdown stay honest between polls.
  const [, tick] = useState(0);
  useEffect(() => {
    const id = setInterval(() => tick((n) => n + 1), 1000);
    return () => clearInterval(id);
  }, []);

  // Selection lives here, not in the row: the drawer is a sibling of the whole list,
  // and two rows must never be open at once.
  const [selected, setSelected] = useState<string | null>(null);
  const results = watch?.results ?? [];
  const active = results.find((r) => `${r.repo}#${r.number}` === selected) ?? null;
  const watching = !!watch?.enabled;
  const blocked = results.filter((r) => r.exit_code === 2).length;
  const countdown = watch?.next_poll
    ? Math.max(0, Math.round(watch.next_poll - Date.now() / 1000))
    : null;

  return (
    <>
      <div className="page-head">
        <h1>Pull requests</h1>
        <div className="head-actions">
          {watching ? (
            <button className="btn" onClick={onStop} disabled={busy}
                    style={{ color: "var(--crit)", borderColor: "var(--crit)" }}>
              {busy ? "stopping…" : "Stop watching"}
            </button>
          ) : (
            <button className="btn primary" onClick={onGoRepos}>Choose repositories</button>
          )}
        </div>
      </div>

      {error && <div className="note bad">{error}</div>}
      {watch?.error && <div className="note bad">Watcher stopped: {watch.error}</div>}

      {/* ── the live strip ────────────────────────────────────────────────── */}
      <div className="panel">
        <div className="body" style={{ flexDirection: "row", flexWrap: "wrap",
                                       alignItems: "center", gap: 26, paddingTop: 16 }}>
          <span style={{ display: "flex", alignItems: "center", gap: 9 }}>
            <span style={{
              width: 9, height: 9, borderRadius: "50%", flex: "none",
              background: watching ? "var(--ok)" : "var(--line-2)",
              animation: watching ? "pulse 1.6s ease-in-out infinite" : undefined,
            }} />
            <span style={{ font: "600 15px var(--sans)" }}>
              {watching ? "Watching" : "Not watching"}
            </span>
          </span>

          <Fact label="Repositories" value={watch?.repos.length ?? 0} />
          <Fact label="Checked" value={ago(watch?.last_poll ?? null)} />
          <Fact
            label="Next check"
            value={watching && countdown !== null ? `${countdown}s` : "—"}
          />
          <Fact label="Verdicts" value={results.length} />
          <Fact label="Blocked" value={blocked}
                tone={blocked ? "var(--crit)" : undefined} />

          {watching && watch!.repos.length > 0 && (
            <span style={{ display: "flex", gap: 6, flexWrap: "wrap",
                           marginLeft: "auto" }}>
              {watch!.repos.map((r) => (
                <span key={r} className="chip">{r.replace(/^github:/, "")}</span>
              ))}
            </span>
          )}
        </div>
      </div>

      {/* ── the stream ───────────────────────────────────────────────────── */}
      {results.length === 0 ? (
        <Panel title="Verdicts">
          <Empty>
            <div style={{ maxWidth: "48ch", lineHeight: 1.8 }}>
              {watching ? (
                <>
                  Nothing yet. docket checks every {watch?.interval_sec ?? 30} seconds
                  and reports only what a change <b>introduced</b> — a pull request
                  that adds nothing gets a passing status and no comment at all.
                </>
              ) : (
                <>
                  docket can watch your repositories and check every pull request as
                  it is pushed. It posts a commit status you can require in branch
                  protection, and comments only when a change makes things worse.
                </>
              )}
            </div>
            {!watching && (
              <button className="btn primary" onClick={onGoRepos}>
                Choose repositories to watch
              </button>
            )}
          </Empty>
        </Panel>
      ) : (
        <Panel title="Verdicts"
               action={<span className="note" style={{ fontSize: 12 }}>
                 newest first
               </span>}>
          <div className="rows">
            {results.map((r) => (
              <Row key={`${r.repo}#${r.number}@${r.head_sha}`} result={r}
                   selected={selected === `${r.repo}#${r.number}`}
                   onSelect={() => setSelected(
                     selected === `${r.repo}#${r.number}` ? null : `${r.repo}#${r.number}`)} />
            ))}
          </div>
        </Panel>
      )}
      {active && <Drawer result={active} onClose={() => setSelected(null)} />}
    </>
  );
}

function Row({ result, selected, onSelect }: {
  result: PrResult; selected: boolean; onSelect: () => void;
}) {
  // Every row opens, including one still scanning — watching it work is the point.
  const v = verdictOf(result);

  return (
    <div style={{ display: "block", padding: 0 }}>
      <button
        onClick={onSelect}
        style={{
          display: "flex", alignItems: "center", gap: 12, width: "100%",
          padding: "12px 16px", border: 0, textAlign: "left",
          color: "inherit", cursor: "pointer",
          background: selected ? "var(--panel-2, rgba(127,127,127,.10))" : "none",
        }}
      >
        <span title={v.label} style={{
          animation: result.scanning ? "pulse 1.4s ease-in-out infinite" : undefined,
          width: 22, height: 22, borderRadius: "50%", flex: "none",
          display: "grid", placeItems: "center",
          font: "600 12px var(--sans)", color: v.tone,
          background: "color-mix(in srgb, currentColor 12%, transparent)",
          border: "1px solid color-mix(in srgb, currentColor 30%, transparent)",
        }}>{v.mark}</span>

        <span style={{ minWidth: 0, flex: 1 }}>
          <span style={{ display: "block", fontSize: 13.5, overflow: "hidden",
                         textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
            {result.title || `Pull request #${result.number}`}
          </span>
          <span className="note" style={{ fontSize: 11.5 }}>
            {result.repo} <span className="mono">#{result.number}</span>
            {result.base_ref && <> → {result.base_ref}</>}
            {result.head_sha && <> · <span className="mono">{result.head_sha}</span></>}
          </span>
        </span>

        {/* The delta, which is the entire point of this row. */}
        <span style={{ display: "flex", gap: 12, flex: "none",
                       font: "500 12.5px var(--sans)" }}>
          {result.new > 0 && (
            <span style={{ color: "var(--crit)" }} title="findings this change introduced">
              +{result.new}
            </span>
          )}
          {result.fixed > 0 && (
            <span style={{ color: "var(--ok)" }} title="findings this change fixed">
              −{result.fixed}
            </span>
          )}
          {result.scanning ? (
            <span className="note" style={{ fontSize: 12 }}>reading the diff…</span>
          ) : result.new === 0 && result.fixed === 0 ? (
            <span className="note" style={{ fontSize: 12 }}>no change</span>
          ) : null}
        </span>

        <span style={{ flex: "none", minWidth: 96, textAlign: "right",
                       font: "500 12px var(--sans)", color: v.tone }}>
          {v.label}
        </span>
        <span className="note" style={{ fontSize: 11.5, flex: "none",
                                        minWidth: 58, textAlign: "right" }}>
          {ago(result.at)}
        </span>
      </button>

    </div>
  );
}

function Fact({ label, value, tone }: {
  label: string; value: number | string; tone?: string;
}) {
  return (
    <div>
      <div className="eyebrow" style={{ fontSize: 11.5 }}>{label}</div>
      <div className="num" style={{ font: "600 17px var(--sans)", marginTop: 2,
                                    color: tone }}>
        {value}
      </div>
    </div>
  );
}


const STEP_TONE: Record<string, string> = {
  done: "var(--ok)", running: "var(--med)", error: "var(--crit)",
  skipped: "var(--info)", pending: "var(--info)",
};

function secs(from: number | null, to: number | null): string {
  if (!from) return "";
  const end = to ?? Date.now() / 1000;
  const d = Math.max(0, Math.round(end - from));
  return d < 60 ? `${d}s` : `${Math.floor(d / 60)}m ${d % 60}s`;
}

/** What docket is doing, right now, in order.
 *
 *  A scan takes minutes, and for all of that time the row said "scanning…" and nothing
 *  else — which looks exactly like a hung process. The steps are the same ones the
 *  engine reports internally (on_stage / on_agent); this is the first screen that
 *  shows them. When the scan ends the timeline is dropped and the verdict takes over,
 *  because the verdict is the durable record and a stale timeline would imply work
 *  that is no longer happening.
 */
function Timeline({ progress }: { progress: PrProgress }) {
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
      {progress.phase && (
        <div className="note" style={{ fontSize: 11.5, marginBottom: 6 }}>
          scanning the <span className="mono">{progress.phase}</span> commit
          {progress.findings > 0 && <> · {progress.findings} finding(s) so far</>}
        </div>
      )}
      {progress.steps.map((s) => (
        <div key={s.name} style={{ display: "flex", gap: 10, alignItems: "baseline",
                                   padding: "5px 0" }}>
          <span style={{
            width: 16, height: 16, borderRadius: "50%", flex: "none",
            display: "grid", placeItems: "center", marginTop: 2,
            font: "600 10px var(--sans)", color: STEP_TONE[s.state] ?? "var(--info)",
            background: "color-mix(in srgb, currentColor 14%, transparent)",
            border: "1px solid color-mix(in srgb, currentColor 34%, transparent)",
            animation: s.state === "running" ? "pulse 1.4s ease-in-out infinite" : undefined,
          }}>
            {s.state === "done" ? "✓" : s.state === "error" ? "✕"
              : s.state === "skipped" ? "–" : "•"}
          </span>
          <span style={{ minWidth: 0, flex: 1 }}>
            <span style={{ fontSize: 13, color: s.state === "pending"
                             ? "var(--muted, #888)" : "inherit" }}>
              {s.label}
            </span>
            {s.detail && (
              <span className="path" style={{ display: "block", fontSize: 11.5,
                                              marginTop: 1 }}>
                {s.detail}
              </span>
            )}
          </span>
          <span className="note mono" style={{ fontSize: 11, flex: "none" }}>
            {s.state === "skipped" ? "skipped" : secs(s.started, s.ended)}
          </span>
        </div>
      ))}
    </div>
  );
}

function Drawer({ result, onClose }: { result: PrResult; onClose: () => void }) {
  // Escape closes it. A panel that can only be dismissed with the mouse is a panel
  // people leave open.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const v = verdictOf(result);
  return (
    <aside
      role="complementary"
      aria-label={`Detail for pull request ${result.number}`}
      style={{
        position: "fixed", top: 0, right: 0, bottom: 0, width: "min(440px, 92vw)",
        background: "var(--panel, #14171c)",
        borderLeft: "1px solid var(--line, rgba(127,127,127,.25))",
        boxShadow: "-18px 0 44px -30px rgba(0,0,0,.8)",
        display: "flex", flexDirection: "column", zIndex: 40,
      }}
    >
      <header style={{ display: "flex", alignItems: "flex-start", gap: 10,
                       padding: "14px 16px",
                       borderBottom: "1px solid var(--line, rgba(127,127,127,.25))" }}>
        <span style={{ minWidth: 0, flex: 1 }}>
          <span style={{ display: "block", fontSize: 13.5, overflow: "hidden",
                         textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
            {result.title || `Pull request #${result.number}`}
          </span>
          <span className="note" style={{ fontSize: 11.5 }}>
            {result.repo} <span className="mono">#{result.number}</span>
            {result.base_ref && <> → {result.base_ref}</>}
          </span>
        </span>
        <span style={{ flex: "none", font: "500 12px var(--sans)", color: v.tone }}>
          {v.label}
        </span>
        <button onClick={onClose} aria-label="Close"
                style={{ flex: "none", background: "none", border: 0, cursor: "pointer",
                         color: "inherit", opacity: .6, font: "16px var(--sans)",
                         lineHeight: 1, padding: 0 }}>×</button>
      </header>

      <div style={{ overflowY: "auto", padding: "14px 16px", display: "flex",
                    flexDirection: "column", gap: 16 }}>
        {result.exit_code === 2 && <FixButton result={result} />}
        {result.progress ? (
          <Timeline progress={result.progress} />
        ) : (
          <div className="note" style={{ fontSize: 12.5 }}>
            {result.error || result.reason}
          </div>
        )}

        {!result.progress && !result.trustworthy && !result.error && (
          <div className="note bad" style={{ fontSize: 12 }}>
            This verdict is not a pass — docket could not finish judging the change.
          </div>
        )}

        {result.findings.length > 0 && (
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            <div className="eyebrow" style={{ fontSize: 11.5 }}>
              Findings this change introduced
            </div>
            {result.findings.map((f, i) => (
              <div key={i} style={{ display: "flex", gap: 10, alignItems: "baseline",
                                    font: "12.5px var(--sans)" }}>
                <span style={{ color: SEV_TONE[f.severity ?? "info"], flex: "none",
                               minWidth: 54, fontWeight: 500 }}>{f.severity}</span>
                <span style={{ minWidth: 0, flex: 1 }}>
                  {f.discovered_by === "recon"
                    ? f.title
                    : (f.rule_id ?? "").split("/").pop()?.split(".").pop()}
                  <span className="path" style={{ display: "block", fontSize: 11.5 }}>
                    {f.where}
                    {f.discovered_by === "recon" && " · found by AI, not blocking"}
                  </span>
                  {/* The anchor above is the line the diff scoped on; this is where the
                      problem really is. Mendor-lab#2 changed only services/db.py while
                      the missing authorization lived in profiles.py. */}
                  {f.root_cause && f.root_cause !== f.where && (
                    <span className="path" style={{ display: "block", fontSize: 11.5,
                                                    color: "var(--med)" }}>
                      cause: {f.root_cause}
                    </span>
                  )}
                  {f.origin === "pre-existing" && (
                    <span className="note" style={{ display: "block", fontSize: 11 }}>
                      the agent judged this pre-existing, not caused by this change
                    </span>
                  )}
                </span>
                {f.verdict === "exploitable" && (
                  <span style={{ color: "var(--crit)", flex: "none",
                                 font: "500 11.5px var(--sans)" }}>reachable</span>
                )}
              </div>
            ))}
          </div>
        )}

        {result.fix && result.fix.files?.length > 0 && (
          <FixDiff fix={result.fix} />
        )}

        {Object.keys(result.posted || {}).length > 0 && (
          <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
            <div className="eyebrow" style={{ fontSize: 11.5 }}>Posted to GitHub</div>
            {Object.entries(result.posted).map(([k, val]) => (
              <div key={k} className="note" style={{ fontSize: 11.5 }}>
                <span className="mono">{k}</span> — {val}
              </div>
            ))}
          </div>
        )}
      </div>
    </aside>
  );
}

/** The fix docket opened, shown as its "files changed" diff — the same view a reviewer
 *  would open on GitHub, inline in the drawer so you never leave the board to see the
 *  patch. Coloured by the unified-diff prefix: green added, red removed, muted context. */
function FixDiff({ fix }: { fix: NonNullable<PrResult["fix"]> }) {
  const lineStyle = (ln: string): React.CSSProperties => {
    const c = ln[0];
    if (c === "+") return { background: "color-mix(in srgb, var(--ok) 14%, transparent)", color: "var(--ok)" };
    if (c === "-") return { background: "color-mix(in srgb, var(--crit) 14%, transparent)", color: "var(--crit)" };
    if (c === "@") return { color: "var(--info)", opacity: 0.8 };
    return { color: "var(--muted, #8a94a3)" };
  };
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
      <div className="eyebrow" style={{ fontSize: 11.5 }}>
        Fix opened{fix.number ? ` — #${fix.number}` : ""}
        {fix.url && (
          <> · <a href={fix.url} target="_blank" rel="noreferrer"
                  style={{ color: "var(--ok)" }}>view on GitHub ↗</a></>
        )}
      </div>
      {fix.files.map((f) => (
        <div key={f.path} style={{ border: "1px solid var(--line, rgba(127,127,127,.25))",
                                   borderRadius: 6, overflow: "hidden" }}>
          <div className="mono" style={{ fontSize: 12, padding: "6px 10px",
                background: "var(--panel-2, rgba(127,127,127,.08))",
                borderBottom: "1px solid var(--line, rgba(127,127,127,.25))" }}>
            {f.path}
          </div>
          <div style={{ overflowX: "auto" }}>
            <pre style={{ margin: 0, font: "11.5px/1.6 var(--mono)", padding: "6px 0" }}>
              {f.lines.map((ln, i) => (
                <div key={i} style={{ ...lineStyle(ln), padding: "0 10px", whiteSpace: "pre" }}>
                  {ln || " "}
                </div>
              ))}
            </pre>
          </div>
        </div>
      ))}
    </div>
  );
}

/** Ask for a fix pull request on a blocked change.
 *
 *  Autofix can be left off — opening pull requests on someone's repository is not a
 *  thing to start doing because a checkbox defaulted on — so a blocked verdict needs a
 *  way to ask for one after the fact. It is also the recovery path when autofix ran and
 *  refused: the refusal is visible, and trying again is one click rather than a re-scan.
 *
 *  The button reports "asked for", not "opened". Writing and PROVING a patch takes
 *  minutes and can legitimately end in a refusal, so claiming success here would be a
 *  lie the timeline would then contradict.
 */
function FixButton({ result }: { result: PrResult }) {
  // `asking` is a LOCAL bridge that covers the gap between the click and the first poll
  // that shows the backend working. It is deliberately not a terminal state: the earlier
  // version set "asked" and never cleared it, so the button read "Writing a fix…" forever
  // even after the attempt finished. The truth of whether a fix is running lives on the
  // backend's live timeline, so hand off to that and let the bridge expire.
  const [asking, setAsking] = useState(false);
  const [error, setError] = useState("");
  const posted = result.posted?.autofix;
  const liveFixRunning = result.progress?.steps?.some(
    (s) => s.name === "fix" && s.state === "running") ?? false;

  useEffect(() => {
    if (!asking) return;
    // The backend picked it up — its live "fix running" step now drives the spinner, so
    // drop the local bridge.
    if (liveFixRunning) { setAsking(false); return; }
    // Fallback: the attempt errored early or finished before a poll caught it. Don't
    // spin forever waiting for a "running" that already came and went.
    const t = setTimeout(() => setAsking(false), 12000);
    return () => clearTimeout(t);
  }, [asking, liveFixRunning]);

  // A fix already landed, so there is nothing to ask for.
  if (posted && posted.startsWith("opened")) {
    return (
      <div className="note ok" style={{ fontSize: 12.5 }}>
        Fix pull request {posted.replace("opened ", "")} is open.
      </div>
    );
  }
  const running = liveFixRunning || asking;

  async function ask() {
    setError(""); setAsking(true);
    try {
      const r = await fetch("/api/pr/fix", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ repo: result.repo, number: result.number }),
      });
      const body = await r.json().catch(() => ({}));
      // 202 = accepted; anything else (409 no verdict held, 429 one already running) is a
      // real answer, not a spinner. Clear the bridge so the button is usable again.
      if (!r.ok) { setAsking(false); setError(body.error ?? `HTTP ${r.status}`); }
    } catch (e) {
      setAsking(false);
      setError(e instanceof Error ? e.message : String(e));
    }
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
      <button
        onClick={ask}
        disabled={running || result.fixable === false}
        title={result.fixable === false
          ? "This verdict predates the current session, so the patch inputs are gone. Re-scan it first."
          : "Write a patch, prove it with a scanner, and open a pull request into this branch"}
        style={{
          alignSelf: "flex-start", padding: "7px 13px", borderRadius: 5,
          font: "500 12.5px var(--sans)", cursor:
            running || result.fixable === false ? "not-allowed" : "pointer",
          color: "var(--ok)", background: "color-mix(in srgb, var(--ok) 12%, transparent)",
          border: "1px solid color-mix(in srgb, var(--ok) 34%, transparent)",
          opacity: running || result.fixable === false ? 0.55 : 1,
        }}
      >
        {running ? "Writing a fix…" : "Open a fix pull request"}
      </button>
      {running && (
        <span className="note" style={{ fontSize: 11.5 }}>
          Writing and proving a patch — a PR opens only if a scanner re-run confirms the
          finding is gone. This takes a minute or two.
        </span>
      )}
      {error && (
        <span className="note bad" style={{ fontSize: 11.5 }}>{error}</span>
      )}
      {!running && posted && !posted.startsWith("opened") && (
        <span className="note" style={{ fontSize: 11.5 }}>Last attempt — {posted}</span>
      )}
    </div>
  );
}
