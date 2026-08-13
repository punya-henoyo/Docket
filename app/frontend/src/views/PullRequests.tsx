import { useEffect, useState } from "react";
import type { PrResult, WatchState } from "../types";
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

  const results = watch?.results ?? [];
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
            {results.map((r) => <Row key={`${r.repo}#${r.number}@${r.head_sha}`} result={r} />)}
          </div>
        </Panel>
      )}
    </>
  );
}

function Row({ result }: { result: PrResult }) {
  const [open, setOpen] = useState(false);
  const v = verdictOf(result);
  const interesting = !result.scanning && (result.exit_code !== 0 || result.new > 0);

  return (
    <div style={{ display: "block", padding: 0 }}>
      <button
        onClick={() => interesting && setOpen(!open)}
        style={{
          display: "flex", alignItems: "center", gap: 12, width: "100%",
          padding: "12px 16px", background: "none", border: 0, textAlign: "left",
          color: "inherit", cursor: interesting ? "pointer" : "default",
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

      {open && (
        <div style={{ padding: "0 16px 14px 50px", display: "flex",
                      flexDirection: "column", gap: 8 }}>
          <div className="note" style={{ fontSize: 12.5 }}>
            {result.error || result.reason}
          </div>
          {!result.trustworthy && !result.error && (
            <div className="note bad" style={{ fontSize: 12 }}>
              This verdict is not a pass — docket could not finish judging the change.
            </div>
          )}
          {result.findings.map((f, i) => (
            <div key={i} style={{ display: "flex", gap: 10, alignItems: "baseline",
                                  font: "12.5px var(--sans)" }}>
              <span style={{ color: SEV_TONE[f.severity ?? "info"], flex: "none",
                             minWidth: 54, fontWeight: 500 }}>
                {f.severity}
              </span>
              <span style={{ minWidth: 0, flex: 1 }}>
                {f.discovered_by === "recon"
                  ? f.title
                  : (f.rule_id ?? "").split("/").pop()?.split(".").pop()}
                <span className="path" style={{ marginLeft: 8, fontSize: 11.5 }}>
                  {f.where}
                </span>
              </span>
              {f.verdict === "exploitable" && (
                <span style={{ color: "var(--crit)", flex: "none",
                               font: "500 11.5px var(--sans)" }}>reachable</span>
              )}
            </div>
          ))}
          {Object.keys(result.posted || {}).length > 0 && (
            <div className="note" style={{ fontSize: 11.5 }}>
              Posted to GitHub — {Object.entries(result.posted)
                .map(([k, v]) => `${k}: ${v}`).join(" · ")}
            </div>
          )}
        </div>
      )}
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
