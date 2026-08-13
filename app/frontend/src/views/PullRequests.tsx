import { useCallback, useEffect, useState } from "react";
import * as api from "../api";
import { ApiError } from "../api";
import type {
  Finding,
  Patch,
  PrScan,
  PrScanDetail,
  PrScanState,
  ServiceStatus,
} from "../types";
import { Empty, findingLocation, Panel, ruleLeaf, SevTag, VerdictTag } from "../components/ui";

/** The PR inbox: what the service half did without being asked.
 *
 *  This view fetches its own state rather than taking it from App. The control plane runs
 *  whether or not anybody has this tab open, so there is nothing here for App to own —
 *  and a 503 from the unbuilt service store must stay contained to this page instead of
 *  becoming a boot error for the whole console.
 */

const POLL_MS = 4000;

const STATES: PrScanState[] = ["queued", "scanning", "delivered", "failed", "abandoned"];

// A state is where the SCAN got to; a conclusion is what the GATE decided. Two different
// questions, so two different colour scales — reusing one for both would read as though a
// delivered scan and a passing gate were the same fact.
const STATE_COLOUR: Record<string, string> = {
  queued: "var(--ink-3)",
  scanning: "var(--low)",
  delivered: "var(--ink-2)",
  failed: "var(--crit)",
  abandoned: "var(--ink-3)",
};

const GATE: Record<string, { label: string; colour: string; blurb: string }> = {
  success: { label: "PASS", colour: "var(--ok)", blurb: "nothing hit the floor and nothing was confirmed reachable" },
  failure: { label: "FAIL", colour: "var(--crit)", blurb: "blocked: a floor rule matched or triage confirmed a finding is reachable" },
  action_required: { label: "ACTION REQUIRED", colour: "var(--high)", blurb: "a human must look: the pull request was not fully scanned" },
};

const message = (err: unknown) => (err instanceof ApiError ? err.message : String(err));

const shortSha = (sha: string | null | undefined) => (sha ? sha.slice(0, 7) : "—");

/** store.py picks its own column type, so a timestamp arrives as an ISO string or as
 *  epoch seconds. Both render; anything else renders as itself rather than "Invalid Date". */
function when(value: string | number | null | undefined): string {
  if (value === null || value === undefined || value === "") return "—";
  const ms = typeof value === "number" ? (value < 1e12 ? value * 1000 : value) : Date.parse(value);
  if (!Number.isFinite(ms)) return String(value);
  return new Date(ms).toLocaleString();
}

function ago(epochSeconds: number | null | undefined): string {
  if (!epochSeconds) return "never";
  const seconds = Math.max(0, Math.round(Date.now() / 1000 - epochSeconds));
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m ago`;
  return `${Math.round(seconds / 3600)}h ago`;
}

function GateTag({ conclusion }: { conclusion: string | null | undefined }) {
  if (!conclusion) return <span className="note">not reported</span>;
  const gate = GATE[conclusion];
  // An unrecognised conclusion is shown verbatim rather than dropped: a value this
  // console has not been taught is still information.
  const colour = gate?.colour ?? "var(--ink-2)";
  return (
    <span className="chip" title={gate?.blurb ?? conclusion}
          style={{ color: colour, borderColor: colour }}>
      {gate?.label ?? conclusion}
    </span>
  );
}

/** A proposed fix.
 *
 *  UNVERIFIED IS THE LOUD CASE, on purpose. docket only earns the word "fix" where it
 *  proved the patch; everything else is a suggestion, and a suggestion rendered like a fix
 *  is how a wrong diff gets merged on docket's word. The backend collapses "proof failed"
 *  and "nobody tried" into the same false, so this label can only err towards caution.
 */
function PatchBlock({ patch }: { patch: Patch }) {
  const colour = patch.verified ? "var(--ok)" : "var(--high)";
  return (
    <div className="evidence" style={{ borderColor: colour }}>
      <div className="lbl" style={{ display: "flex", alignItems: "center", gap: 10,
                                    flexWrap: "wrap" }}>
        <span className="mono">{patch.name || "patch"}</span>
        {patch.status && <span className="chip mono">{patch.status}</span>}
        {(patch.files ?? []).length > 0 && (
          <span className="note">{(patch.files ?? []).length} file(s)</span>
        )}
        <span className="chip" style={{ color: colour, borderColor: colour, marginLeft: "auto" }}
              title={patch.verified
                ? "docket re-ran its check against the patched source and the finding was gone."
                : "Nothing proved this patch. It has not been validated, or validation failed — either way it is a suggestion for a human to read, not a fix."}>
          {patch.verified ? "VERIFIED FIX" : "UNVERIFIED — NOT A PROVEN FIX"}
        </span>
      </div>
      {!patch.verified && (
        <div className="note bad" style={{ padding: "8px 11px" }}>
          Review this by hand before applying it. docket did not prove it removes the
          finding.
        </div>
      )}
      {patch.summary && (
        <div className="note" style={{ padding: "8px 11px" }}>{patch.summary}</div>
      )}
      <pre>{patch.diff || "(empty diff)"}</pre>
      {patch.truncated && (
        <div className="note" style={{ padding: "8px 11px" }}>
          Truncated for display. The full diff is on the pull request.
        </div>
      )}
    </div>
  );
}

function FindingRow({ finding }: { finding: Finding }) {
  const triage = finding.triage;
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 5,
                  paddingBottom: 10, borderBottom: "1px solid var(--line)" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
        <SevTag severity={finding.severity ?? "info"} />
        <span className="mono" style={{ fontSize: 12.5 }}
              title={finding.rule_id ?? finding.rule_type ?? ""}>
          {ruleLeaf(finding.rule_id ?? finding.rule_type)}
        </span>
        <span className="path">{findingLocation(finding)}</span>
        {triage ? <VerdictTag verdict={triage.verdict} /> :
          <span className="note" title="Nobody judged this. Different from judged-and-unsure.">
            not triaged
          </span>}
      </div>
      {triage?.reasoning && (
        <div className="note" style={{ maxWidth: "90ch" }}>{triage.reasoning}</div>
      )}
      {triage?.evidence && (
        <div className="path" style={{ fontSize: 11.5 }}>{triage.evidence}</div>
      )}
    </div>
  );
}

export function PullRequests() {
  const [status, setStatus] = useState<ServiceStatus | null>(null);
  const [statusError, setStatusError] = useState<string | null>(null);
  const [scans, setScans] = useState<PrScan[] | null>(null);
  const [scansError, setScansError] = useState<string | null>(null);
  const [stateFilter, setStateFilter] = useState<PrScanState | "">("");
  const [repoFilter, setRepoFilter] = useState("");
  const [openId, setOpenId] = useState<string | number | null>(null);
  const [detail, setDetail] = useState<PrScanDetail | null>(null);
  const [detailError, setDetailError] = useState<string | null>(null);
  // The id whose rescan was refused because a worker holds its lease. Kept so the refusal
  // offers the force retry instead of being a dead end.
  const [conflictId, setConflictId] = useState<string | number | null>(null);
  const [busy, setBusy] = useState(false);
  const [pollEvery, setPollEvery] = useState(30);
  // Bumped after any write, to pull the new state rather than wait for the next tick.
  const [refresh, setRefresh] = useState(0);

  const load = useCallback(async () => {
    try {
      setStatus(await api.service.getStatus());
      setStatusError(null);
    } catch (err) {
      setStatus(null);
      setStatusError(message(err));
    }
    try {
      setScans(await api.service.getScans({
        repo: repoFilter.trim() || undefined,
        state: stateFilter || undefined,
      }));
      setScansError(null);
    } catch (err) {
      setScans([]);
      setScansError(message(err));
    }
  }, [repoFilter, stateFilter]);

  useEffect(() => {
    load();
    // setInterval, not a self-rearming timeout: a failed tick sets an error and the next
    // tick still fires, so a dropped request cannot end polling for good.
    const timer = setInterval(load, POLL_MS);
    return () => clearInterval(timer);
  }, [load, refresh]);

  useEffect(() => {
    if (openId === null || openId === undefined) {
      setDetail(null);
      setDetailError(null);
      return;
    }
    let alive = true;
    api.service.getScan(openId)
      .then((data) => {
        if (!alive) return;
        setDetail(data);
        setDetailError(null);
      })
      .catch((err) => {
        if (!alive) return;
        setDetail(null);
        setDetailError(message(err));
      });
    return () => {
      alive = false;
    };
  }, [openId, refresh]);

  const togglePoller = useCallback(async () => {
    setBusy(true);
    try {
      if (status?.running) await api.service.stopPoller();
      else await api.service.startPoller(pollEvery);
      setStatusError(null);
    } catch (err) {
      setStatusError(message(err));
    } finally {
      setBusy(false);
      setRefresh((n) => n + 1);
    }
  }, [status?.running, pollEvery]);

  const rescan = useCallback(async (id: string | number, force: boolean) => {
    setBusy(true);
    setConflictId(null);
    try {
      await api.service.rescan(id, force);
      setDetailError(null);
    } catch (err) {
      setDetailError(message(err));
      // 409: a live lease. Surfacing the force path is the difference between a refusal
      // and a stuck row nobody can ever re-scan after a worker died holding it.
      if (err instanceof ApiError && err.status === 409) setConflictId(id);
    } finally {
      setBusy(false);
      setRefresh((n) => n + 1);
    }
  }, []);

  const rows = scans ?? [];
  const running = status?.running === true;

  return (
    <>
      <div className="page-head">
        <h1>Pull requests</h1>
        <div className="head-actions">
          <span className={running ? "live-pill on" : "live-pill"}
                title={running
                  ? "The poller is looking for new pull request head commits."
                  : "Nothing is watching for new pull requests."}>
            {running ? "● poller running" : "○ poller stopped"}
          </span>
          <span className="note" title="What the last pass saw. A pass that reports repos but no pull requests is working; a pass that reports no repos means nothing is enabled.">
            last tick {ago(status?.last_tick)}
            {status?.ticks ? ` · ${status.ticks} passes` : ""}
            {status?.last_summary
              ? ` · ${status.last_summary.repos ?? 0} repos, ` +
                `${status.last_summary.pull_requests ?? 0} PRs, ` +
                `${(status.last_summary.enqueued ?? []).length} queued`
              : ""}
          </span>
          <label className="btn"
                 style={{ display: "flex", alignItems: "center", gap: 7, cursor: "text" }}
                 title="Seconds between passes. GitHub rate-limits, so a tighter loop buys latency you cannot spend.">
            every
            <input
              type="number"
              min={1}
              step={5}
              value={pollEvery}
              disabled={running}
              onChange={(e) => setPollEvery(Math.max(1, Number(e.target.value) || 1))}
              style={{ width: 46, background: "none", border: 0, color: "var(--ink)",
                       font: "inherit", textAlign: "right", outline: "none" }}
            />
            s
          </label>
          <button className={running ? "btn danger" : "btn primary"}
                  disabled={busy} onClick={togglePoller}>
            {running ? "stop poller" : "start poller"}
          </button>
        </div>
      </div>

      {/* The service store is a separate half of the product and may simply not be built
          on this machine. Say which half and why, rather than showing an empty inbox that
          reads as "no pull requests have ever been scanned". */}
      {statusError && (
        <div className="note bad" style={{ maxWidth: "80ch" }}>{statusError}</div>
      )}

      {status && (
        <div className="kpis">
          <div>
            <span className="eyebrow">watched repos</span>
            <div className="v num">
              {status.enabled ?? 0}
              <small> of {status.watched ?? 0}</small>
            </div>
          </div>
          <div>
            <span className="eyebrow">queued</span>
            <div className="v num">{status.queue_depth ?? 0}</div>
          </div>
          <div>
            <span className="eyebrow">scanning</span>
            <div className="v num">{status.scanning ?? 0}</div>
          </div>
          <div>
            <span className="eyebrow">spend, shown scans</span>
            <div className="v num">
              ${rows.reduce((sum, s) => sum + (s.cost_usd ?? 0), 0).toFixed(2)}
            </div>
          </div>
        </div>
      )}

      {/* A poller that keeps looping while every pass fails looks identical to a healthy
          one. It is deliberately NOT stopped on error — a GitHub 502 is transient — so the
          failure has to be visible instead. */}
      {status?.error && (
        <div className="note bad" style={{ maxWidth: "80ch" }}>
          Last poll failed: {status.error}
        </div>
      )}

      <Panel
        title="PR scans"
        action={
          <span style={{ display: "flex", gap: 8, alignItems: "center" }}>
            <input
              className="btn sm"
              style={{ width: 170, color: "var(--ink)" }}
              placeholder="owner/name"
              aria-label="filter by repository"
              value={repoFilter}
              onChange={(e) => setRepoFilter(e.target.value)}
            />
            <select
              className="btn sm"
              aria-label="filter by state"
              value={stateFilter}
              onChange={(e) => setStateFilter(e.target.value as PrScanState | "")}
            >
              <option value="">every state</option>
              {STATES.map((s) => (
                <option key={s} value={s}>{s}</option>
              ))}
            </select>
          </span>
        }
      >
        {scansError ? (
          <div className="note bad">{scansError}</div>
        ) : scans === null ? (
          <Empty>Loading pull request scans…</Empty>
        ) : rows.length === 0 ? (
          <Empty>
            {repoFilter || stateFilter
              ? "No PR scan matches that filter."
              : "No pull request has been scanned yet. Enable a repository under Repositories, then start the poller."}
          </Empty>
        ) : (
          <div className="tablewrap">
            <table>
              <thead>
                <tr>
                  <th>Repository</th>
                  <th>Pull request</th>
                  <th>Head</th>
                  <th>State</th>
                  <th>Gate</th>
                  <th>Findings</th>
                  <th>Spend</th>
                  <th>Updated</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((scan) => (
                  <tr
                    key={String(scan.id)}
                    tabIndex={0}
                    aria-selected={String(scan.id) === String(openId)}
                    onClick={() => setOpenId(String(scan.id) === String(openId) ? null : scan.id)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter" || e.key === " ") {
                        e.preventDefault();
                        setOpenId(String(scan.id) === String(openId) ? null : scan.id);
                      }
                    }}
                  >
                    <td style={{ wordBreak: "break-all" }}>{scan.repo || "—"}</td>
                    <td title={scan.title ?? undefined}
                        style={{ maxWidth: "24rem", overflow: "hidden",
                                 textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                      #{scan.pr ?? "?"}
                      {scan.title ? ` ${scan.title}` : ""}
                    </td>
                    <td className="path" title={scan.head_sha ?? undefined}>
                      {shortSha(scan.head_sha)}
                    </td>
                    <td>
                      <span className="chip"
                            style={{ color: STATE_COLOUR[scan.state] ?? "var(--ink-2)",
                                     borderColor: STATE_COLOUR[scan.state] ?? "var(--line-2)" }}>
                        {scan.state ?? "—"}
                      </span>
                    </td>
                    <td><GateTag conclusion={scan.conclusion} /></td>
                    <td className="num">{scan.finding_count ?? 0}</td>
                    <td className="num">${(scan.cost_usd ?? 0).toFixed(2)}</td>
                    <td className="note">{when(scan.updated_at ?? scan.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

      {openId !== null && (
        <Panel
          title={detail
            ? `${detail.repo || "?"} #${detail.pr ?? "?"} · ${shortSha(detail.head_sha)}`
            : "Scan"}
          action={
            <span style={{ display: "flex", gap: 8, alignItems: "center" }}>
              <button className="btn sm" disabled={busy}
                      onClick={() => rescan(openId, false)}
                      title="Re-queue this scan at the same head commit.">
                re-scan
              </button>
              {String(conflictId) === String(openId) && (
                <button className="btn sm danger" disabled={busy}
                        onClick={() => rescan(openId, true)}
                        title="Overrides a live lease. Only correct when the worker holding it is gone — otherwise the same commit is scanned twice and two check runs are posted.">
                  force re-scan
                </button>
              )}
              <button className="btn sm ghost" onClick={() => setOpenId(null)}>close</button>
            </span>
          }
        >
          {detailError && <div className="note bad">{detailError}</div>}
          {detail === null ? (
            detailError ? null : <Empty>Loading…</Empty>
          ) : (
            <>
              <div className="note" style={{ display: "flex", gap: 14, flexWrap: "wrap" }}>
                <span>state <b>{detail.state}</b></span>
                <span>base {shortSha(detail.base_sha)}</span>
                <span>run {detail.run_name ?? "—"}</span>
                <span>spend ${(detail.cost_usd ?? 0).toFixed(2)}</span>
                <span>created {when(detail.created_at)}</span>
                {detail.lease_owner && <span>lease {detail.lease_owner}</span>}
              </div>

              {/* The gate's argument, not just its verdict. A red check with no reason is
                  something a developer has to guess at, and they guess "flaky". */}
              <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                  <span className="eyebrow">gate</span>
                  <GateTag conclusion={detail.gate?.conclusion ?? detail.conclusion} />
                  {detail.gate && (
                    <span className="note">exit {detail.gate.exit_code}</span>
                  )}
                </div>
                {(detail.gate?.reasons ?? []).length > 0 ? (
                  <ul className="scopes">
                    {(detail.gate?.reasons ?? []).map((reason, i) => (
                      <li key={i}>
                        <span className="no">·</span>
                        <span>{reason}</span>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <div className="note">
                    {detail.report_found
                      ? "The gate recorded no reasons."
                      : "No report.json for this run, so the gate cannot be shown. The scan produced no result rather than producing a clean one."}
                  </div>
                )}
              </div>

              <div>
                <span className="eyebrow">
                  findings · {detail.finding_count ?? (detail.findings ?? []).length}
                </span>
                {(detail.findings ?? []).length === 0 ? (
                  <div className="note">
                    {detail.report_found
                      ? "This diff produced no findings."
                      : "Nothing to show: the run wrote no report."}
                  </div>
                ) : (
                  <div style={{ display: "flex", flexDirection: "column", gap: 10,
                                marginTop: 8 }}>
                    {(detail.findings ?? []).map((finding, i) => (
                      <FindingRow key={finding?.id ?? i} finding={finding} />
                    ))}
                  </div>
                )}
              </div>

              <div>
                <span className="eyebrow">patches · {(detail.patches ?? []).length}</span>
                {(detail.patches ?? []).length === 0 ? (
                  <div className="note">No patch was proposed for this pull request.</div>
                ) : (
                  <div style={{ display: "flex", flexDirection: "column", gap: 10,
                                marginTop: 8 }}>
                    {(detail.patches ?? []).map((patch, i) => (
                      <PatchBlock key={patch?.name ?? i} patch={patch} />
                    ))}
                  </div>
                )}
              </div>
            </>
          )}
        </Panel>
      )}
    </>
  );
}
