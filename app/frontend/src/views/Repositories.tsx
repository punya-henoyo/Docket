import { useCallback, useEffect, useMemo, useState } from "react";
import * as api from "../api";
import { ApiError } from "../api";
import type { AutofixMode, Policy, Repo, Session, WatchedRepo } from "../types";
import { EMPTY_POLICY } from "../types";
import { Empty, Panel } from "../components/ui";

/** Tri-state helpers. An empty control means INHERIT the org default, which is a
 *  different answer from a value of off/0/false — so the empty string maps to null and
 *  never to a zero. Getting this wrong turns "not configured" into "configured to
 *  nothing", and for budget_usd that is a fail-open: a $0 ceiling trips every triage
 *  agent's budget check before its first turn and records `uncertain`. */
const asNumber = (raw: string, min: number): number | null =>
  raw.trim() === "" ? null : Math.max(min, Number(raw) || min);

const asBool = (raw: string): boolean | null =>
  raw === "" ? null : raw === "true";

const asList = (raw: string): string[] | null => {
  const items = raw.split(",").map((s) => s.trim()).filter(Boolean);
  // "" is inherit; a comma-only string is an operator saying "none", which is a real
  // setting and must survive as [] rather than collapsing back to inherit.
  return raw.trim() === "" ? null : items;
};

const text = (value: number | string | null | undefined): string =>
  value === null || value === undefined ? "" : String(value);

const AUTOFIX_HELP: Record<AutofixMode, string> = {
  off: "Never open anything. Findings are reported and the gate still decides.",
  suggest: "Attach the diff to the check run for a human to apply. No branch, no PR.",
  open_pr: "Open a fix pull request from docket's own branch. Needs push permission.",
};

/** The policy editor for one repository. Every member may be left blank to inherit.
 *
 *  Mounted fresh per repo (it is rendered only for the row being edited), so the draft
 *  starts from the saved policy without needing to sync on every prop change. */
function PolicyForm({
  value,
  busy,
  onSave,
  onCancel,
}: {
  value: Policy;
  busy: boolean;
  onSave: (policy: Policy) => void;
  onCancel: () => void;
}) {
  const [draft, setDraft] = useState<Policy>({ ...EMPTY_POLICY, ...value });
  const set = <K extends keyof Policy>(key: K, next: Policy[K]) =>
    setDraft((prev) => ({ ...prev, [key]: next }));

  return (
    <div style={{ borderTop: "1px solid var(--line)", padding: "12px 0 4px" }}>
      <div className="grid two">
        <label className="field">
          <span>autofix</span>
          <select
            value={draft.autofix_mode ?? ""}
            onChange={(e) => set("autofix_mode", (e.target.value || null) as AutofixMode | null)}
          >
            <option value="">inherit the org default</option>
            <option value="off">off</option>
            <option value="suggest">suggest</option>
            <option value="open_pr">open a fix PR</option>
          </select>
          <em>
            {draft.autofix_mode
              ? AUTOFIX_HELP[draft.autofix_mode]
              : "Whatever the organisation default says."}
          </em>
        </label>

        <label className="field">
          <span>require verified validation</span>
          <select
            value={draft.require_verified_validation === null
              ? "" : String(draft.require_verified_validation)}
            onChange={(e) => set("require_verified_validation", asBool(e.target.value))}
          >
            <option value="">inherit</option>
            <option value="true">yes — only proven patches</option>
            <option value="false">no — unproven patches may be offered</option>
          </select>
          <em>
            A patch docket did not prove is a suggestion. Turning this off lets one reach a
            pull request labelled unverified.
          </em>
        </label>

        <label className="field">
          <span>max files changed</span>
          <input
            type="number"
            min={1}
            placeholder="inherit"
            value={text(draft.max_files_changed)}
            onChange={(e) => set("max_files_changed", asNumber(e.target.value, 1))}
          />
          <em>A fix touching more files than this is not offered. A wide diff is a refactor.</em>
        </label>

        <label className="field">
          <span>triage max</span>
          <input
            type="number"
            min={0}
            placeholder="inherit"
            value={text(draft.triage_max)}
            onChange={(e) => set("triage_max", asNumber(e.target.value, 0))}
          />
          <em>Findings judged per pull request. 0 means judge none; blank inherits.</em>
        </label>

        <label className="field">
          <span>budget, USD per scan</span>
          <input
            type="number"
            min={0.25}
            step={0.25}
            placeholder="inherit"
            value={text(draft.budget_usd)}
            onChange={(e) => set("budget_usd", asNumber(e.target.value, 0.25))}
          />
          <em>Blank inherits. 0 is refused: it would stop every agent before its first turn.</em>
        </label>

        <label className="field">
          <span>label</span>
          <input
            type="text"
            maxLength={50}
            placeholder="inherit"
            value={draft.label ?? ""}
            onChange={(e) => set("label", e.target.value.trim() || null)}
          />
          <em>Applied to check runs and fix PRs so they are filterable on GitHub.</em>
        </label>
      </div>

      <label className="field">
        <span>enabled classes</span>
        <input
          type="text"
          placeholder="inherit — e.g. command-injection, sql-injection"
          value={(draft.enabled_classes ?? []).join(", ")}
          onChange={(e) => set("enabled_classes", asList(e.target.value))}
        />
        <em>
          Comma separated. Blank inherits the org default; the deterministic floor in
          service/gate.py still applies whatever is listed here.
        </em>
      </label>

      <div className="row">
        <button className="btn primary sm" disabled={busy} onClick={() => onSave(draft)}>
          {busy ? "saving…" : "save policy"}
        </button>
        <button className="btn sm ghost" disabled={busy} onClick={onCancel}>
          cancel
        </button>
      </div>
    </div>
  );
}

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
  onScan: (repo: string, ref?: string, triageMax?: number, recon?: boolean,
           budgetUsd?: number) => void;
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

const APPROX_USD_PER_FINDING = 0.033;

  // --- the watch list -----------------------------------------------------------------
  // Fetched here rather than passed down, and deliberately NOT a second repository list:
  // "which repos exist" and "which repos docket watches" are two facts about the same
  // row, and splitting them across two pages is how an operator ends up scanning one repo
  // by hand for a week while the poller watches a different one.
  const [watched, setWatched] = useState<Record<string, WatchedRepo> | null>(null);
  const [serviceError, setServiceError] = useState<string | null>(null);
  const [editing, setEditing] = useState<string | null>(null);
  const [saving, setSaving] = useState<string | null>(null);

  const loadWatched = useCallback(async () => {
    try {
      const rows = await api.service.getWatched();
      setWatched(Object.fromEntries(rows.map((row) => [row.full_name, row])));
      setServiceError(null);
    } catch (err) {
      // A 503 here means the service half is not built on this machine. Manual scanning
      // below still works, so this is a note, not a broken page.
      setWatched({});
      setServiceError(err instanceof ApiError ? err.message : String(err));
    }
  }, []);

  useEffect(() => {
    if (session?.connected) loadWatched();
  }, [session?.connected, loadWatched]);

  const save = useCallback(
    async (fullName: string, enabled: boolean, policy: Policy) => {
      setSaving(fullName);
      try {
        const row = await api.service.setWatched(fullName, enabled, policy);
        setWatched((prev) => ({ ...(prev ?? {}), [fullName]: row }));
        setServiceError(null);
        setEditing(null);
      } catch (err) {
        setServiceError(err instanceof ApiError ? err.message : String(err));
      } finally {
        setSaving(null);
      }
    },
    [],
  );

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

  const watchedCount = Object.values(watched ?? {}).filter((w) => w?.enabled).length;

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

      <div className="note" style={{ maxWidth: "70ch" }}>
        <b>watch</b> is the other mode: docket polls the repository for new pull requests and
        scans each diff on its own, with no workflow file and nothing added to the
        repository. {watchedCount} watched. Policy per repo, blank meaning inherit the
        organisation default.
      </div>

      {error && <div className="note bad">{error}</div>}
      {serviceError && <div className="note bad" style={{ maxWidth: "80ch" }}>{serviceError}</div>}

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
            {shown.map((repo) => {
              const watch = watched?.[repo.full_name];
              const on = watch?.enabled === true;
              const policy = { ...EMPTY_POLICY, ...(watch?.policy ?? {}) };
              return (
                <div key={repo.full_name}
                     style={{ display: "flex", flexDirection: "column" }}>
                  <div className="repo-row">
                    <span style={{ minWidth: 0, wordBreak: "break-all" }}>{repo.full_name}</span>
                    <span className="meta">
                      {repo.private ? "private" : "public"}
                      {repo.language ? ` · ${repo.language}` : ""}
                      {policy.label ? ` · ${policy.label}` : ""}
                    </span>
                    <button
                      className={on ? "btn sm primary" : "btn sm"}
                      style={{ marginLeft: 10 }}
                      disabled={saving === repo.full_name}
                      aria-pressed={on}
                      onClick={() => save(repo.full_name, !on, policy)}
                      title={on
                        ? "Stop polling this repository for new pull requests."
                        : "Poll this repository for new pull requests and scan each diff."}
                    >
                      {saving === repo.full_name ? "…" : on ? "watching" : "watch"}
                    </button>
                    <button
                      className="btn sm ghost"
                      aria-expanded={editing === repo.full_name}
                      onClick={() =>
                        setEditing(editing === repo.full_name ? null : repo.full_name)
                      }
                      title="Autofix mode, budget, triage count and the classes this repo gates on."
                    >
                      policy
                    </button>
                    <input
                      className="btn sm"
                      style={{ width: 130, color: "var(--ink)" }}
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
                  </div>
                  {editing === repo.full_name && (
                    <PolicyForm
                      value={policy}
                      busy={saving === repo.full_name}
                      onCancel={() => setEditing(null)}
                      // Saving policy does not silently start watching: enabling a repo is
                      // a separate, deliberate click, because it is the one that makes
                      // docket spend money on its own.
                      onSave={(next) => save(repo.full_name, on, next)}
                    />
                  )}
                </div>
              );
            })}
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
