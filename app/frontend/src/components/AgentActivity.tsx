import type { AgentRecord, ScanState } from "../types";

/** Live agent roster.
 *
 *  Shows what is ACTUALLY happening, which is a queue draining one agent at a time,
 *  not a swarm. docket runs `AgentCoordinator(max_agents=1)` for both recon and
 *  triage — triage deliberately so, because concurrent agents make the budget gate
 *  racy. A grid of six pulsing avatars would look better and would be a lie, and the
 *  first customer to compare it against the token log would stop trusting the rest of
 *  the console.
 *
 *  So the shape here is a timeline: finished agents above, the live one highlighted,
 *  the queue depth stated. That is honest and it still reads as agentic, because it
 *  is — each row is a separate model conversation with its own turns and its own bill.
 */

const ROLE_TONE: Record<string, string> = {
  triage: "var(--med)",
  recon: "var(--low)",
};

const OUTCOME: Record<string, { label: string; tone: string }> = {
  exploitable: { label: "reachable", tone: "var(--crit)" },
  not_reachable: { label: "ruled out", tone: "var(--ok)" },
  uncertain: { label: "uncertain", tone: "var(--med)" },
};

export function AgentActivity({
  scan,
  queued,
}: {
  scan: ScanState | null;
  /** Agents not yet started: triage_max minus those spawned. Queue depth is the
   *  difference between "a scan is running" and "43 more of these are coming". */
  queued: number;
}) {
  const agents: AgentRecord[] = scan?.agents ?? [];
  if (agents.length === 0 && queued <= 0) return null;

  const active = agents.filter((a) => a.status === "running");
  const done = agents.filter((a) => a.status !== "running");
  const perAgent = agents.reduce((sum, a) => sum + (a.cost_usd ?? 0), 0);
  const turns = agents.reduce((sum, a) => sum + (a.turns ?? 0), 0);
  // The ledger total is authoritative: it includes spend not attributable to a listed
  // agent row, so it can only ever be >= the sum of the rows.
  const spend = Math.max(scan?.cost_usd ?? 0, perAgent);
  const inTok = scan?.input_tokens ?? 0;
  const outTok = scan?.output_tokens ?? 0;
  const budget = scan?.budget_usd ?? 0;
  // Tokens but no dollars means LiteLLM could not price this model, so core/hooks.py
  // charged 0.0 — and the budget gate is therefore inert. Saying "$0.0000" with no
  // qualifier reads as "this run was free", which is the opposite of the truth: it is
  // unmetered. Set DOCKET_PRICE_INPUT_PER_1M / _OUTPUT_PER_1M to arm it.
  const unpriced = spend === 0 && inTok + outTok > 0;
  // Capped for the bar only; the number beside it stays true, so an overrun reads as
  // "full bar, $2.14 of $2.00" rather than being silently clipped.
  const pct = budget > 0 ? Math.min((spend / budget) * 100, 100) : 0;
  const tight = budget > 0 && spend / budget >= 0.8;

  // Newest first, but the running one always on top: it is the only row that changes.
  const ordered = [...active, ...done.reverse()];

  return (
    <div className="panel">
      <header>
        <span>Agents</span>
        <span className="note" style={{ fontSize: 12 }}>
          {agents.length} run · {active.length} active
          {queued > 0 && <> · {queued} queued</>}
        </span>
      </header>
      <div className="body">
        <div style={{ display: "flex", gap: 22, flexWrap: "wrap" }}>
          <Stat label="Model turns" value={turns} />
          <Stat
            label="Spend"
            value={`$${spend.toFixed(4)}`}
            sub={unpriced ? "model unpriced" : budget > 0 ? `of $${budget.toFixed(2)}` : undefined}
          />
          {/* Tokens, not only dollars. They are the one figure that is non-zero even on
              a model LiteLLM cannot price, and they lived only in the Triage panel — so a
              recon-only run showed no usage at all. */}
          <Stat
            label="Tokens"
            value={(inTok + outTok).toLocaleString()}
            sub={`${inTok.toLocaleString()} in · ${outTok.toLocaleString()} out`}
          />
          <Stat label="Concurrency" value="1" sub="sequential" />
        </div>

        {budget > 0 && (
          <div
            style={{ display: "flex", height: 6, borderRadius: 2, overflow: "hidden", background: "var(--wash)" }}
            title={`$${spend.toFixed(4)} of $${budget.toFixed(2)}`}
          >
            <span style={{ width: `${pct}%`, background: tight ? "var(--warn)" : "var(--ok)" }} />
          </div>
        )}

        {/* Queue depth as a bar: filled = finished, outlined = still to come. At 48
            findings this is the difference between "working" and "8% done". */}
        {queued > 0 && (
          <div style={{ display: "flex", gap: 2, flexWrap: "wrap" }}>
            {Array.from({ length: Math.min(agents.length + queued, 60) }, (_, i) => (
              <span
                key={i}
                style={{
                  width: 6, height: 14, borderRadius: 1,
                  background: i < done.length
                    ? "var(--ok)"
                    : i < agents.length ? "var(--med)" : "var(--line-2)",
                  opacity: i < agents.length ? 1 : 0.5,
                }}
              />
            ))}
          </div>
        )}

        <div style={{ display: "flex", flexDirection: "column", maxHeight: 320,
                      overflowY: "auto", margin: "0 -16px" }}>
          {ordered.slice(0, 40).map((a) => (
            <AgentRow key={a.id} agent={a} />
          ))}
        </div>

        <div className="note" style={{ fontSize: 12 }}>
          One agent at a time, each a separate conversation with its own history and
          its own bill. Turn counts differ because some findings settle in two reads
          and some do not settle at all.
        </div>
      </div>
    </div>
  );
}

function AgentRow({ agent }: { agent: AgentRecord }) {
  const running = agent.status === "running";
  const outcome = agent.outcome ? OUTCOME[agent.outcome] : undefined;
  const tone = ROLE_TONE[agent.role] ?? "var(--ink-3)";

  return (
    <div
      style={{
        display: "flex", alignItems: "center", gap: 10,
        padding: "9px 16px",
        borderTop: "1px solid var(--line)",
        background: running ? "var(--wash)" : undefined,
      }}
    >
      <span
        title={agent.status}
        style={{
          width: 7, height: 7, borderRadius: "50%", flex: "none",
          background: agent.status === "error" ? "var(--crit)"
            : running ? "var(--ok)" : "var(--line-2)",
          animation: running ? "pulse 1.2s ease-in-out infinite" : undefined,
        }}
      />
      <span style={{ font: "500 11.5px var(--sans)", color: tone, flex: "none",
                     minWidth: 46 }}>
        {agent.role}
      </span>

      <span style={{ minWidth: 0, flex: 1 }}>
        <span className="path" style={{ display: "block", fontSize: 12,
                                        overflow: "hidden", textOverflow: "ellipsis",
                                        whiteSpace: "nowrap" }}>
          {agent.label ?? agent.id}
        </span>
        {agent.detail && (
          <span className="note" style={{ fontSize: 11 }}>{agent.detail}</span>
        )}
      </span>

      {/* Turns as ticks. Reading the shape of a column tells you which findings were
          hard far faster than reading the numbers would. */}
      {agent.turns ? (
        <span title={`${agent.turns} model turn(s)`}
              style={{ display: "flex", gap: 2, flex: "none" }}>
          {Array.from({ length: Math.min(agent.turns, 12) }, (_, i) => (
            <span key={i} style={{ width: 3, height: 11, borderRadius: 1,
                                   background: running ? "var(--ok)" : "var(--line-2)" }} />
          ))}
          {agent.turns > 12 && (
            <span className="note" style={{ fontSize: 10.5 }}>+{agent.turns - 12}</span>
          )}
        </span>
      ) : null}

      {agent.cost_usd != null && agent.cost_usd > 0 && (
        <span className="num note" style={{ fontSize: 11.5, flex: "none", minWidth: 50,
                                            textAlign: "right" }}>
          ${agent.cost_usd.toFixed(4)}
        </span>
      )}

      <span style={{ flex: "none", minWidth: 70, textAlign: "right",
                     font: "500 11.5px var(--sans)",
                     color: outcome?.tone ?? "var(--ink-3)" }}>
        {running ? "reading…" : outcome?.label ?? agent.outcome ?? agent.status}
      </span>
    </div>
  );
}

function Stat({ label, value, sub }: { label: string; value: number | string; sub?: string }) {
  return (
    <div>
      <div className="eyebrow" style={{ fontSize: 11.5 }}>{label}</div>
      <div className="num" style={{ font: "600 19px var(--sans)", marginTop: 2 }}>
        {value}
        {sub && <span className="note" style={{ fontSize: 11.5, marginLeft: 6 }}>{sub}</span>}
      </div>
    </div>
  );
}
