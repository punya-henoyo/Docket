import type { AgentNode } from "../types";

export function AgentTree({ agents }: { agents: AgentNode[] }) {
  if (agents.length === 0) return <div className="empty">No agents yet.</div>;
  return (
    <ul className="tree">
      {agents.map((agent) => (
        <li key={agent.agent_id} style={{ paddingLeft: `${agent.depth * 18}px` }}>
          <span className={`dot ${agent.status}`} aria-hidden="true" />
          <span className="who">{agent.name || agent.agent_id}</span>
          {agent.role && <span className="role">{agent.role}</span>}
          {/* Status as text too: the dot alone is colour-only meaning. */}
          <span className="role">{agent.status}</span>
          <span className="nums">
            {agent.tool_calls} calls · {agent.findings} found
          </span>
        </li>
      ))}
    </ul>
  );
}
