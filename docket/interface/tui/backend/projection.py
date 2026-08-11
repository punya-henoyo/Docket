"""Folds the event stream into renderable state. Mirrors
docket/interface/tui/backend/projection.py.

A pure reduce over events: (state, event) -> state, with no I/O and no framework
imports. That is deliberate — it means the TUI, the web viewer, and the tests all
derive their view from the same function, and the interesting logic (what counts as
"running", how findings dedupe on screen) is testable without spinning up a UI.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from docket.interface.tui.backend.protocol import Event

TERMINAL = {"completed", "failed", "crashed", "stopped"}


@dataclass
class AgentView:
    agent_id: str
    name: str = ""
    role: str = ""
    status: str = "pending"
    parent_id: str | None = None
    tool_calls: int = 0
    findings: int = 0
    last_tool: str = ""
    summary: str = ""

    @property
    def is_active(self) -> bool:
        return self.status not in TERMINAL


@dataclass
class ScanView:
    target: str = ""
    run_name: str = ""
    started_at: float = 0.0
    finished_at: float | None = None
    agents: dict[str, AgentView] = field(default_factory=dict)
    findings: list[dict] = field(default_factory=list)
    transcript: list[dict] = field(default_factory=list)
    notes: list[dict] = field(default_factory=list)
    messages: list[dict] = field(default_factory=list)
    cost_usd: float = 0.0
    tokens: int = 0
    summary: str = ""

    @property
    def active_agents(self) -> list[AgentView]:
        return [a for a in self.agents.values() if a.is_active]

    @property
    def finished(self) -> bool:
        return self.finished_at is not None

    def severity_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for finding in self.findings:
            severity = finding.get("severity", "info")
            counts[severity] = counts.get(severity, 0) + 1
        return counts

    def tree(self) -> list[tuple[int, AgentView]]:
        """(depth, agent) in parent-before-child order, for rendering the agent graph."""
        children: dict[str | None, list[AgentView]] = {}
        for agent in self.agents.values():
            children.setdefault(agent.parent_id, []).append(agent)

        ordered: list[tuple[int, AgentView]] = []

        def walk(parent: str | None, depth: int) -> None:
            for agent in sorted(children.get(parent, []), key=lambda a: a.agent_id):
                ordered.append((depth, agent))
                walk(agent.agent_id, depth + 1)

        walk(None, 0)
        # Any agent whose parent was never announced still has to appear, or the view
        # would silently drop a running agent.
        seen = {a.agent_id for _, a in ordered}
        ordered.extend((0, a) for a in self.agents.values() if a.agent_id not in seen)
        return ordered


def _agent(view: ScanView, event: Event) -> AgentView:
    agent = view.agents.get(event.agent_id)
    if agent is None:
        agent = AgentView(agent_id=event.agent_id, name=event.agent_id, role=event.role)
        view.agents[event.agent_id] = agent
    return agent


def apply_event(view: ScanView, event: Event) -> ScanView:
    data = event.data
    if event.type == "scan_started":
        view.target = data.get("target", "")
        view.run_name = data.get("run_name", "")
        view.started_at = event.ts
        root = _agent(view, event)
        root.status, root.name, root.parent_id = "running", data.get("root_name", "root"), None
    elif event.type == "scan_finished":
        view.finished_at = event.ts
        view.summary = data.get("summary", "")
        root = _agent(view, event)
        root.status = "completed" if data.get("success") else "failed"
    elif event.type == "agent_spawned":
        agent = _agent(view, event)
        agent.name = data.get("name", event.agent_id)
        agent.role = event.role
        agent.parent_id = data.get("parent_id", "root")
        agent.status = "running"
    elif event.type in {"agent_status", "agent_finished"}:
        agent = _agent(view, event)
        agent.status = data.get("status", agent.status)
        agent.summary = data.get("summary", agent.summary)
    elif event.type == "tool_call":
        agent = _agent(view, event)
        agent.tool_calls += 1
        agent.last_tool = data.get("tool", "")
        view.transcript.append({"ts": event.ts, "agent_id": event.agent_id,
                                 "role": event.role, "kind": "call",
                                 "tool": data.get("tool", ""), "args": data.get("args", {})})
    elif event.type == "tool_result":
        view.transcript.append({"ts": event.ts, "agent_id": event.agent_id,
                                 "role": event.role, "kind": "result",
                                 "tool": data.get("tool", ""), "output": data.get("output", "")})
    elif event.type == "finding":
        agent = _agent(view, event)
        agent.findings += 1
        # Dedupe on screen the same way the report does, so a corroborated finding
        # doesn't appear twice in the UI.
        key = data.get("dedupe_key") or data.get("finding_id")
        if not any((f.get("dedupe_key") or f.get("finding_id")) == key for f in view.findings):
            view.findings.append(dict(data))
    elif event.type == "note":
        view.notes.append({"ts": event.ts, "agent_id": event.agent_id, **data})
    elif event.type == "message":
        view.messages.append({"ts": event.ts, "agent_id": event.agent_id, **data})
    elif event.type == "usage":
        view.cost_usd = float(data.get("cost_usd", view.cost_usd))
        view.tokens = int(data.get("total_tokens", view.tokens))
    return view


def project(events: list[Event], view: ScanView | None = None) -> ScanView:
    result = view or ScanView()
    for event in events:
        apply_event(result, event)
    return result


def demo() -> None:
    events = [
        Event(type="scan_started", ts=1.0, data={"target": "http://x", "run_name": "r"}),
        Event(type="agent_spawned", ts=2.0, agent_id="a1", role="sqli",
              data={"name": "sqli-login", "parent_id": "root"}),
        Event(type="agent_spawned", ts=2.1, agent_id="a2", role="xss",
              data={"name": "xss-search", "parent_id": "root"}),
        Event(type="tool_call", ts=3.0, agent_id="a1", role="sqli",
              data={"tool": "shell", "args": {"command": "sqlmap"}}),
        Event(type="tool_result", ts=4.0, agent_id="a1", role="sqli",
              data={"tool": "shell", "output": "injectable"}),
        Event(type="finding", ts=5.0, agent_id="a1", role="sqli",
              data={"rule_id": "sql-injection", "severity": "high", "dedupe_key": "k1"}),
        Event(type="finding", ts=5.5, agent_id="a1", role="sqli",
              data={"rule_id": "sql-injection", "severity": "high", "dedupe_key": "k1"}),
        Event(type="agent_finished", ts=6.0, agent_id="a1", data={"status": "completed"}),
        Event(type="usage", ts=6.5, data={"cost_usd": 0.12, "total_tokens": 9000}),
    ]
    view = project(events)

    assert view.target == "http://x" and view.run_name == "r"
    assert set(view.agents) == {"root", "a1", "a2"}
    assert view.agents["a1"].tool_calls == 1 and view.agents["a1"].last_tool == "shell"
    # Duplicate finding collapses on screen, but still counts toward the agent's total.
    assert len(view.findings) == 1, view.findings
    assert view.agents["a1"].findings == 2
    assert view.severity_counts() == {"high": 1}
    assert len(view.transcript) == 2
    assert view.cost_usd == 0.12 and view.tokens == 9000

    # a1 finished; root and a2 are still running (root stays active until the scan
    # itself finishes, which is correct — it's still coordinating).
    assert {a.agent_id for a in view.active_agents} == {"root", "a2"}, view.active_agents
    assert view.agents["a1"].is_active is False
    assert not view.finished

    depths = {a.agent_id: d for d, a in view.tree()}
    assert depths["root"] == 0 and depths["a1"] == 1 and depths["a2"] == 1, depths

    # An agent whose parent was never announced must still be shown, not dropped.
    orphan = project([Event(type="agent_status", agent_id="zz", data={"status": "running"})])
    assert any(a.agent_id == "zz" for _, a in orphan.tree())

    final = project([Event(type="scan_finished", ts=9.0, data={"success": True, "summary": "done"})])
    assert final.finished and final.summary == "done"
    assert final.agents["root"].status == "completed"
    print("tui.backend.projection: ok")


if __name__ == "__main__":
    demo()
