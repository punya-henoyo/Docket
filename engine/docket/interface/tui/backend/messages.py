"""Event emission from a running scan.

The emitter is a thin, always-safe writer: a scan must never fail because a UI is
watching it, so every call is wrapped and any error is swallowed at the protocol layer.

Emission points are deliberately few — spawn, status, tool call/result, finding — so
adding a UI never means threading a display object through the agent loop.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from docket.interface.tui.backend.protocol import Event, append_event
from docket.interface.utils import truncate


class EventEmitter:
    def __init__(self, run_dir: Path | None) -> None:
        self.run_dir = Path(run_dir) if run_dir else None

    @property
    def enabled(self) -> bool:
        return self.run_dir is not None

    def emit(self, type_: str, *, agent_id: str = "root", role: str = "root", **data: Any) -> None:
        if self.run_dir is None:
            return
        append_event(self.run_dir, Event(type=type_, agent_id=agent_id, role=role, data=data))

    # -- convenience wrappers, one per emission point -----------------------------

    def scan_started(self, target: str, run_name: str) -> None:
        self.emit("scan_started", target=target, run_name=run_name)

    def scan_finished(self, success: bool, summary: str) -> None:
        self.emit("scan_finished", success=success, summary=summary)

    def agent_spawned(self, agent_id: str, name: str, role: str, parent_id: str) -> None:
        self.emit("agent_spawned", agent_id=agent_id, role=role, name=name, parent_id=parent_id)

    def agent_finished(self, agent_id: str, role: str, status: str, summary: str = "") -> None:
        self.emit("agent_finished", agent_id=agent_id, role=role, status=status, summary=summary)

    def tool_call(self, agent_id: str, role: str, tool: str, args: dict) -> None:
        # Args are truncated at the boundary: a full sqlmap invocation or an HTML body
        # would bloat the event log and the UI without adding information.
        self.emit("tool_call", agent_id=agent_id, role=role, tool=tool,
                  args={k: truncate(str(v), 200) for k, v in (args or {}).items()})

    def tool_result(self, agent_id: str, role: str, tool: str, output: Any) -> None:
        self.emit("tool_result", agent_id=agent_id, role=role, tool=tool,
                  output=truncate(str(output), 600))

    def finding(self, agent_id: str, role: str, **finding: Any) -> None:
        self.emit("finding", agent_id=agent_id, role=role, **finding)

    def usage(self, cost_usd: float, total_tokens: int) -> None:
        self.emit("usage", cost_usd=cost_usd, total_tokens=total_tokens)


_emitter = EventEmitter(None)


def get_emitter() -> EventEmitter:
    return _emitter


def set_emitter(run_dir: Path | None) -> EventEmitter:
    global _emitter
    _emitter = EventEmitter(run_dir)
    return _emitter


def demo() -> None:
    import shutil
    import tempfile

    from docket.interface.tui.backend.protocol import read_events

    # Disabled by default: no run dir means every call is a silent no-op.
    assert get_emitter().enabled is False
    get_emitter().scan_started("http://x", "r")   # must not raise

    tmp = Path(tempfile.mkdtemp())
    try:
        emitter = set_emitter(tmp)
        assert emitter.enabled
        emitter.scan_started("http://x", "r")
        emitter.agent_spawned("a1", "sqli-login", "sqli", "root")
        emitter.tool_call("a1", "sqli", "shell", {"command": "x" * 500})
        emitter.tool_result("a1", "sqli", "shell", "y" * 2000)
        emitter.finding("a1", "sqli", rule_id="sql-injection", severity="high")
        emitter.scan_finished(True, "done")

        events, _ = read_events(tmp)
        assert [e.type for e in events] == [
            "scan_started", "agent_spawned", "tool_call", "tool_result",
            "finding", "scan_finished",
        ], [e.type for e in events]
        # Truncation happens at the boundary, so the log can't be flooded.
        assert len(events[2].data["args"]["command"]) <= 200
        assert len(events[3].data["output"]) <= 600
    finally:
        set_emitter(None)
        shutil.rmtree(tmp, ignore_errors=True)
    print("tui.backend.messages: ok")


if __name__ == "__main__":
    demo()
