"""Event protocol shared by the TUI and the web viewer. Mirrors
docket/interface/tui/backend/protocol.py (and its Go twin, internal/protocol).

One event vocabulary, serialised as JSON lines, is what lets a live TUI and an
after-the-fact web dashboard render the same run without either one reaching into
agent internals. Events are appended to <run>/events.jsonl, so "watch it live" and
"open it a week later" are the same code path reading the same file.
"""
from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Literal

EVENTS_FILENAME = "events.jsonl"

EventType = Literal[
    "scan_started", "scan_finished",
    "agent_spawned", "agent_status", "agent_finished",
    "tool_call", "tool_result",
    "finding", "note", "message", "usage",
]


@dataclass(slots=True)
class Event:
    type: EventType
    ts: float = field(default_factory=time.time)
    agent_id: str = "root"
    role: str = "root"
    data: dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

    @staticmethod
    def from_dict(raw: dict) -> "Event":
        return Event(
            type=raw.get("type", "message"),
            ts=float(raw.get("ts", 0.0)),
            agent_id=raw.get("agent_id", "root"),
            role=raw.get("role", "root"),
            data=raw.get("data") or {},
        )


def events_path(run_dir: Path) -> Path:
    return run_dir / EVENTS_FILENAME


def append_event(run_dir: Path, event: Event) -> None:
    """Append-only, one JSON object per line. Append-only matters: a reader can tail
    the file while a scan is still writing it, with no locking and no partial-state
    reads beyond the final (possibly incomplete) line."""
    try:
        run_dir.mkdir(parents=True, exist_ok=True)
        with events_path(run_dir).open("a") as handle:
            handle.write(event.to_json() + "\n")
    except OSError:
        # Telemetry must never take down a scan.
        pass


def read_events(run_dir: Path, offset: int = 0) -> tuple[list[Event], int]:
    """Read events from line `offset` onward. Returns (events, next_offset) so a
    caller can poll for just what's new."""
    path = events_path(run_dir)
    if not path.exists():
        return [], offset
    lines = path.read_text().splitlines()
    events = []
    for line in lines[offset:]:
        if not line.strip():
            continue
        try:
            events.append(Event.from_dict(json.loads(line)))
        except json.JSONDecodeError:
            continue  # a half-written final line while the scan is still running
    return events, len(lines)


def demo() -> None:
    import shutil
    import tempfile

    tmp = Path(tempfile.mkdtemp())
    try:
        assert read_events(tmp) == ([], 0)
        append_event(tmp, Event(type="scan_started", data={"target": "http://x"}))
        append_event(tmp, Event(type="agent_spawned", agent_id="a1", role="sqli",
                                 data={"name": "sqli-login"}))
        events, offset = read_events(tmp)
        assert [e.type for e in events] == ["scan_started", "agent_spawned"], events
        assert events[1].role == "sqli" and events[1].data["name"] == "sqli-login"
        assert offset == 2

        # Incremental read: only what's new since the last offset.
        append_event(tmp, Event(type="finding", agent_id="a1", data={"rule_id": "sql-injection"}))
        fresh, offset2 = read_events(tmp, offset)
        assert len(fresh) == 1 and fresh[0].type == "finding"
        assert offset2 == 3

        # A partially-written trailing line is skipped, not fatal.
        with events_path(tmp).open("a") as handle:
            handle.write('{"type": "tool_call"')
        recovered, _ = read_events(tmp)
        assert len(recovered) == 3, recovered
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print("tui.backend.protocol: ok")


if __name__ == "__main__":
    demo()
