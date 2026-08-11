"""Assembles a run's on-disk artifacts into the JSON the dashboard renders.

Everything is read straight off disk — report.json, events.jsonl, notes, todos. There
is no upload and no account: `docket view --web` shows YOUR run from YOUR filesystem,
which is the whole point of a local viewer for a security tool.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from docket.interface.tui.backend.projection import project
from docket.interface.tui.backend.protocol import read_events
from docket.tools.notes.tools import view_notes
from docket.tools.todo.tools import all_todos


def _load_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return default


def build_payload(run_dir: Path) -> dict:
    run_dir = Path(run_dir)
    report = _load_json(run_dir / "report.json", {})
    events, _ = read_events(run_dir)
    view = project(events)

    agents = [
        {
            "agent_id": a.agent_id, "name": a.name, "role": a.role, "status": a.status,
            "parent_id": a.parent_id, "tool_calls": a.tool_calls,
            "findings": a.findings, "summary": a.summary, "depth": depth,
        }
        for depth, a in view.tree()
    ]
    # Prefer the report's findings (validated, deduped, with full PoC); fall back to
    # the event stream while a scan is still running and no report exists yet.
    findings = report.get("findings") or view.findings
    return {
        "run_name": report.get("run_name") or view.run_name or run_dir.name,
        "target": report.get("target") or view.target,
        "generated_at": report.get("generated_at"),
        "finished": view.finished or bool(report),
        "summary": report.get("summary") or view.summary,
        "severity_counts": report.get("severity_counts") or view.severity_counts(),
        "finding_count": report.get("finding_count", len(findings)),
        "cost_usd": report.get("cost_usd", view.cost_usd),
        "usage": report.get("usage", {}),
        "agents": agents,
        "findings": findings,
        "transcript": view.transcript[-500:],
        "notes": view_notes(run_dir).get("notes", []),
        "todos": all_todos(run_dir),
        "has_sarif": (run_dir / "report.sarif").exists(),
    }


def demo() -> None:
    import shutil
    import tempfile

    from docket.interface.tui.backend.protocol import Event, append_event

    tmp = Path(tempfile.mkdtemp())
    try:
        # A live run with no report.json yet still renders from events alone.
        append_event(tmp, Event(type="scan_started", data={"target": "http://x", "run_name": "r"}))
        append_event(tmp, Event(type="agent_spawned", agent_id="a1", role="sqli",
                                 data={"name": "sqli-login", "parent_id": "root"}))
        append_event(tmp, Event(type="finding", agent_id="a1", role="sqli", data={
            "severity": "high", "rule_type": "sqli",
            "location": {"method": "POST", "path": "/login", "parameter": "username"}}))
        live = build_payload(tmp)
        assert live["target"] == "http://x" and live["finding_count"] == 1
        assert [a["agent_id"] for a in live["agents"]][0] == "root"
        assert live["has_sarif"] is False

        # Once a report exists it wins, because it is the validated, deduped view.
        (tmp / "report.json").write_text(json.dumps({
            "run_name": "r", "target": "http://x", "finding_count": 2,
            "severity_counts": {"high": 1, "critical": 1}, "cost_usd": 0.5,
            "findings": [{"rule_id": "sql-injection"}, {"rule_id": "command-injection"}],
        }))
        (tmp / "report.sarif").write_text("{}")
        final = build_payload(tmp)
        assert final["finding_count"] == 2 and final["cost_usd"] == 0.5
        assert final["severity_counts"] == {"high": 1, "critical": 1}
        assert final["has_sarif"] is True
        # A corrupt report degrades to the event view rather than raising.
        (tmp / "report.json").write_text("{not json")
        assert build_payload(tmp)["finding_count"] == 1
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print("viewer.transcript: ok")


if __name__ == "__main__":
    demo()
