"""The `todo` tool: an agent's own task list for a multi-step investigation.

Same persistence rationale as notes (run_dir/todos.json): survives a crash and is
readable live by the TUI/viewer, which is what makes "what is this agent doing right
now" answerable at a glance.

Scoped PER AGENT, unlike notes: a todo is one agent's plan, and merging three
specialists' checklists into one list would make each of them unreadable.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Literal

TODOS_FILENAME = "todos.json"
Status = Literal["pending", "in_progress", "done"]
_VALID: set[str] = {"pending", "in_progress", "done"}


def _path(run_dir: Path) -> Path:
    return run_dir / TODOS_FILENAME


def _load_all(run_dir: Path) -> dict[str, list[dict]]:
    path = _path(run_dir)
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return {}


def _save_all(run_dir: Path, data: dict[str, list[dict]]) -> None:
    run_dir.mkdir(parents=True, exist_ok=True)
    _path(run_dir).write_text(json.dumps(data, indent=2))


def set_todos(run_dir: Path, items: list[dict], agent_id: str = "root") -> dict:
    """Replace this agent's list. Whole-list replacement rather than per-item edits:
    the model already has the full list in context, so one call keeps it consistent
    instead of drifting through partial updates."""
    normalized = []
    for index, item in enumerate(items):
        status = str(item.get("status", "pending"))
        normalized.append({
            "id": str(item.get("id") or index + 1),
            "text": str(item.get("text", "")).strip(),
            "status": status if status in _VALID else "pending",
        })
    data = _load_all(run_dir)
    data[agent_id] = normalized
    _save_all(run_dir, data)
    return view_todos(run_dir, agent_id)


def view_todos(run_dir: Path, agent_id: str = "root") -> dict:
    todos = _load_all(run_dir).get(agent_id, [])
    counts = {status: sum(1 for t in todos if t["status"] == status) for status in _VALID}
    return {"todos": todos, "counts": counts, "agent_id": agent_id}


def all_todos(run_dir: Path) -> dict[str, list[dict]]:
    """Every agent's list — used by the TUI/viewer, not exposed to agents."""
    return _load_all(run_dir)


def demo() -> None:
    import shutil
    import tempfile

    tmp = Path(tempfile.mkdtemp())
    try:
        assert view_todos(tmp)["todos"] == []
        result = set_todos(tmp, [
            {"text": "probe /login", "status": "done"},
            {"text": "run sqlmap", "status": "in_progress"},
            {"text": "file finding"},                      # defaults to pending
            {"text": "bogus", "status": "not-a-status"},    # invalid falls back
        ], agent_id="a1")
        assert result["counts"] == {"done": 1, "in_progress": 1, "pending": 2}, result["counts"]
        assert result["todos"][0]["id"] == "1"

        # Per-agent scoping: one agent's list never bleeds into another's.
        set_todos(tmp, [{"text": "browser xss"}], agent_id="a2")
        assert len(view_todos(tmp, "a1")["todos"]) == 4
        assert len(view_todos(tmp, "a2")["todos"]) == 1
        assert set(all_todos(tmp)) == {"a1", "a2"}

        # Replacement semantics, not append.
        set_todos(tmp, [{"text": "only one now"}], agent_id="a1")
        assert len(view_todos(tmp, "a1")["todos"]) == 1
    finally:
        shutil.rmtree(tmp)
    print("tools.todo: ok")


if __name__ == "__main__":
    demo()
