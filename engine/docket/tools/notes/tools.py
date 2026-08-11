"""The `notes` tool: an agent's durable scratchpad for findings-in-progress.

Persisted to run_dir/notes.json rather than kept in memory, for two reasons: notes
survive an agent that crashes mid-investigation, and the TUI/viewer can read them
live to show what an agent is currently thinking about.

Notes are shared across agents on purpose — a note from the sqli specialist ("login
returns 401 on failure, 200 'Welcome' on success") is exactly the kind of fact the
cmdi specialist would otherwise rediscover.
"""
from __future__ import annotations

import json
import time
import uuid
from pathlib import Path

NOTES_FILENAME = "notes.json"
MAX_NOTES_RETURNED = 50


def _path(run_dir: Path) -> Path:
    return run_dir / NOTES_FILENAME


def _load(run_dir: Path) -> list[dict]:
    path = _path(run_dir)
    if not path.exists():
        return []
    try:
        return json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return []


def _save(run_dir: Path, notes: list[dict]) -> None:
    run_dir.mkdir(parents=True, exist_ok=True)
    _path(run_dir).write_text(json.dumps(notes, indent=2))


def add_note(run_dir: Path, text: str, tags: list[str] | None = None, author: str = "agent") -> dict:
    notes = _load(run_dir)
    note = {
        "id": uuid.uuid4().hex[:8],
        "text": text,
        "tags": tags or [],
        "author": author,
        "created_at": time.time(),
    }
    notes.append(note)
    _save(run_dir, notes)
    return {"ok": True, "note": note, "total": len(notes)}


def view_notes(run_dir: Path, tag: str | None = None, limit: int = MAX_NOTES_RETURNED) -> dict:
    notes = _load(run_dir)
    if tag:
        notes = [n for n in notes if tag in n.get("tags", [])]
    return {"notes": notes[-limit:], "total": len(notes)}


def demo() -> None:
    import shutil
    import tempfile

    tmp = Path(tempfile.mkdtemp())
    try:
        assert view_notes(tmp) == {"notes": [], "total": 0}
        first = add_note(tmp, "login 401 on failure, 200 Welcome on success", ["login"], author="sqli")
        assert first["ok"] and first["total"] == 1
        add_note(tmp, "export is blind", ["export"], author="cmdi")
        assert view_notes(tmp)["total"] == 2
        # Cross-agent visibility is the point: a tag filter still sees another
        # agent's note.
        tagged = view_notes(tmp, tag="login")
        assert len(tagged["notes"]) == 1 and tagged["notes"][0]["author"] == "sqli"
        # Survives process restart (it's on disk, not in memory).
        assert len(_load(tmp)) == 2
        # Corrupt file degrades to empty rather than raising.
        _path(tmp).write_text("{not json")
        assert view_notes(tmp)["total"] == 0
    finally:
        shutil.rmtree(tmp)
    print("tools.notes: ok")


if __name__ == "__main__":
    demo()
