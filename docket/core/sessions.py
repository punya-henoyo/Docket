"""SDK session helpers. Mirrors docket/core/sessions.py.

Each agent gets its own SQLite-backed conversation history, so history lives on disk
rather than in a Python list that dies with the process — which is what makes a run
inspectable after the fact and resumable in principle.

Also holds scrub_images_from_items: some providers reject image content parts that
others accept, and a rejected image poisons every subsequent turn because it stays in
history. Stripping images and retrying is the recovery path (see core/execution.py).
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from agents.memory import SQLiteSession

from docket.core.paths import runtime_state_dir

logger = logging.getLogger(__name__)

SESSIONS_DB_NAME = "sessions.db"

_IMAGE_KEYS = ("image_url", "image", "input_image", "b64_json", "image_data")


def session_db_path(run_dir: Path) -> Path:
    state_dir = runtime_state_dir(run_dir)
    state_dir.mkdir(parents=True, exist_ok=True)
    return state_dir / SESSIONS_DB_NAME


def make_session(run_dir: Path, agent_id: str) -> SQLiteSession:
    """One session row-space per agent, all inside a single per-run DB file."""
    return SQLiteSession(session_id=agent_id, db_path=session_db_path(run_dir))


def _strip_images_from_content(content: Any) -> tuple[Any, bool]:
    if not isinstance(content, list):
        return content, False
    kept, removed = [], False
    for part in content:
        if isinstance(part, dict) and (
            part.get("type") in {"input_image", "image_url", "image"}
            or any(k in part for k in _IMAGE_KEYS)
        ):
            removed = True
            kept.append({"type": "input_text", "text": "[image removed]"})
            continue
        kept.append(part)
    return kept, removed


def scrub_images_from_items(items: list[Any]) -> tuple[list[Any], int]:
    """Return (items_without_images, count_removed). Non-destructive: the caller
    decides whether to use the scrubbed copy."""
    scrubbed: list[Any] = []
    removed_total = 0
    for item in items:
        if isinstance(item, dict) and "content" in item:
            content, removed = _strip_images_from_content(item["content"])
            if removed:
                removed_total += 1
                item = {**item, "content": content}
        scrubbed.append(item)
    return scrubbed, removed_total


def demo() -> None:
    import asyncio
    import shutil
    import tempfile

    tmp = Path(tempfile.mkdtemp())
    try:
        session = make_session(tmp, "agent-1")
        assert session_db_path(tmp).parent.name == ".state"

        async def _roundtrip() -> list[Any]:
            await session.add_items([{"role": "user", "content": "hello"}])
            return await session.get_items()

        items = asyncio.run(_roundtrip())
        assert items and items[0]["content"] == "hello", items
        assert session_db_path(tmp).exists()

        with_image = [
            {"role": "user", "content": [
                {"type": "input_text", "text": "look"},
                {"type": "input_image", "image_url": "data:image/png;base64,AAAA"},
            ]},
            {"role": "assistant", "content": "plain string is untouched"},
        ]
        scrubbed, removed = scrub_images_from_items(with_image)
        assert removed == 1, removed
        assert scrubbed[0]["content"][1]["text"] == "[image removed]"
        assert scrubbed[1]["content"] == "plain string is untouched"
        assert with_image[0]["content"][1]["type"] == "input_image"  # original intact
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print("core.sessions: ok")


if __name__ == "__main__":
    demo()
