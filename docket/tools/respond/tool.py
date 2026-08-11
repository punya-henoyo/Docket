"""The `respond` tool: send a message to the human operator mid-run.

Only meaningful in interactive mode (docket/interface/interactive.py). In
non-interactive/CI runs there is nobody watching, so the message is recorded to the
run directory rather than dropped — it still shows up in the transcript and viewer.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

RESPONSES_FILENAME = "responses.jsonl"


def respond(run_dir: Path, message: str, agent_id: str = "root") -> dict:
    run_dir.mkdir(parents=True, exist_ok=True)
    record = {"ts": time.time(), "agent_id": agent_id, "message": message}
    with (run_dir / RESPONSES_FILENAME).open("a") as handle:
        handle.write(json.dumps(record) + "\n")
    return {"ok": True, "delivered": True}


def read_responses(run_dir: Path) -> list[dict]:
    path = run_dir / RESPONSES_FILENAME
    if not path.exists():
        return []
    out = []
    for line in path.read_text().splitlines():
        if line.strip():
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return out


def demo() -> None:
    import shutil
    import tempfile

    tmp = Path(tempfile.mkdtemp())
    try:
        assert read_responses(tmp) == []
        assert respond(tmp, "found something odd on /export", agent_id="cmdi")["ok"]
        respond(tmp, "second message")
        messages = read_responses(tmp)
        assert len(messages) == 2, messages
        assert messages[0]["agent_id"] == "cmdi"
        assert messages[1]["message"] == "second message"
    finally:
        shutil.rmtree(tmp)
    print("tools.respond: ok")


if __name__ == "__main__":
    demo()
