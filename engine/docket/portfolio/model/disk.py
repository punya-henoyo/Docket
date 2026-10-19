"""Guarded reads of the files the console derives everything from.

Every byte here is untrusted: run directories are written by scans (and by anyone with
write access to the working directory), and run names and application ids reach us from a
URL. So reads are size-capped, a run name is validated AND containment-checked after
resolving (the same two checks `load_run` in connect.py makes, because `[A-Za-z0-9._-]+`
alone admits ".."), hidden directories are skipped (`docket_runs/.docket` holds uploaded
control packs, not runs), and a file that does not parse is skipped rather than raised on:
one corrupt report must not blank the portfolio.

Parsed JSON is memoised by (path, mtime, size) so a page that asks for the same twelve
reports four times reads them once, and a rewritten report is re-read immediately. Nothing
outlives a file change, so the cache can never serve a stale answer.
"""
from __future__ import annotations

import json
import re
from collections import OrderedDict
from pathlib import Path
from typing import Any

from docket.core.paths import runs_root

MAX_REPORT_BYTES = 24 * 1024 * 1024
MAX_EVENTS_BYTES = 8 * 1024 * 1024
MAX_EVENTS = 20_000
MAX_CONFIG_BYTES = 1_000_000
MAX_RUNS = 5_000
PORTFOLIO_FILE = "docket_portfolio.json"

RUN_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,200}$")

_CACHE: OrderedDict[str, tuple[int, int, Any]] = OrderedDict()
_CACHE_MAX = 512


def valid_run_name(name: object) -> bool:
    """Shape check only; `run_dir_for` adds containment. No leading dot, so no "..", no
    ".docket"."""
    return isinstance(name, str) and bool(RUN_NAME.match(name)) and ".." not in name


def read_json(path: Path, max_bytes: int = MAX_REPORT_BYTES) -> Any | None:
    """Parsed JSON, or None if missing, too large, unreadable or not JSON."""
    try:
        stat = path.stat()
    except OSError:
        return None
    if stat.st_size > max_bytes or not path.is_file():
        return None
    key = str(path)
    hit = _CACHE.get(key)
    if hit and hit[0] == stat.st_mtime_ns and hit[1] == stat.st_size:
        _CACHE.move_to_end(key)
        return hit[2]
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    _CACHE[key] = (stat.st_mtime_ns, stat.st_size, data)
    while len(_CACHE) > _CACHE_MAX:
        _CACHE.popitem(last=False)
    return data


def run_dir_for(name: object, cwd: Path | None = None) -> Path | None:
    """The run directory for an untrusted name, or None. Resolved and contained."""
    if not valid_run_name(name):
        return None
    root = runs_root(cwd=cwd).resolve()
    directory = (root / str(name)).resolve()
    if root not in directory.parents or not directory.is_dir():
        return None
    return directory


def list_runs(cwd: Path | None = None) -> list[tuple[str, Path]]:
    """(name, dir) for every run directory that holds a report.json, name-sorted."""
    root = runs_root(cwd=cwd)
    try:
        children = sorted(root.iterdir())
    except OSError:
        return []
    out: list[tuple[str, Path]] = []
    for child in children:
        if not valid_run_name(child.name) or child.is_symlink() or not child.is_dir():
            continue
        if (child / "report.json").is_file():
            out.append((child.name, child))
        if len(out) >= MAX_RUNS:
            break
    return out


def read_report(directory: Path) -> dict[str, Any] | None:
    data = read_json(directory / "report.json")
    return data if isinstance(data, dict) else None


def read_events(directory: Path) -> list[dict[str, Any]]:
    """events.jsonl as dicts. Capped by bytes and lines; a torn last line (the file is
    append-only and may be tailed mid-write) and any non-object line are skipped."""
    path = directory / "events.jsonl"
    try:
        if not path.is_file() or path.stat().st_size > MAX_EVENTS_BYTES:
            return []
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    events: list[dict[str, Any]] = []
    for line in lines[:MAX_EVENTS]:
        try:
            item = json.loads(line)
        except ValueError:
            continue
        if isinstance(item, dict):
            events.append(item)
    return events


def read_portfolio(cwd: Path | None = None) -> dict[str, Any]:
    """docket_portfolio.json, or {} when absent or malformed."""
    data = read_json((cwd or Path.cwd()) / PORTFOLIO_FILE, MAX_CONFIG_BYTES)
    return data if isinstance(data, dict) else {}


def demo() -> None:
    import os
    import tempfile

    assert valid_run_name("connect-ab12") and valid_run_name("scan.1")
    for bad in ("", "..", ".docket", "../x", "a/b", "a b", ".hidden", "x" * 300, None, 5):
        assert not valid_run_name(bad), bad
    with tempfile.TemporaryDirectory() as tmp:
        cwd = Path(tmp)
        runs = cwd / "docket_runs"
        (runs / "good").mkdir(parents=True)
        (runs / "good" / "report.json").write_text('{"run_name": "good"}')
        (runs / "good" / "events.jsonl").write_text('{"type": "a"}\n{"type": "b"\n[1]\n{"type": "c"}\n')
        (runs / ".docket").mkdir()
        (runs / ".docket" / "report.json").write_text("{}")
        (runs / "torn").mkdir()
        (runs / "torn" / "report.json").write_text("{not json")
        (runs / "huge").mkdir()
        (runs / "huge" / "report.json").write_text('{"x": "' + "a" * 100 + '"}')
        assert [n for n, _ in list_runs(cwd)] == ["good", "huge", "torn"]
        good = run_dir_for("good", cwd)
        assert good is not None and read_report(good) == {"run_name": "good"}
        assert [e["type"] for e in read_events(good)] == ["a", "c"]
        assert read_report(runs / "torn") is None            # unparseable is skipped, not raised
        assert read_json(runs / "huge" / "report.json", max_bytes=10) is None   # size cap
        # Traversal and symlink escapes never resolve to a run directory.
        assert run_dir_for("..", cwd) is None and run_dir_for("../good", cwd) is None
        outside = cwd / "outside"
        outside.mkdir()
        os.symlink(outside, runs / "escape")
        assert run_dir_for("escape", cwd) is None
        assert "escape" not in [n for n, _ in list_runs(cwd)]
        # A rewritten report is re-read, not served from the memo.
        (runs / "good" / "report.json").write_text('{"run_name": "changed", "pad": 1}')
        assert read_report(good)["run_name"] == "changed"
        assert read_portfolio(cwd) == {}
        (cwd / PORTFOLIO_FILE).write_text('["not", "an object"]')
        assert read_portfolio(cwd) == {}
    print("portfolio.model.disk: ok")


if __name__ == "__main__":
    demo()
