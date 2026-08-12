"""Reading the target's source from inside the sandbox.

The sandbox shim already exposes a raw `read_file`, but nothing agent-facing wrapped
it, so an agent could run a scanner over source and never look at the code the scanner
was complaining about. These are the two tools a triage agent actually needs: read a
window around a line, and find where a symbol is used.

Everything is confined to the mounted source (`/work/source`, read-only — see
runtime/sandbox.py). The agent supplies these paths, so containment is checked here
rather than trusted: a scanner-reported path is attacker-influenced input the moment
the scanned repository is someone else's.
"""
from __future__ import annotations

import asyncio
import shlex
from typing import Any

from agents import RunContextWrapper, function_tool

from docket.core.execution import ScanContext

SOURCE_ROOT = "/work/source"
MAX_LINES = 400
MAX_MATCHES = 60
# Every listing stays in the conversation and is re-sent each turn. 400 paths in a
# 1254-file repo was a large slice of the 808k input tokens one failed run spent.
MAX_FILES = 200


# Reading budget, enforced by TELLING the agent, not by refusing.
#
# Measured across four live runs: recon read 26-40 files per run, hit its turn ceiling
# every single time, and ignored every prompt instruction about when to stop. The
# reason is mechanical — turn warnings go to logger.warning (core/hooks.py), which the
# operator sees and the model never does. A tool RESULT, by contrast, lands directly in
# the conversation the model reads.
#
# So the budget is reported here, where it cannot be missed. Refusing the read outright
# would be worse: an agent mid-way through mapping auth needs one more file, and a hard
# stop loses the map. It is told, escalating, and the salvage turn in core/execution.py
# remains the backstop for an agent that ignores even this.
SOFT_READ_BUDGET = 14
HARD_READ_BUDGET = 20


def _budget_note(reads: int) -> str | None:
    if reads >= HARD_READ_BUDGET:
        return (f"BUDGET SPENT — {reads} files read. Stop reading NOW and call your "
                "finish tool with what you have. Further reads risk ending the run "
                "with no result at all, losing everything above.")
    if reads >= SOFT_READ_BUDGET:
        return (f"{reads} files read of ~{HARD_READ_BUDGET} budgeted. Start closing: "
                "read only what you still need to finish, then call your finish tool.")
    return None


def _confine(path: str) -> str:
    """Absolute path under SOURCE_ROOT, or raise. Rejects traversal before it reaches
    the container rather than hoping the shim notices."""
    cleaned = path.strip().lstrip("/")
    if not cleaned or ".." in cleaned.split("/"):
        raise ValueError(f"path must stay inside the repository: {path!r}")
    return f"{SOURCE_ROOT}/{cleaned}"


def normalise_glob(path_glob: str) -> str:
    """Make a path-shaped glob work with grep's --include, which matches the FILENAME
    and not the path.

    "**/*.py" is the obvious thing to write and silently matches NOTHING — measured:
    grep returns 0 for `--include=**/*.py` where `--include=*.py` returns 3. A triage
    agent spent 3 of its 12 turns on exactly that, searching twice, getting empty
    results, then retrying without a filter. Rewriting it here costs one line; leaving
    it costs a quarter of every agent's budget that reaches for a path glob.
    """
    cleaned = path_glob.strip()
    while cleaned.startswith(("**/", "*/", "./", "/")):
        cleaned = cleaned.split("/", 1)[1]
    return cleaned or "*"


def _no_sandbox() -> dict:
    return {"ok": False, "error": "no sandbox — source is only readable inside the container."}


@function_tool
async def read_source(
    ctx: RunContextWrapper[ScanContext],
    path: str,
    start_line: int = 1,
    end_line: int = 0,
) -> dict:
    """Read a window of the scanned repository's source. `path` is repo-relative
    (e.g. "app/views.py"). Omit end_line for ~120 lines from start_line. Line numbers
    are 1-based and returned alongside each line so you can cite them exactly."""
    sandbox = ctx.context.sandbox
    if sandbox is None:
        return _no_sandbox()
    try:
        target = _confine(path)
    except ValueError as exc:
        return {"ok": False, "error": str(exc)}

    start = max(1, start_line)
    end = end_line if end_line and end_line >= start else start + 119
    end = min(end, start + MAX_LINES - 1)

    # sed rather than reading the whole file: a scanner points at one line in what may
    # be a 10k-line file, and pulling all of it would blow the context for no gain.
    command = f"sed -n '{start},{end}p' {shlex.quote(target)}"
    result = await asyncio.to_thread(sandbox.call, "shell", command=command, timeout_sec=15)
    if result.get("error"):
        return {"ok": False, "error": result["error"]}
    if result.get("exit_code") != 0:
        return {"ok": False, "error": (result.get("stderr") or "cannot read").strip()[:300]}

    body = result.get("stdout", "")
    numbered = [f"{start + i}\t{line}" for i, line in enumerate(body.splitlines())]
    ctx.context.reads += 1
    payload = {
        "ok": True,
        "path": path,
        "start_line": start,
        "end_line": start + max(0, len(numbered) - 1),
        "text": "\n".join(numbered),
        "truncated": bool(result.get("truncated")),
        "files_read": ctx.context.reads,
    }
    note = _budget_note(ctx.context.reads)
    if note:
        payload["budget"] = note
    return payload


@function_tool
async def list_source(
    ctx: RunContextWrapper[ScanContext],
    subdir: str = "",
    name_filter: str = "",
) -> dict:
    """List files in the scanned repository so you can see its shape before reading
    anything. `subdir` narrows to a directory; `name_filter` is a filename glob like
    "*.py". Start here: reading files at random in a repo you have not mapped wastes
    turns."""
    sandbox = ctx.context.sandbox
    if sandbox is None:
        return _no_sandbox()
    try:
        root = _confine(subdir) if subdir.strip() else SOURCE_ROOT
    except ValueError as exc:
        return {"ok": False, "error": str(exc)}

    name = f"-name {shlex.quote(normalise_glob(name_filter))} " if name_filter.strip() else ""
    # Prunes the same noise semgrep excludes, for the same reason: a listing dominated
    # by node_modules tells the agent nothing about the application.
    prune = " ".join(
        f"-path '*/{d}' -prune -o" for d in ("node_modules", ".git", "vendor", "dist", "build")
    )
    command = (
        f"find {shlex.quote(root)} {prune} -type f {name}-print 2>/dev/null "
        f"| head -{MAX_FILES}"
    )
    result = await asyncio.to_thread(sandbox.call, "shell", command=command, timeout_sec=30)
    if result.get("error"):
        return {"ok": False, "error": result["error"]}

    files = [
        line.replace(f"{SOURCE_ROOT}/", "", 1)
        for line in (result.get("stdout") or "").splitlines() if line.strip()
    ]
    return {
        "ok": True,
        "file_count": len(files),
        "capped": len(files) >= MAX_FILES,
        "files": files,
    }


@function_tool
async def search_source(
    ctx: RunContextWrapper[ScanContext],
    pattern: str,
    path_glob: str = "",
) -> dict:
    """Find where something appears in the scanned repository — a function name, a
    variable, a route. Use this to answer "can user input actually reach here?" rather
    than guessing from one line of context. Returns file:line:text, capped.

    `path_glob` filters by FILENAME, not path: use "*.py", not "**/*.py". Leave it
    empty to search everything, which is usually what you want."""
    sandbox = ctx.context.sandbox
    if sandbox is None:
        return _no_sandbox()
    if not pattern.strip():
        return {"ok": False, "error": "pattern must not be empty"}

    # -F: the agent is searching for identifiers, not writing regexes, and an
    # unescaped "(" from a function name would otherwise be a syntax error rather
    # than a search. shlex.quote keeps the whole thing out of shell interpretation.
    include = f"--include={shlex.quote(normalise_glob(path_glob))} " if path_glob.strip() else ""
    command = (
        f"grep -rnF --binary-files=without-match {include}"
        f"-- {shlex.quote(pattern)} {SOURCE_ROOT} 2>/dev/null | head -{MAX_MATCHES}"
    )
    result = await asyncio.to_thread(sandbox.call, "shell", command=command, timeout_sec=30)
    if result.get("error"):
        return {"ok": False, "error": result["error"]}

    matches = [
        line.replace(f"{SOURCE_ROOT}/", "", 1)
        for line in (result.get("stdout") or "").splitlines() if line.strip()
    ]
    return {
        "ok": True,
        "pattern": pattern,
        "match_count": len(matches),
        "capped": len(matches) >= MAX_MATCHES,
        "matches": matches,
    }


def demo() -> None:
    # Containment is the whole security surface here: these paths arrive from a model
    # reading a third party's scanner output.
    for bad in ("../../etc/passwd", "a/../../b", "..", "/../etc", "  ", ""):
        try:
            _confine(bad)
            raise AssertionError(f"should have refused {bad!r}")
        except ValueError:
            pass
    assert _confine("app/views.py") == "/work/source/app/views.py"
    assert _confine("/app/views.py") == "/work/source/app/views.py"
    # A leading dot is a real filename, not traversal.
    assert _confine(".github/workflows/ci.yml") == "/work/source/.github/workflows/ci.yml"

    # grep --include matches the filename; a path-shaped glob silently matches nothing.
    assert normalise_glob("**/*.py") == "*.py"
    assert normalise_glob("*/*.ts") == "*.ts"
    assert normalise_glob("./src/*.go") == "src/*.go"
    assert normalise_glob("*.py") == "*.py"      # already correct, left alone
    assert normalise_glob("") == "*"
    assert normalise_glob("**/") == "*"
    # ── read budget ─────────────────────────────────────────────────────────
    # Silent while there is room: a budget line on read 3 is noise the agent learns
    # to skip, which is exactly how it would learn to skip the one that matters.
    assert _budget_note(1) is None
    assert _budget_note(SOFT_READ_BUDGET - 1) is None

    soft = _budget_note(SOFT_READ_BUDGET)
    assert soft and "Start closing" in soft, soft
    hard = _budget_note(HARD_READ_BUDGET)
    assert hard and "Stop reading NOW" in hard, hard
    # The hard note must say what is LOST by continuing. "You are over budget" is
    # ignorable; "the run ends with no result at all" is the thing that actually
    # happened on a real repository before the salvage turn existed.
    assert "no result at all" in hard
    assert _budget_note(HARD_READ_BUDGET + 30).startswith("BUDGET SPENT")

    print("tools.source: ok")


if __name__ == "__main__":
    demo()
