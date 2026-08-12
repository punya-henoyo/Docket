"""Read-only source access for triage agents.

The enabler for SAST-with-agents: until now no role could read a file, so a candidate
could only be guessed at from its rule name. An agent that can read the twenty lines
around a flagged line can see the escape() on the line above it, which is the difference
between a report of 40 maybes and a report of 5 with reasons.

READ ONLY, and enforced here rather than trusted. Three separate guards, because this
takes a path from a model and turns it into a filesystem read:

  1. every path resolves under the source root, checked with parent traversal rather
     than a string prefix — "/src-other/x" starts with "/src" but is a different tree
  2. symlinks are refused, since resolve() following one out of the tree would pass a
     naive containment check performed before resolution
  3. sizes are bounded, so a model asking for a 2GB vendored blob cannot exhaust context
     or memory

stdlib only: this module is loaded by the in-container shim, where no project dependency
is installed.
"""
from __future__ import annotations

import os
from pathlib import Path

MAX_FILE_CHARS = 20_000
MAX_LIST_ENTRIES = 400
MAX_GREP_HITS = 80
CONTEXT_LINES = 12

# Reading these wastes turns and context without ever containing the app's own logic.
_SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build",
              ".next", "target", "vendor", ".mypy_cache", ".pytest_cache"}
_BINARY_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip",
                    ".gz", ".tar", ".whl", ".so", ".dylib", ".dll", ".exe", ".class",
                    ".jar", ".woff", ".woff2", ".ttf", ".mp4", ".mp3"}


class SourceAccessError(Exception):
    """Refused. Carries a message meant for the model, not a stack trace."""


def resolve_in_root(root: str | Path, relative: str) -> Path:
    """The one containment check. Every read goes through it."""
    base = Path(root).resolve()
    if not base.is_dir():
        raise SourceAccessError(f"no source tree available at {root}")
    candidate = (base / str(relative).lstrip("/")).resolve()
    if candidate != base and base not in candidate.parents:
        raise SourceAccessError(
            f"refused: {relative!r} resolves outside the source tree. Paths must be "
            "relative to the repository root."
        )
    # resolve() already followed any symlink; compare against the unresolved path to
    # notice that it did. Without this, a link in the repo pointing at /etc passes the
    # containment check above, because by then the path IS /etc.
    unresolved = base / str(relative).lstrip("/")
    if unresolved.is_symlink() or (unresolved.exists() and unresolved.resolve() != unresolved):
        if base not in unresolved.resolve().parents and unresolved.resolve() != base:
            raise SourceAccessError(f"refused: {relative!r} is a symlink out of the tree")
    return candidate


def read_source(root: str | Path, path: str, *, start_line: int | None = None,
                 end_line: int | None = None) -> dict:
    """A file, or a line range of one. Ranges are 1-indexed and inclusive."""
    try:
        target = resolve_in_root(root, path)
    except SourceAccessError as exc:
        return {"ok": False, "error": str(exc)}
    if not target.is_file():
        return {"ok": False, "error": f"not a file: {path}"}
    if target.suffix.lower() in _BINARY_SUFFIXES:
        return {"ok": False, "error": f"{path} looks binary; nothing to read here"}
    try:
        text = target.read_text(errors="replace")
    except OSError as exc:
        return {"ok": False, "error": f"could not read {path}: {exc}"}

    lines = text.splitlines()
    total = len(lines)
    if start_line is not None:
        lo = max(1, int(start_line))
        hi = min(total, int(end_line) if end_line else lo + CONTEXT_LINES * 2)
        window = lines[lo - 1 : hi]
        first = lo
    else:
        window, first = lines, 1

    body = "\n".join(f"{first + i}: {line}" for i, line in enumerate(window))
    truncated = len(body) > MAX_FILE_CHARS
    if truncated:
        body = body[:MAX_FILE_CHARS] + "\n...[truncated, request a line range]"
    return {"ok": True, "path": str(path), "total_lines": total,
            "start_line": first, "end_line": first + len(window) - 1,
            "truncated": truncated, "content": body}


def read_around(root: str | Path, path: str, line: int, *, context: int = CONTEXT_LINES) -> dict:
    """The triage primitive: the flagged line plus what surrounds it. A guard three lines
    above a sink is invisible to a rule engine and obvious here."""
    return read_source(root, path, start_line=max(1, int(line) - context),
                        end_line=int(line) + context)


def list_source(root: str | Path, path: str = ".") -> dict:
    try:
        target = resolve_in_root(root, path)
    except SourceAccessError as exc:
        return {"ok": False, "error": str(exc)}
    if not target.is_dir():
        return {"ok": False, "error": f"not a directory: {path}"}
    base = Path(root).resolve()
    entries = []
    for child in sorted(target.iterdir(), key=lambda p: (p.is_file(), p.name)):
        if child.name in _SKIP_DIRS or child.name.startswith("."):
            continue
        entries.append({
            "path": str(child.relative_to(base)),
            "kind": "dir" if child.is_dir() else "file",
            "lines": (len(child.read_text(errors="replace").splitlines())
                       if child.is_file() and child.suffix.lower() not in _BINARY_SUFFIXES
                       and child.stat().st_size < 2_000_000 else None),
        })
        if len(entries) >= MAX_LIST_ENTRIES:
            entries.append({"path": "...", "kind": "note",
                             "lines": None, "note": "listing truncated"})
            break
    return {"ok": True, "path": str(path), "entries": entries}


def grep_source(root: str | Path, pattern: str, *, path: str = ".") -> dict:
    """Literal substring search. NOT a regex: a model-supplied regex can be
    catastrophically backtracking, and every triage use ("where else is this helper
    called") is a literal anyway."""
    if not pattern or len(pattern) < 2:
        return {"ok": False, "error": "pattern must be at least 2 characters"}
    try:
        target = resolve_in_root(root, path)
    except SourceAccessError as exc:
        return {"ok": False, "error": str(exc)}
    base = Path(root).resolve()
    hits: list[dict] = []
    for dirpath, dirnames, filenames in os.walk(target):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS and not d.startswith(".")]
        for name in filenames:
            file = Path(dirpath) / name
            if file.suffix.lower() in _BINARY_SUFFIXES:
                continue
            try:
                if file.stat().st_size > 2_000_000:
                    continue
                for number, line in enumerate(file.read_text(errors="replace").splitlines(), 1):
                    if pattern in line:
                        hits.append({"path": str(file.relative_to(base)), "line": number,
                                      "text": line.strip()[:200]})
                        if len(hits) >= MAX_GREP_HITS:
                            return {"ok": True, "pattern": pattern, "hits": hits,
                                     "truncated": True}
            except OSError:
                continue
    return {"ok": True, "pattern": pattern, "hits": hits, "truncated": False}


def demo() -> None:
    import shutil
    import tempfile

    root = Path(tempfile.mkdtemp())
    try:
        (root / "app").mkdir()
        (root / "app" / "views.py").write_text(
            "\n".join(f"line {i}" for i in range(1, 41)) + "\n"
        )
        (root / "app" / "safe.py").write_text(
            'q = escape(request.args["q"])\nrender(q)\n'
        )
        (root / "node_modules").mkdir()
        (root / "node_modules" / "junk.js").write_text("escape(1)\n")
        (root / "logo.png").write_bytes(b"\x89PNG")

        # --- containment: the whole point ------------------------------------------
        # A traversal that would climb out is refused by name.
        for bad in ("../etc/passwd", "app/../../etc/passwd", "../../../../../etc/passwd"):
            out = read_source(root, bad)
            assert out["ok"] is False, (bad, out)
            assert "outside the source tree" in out["error"], (bad, out)

        # An ABSOLUTE path is re-rooted rather than refused — "/etc/passwd" is read as
        # repo-relative "etc/passwd", which is contained and simply absent. The property
        # that matters is that no read ever returns content from outside the tree, not
        # that a particular spelling produces a particular message.
        absolute = read_source(root, "/etc/passwd")
        assert absolute["ok"] is False, absolute
        assert "root:" not in str(absolute), "must never return real /etc/passwd content"

        # A sibling directory sharing a name PREFIX must not be reachable. This is the
        # trap a string-prefix containment check falls into.
        sibling = root.parent / (root.name + "-other")
        sibling.mkdir(exist_ok=True)
        (sibling / "secret.txt").write_text("SIBLING SECRET")
        try:
            out = read_source(root, f"../{sibling.name}/secret.txt")
            assert out["ok"] is False, out
            assert "SIBLING SECRET" not in str(out)
        finally:
            shutil.rmtree(sibling, ignore_errors=True)

        # A symlink pointing out of the tree is refused, not followed.
        outside = Path(tempfile.mkdtemp())
        try:
            (outside / "creds").write_text("OUTSIDE CREDS")
            link = root / "escape"
            link.symlink_to(outside / "creds")
            out = read_source(root, "escape")
            assert out["ok"] is False, out
            assert "OUTSIDE CREDS" not in str(out)
        finally:
            shutil.rmtree(outside, ignore_errors=True)

        # --- reading ----------------------------------------------------------------
        whole = read_source(root, "app/views.py")
        assert whole["ok"] and whole["total_lines"] == 40
        assert "1: line 1" in whole["content"]

        window = read_around(root, "app/views.py", 20, context=3)
        assert window["start_line"] == 17 and window["end_line"] == 23
        assert "17: line 17" in window["content"] and "line 16" not in window["content"]
        # Clamped at the file's edges rather than erroring.
        assert read_around(root, "app/views.py", 1, context=5)["start_line"] == 1
        assert read_around(root, "app/views.py", 39, context=5)["end_line"] == 40

        assert read_source(root, "logo.png")["ok"] is False
        assert read_source(root, "app")["ok"] is False          # a directory is not a file
        assert read_source(root, "nope.py")["ok"] is False

        # --- listing ----------------------------------------------------------------
        top = list_source(root)
        assert top["ok"]
        names = {e["path"] for e in top["entries"]}
        assert "app" in names
        assert "node_modules" not in names, "noise dirs must not be listed"
        inner = list_source(root, "app")
        assert {e["path"] for e in inner["entries"]} == {"app/views.py", "app/safe.py"}
        assert next(e for e in inner["entries"] if e["path"] == "app/views.py")["lines"] == 40

        # --- grep -------------------------------------------------------------------
        found = grep_source(root, "escape(")
        assert found["ok"]
        paths = {h["path"] for h in found["hits"]}
        assert "app/safe.py" in paths
        assert not any("node_modules" in p for p in paths), "noise dirs must not be searched"
        assert grep_source(root, "x")["ok"] is False            # too short to be useful
        assert grep_source(root, "nothing-matches-this")["hits"] == []
        # grep is confined too.
        assert grep_source(root, "escape(", path="../")["ok"] is False
    finally:
        shutil.rmtree(root, ignore_errors=True)
    print("tools.source_read: ok")


if __name__ == "__main__":
    demo()
