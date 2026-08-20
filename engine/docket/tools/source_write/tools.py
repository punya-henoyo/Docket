"""Anchored edits for the fix agent, and a diff DERIVED from the trees.

Two callables, and the difference between them is the point.

`propose_edit` is the ONE way a fix agent changes a byte. It is anchored rather than
line-numbered because a model's line numbers drift the moment it edits anything, and
because an anchor that matches twice is a bug the tool can see and a line number is not.
It refuses rather than guesses, and every refusal is a dict the model can read and act on
— it never raises into the SDK, where an exception becomes a dead turn.

`collect_changes` is the diff, and it is DERIVED by walking the two trees and comparing
bytes. The model's account of what it edited is not an input and never will be. That is
what stops a patch shipping a file nobody reviewed: if it is not a byte difference between
the pristine tree and the patched one, it does not exist, and if it IS one it is reported
whether the model mentioned it or not.

Three refusals here exist because of the fix workflow's own rules (skills/fix/workflow.md):

  * CI config, secrets and lockfiles are out of scope (`path_denied`) — a "fix" that edits
    `.github/workflows` is a supply-chain change wearing a security patch's clothes.
  * a whitespace-only change is a reformat (`reformat_only`), which buries the one line
    that matters in noise and is rejected outright.
  * adding `# nosemgrep` (or `noqa`, or `@SuppressWarnings`) is `suppression_not_a_fix`.
    It makes the scanner quiet and the bug permanent, and it would sail through every
    gate in service/validate.py precisely because it works: the finding really is gone.
    So it is refused here, before it can become evidence.

Containment is `source_read.resolve_in_root` — a parent walk plus a symlink refusal, not a
string prefix. It is reused rather than reimplemented: there is one containment check in
this codebase and a second one would only ever be the weaker of the two.

stdlib only, like source_read.tools, so nothing here depends on the SDK being importable.
"""
from __future__ import annotations

import difflib
import fnmatch
import logging
import re
from pathlib import Path, PurePosixPath

from docket.tools.source_read.tools import SourceAccessError, resolve_in_root

logger = logging.getLogger(__name__)

# source_read.read_source renders file contents as f"{first + i}: {line}" (tools.py:103),
# so an anchor copied out of tool output carries prefixes that are NOT in the file's
# bytes. workflow.md tells the agent to strip them, which means it will sometimes forget.
_DISPLAY_PREFIX = re.compile(r"^\s*\d+:\s?")

# Denylisted by PATH PART and by FILENAME, never by substring of the whole path: a repo
# with a directory called "environments" or a module called "keyring.py" is normal, and a
# substring check would refuse to fix either of them.
_DENY_PARTS = frozenset({".github", ".git", "node_modules"})
_DENY_NAMES = frozenset({
    ".gitlab-ci.yml", "jenkinsfile", "dockerfile",
    # Lockfiles: regenerating one is a dependency decision, not a code fix, and a diff
    # nobody can read by hand is the last place to hide a change.
    "uv.lock", "poetry.lock", "package-lock.json", "yarn.lock", "cargo.lock",
    "go.sum", "gemfile.lock",
})
_DENY_GLOBS = (".env*", "*.pem", "*.key", "*.p12", "*.keystore")

# Removing a secret from a file does not un-leak it (workflow.md phase 4: rotation is the
# fix), and editing a key file is how a patch breaks every deployment that reads it.
SUPPRESSIONS = ("nosemgrep", "noqa", "# type: ignore", "eslint-disable",
                 "@SuppressWarnings")

_SKIP_TREE_PARTS = frozenset({".git"})


class EditRefused(Exception):
    """code is one of: anchor_not_found | anchor_ambiguous | diff_out_of_bounds |
    reformat_only | path_denied | suppression_not_a_fix | not_a_file

    `suppression_not_a_fix` is a policy refusal in the same family as `path_denied` —
    split out with its own code because "you may not edit that path" and "that edit
    silences the check instead of fixing it" need different corrections from the agent.
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def scope_denied(path: str) -> str | None:
    """A reason the path may never be written, or None."""
    pure = PurePosixPath(str(path).replace("\\", "/"))
    for part in pure.parts:
        if part.casefold() in _DENY_PARTS:
            return (f"refused: {part} is out of scope for a fix. CI configuration, git "
                    "internals and vendored trees are not application source, and a "
                    "security patch that edits them is a supply-chain change.")
    name = pure.name.casefold()
    if name in _DENY_NAMES:
        return (f"refused: {pure.name} is out of scope for a fix — CI config, container "
                "build files and lockfiles are changed deliberately by a human, not as "
                "a side effect of a patch.")
    for glob in _DENY_GLOBS:
        if fnmatch.fnmatch(name, glob):
            return (f"refused: {pure.name} looks like a secrets or key file. Deleting a "
                    "leaked credential does not un-leak it — report that rotation is "
                    "required and name what must be rotated instead.")
    return None


def _strip_display_prefixes(text: str) -> str:
    return "\n".join(_DISPLAY_PREFIX.sub("", line) for line in text.split("\n"))


def _looks_like_display_block(text: str) -> bool:
    """Every non-blank line carries an `NN: ` prefix — i.e. this is pasted tool output,
    not code. Hand-written code with a line-number prefix on EVERY line does not occur;
    code with one such line (`404: "not found",`) does, which is why this is all-or-none.
    """
    lines = [line for line in text.split("\n") if line.strip()]
    return bool(lines) and all(_DISPLAY_PREFIX.match(line) for line in lines)


def _find_all(haystack: str, needle: str) -> list[int]:
    hits, at = [], haystack.find(needle)
    while at != -1:
        hits.append(at)
        at = haystack.find(needle, at + 1)
    return hits


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _locate_flexible(text: str, anchor: str) -> tuple[str, int] | None:
    """Whole-line match with per-line whitespace NORMALISED — the fallback when every
    exact form failed. It exists because the dominant real failure is not a wrong anchor,
    it is DRIFTED INDENTATION: a model quotes the right lines but off by a space or a tab,
    and exact byte matching then reports `anchor_not_found` on a fix that was otherwise
    correct. Measured all night — the intermittent `not_fixed` where the agent's tree came
    back unchanged is this.

    The safety that makes exact matching trustworthy is kept: the match must still be
    UNIQUE. Two windows matching after normalisation raises `anchor_ambiguous`, exactly as
    an exact double-match does — editing the first of several is how a patch lands in the
    wrong place, normalised or not. And the span replaced is the file's REAL bytes on
    whole-line boundaries, so nothing mid-line is ever cut.
    """
    want = [ln.strip() for ln in anchor.strip("\n").splitlines()]
    while want and want[0] == "":
        want.pop(0)
    while want and want[-1] == "":
        want.pop()
    if not want:
        return None

    lines: list[tuple[str, int, int]] = []  # (text, start_offset, content_end_offset)
    off = 0
    for raw in text.splitlines(keepends=True):
        content = raw.rstrip("\r\n")
        lines.append((content, off, off + len(content)))
        off += len(raw)

    n = len(want)
    hits: list[tuple[str, int]] = []
    for i in range(0, len(lines) - n + 1):
        window = lines[i:i + n]
        if [w[0].strip() for w in window] == want:
            start, end = window[0][1], window[-1][2]
            hits.append((text[start:end], start))
    if len(hits) == 1:
        return hits[0]
    if len(hits) > 1:
        raise EditRefused("anchor_ambiguous", (
            f"refused: your anchor matches {len(hits)} places (compared ignoring "
            "indentation). Editing the first of several lands the patch in the wrong "
            "place. Widen the anchor with surrounding lines until it is unique."))
    return None


def _locate(text: str, anchor: str) -> tuple[str, int, list[str], bool]:
    """(the anchor as it appears in the file, its offset, notes, prefixes_were_stripped).

    Tries the anchor verbatim FIRST, so a file whose real bytes happen to look like
    display output is still editable, and only then the stripped form.
    """
    forms: list[tuple[str, str, bool]] = [(anchor, "", False)]
    stripped = _strip_display_prefixes(anchor)
    if stripped != anchor:
        forms.append((stripped, "stripped the NN: line-number prefixes off your anchor",
                      True))
    if "\r\n" in text:
        # The file has CRLF endings; an anchor copied out of tool output has LF, because
        # read_source splits lines before rendering them. Without this every multi-line
        # anchor in a Windows-authored repo is anchor_not_found forever.
        forms += [(form.replace("\n", "\r\n"),
                   "; ".join(filter(None, [note, "matched CRLF line endings"])), was)
                  for form, note, was in list(forms) if "\r\n" not in form]

    ambiguous: tuple[str, list[int]] | None = None
    for form, note, was_stripped in forms:
        hits = _find_all(text, form)
        if len(hits) == 1:
            return form, hits[0], [note] if note else [], was_stripped
        if len(hits) > 1 and ambiguous is None:
            ambiguous = (form, hits)

    if ambiguous is not None:
        _, hits = ambiguous
        lines = ", ".join(str(_line_of(text, hit)) for hit in hits)
        raise EditRefused("anchor_ambiguous", (
            f"refused: your anchor matches {len(hits)} places in this file (lines "
            f"{lines}). Nothing was edited — editing the first of several is how a patch "
            "lands in the wrong function. Re-read one of those regions and widen the "
            "anchor with surrounding lines until it is unique."))
    # Every exact form missed. Before giving up, try the whitespace-normalised match:
    # the anchor is usually right and the indentation is what drifted.
    flexible = _locate_flexible(text, anchor)
    if flexible is not None:
        matched, offset = flexible
        return matched, offset, ["matched after normalising indentation"], False

    raise EditRefused("anchor_not_found", (
        "refused: your anchor matches nothing in this file, even ignoring indentation. "
        "Re-read the region and copy the anchor from what you read, without the NN: "
        "line-number prefixes, and widen it to several whole lines. Nothing was edited."))


def _refuse_suppression(anchor: str, replacement: str) -> None:
    for marker in SUPPRESSIONS:
        if replacement.count(marker) > anchor.count(marker):
            raise EditRefused("suppression_not_a_fix", (
                f"refused: your replacement adds `{marker}`, which silences the check "
                "rather than fixing the bug — it makes the scanner quiet and leaves the "
                "vulnerability permanent. Fix the root cause, or report no_safe_fix with "
                "your reason. That is a respected answer; this is not."))


def propose_edit(root: str | Path, path: str, anchor: str, replacement: str) -> dict:
    """{"ok": True, "path", "line", "replaced_lines", "note"} on success,
       {"ok": False, "code", "error"} on refusal. NEVER raises to the SDK."""
    try:
        return _edit(root, path, anchor, replacement)
    except EditRefused as refusal:
        return {"ok": False, "code": refusal.code, "error": refusal.message}
    except Exception as exc:  # noqa: BLE001 - a raise here would burn the agent's turn
        # Everything reachable is a filesystem or decoding failure on the target; the
        # guarantee that matters is that the tree is unchanged and the model is told.
        logger.exception("propose_edit failed on %s", path)
        return {"ok": False, "code": "not_a_file",
                "error": f"refused: could not apply an edit to {path}: "
                         f"{type(exc).__name__}: {exc}"}


def _edit(root: str | Path, path: str, anchor: str, replacement: str) -> dict:
    if not str(anchor).strip():
        raise EditRefused("anchor_not_found", (
            "refused: an empty anchor matches everything and identifies nothing. Quote "
            "the lines you are replacing."))
    if (reason := scope_denied(path)) is not None:
        raise EditRefused("path_denied", reason)
    try:
        target = resolve_in_root(root, path)
    except SourceAccessError as exc:
        # Includes the symlink refusal and an unset root. Everything that is not
        # provably inside the tree is out of bounds.
        raise EditRefused("diff_out_of_bounds", f"refused: {exc}") from exc
    if not target.is_file():
        raise EditRefused("not_a_file", f"refused: {path} is not a file in this tree.")

    _refuse_suppression(anchor, replacement)

    try:
        # Bytes, not read_text(): text mode translates CRLF to LF, so writing back would
        # rewrite every line ending in the file and the derived diff would show the whole
        # file changed. Preserving the bytes we did not touch is the point of an edit.
        text = target.read_bytes().decode("utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise EditRefused("not_a_file", (
            f"refused: {path} is not decodable UTF-8 text ({type(exc).__name__}). "
            "There is no source fix to make in a binary file.")) from exc

    matched, offset, notes, was_stripped = _locate(text, anchor)
    if was_stripped and _looks_like_display_block(replacement):
        # ponytail: heuristic, deliberately narrow. Only when the anchor needed stripping
        # AND every non-blank replacement line is prefixed — i.e. both were pasted out of
        # tool output. Writing "42: return x" into a source file is the syntax error the
        # validator exists to catch, and absorbing the agent's own documented mistake here
        # is cheaper than a round trip.
        replacement = _strip_display_prefixes(replacement)
        notes.append("stripped the NN: prefixes off your replacement too")
    if "\r\n" in matched and "\r\n" not in replacement:
        replacement = replacement.replace("\n", "\r\n")

    # Whitespace-normalised equality: a reflow, a re-indent and a no-op all land here.
    if "".join(matched.split()) == "".join(replacement.split()):
        raise EditRefused("reformat_only", (
            "refused: that replacement changes only whitespace. A patch that reflows or "
            "re-indents a file is rejected outright — it buries the one line that "
            "matters. Change the code, or report no_safe_fix."))

    target.write_bytes((text[:offset] + replacement
                        + text[offset + len(matched):]).encode("utf-8"))
    return {
        "ok": True,
        "path": str(path),
        "line": _line_of(text, offset),
        "replaced_lines": len(matched.splitlines()) or 1,
        "note": "; ".join(notes) or "anchor matched exactly once",
    }


def _tree_files(root: Path) -> dict[str, Path]:
    """Every regular file under root, keyed by POSIX-relative path. Symlinks are skipped
    rather than followed: a link added inside the tree pointing at /etc/shadow would
    otherwise have its "content" collected into a pull request."""
    found: dict[str, Path] = {}
    for candidate in root.rglob("*"):
        relative = candidate.relative_to(root)
        if _SKIP_TREE_PARTS & set(relative.parts):
            continue
        if candidate.is_symlink() or not candidate.is_file():
            continue
        found[relative.as_posix()] = candidate
    return found


def _decode(raw: bytes | None) -> str | None:
    if raw is None:
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _line_delta(before: str, after: str) -> tuple[list[str], list[str]]:
    diff = list(difflib.unified_diff(before.splitlines(), after.splitlines(),
                                     n=0, lineterm=""))
    added = [line[1:] for line in diff
             if line.startswith("+") and not line.startswith("+++")]
    removed = [line[1:] for line in diff
               if line.startswith("-") and not line.startswith("---")]
    return added, removed


def collect_changes(patched_root: str | Path, base_root: str | Path, *,
                    notes: list[str] | None = None) -> list[dict]:
    """[{"path", "content", "added_lines": [str], "removed_lines": [str]}] for every
    file whose bytes differ. DERIVED by walking the trees. Never reads a model claim.

    `content` is None for a file deleted in the patched tree. `notes` collects anything
    skipped (binary, undecodable) so a caller can put it in the report instead of it
    vanishing.
    """
    patched, base = Path(patched_root), Path(base_root)
    new_files, old_files = _tree_files(patched), _tree_files(base)
    changes: list[dict] = []

    for relative in sorted(set(new_files) | set(old_files)):
        new_raw = new_files[relative].read_bytes() if relative in new_files else None
        old_raw = old_files[relative].read_bytes() if relative in old_files else None
        if new_raw == old_raw:
            continue
        new_text, old_text = _decode(new_raw), _decode(old_raw)
        if (new_raw is not None and new_text is None) or (
                old_raw is not None and old_text is None):
            note = (f"{relative} changed but is not UTF-8 text, so it is not included in "
                    "the patch — a binary change is not a source fix")
            logger.warning("collect_changes: %s", note)
            if notes is not None:
                notes.append(note)
            continue
        added, removed = _line_delta(old_text or "", new_text or "")
        changes.append({"path": relative, "content": new_text,
                        "added_lines": added, "removed_lines": removed})
    return changes


def demo() -> None:
    import shutil
    import tempfile

    root = Path(tempfile.mkdtemp())
    base = Path(tempfile.mkdtemp())
    try:
        source = ('import sqlite3\n\n\ndef get(conn, uid):\n'
                  '    q = f"SELECT * FROM users WHERE id={uid}"\n'
                  '    return conn.execute(q)\n')
        for tree in (root, base):
            (tree / "app").mkdir()
            (tree / "app" / "db.py").write_text(source)

        # --- the denylist, over parts and filenames, not substrings -----------------
        for denied in (".github/workflows/ci.yml", "app/.env", "keys/server.pem",
                       "uv.lock", "Dockerfile", "sub/node_modules/x.js"):
            assert scope_denied(denied), denied
        for allowed in ("app/db.py", "environments/settings.py", "app/keyring.py",
                        "src/dockerfiles.md"):
            assert scope_denied(allowed) is None, allowed
        refusal = propose_edit(root, ".github/workflows/ci.yml", "on:", "on: []")
        assert refusal["code"] == "path_denied", refusal

        # --- containment -----------------------------------------------------------
        out = propose_edit(root, "../escape.py", "x", "y")
        assert out["code"] == "diff_out_of_bounds", out

        # --- an anchor pasted out of tool output, prefixes and all ------------------
        display = '    5:     q = f"SELECT * FROM users WHERE id={uid}"'
        assert display not in (root / "app" / "db.py").read_text(), "raw display must not match"
        ok = propose_edit(root, "app/db.py", display,
                          '    q = "SELECT * FROM users WHERE id=?"')
        assert ok["ok"] and ok["line"] == 5, ok
        assert "stripped" in ok["note"], ok
        patched = (root / "app" / "db.py").read_text()
        assert 'id=?' in patched and "5:" not in patched, patched

        # --- two identical anchors are ambiguous, never a first-match edit ----------
        (root / "app" / "twice.py").write_text("run(x)\nprint(1)\nrun(x)\n")
        (base / "app" / "twice.py").write_text("run(x)\nprint(1)\nrun(x)\n")
        dup = propose_edit(root, "app/twice.py", "run(x)", "run(escape(x))")
        assert dup["code"] == "anchor_ambiguous", dup
        assert "1, 3" in dup["error"], dup["error"]
        assert (root / "app" / "twice.py").read_text() == "run(x)\nprint(1)\nrun(x)\n"

        # --- reformats and suppressions --------------------------------------------
        assert propose_edit(root, "app/twice.py", "print(1)",
                            "  print(1)  ")["code"] == "reformat_only"
        silenced = propose_edit(root, "app/twice.py", "print(1)",
                                "print(1)  # nosemgrep")
        assert silenced["code"] == "suppression_not_a_fix", silenced

        # --- the diff is DERIVED, not claimed --------------------------------------
        (root / "sneaked.py").write_text("print('never mentioned')\n")
        (base / "gone.py").write_text("legacy = 1\n")
        (root / "logo.png").write_bytes(b"\x89PNG\x00\xff")
        (base / "logo.png").write_bytes(b"\x89PNG\x00\xfe")
        skipped: list[str] = []
        changes = collect_changes(root, base, notes=skipped)
        by_path = {c["path"]: c for c in changes}
        assert set(by_path) == {"app/db.py", "sneaked.py", "gone.py"}, sorted(by_path)
        assert by_path["sneaked.py"]["removed_lines"] == []
        assert by_path["gone.py"]["content"] is None, "a deleted file reports content=None"
        assert by_path["app/db.py"]["added_lines"] == ['    q = "SELECT * FROM users WHERE id=?"']
        assert any("logo.png" in note for note in skipped), skipped
    finally:
        shutil.rmtree(root, ignore_errors=True)
        shutil.rmtree(base, ignore_errors=True)
    # ── indentation-drift fallback: the anchored-edit reliability fix ───────────
    import tempfile as _tmp
    def _mk(c):
        d = Path(_tmp.mkdtemp()); (d / "a.py").write_text(c); return d
    _F = "def run(sql):\n    return execute(sql)\n\n\ndef h(x):\n    q = build(x)\n    return run(q)\n"
    # a MULTI-LINE anchor whose indentation drifted (dedented, and with a tab) does not
    # substring-match, and used to be anchor_not_found — the real all-night failure. It
    # now lands, on the file's real bytes.
    _r = propose_edit(_mk(_F), "a.py",
                      anchor="q = build(x)\n\treturn run(q)",   # no indent + a tab
                      replacement="    q = safe(x)\n    return run(q)")
    assert _r["ok"] and "normalising indentation" in _r["note"], _r
    # exact anchor unaffected
    assert propose_edit(_mk(_F), "a.py", anchor="    q = build(x)", replacement="    q = safe(x)")["ok"]
    # a genuinely absent anchor is still refused, not force-matched
    assert propose_edit(_mk(_F), "a.py", anchor="no such line", replacement="x")["code"] == "anchor_not_found"
    # uniqueness is preserved: two windows matching after normalisation is still ambiguous
    _amb = propose_edit(_mk("def a():\n    x = 1\n\ndef b():\n    x = 1\n"),
                        "a.py", anchor="  x = 1", replacement="  x = 2")
    assert _amb["code"] == "anchor_ambiguous", _amb

    print("tools.source_write: ok")


if __name__ == "__main__":
    demo()
