"""Plain-assert checks for the anchored-edit tool. Run: uv run python tests/test_source_write.py

The property under test is not "an edit works". It is that every refusal is REACHABLE —
a refusal code that no input can produce is decoration, and decoration is what a fail-open
looks like from the inside. So each check builds the input that fires the refusal, and then
asserts the tree is unchanged, because a refusal that already wrote is not a refusal.

No pytest: plain asserts, like every other script in tests/.
"""
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from docket.tools.source_write.tools import (
    EditRefused,
    collect_changes,
    propose_edit,
    scope_denied,
)

VULNERABLE = (
    "import sqlite3\n"
    "\n"
    "\n"
    "def get_user(conn, uid):\n"
    '    query = f"SELECT * FROM users WHERE id={uid}"\n'
    "    return conn.execute(query).fetchone()\n"
)
PARAMETERISED = '    query = "SELECT * FROM users WHERE id=?"'


def tree(**files: str) -> Path:
    root = Path(tempfile.mkdtemp())
    for name, body in ({"app/db.py": VULNERABLE} | files).items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body)
    return root


def test_display_prefixes_are_stripped_off_the_anchor() -> None:
    """The single most common way an anchored edit fails: the agent pastes back the
    `NN: ` output it was shown. workflow.md tells it to strip them, so it sometimes
    will not."""
    root = tree()
    try:
        target = root / "app" / "db.py"
        display = '    5:     query = f"SELECT * FROM users WHERE id={uid}"'
        # Proof that this is a real trap and not a ceremony: the string the agent copied
        # is nowhere in the file's bytes, so a tool that matched verbatim would refuse.
        assert display not in target.read_text(), "the raw display string must NOT match"

        out = propose_edit(root, "app/db.py", display, PARAMETERISED)
        assert out["ok"] is True, out
        assert out["line"] == 5, out
        assert out["replaced_lines"] == 1, out
        assert "stripped" in out["note"], out

        after = target.read_text()
        assert "id=?" in after, after
        # And the display prefix must not have been written INTO the file.
        assert "5:     query" not in after, after
        assert after.startswith("import sqlite3\n"), "untouched lines must stay untouched"
        assert after.count("\n") == VULNERABLE.count("\n"), after

        # A clean anchor still works, and a multi-line one reports its span.
        out = propose_edit(root, "app/db.py",
                           "def get_user(conn, uid):\n" + PARAMETERISED,
                           "def get_user(conn, uid):\n    query = SELECT_USER")
        assert out["ok"] and out["replaced_lines"] == 2, out
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_a_pasted_display_replacement_is_not_written_verbatim() -> None:
    """If the anchor needed stripping, the replacement was pasted from the same output.
    Writing `5: query = ...` into the file is exactly the syntax error the validator
    exists to catch, so it is absorbed here."""
    root = tree(config=('{\n  "timeout": 1,\n  "404": "not found"\n}\n'))
    try:
        out = propose_edit(root, "app/db.py",
                           '    5:     query = f"SELECT * FROM users WHERE id={uid}"',
                           "    5:     query = SELECT_USER")
        assert out["ok"], out
        body = (root / "app" / "db.py").read_text()
        assert "query = SELECT_USER" in body and "5:" not in body, body

        # But a CLEAN anchor never triggers the heuristic, so a replacement whose lines
        # genuinely begin with digits and a colon survives intact.
        out = propose_edit(root, "config", '  "timeout": 1,', '  "80": 443,')
        assert out["ok"], out
        assert '"80": 443,' in (root / "config").read_text()
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_two_identical_anchors_refuse_instead_of_editing_the_first() -> None:
    root = tree(**{"app/twice.py": "run(cmd)\nlog(1)\nrun(cmd)\n"})
    try:
        before = (root / "app" / "twice.py").read_text()
        out = propose_edit(root, "app/twice.py", "run(cmd)", "run(shlex.split(cmd))")
        assert out["ok"] is False and out.get("code") == "anchor_ambiguous", out
        assert "2 places" in out["error"], out["error"]
        assert "1, 3" in out["error"], "the refusal must name the lines"
        assert (root / "app" / "twice.py").read_text() == before, "nothing may be written"
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_a_missing_anchor_refuses_and_says_to_widen() -> None:
    root = tree()
    try:
        before = (root / "app" / "db.py").read_text()
        out = propose_edit(root, "app/db.py", "nothing like this is in the file", "x")
        assert out.get("code") == "anchor_not_found", out
        assert "re-read" in out["error"].lower(), out["error"]
        assert "widen" in out["error"], out["error"]
        assert propose_edit(root, "app/db.py", "   ", "x").get("code") == "anchor_not_found"
        assert (root / "app" / "db.py").read_text() == before
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_traversal_and_symlinks_are_out_of_bounds() -> None:
    root = tree()
    outside = Path(tempfile.mkdtemp())
    try:
        (outside / "creds.txt").write_text("OUTSIDE SECRET\n")
        for escape in ("../creds.txt", "app/../../creds.txt", "../../../../etc/hosts"):
            out = propose_edit(root, escape, "OUTSIDE SECRET", "owned")
            assert out.get("code") == "diff_out_of_bounds", (escape, out)

        # A symlink out of the tree is refused, not followed. resolve() would already
        # have turned it into the outside path, which is why the check is on the
        # unresolved one.
        (root / "escape.txt").symlink_to(outside / "creds.txt")
        out = propose_edit(root, "escape.txt", "OUTSIDE SECRET", "owned")
        assert out.get("code") == "diff_out_of_bounds", out
        assert (outside / "creds.txt").read_text() == "OUTSIDE SECRET\n", "wrote outside!"

        # A sibling directory sharing a name prefix is a different tree: the trap a
        # string-prefix containment check falls into.
        sibling = root.parent / (root.name + "-other")
        sibling.mkdir(exist_ok=True)
        try:
            (sibling / "x.py").write_text("secret = 1\n")
            out = propose_edit(root, f"../{sibling.name}/x.py", "secret = 1", "secret = 2")
            assert out.get("code") == "diff_out_of_bounds", out
            assert (sibling / "x.py").read_text() == "secret = 1\n"
        finally:
            shutil.rmtree(sibling, ignore_errors=True)

        # An ABSOLUTE path is re-rooted rather than followed: "/etc/hosts" is treated as
        # repo-relative "etc/hosts", which is contained and simply absent. The property
        # that matters is that no write ever lands outside the tree.
        hosts = Path("/etc/hosts").read_bytes()
        out = propose_edit(root, "/etc/hosts", "127.0.0.1", "0.0.0.0")
        assert out["ok"] is False, out
        assert Path("/etc/hosts").read_bytes() == hosts, "wrote to an absolute path!"

        # An unset root cannot silently become the process CWD (docket's own source).
        assert propose_edit("", "app/db.py", "x", "y").get("code") == "diff_out_of_bounds"
    finally:
        shutil.rmtree(root, ignore_errors=True)
        shutil.rmtree(outside, ignore_errors=True)


def test_ci_secrets_and_lockfiles_are_denied() -> None:
    root = tree(**{
        ".github/workflows/x.yml": "on: [push]\njobs: {}\n",
        "Jenkinsfile": "pipeline { }\n",
        "Dockerfile": "FROM python:3.12\n",
        ".gitlab-ci.yml": "stages: [test]\n",
        ".env": "TOKEN=abc\n",
        ".env.production": "TOKEN=abc\n",
        "deploy/server.pem": "-----BEGIN KEY-----\n",
        "deploy/id.key": "k\n",
        "deploy/store.p12": "p\n",
        "deploy/a.keystore": "k\n",
        "uv.lock": "[[package]]\n",
        "poetry.lock": "x\n",
        "package-lock.json": "{}\n",
        "yarn.lock": "x\n",
        "Cargo.lock": "x\n",
        "go.sum": "x\n",
        "Gemfile.lock": "x\n",
        "web/node_modules/left-pad/index.js": "module.exports = 1\n",
        # Names that only LOOK denied. The denylist is over path parts and filenames, so
        # a substring check would refuse to fix any of these, which are ordinary source.
        "environments/settings.py": "DEBUG = True\n",
        "app/keyring.py": "KEY = 1\n",
        "docs/dockerfile-notes.md": "x\n",
        "app/envelope.py": "x = 1\n",
    })
    try:
        denied = [".github/workflows/x.yml", "Jenkinsfile", "Dockerfile", ".gitlab-ci.yml",
                  ".env", ".env.production", "deploy/server.pem", "deploy/id.key",
                  "deploy/store.p12", "deploy/a.keystore", "uv.lock", "poetry.lock",
                  "package-lock.json", "yarn.lock", "Cargo.lock", "go.sum",
                  "Gemfile.lock", "web/node_modules/left-pad/index.js"]
        for path in denied:
            assert scope_denied(path), path
            body = (root / path).read_text()
            out = propose_edit(root, path, body.splitlines()[0], "owned: true")
            assert out.get("code") == "path_denied", (path, out)
            assert (root / path).read_text() == body, path

        for path in ("environments/settings.py", "app/keyring.py",
                     "docs/dockerfile-notes.md", "app/envelope.py", "app/db.py"):
            assert scope_denied(path) is None, path
        # Editable, and proved so rather than assumed.
        assert propose_edit(root, "environments/settings.py",
                            "DEBUG = True", "DEBUG = False")["ok"] is True
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_whitespace_only_changes_are_reformats() -> None:
    root = tree()
    try:
        before = (root / "app" / "db.py").read_text()
        for replacement in (
            '        query = f"SELECT * FROM users WHERE id={uid}"',     # re-indented
            '    query   =   f"SELECT * FROM users WHERE id={uid}"',     # re-spaced
            '    query = f"SELECT * FROM users WHERE id={uid}"',         # identical
            '    query = f"SELECT * FROM users WHERE id={uid}"\n',       # newline added
        ):
            out = propose_edit(root, "app/db.py",
                               '    query = f"SELECT * FROM users WHERE id={uid}"',
                               replacement)
            assert out.get("code") == "reformat_only", (replacement, out)
        assert (root / "app" / "db.py").read_text() == before
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_silencing_the_scanner_is_refused() -> None:
    root = tree()
    try:
        before = (root / "app" / "db.py").read_text()
        anchor = '    query = f"SELECT * FROM users WHERE id={uid}"'
        for silencer in ("  # nosemgrep", "  # noqa: S608", "  # type: ignore",
                         "  // eslint-disable-next-line", "  @SuppressWarnings"):
            out = propose_edit(root, "app/db.py", anchor, anchor + silencer)
            assert out.get("code") == "suppression_not_a_fix", (silencer, out)
            assert "root cause" in out["error"], out["error"]
            assert (root / "app" / "db.py").read_text() == before, silencer

        # A marker the anchor ALREADY carried is not an addition: an agent that
        # legitimately rewrites a line keeping its existing pragma is not silencing
        # anything, and refusing that would make the real fix unreachable.
        pragma = "x = eval(s)  # noqa: S307\n"
        (root / "app" / "pragma.py").write_text(pragma)
        out = propose_edit(root, "app/pragma.py", pragma.rstrip("\n"),
                           "x = ast.literal_eval(s)  # noqa: S307")
        assert out["ok"] is True, out
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_not_a_file() -> None:
    root = tree()
    try:
        assert propose_edit(root, "app", "x", "y").get("code") == "not_a_file"
        assert propose_edit(root, "app/absent.py", "x", "y").get("code") == "not_a_file"
        (root / "logo.png").write_bytes(b"\x89PNG\r\n\x1a\n\xff\xfe")
        out = propose_edit(root, "logo.png", "x", "y")
        assert out.get("code") == "not_a_file", out
        assert "decodable" in out["error"], out["error"]
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_every_refusal_code_is_reachable() -> None:
    """The codes EditRefused documents and the codes any input can actually produce must
    be the same set. A code nobody can trigger is a check nobody wrote."""
    documented = {word.strip() for word in
                  (EditRefused.__doc__ or "").split("code is one of:")[1]
                  .split("\n\n")[0].replace("\n", " ").split("|")}
    root = tree(**{"app/twice.py": "run(cmd)\nrun(cmd)\n",
                   ".github/ci.yml": "on: push\n"})
    try:
        (root / "logo.png").write_bytes(b"\xff\xfe\x00")
        produced = {
            propose_edit(root, "app/db.py", "absent", "x").get("code"),
            propose_edit(root, "app/twice.py", "run(cmd)", "run(safe)").get("code"),
            propose_edit(root, "../x.py", "a", "b").get("code"),
            propose_edit(root, "app/db.py", "import sqlite3", " import  sqlite3 ").get("code"),
            propose_edit(root, ".github/ci.yml", "on: push", "on: pull").get("code"),
            propose_edit(root, "app/db.py", "import sqlite3",
                         "import sqlite3  # nosemgrep").get("code"),
            propose_edit(root, "logo.png", "a", "b").get("code"),
        }
        assert produced == documented, (sorted(produced), sorted(documented))
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_crlf_files_are_editable_and_keep_their_endings() -> None:
    root = tree()
    try:
        (root / "win.py").write_bytes(b'q = "SELECT %s" % x\r\nprint(q)\r\n')
        # The anchor comes from tool output, which splits lines, so it has LF endings.
        out = propose_edit(root, "win.py", 'q = "SELECT %s" % x\nprint(q)',
                           'q = "SELECT ?"\nprint(q)')
        assert out["ok"] is True, out
        raw = (root / "win.py").read_bytes()
        assert raw == b'q = "SELECT ?"\r\nprint(q)\r\n', raw
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_collect_changes_is_derived_from_the_trees() -> None:
    """The model's account of what it edited is never an input. A file it never mentioned
    is reported because the bytes differ, which is what stops one being smuggled through."""
    base = tree(**{"app/keep.py": "untouched = 1\n", "app/legacy.py": "old = 1\n"})
    patched = tree(**{"app/keep.py": "untouched = 1\n", "app/legacy.py": "old = 1\n"})
    try:
        propose_edit(patched, "app/db.py",
                     '    query = f"SELECT * FROM users WHERE id={uid}"', PARAMETERISED)
        (patched / "app" / "brand_new.py").write_text("SELECT_USER = 1\n")   # never mentioned
        (patched / "app" / "legacy.py").unlink()                              # deleted
        (patched / ".git").mkdir()
        (patched / ".git" / "config").write_text("[core]\n")                  # must be skipped
        (base / ".git").mkdir()
        (base / ".git" / "config").write_text("[core]\n[remote]\n")

        notes: list[str] = []
        changes = collect_changes(patched, base, notes=notes)
        by_path = {change["path"]: change for change in changes}
        assert set(by_path) == {"app/db.py", "app/brand_new.py", "app/legacy.py"}, sorted(by_path)
        assert not notes, notes

        edited = by_path["app/db.py"]
        assert edited["added_lines"] == [PARAMETERISED], edited
        assert edited["removed_lines"] == [
            '    query = f"SELECT * FROM users WHERE id={uid}"'], edited
        assert edited["content"].startswith("import sqlite3")

        created = by_path["app/brand_new.py"]
        assert created["added_lines"] == ["SELECT_USER = 1"] and created["removed_lines"] == []

        deleted = by_path["app/legacy.py"]
        assert deleted["content"] is None, "a deleted file is content=None"
        assert deleted["removed_lines"] == ["old = 1"] and deleted["added_lines"] == []

        # Identical bytes are not a change, in either direction.
        assert "app/keep.py" not in by_path
        assert collect_changes(base, base) == []
    finally:
        shutil.rmtree(base, ignore_errors=True)
        shutil.rmtree(patched, ignore_errors=True)


def test_collect_changes_skips_what_it_cannot_ship() -> None:
    base = tree()
    patched = tree()
    outside = Path(tempfile.mkdtemp())
    try:
        (outside / "shadow").write_text("root:!:0:0\n")
        (patched / "logo.png").write_bytes(b"\x89PNG\x00\xff")
        (base / "logo.png").write_bytes(b"\x89PNG\x00\xfe")
        # A symlink planted in the patched tree must not have its target's contents
        # collected into a pull request.
        (patched / "notes.txt").symlink_to(outside / "shadow")

        notes: list[str] = []
        changes = collect_changes(patched, base, notes=notes)
        assert [c["path"] for c in changes] == [], changes
        assert any("logo.png" in note for note in notes), notes
        assert "root:!:0:0" not in str(changes), "a symlink target must never be shipped"
    finally:
        for path in (base, patched, outside):
            shutil.rmtree(path, ignore_errors=True)


if __name__ == "__main__":
    test_display_prefixes_are_stripped_off_the_anchor()
    test_a_pasted_display_replacement_is_not_written_verbatim()
    test_two_identical_anchors_refuse_instead_of_editing_the_first()
    test_a_missing_anchor_refuses_and_says_to_widen()
    test_traversal_and_symlinks_are_out_of_bounds()
    test_ci_secrets_and_lockfiles_are_denied()
    test_whitespace_only_changes_are_reformats()
    test_silencing_the_scanner_is_refused()
    test_not_a_file()
    test_every_refusal_code_is_reachable()
    test_crlf_files_are_editable_and_keep_their_endings()
    test_collect_changes_is_derived_from_the_trees()
    test_collect_changes_skips_what_it_cannot_ship()
    print("test_source_write: ok")
