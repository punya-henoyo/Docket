"""Put the result on the pull request: check run, then comments, then a fix PR.

Three steps in that order, each independently useful. The check run is the product — it
is the thing that blocks a merge — so it goes first and lands even if there is no patch
to offer. Review comments are decoration on top of the annotations the check already
carries. A fix branch is last because it is the only step that writes to the repository.

WHAT THIS WILL NOT DO
---------------------
It never approves, never merges, and never forces a ref. Not by policy — by absence:
interface/scm.py has no method for any of the three (read its docstring). Delivery could
not merge a PR if it wanted to.

THE FIX BRANCH RULES, AND WHY EACH ONE EXISTS
---------------------------------------------
* the branch name is deterministic — docket/fix/<pr>-<key8> — so a re-run of the same
  finding finds its own branch instead of littering a repo with fix-1, fix-2, fix-3
* the FIRST thing done is a read: GET /pulls?head=owner:branch&state=all. If a PR is
  already open (or was closed by a human who disagreed), it is adopted and reported, not
  duplicated. A tool that opens a second PR after someone closed the first is a tool
  people uninstall.
* the branch is cut from the head_sha THE SCAN RECORDED. If the PR has moved on, the
  patch was written against code that is no longer there, so this refuses with
  base_commit_stale and writes nothing. Committing anyway is how a fix silently reverts
  someone's newer commit.
* the base is the ORIGINAL PR's head branch, so the fix merges INTO their PR and rides
  their review. Basing it on main would open a competing PR against the default branch.
* only verified_fixed patches get a branch. unverified_plausible never does: a patch
  nobody re-tested is a suggestion, and suggestions belong in a comment.
"""
from __future__ import annotations

import hashlib
import logging
import urllib.parse
from typing import Any

from docket.interface.scm import FileChange, ScmError

logger = logging.getLogger(__name__)

VERIFIED = "verified_fixed"
CHECK_NAME = "docket"

# Annotations already carry every finding inline; comments are a louder duplicate of the
# worst few, so they are capped and off by default.
MAX_REVIEW_COMMENTS = 10


def fix_branch_name(pr: int | str, key: str) -> str:
    """docket/fix/<pr>-<8 hex of the finding key>. Same finding -> same branch, forever."""
    digest = hashlib.sha256(str(key).encode()).hexdigest()[:8]
    return f"docket/fix/{int(pr)}-{digest}"


def _field(patch: Any, name: str, default: Any = None) -> Any:
    """Read a field off a dataclass, an object, or a dict — the patch producer is a
    different phase, and this should not care which shape it settled on."""
    if isinstance(patch, dict):
        return patch.get(name, default)
    return getattr(patch, name, default)


def _file_changes(patch: Any) -> list[FileChange]:
    changes = []
    for entry in _field(patch, "files", []) or []:
        if isinstance(entry, FileChange):
            changes.append(entry)
        elif isinstance(entry, dict):
            changes.append(FileChange(entry["path"], entry.get("content")))
        else:  # (path, content)
            path, content = entry
            changes.append(FileChange(path, content))
    if not changes:
        raise ScmError("bad_change", "a verified patch with no files is not a patch")
    return changes


def _gate(gate_result: Any) -> Any:
    """Accept a GateResult, or a raw report dict to run the gate over.

    docket.service.gate is imported HERE and not at module import time on purpose: this
    module must import (and its demo must run) whether or not the gate module exists, and
    the result is duck-typed anyway — anything with .conclusion/.reasons/.annotations
    works, which is what makes this testable with no gate at all.
    """
    if hasattr(gate_result, "conclusion"):
        return gate_result
    if isinstance(gate_result, dict) and "conclusion" in gate_result:
        return gate_result
    from docket.service.gate import evaluate  # what arrived is a report, not a verdict

    return evaluate(gate_result)


def deliver(scm: Any, store: Any, scan_row: dict, gate_result: Any,
            patches: list[Any] | None = None, *, review_comments: bool = False,
            check_name: str = CHECK_NAME, details_url: str | None = None) -> dict:
    """Deliver one scan's verdict to its pull request. Returns what was done.

    A fix-branch failure is reported in the return value (`fix_error`) rather than
    raised: the check run has already landed by then and is the part that matters, so
    losing it to an exception would be a worse outcome than a missing fix PR.
    """
    verdict = _gate(gate_result)
    repo = scan_row["repo"]
    pr = int(scan_row["pr"])
    head_sha = scan_row["head_sha"]
    conclusion = _field(verdict, "conclusion", "action_required")
    reasons = list(_field(verdict, "reasons", []) or [])
    annotations = list(_field(verdict, "annotations", []) or [])

    result: dict[str, Any] = {"repo": repo, "pr": pr, "conclusion": conclusion,
                             "check_run_id": None, "annotations": len(annotations),
                             "comments": 0, "fix_prs": [], "skipped": [],
                             "fix_error": None}

    run = scm.create_check_run(
        repo, head_sha, name=check_name, conclusion=conclusion,
        title=f"docket: {conclusion}",
        summary="\n".join(f"- {reason}" for reason in reasons) or "no findings",
        annotations=annotations, details_url=details_url,
    )
    result["check_run_id"] = run.get("id") if isinstance(run, dict) else None

    if review_comments:
        for annotation in annotations[:MAX_REVIEW_COMMENTS]:
            path, line = annotation.get("path"), annotation.get("start_line")
            if not path or not line:
                continue
            try:
                scm.create_review_comment(repo, pr, path, int(line),
                                          annotation.get("message", ""),
                                          commit_id=head_sha)
                result["comments"] += 1
            except ScmError as exc:
                # A comment on a line outside the diff is a 422 and is not worth failing
                # the delivery over — the annotation already says it.
                logger.info("review comment on %s:%s refused: %s", path, line, exc)

    for patch in patches or []:
        key = _field(patch, "key") or _field(patch, "rule_id") or "patch"
        if _field(patch, "status") != VERIFIED:
            result["skipped"].append({"key": key, "status": _field(patch, "status")})
            continue
        try:
            result["fix_prs"].append(_fix_pr(scm, repo, pr, head_sha, patch, key))
        except ScmError as exc:
            logger.warning("fix branch for %s#%s (%s) refused: %s", repo, pr, key, exc)
            result["fix_error"] = exc.code
            if exc.code == "base_commit_stale":
                break  # every other patch is stale for the same reason

    if store is not None:
        store.set_state(scan_row["id"], "delivered", conclusion=conclusion)
    return result


def _fix_pr(scm: Any, repo: str, pr: int, head_sha: str, patch: Any, key: str) -> dict:
    branch = fix_branch_name(pr, key)
    owner = repo.split("/")[0]

    # READ FIRST. Adoption before creation, so a re-run cannot duplicate a PR.
    query = urllib.parse.urlencode({"head": f"{owner}:{branch}", "state": "all"})
    existing = scm.get(f"/repos/{repo}/pulls?{query}") or []
    if existing:
        found = existing[0]
        return {"key": key, "branch": branch, "number": found.get("number"),
                "url": found.get("html_url"), "adopted": True,
                "state": found.get("state")}

    target = scm.get(f"/repos/{repo}/pulls/{pr}") or {}
    current = (target.get("head") or {}).get("sha")
    if current != head_sha:
        raise ScmError(
            "base_commit_stale",
            f"{repo}#{pr} is now at {str(current)[:8]}, the scan ran on {head_sha[:8]}. "
            "The patch was written against code that has moved; nothing was written.",
        )
    base = (target.get("head") or {}).get("ref")
    if not base:
        raise ScmError("base_commit_stale", f"{repo}#{pr} has no head branch to merge into")

    changes = _file_changes(patch)
    title = _field(patch, "title") or f"fix: {key}"
    body = _field(patch, "summary") or _field(patch, "body") or ""
    scm.create_branch(repo, branch, head_sha)
    scm.commit_files(repo, branch, changes, title)
    opened = scm.open_pr(
        repo, branch, base, title,
        f"{body}\n\n---\ndocket verified this fix against the finding it closes "
        f"(`{key}`). It targets `{base}` so it merges into #{pr}.\n"
        "docket does not merge or approve anything — that is your call.".strip(),
    )
    return {"key": key, "branch": branch, "number": opened.get("number"),
            "url": opened.get("html_url"), "adopted": False, "state": "open"}


def demo() -> None:
    import tempfile
    from pathlib import Path
    from types import SimpleNamespace

    from docket.interface.scm import GitHubApp, _fake_config, _FakeTransport
    from docket.service.store import Store, db_path

    head = "a" * 40
    config = _fake_config()

    # Anything carrying these three attributes will do — gate.GateResult is one, and
    # this stands in for it so the demo runs whether or not gate.py exists.
    def _verdict() -> SimpleNamespace:
        return SimpleNamespace(
            conclusion="failure",
            reasons=["1 confirmed finding: sql-injection at POST /login"],
            annotations=[{"path": "app/main.py", "start_line": 42, "end_line": 42,
                          "annotation_level": "failure", "message": "unescaped query"}])

    verified = {"key": "sql-injection:app/main.py:42", "status": VERIFIED,
                "title": "fix: parameterise the login query",
                "files": [{"path": "app/main.py", "content": "cursor.execute(q, (u,))\n"}]}
    plausible = {"key": "xss:app/view.py:7", "status": "unverified_plausible",
                 "files": [{"path": "app/view.py", "content": "escape(x)\n"}]}

    scratch = tempfile.TemporaryDirectory()

    def _fresh() -> tuple[Store, dict, _FakeTransport, GitHubApp]:
        # A fresh store per scenario, all under one directory that gets cleaned up.
        home = Path(scratch.name) / str(len(list(Path(scratch.name).iterdir())))
        store = Store(db_path(cwd=home))
        store.watch("o/r")
        scan_id = store.enqueue("o/r", 7, head, "b" * 40)
        store.claim(scan_id, "worker-1")
        fake = _FakeTransport(
            refs={"main": "z" * 40, "feature-7": head}, default_branch="main",
            pulls={7: {"number": 7, "head": {"sha": head, "ref": "feature-7"},
                       "base": {"sha": "b" * 40, "ref": "main"}}})
        return store, store.scan(scan_id), fake, GitHubApp(config=config, transport=fake)

    # deterministic name, and it survives a re-run
    assert fix_branch_name(7, "k") == fix_branch_name("7", "k")
    assert fix_branch_name(7, "k").startswith("docket/fix/7-")
    assert len(fix_branch_name(7, "k").split("-")[-1]) == 8

    # ── the whole path: check run, comments, one fix PR ────────────────────────────
    store, row, fake, app = _fresh()
    try:
        out = deliver(app, store, row, _verdict(), [verified, plausible],
                      review_comments=True)
        assert out["check_run_id"] == 1 and out["conclusion"] == "failure", out
        assert fake.check_runs[0]["output"]["annotations"][0]["start_line"] == 42
        assert out["comments"] == 1 and fake.comments[0]["line"] == 42, fake.comments
        assert len(out["fix_prs"]) == 1 and out["fix_prs"][0]["adopted"] is False, out
        assert out["skipped"] == [{"key": "xss:app/view.py:7",
                                  "status": "unverified_plausible"}], out
        branch = out["fix_prs"][0]["branch"]
        assert fake.refs[branch] == fake.commits[-1]["sha"]
        # the fix merges INTO the PR, never into the default branch
        assert fake.created_pulls[0]["base"] == "feature-7", fake.created_pulls
        assert fake.created_pulls[0]["head"] == branch
        assert store.scan(row["id"])["state"] == "delivered"
        assert store.scan(row["id"])["conclusion"] == "failure"
        # The unverified patch touched nothing at all.
        assert not any("view.py" in str(commit) for commit in fake.commits)
    finally:
        store.close()

    # ── a second run adopts the PR it already opened ───────────────────────────────
    store, row, fake, app = _fresh()
    try:
        fake.head_pulls = [{"number": 901, "state": "open",
                            "html_url": "https://example.test/pull/901"}]
        out = deliver(app, store, row, _verdict(), [verified])
        assert out["fix_prs"] == [{"key": verified["key"],
                                   "branch": fix_branch_name(7, verified["key"]),
                                   "number": 901, "url": "https://example.test/pull/901",
                                   "adopted": True, "state": "open"}], out
        assert fake.created_pulls == [] and fake.commits == [], "adoption writes nothing"
    finally:
        store.close()

    # ── the PR head moved: refuse, and write nothing ───────────────────────────────
    store, row, fake, app = _fresh()
    try:
        fake.pulls[7]["head"]["sha"] = "f" * 40
        out = deliver(app, store, row, _verdict(), [verified])
        assert out["fix_error"] == "base_commit_stale", out
        assert out["fix_prs"] == [] and fake.commits == [] and fake.created_pulls == []
        assert fix_branch_name(7, verified["key"]) not in fake.refs
        assert out["check_run_id"] == 1, "the check run still landed"
    finally:
        store.close()

    scratch.cleanup()
    print("service.delivery: ok")


if __name__ == "__main__":
    demo()
