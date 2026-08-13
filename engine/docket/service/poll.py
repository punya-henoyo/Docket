"""Find open pull requests worth scanning. One callable, driven by whoever wants to.

No thread, no asyncio loop, no scheduler. tick() is a single pass the console (or a cron
line, or a test) calls when it feels like it — which is the only version that is
debuggable, and the only version that cannot leak a background thread into a process
that already has an event loop.

Idempotent by construction: the work of not-scanning-twice is done by the UNIQUE index
on (repo, pr, head_sha) in store.py, so calling tick() in a loop with no new commits
writes nothing at all. That property is asserted, not assumed — see demo().

Polling rather than webhooks, deliberately: a webhook needs a public URL, a shared
secret, and a delivery-retry story before it works once, and docket runs on someone's
laptop. Webhooks are the upgrade, not the starting point.
"""
from __future__ import annotations

import logging
from typing import Any

# The one owner/repo check, imported rather than re-spelled: the value is interpolated
# into an api.github.com path, and two copies of a security regex is one copy too many.
from docket.interface.scm import _checked_repo

logger = logging.getLogger(__name__)

# GitHub's page cap. One page of most-recently-updated PRs is what a poll needs; a repo
# with more than 100 open PRs gets its oldest-updated ones on the next tick.
# ponytail: single page, ceiling is 100 open PRs per repo per tick. Paginate if a real
# repo hits it.
PER_PAGE = 100


def open_pull_requests(scm: Any, repo: str) -> list[dict]:
    return scm.get(f"/repos/{_checked_repo(repo)}/pulls"
                   f"?state=open&sort=updated&direction=desc&per_page={PER_PAGE}") or []


def tick(store: Any, scm: Any) -> dict:
    """One pass over every enabled watched repo. Returns a summary of what it found.

    A repo that fails (uninstalled App, deleted repo, rate limit) is recorded and the
    pass continues: one broken repo must not stop the other twenty from being scanned.
    """
    summary: dict[str, Any] = {"repos": 0, "pull_requests": 0, "enqueued": [], "errors": []}
    for watched in store.watched():
        repo = watched["full_name"]
        summary["repos"] += 1
        try:
            pulls = open_pull_requests(scm, repo)
        except Exception as exc:  # noqa: BLE001 — one repo's failure is not the tick's
            logger.warning("poll: %s failed: %s", repo, exc)
            summary["errors"].append({"repo": repo, "error": str(exc)})
            continue
        for pull in pulls:
            head = (pull.get("head") or {}).get("sha")
            number = pull.get("number")
            if not head or not number:
                continue  # a PR from a deleted fork can have no head
            summary["pull_requests"] += 1
            scan_id = store.enqueue(repo, number, head, (pull.get("base") or {}).get("sha"))
            if scan_id is not None:
                summary["enqueued"].append(scan_id)
    return summary


class _FakeScm:
    """Answers the one GET tick() makes, from a dict. Demos and tests only."""

    def __init__(self, pulls: dict[str, list[dict]], *, fail: tuple[str, ...] = ()) -> None:
        self.pulls = pulls
        self.fail = fail
        self.calls: list[str] = []

    def get(self, path: str) -> Any:
        self.calls.append(path)
        repo = "/".join(path.split("/")[2:4])
        if repo in self.fail:
            raise RuntimeError("HTTP 404: Not Found")
        return self.pulls.get(repo, [])


def _pull(number: int, sha: str, base: str = "b" * 40) -> dict:
    return {"number": number, "head": {"sha": sha, "ref": f"feature-{number}"},
            "base": {"sha": base, "ref": "main"}}


def demo() -> None:
    import tempfile
    from pathlib import Path

    from docket.service.store import Store, db_path

    with tempfile.TemporaryDirectory() as tmp:
        store = Store(db_path(cwd=Path(tmp)))
        try:
            store.watch("o/r")
            store.watch("o/paused", enabled=False)
            store.watch("o/gone")
            scm = _FakeScm({"o/r": [_pull(7, "a" * 40), _pull(8, "b" * 40)],
                            "o/paused": [_pull(1, "c" * 40)],
                            "o/gone": []}, fail=("o/gone",))

            first = tick(store, scm)
            assert first["repos"] == 2, first  # the disabled repo is never asked
            assert len(first["enqueued"]) == 2, first
            assert first["errors"] and first["errors"][0]["repo"] == "o/gone", first
            assert not any("o/paused" in call for call in scm.calls), scm.calls

            # Re-running with the same commits enqueues nothing AND writes nothing.
            before = store.db.execute("SELECT id, updated_at FROM pr_scans").fetchall()
            again = tick(store, scm)
            assert again["enqueued"] == [], again
            assert again["pull_requests"] == 2, again
            after = store.db.execute("SELECT id, updated_at FROM pr_scans").fetchall()
            assert [tuple(r) for r in before] == [tuple(r) for r in after], "a re-poll must not touch rows"

            # A new commit on the same PR is new work: the fix has to be re-checked.
            scm.pulls["o/r"] = [_pull(7, "d" * 40), _pull(8, "b" * 40)]
            third = tick(store, scm)
            assert len(third["enqueued"]) == 1, third
            assert len(store.scans(repo="o/r")) == 3
        finally:
            store.close()
    print("service.poll: ok")


if __name__ == "__main__":
    demo()
