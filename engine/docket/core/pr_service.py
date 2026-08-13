"""Scan one pull request end to end, and watch a repository for more.

This is the seam between "which PR changed" (core/pr_watcher) and "what does that
mean" (core/pull_request, report/diff, report/pr_report). Everything below is trigger
agnostic on purpose: `scan_pull_request` does not know or care whether a webhook, a
poll, or an operator with curl asked for it. Swapping polling for a webhook later
replaces the caller and nothing here.

THE BASELINE IS THE EXPENSIVE PART
Comparing head against base means having a scan of base. Scanning it per pull request
would double the cost and most pull requests against a branch share the same base
commit, so it is cached by (repo, base_sha) and reused. That cache is what makes the
whole feature affordable; without it this is just two scans wearing a trenchcoat.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from docket.core.pr_watcher import PullRequestRef

logger = logging.getLogger(__name__)


@dataclass
class BaselineCache:
    """report.json for a (repo, base_sha), so a base is scanned once not per PR.

    Keyed on the commit, never the branch name: `main` moves, and a baseline from
    last week's main compared against today's head reports every intervening commit's
    findings as introduced by this pull request.
    """

    _by_key: dict[str, dict[str, Any]] = field(default_factory=dict)
    max_entries: int = 32

    @staticmethod
    def key(repo: str, sha: str) -> str:
        return f"{repo}@{sha}"

    def get(self, repo: str, sha: str) -> dict[str, Any] | None:
        return self._by_key.get(self.key(repo, sha))

    def put(self, repo: str, sha: str, report: dict[str, Any]) -> None:
        # Oldest out first. A long-lived watcher across many repos would otherwise
        # hold every base scan it ever ran.
        while len(self._by_key) >= self.max_entries:
            self._by_key.pop(next(iter(self._by_key)))
        self._by_key[self.key(repo, sha)] = report


@dataclass
class PullRequestOutcome:
    ref: PullRequestRef
    verdict: dict[str, Any]
    posted: dict[str, str] = field(default_factory=dict)
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None


def scan_pull_request(
    ref: PullRequestRef,
    *,
    token: str,
    fetch_files: Callable[[str, str, str, str], list[dict[str, Any]]],
    scan: Callable[..., dict[str, Any] | None],
    baselines: BaselineCache,
    post: Callable[..., dict[str, str]] | None = None,
    triage_max: int = 10,
    budget_usd: float | None = None,
    run_url: str | None = None,
) -> PullRequestOutcome:
    """Scan one pull request and, when `post` is given, publish the verdict.

    The callables are injected rather than imported so this is testable without a
    network or Docker — the interesting logic is the ordering and the short-circuits,
    and those are exactly what a live-only test would fail to cover.
    """
    from docket.core.pull_request import evaluate, plan_scan

    try:
        files = fetch_files(ref.repo, token, ref.base_sha, ref.head_sha)
    except Exception as exc:  # noqa: BLE001
        return PullRequestOutcome(ref, {}, error=f"could not read the diff: {exc}")

    plan = plan_scan(files)
    if not plan.worth_scanning:
        # A documentation-only pull request. Report a pass without starting a
        # container: proving that markdown has no SQL injection costs real seconds.
        verdict = {
            "exit_code": 0, "reason": "No files a static scanner reads were changed",
            "summary": "No scannable changes", "new": [], "fixed": [],
            "new_reachable": [], "trustworthy": True, "caveats": [],
            "scoped_to": [], "notes": plan.notes,
        }
        posted = post(ref, verdict) if post else {}
        return PullRequestOutcome(ref, verdict, posted)

    try:
        head_report = scan(repo=ref.repo, sha=ref.head_sha, paths=plan.paths,
                           triage_max=0, budget_usd=budget_usd)
        if head_report is None:
            raise RuntimeError("the head scan produced no report")

        # Base is cached by commit. Most pull requests against a branch share one.
        base_report = baselines.get(ref.repo, ref.base_sha)
        if base_report is None:
            # Triage is off for the baseline deliberately: nothing in it is reported,
            # it exists only to be subtracted, and judging it would double the bill.
            base_report = scan(repo=ref.repo, sha=ref.base_sha, paths=plan.paths,
                               triage_max=0, budget_usd=budget_usd)
            if base_report is not None:
                baselines.put(ref.repo, ref.base_sha, base_report)

        verdict = evaluate(base_report, head_report, plan)

        # Triage LAST, and only what the diff calls new. Running it before the diff
        # would judge the whole backlog on every push.
        if triage_max and verdict["new"]:
            head_report = scan(repo=ref.repo, sha=ref.head_sha, paths=plan.paths,
                               triage_max=min(triage_max, len(verdict["new"])),
                               budget_usd=budget_usd,
                               only=[f.get("id") for f in verdict["new"]]) or head_report
            verdict = evaluate(base_report, head_report, plan)
    except Exception as exc:  # noqa: BLE001
        return PullRequestOutcome(ref, {}, error=f"the scan failed: {exc}")

    posted = post(ref, verdict) if post else {}
    return PullRequestOutcome(ref, verdict, posted)


def watch_forever(
    repos: list[str],
    *,
    list_pulls: Callable[[str], tuple[Any, Any]],
    handle: Callable[[PullRequestRef], PullRequestOutcome],
    seen: Any,
    interval_sec: int = 30,
    should_stop: Callable[[], bool] = lambda: False,
    sleep: Callable[[float], None] = time.sleep,
) -> None:
    """Poll `repos` until told to stop. One pull request at a time, deliberately.

    Serial because a scan needs Docker and a sandbox, and two at once on a laptop is
    how a demo runs out of memory. A queue and a worker pool belong with the webhook,
    not here.
    """
    from docket.core.pr_watcher import due, parse_pulls, poll_interval

    while not should_stop():
        wait = interval_sec
        for repo in repos:
            if should_stop():
                return
            try:
                payload, headers = list_pulls(repo)
            except Exception as exc:  # noqa: BLE001 — one bad repo must not stop the rest
                logger.warning("could not list pull requests for %s: %s", repo, exc)
                continue

            wait = max(wait, poll_interval(headers, interval_sec))
            for ref in due(parse_pulls(repo, payload), seen):
                if should_stop():
                    return
                outcome = handle(ref)
                # Marked only on success. Recording a commit docket did not finish
                # scanning would skip that pull request forever.
                if outcome.ok:
                    seen.mark(ref)
                else:
                    logger.warning("pull request %s failed: %s", ref.key, outcome.error)
        sleep(wait)


def demo() -> None:
    from docket.core.pr_watcher import SeenStore

    ref = PullRequestRef(repo="o/r", number=1, base_sha="base1", head_sha="head1",
                         base_ref="main")

    def files_py(*_a):
        return [{"filename": "app.py", "status": "modified"}]

    def files_docs(*_a):
        return [{"filename": "README.md", "status": "modified"}]

    def report(findings, **kw):
        base = {"findings": findings, "success": True,
                "coverage": {"semgrep": {"files_scanned": 1}}}
        base.update(kw)
        return base

    def finding(rule, path="app.py", verdict=None):
        f = {"rule_id": rule, "severity": "high", "discovered_by": "semgrep",
             "location": {"method": "STATIC", "path": path, "parameter": None,
                          "source_file": f"{path}:1"}}
        if verdict:
            f["triage"] = {"verdict": verdict, "reasoning": "r", "evidence": "e"}
        return f

    # ── the baseline cache ──────────────────────────────────────────────────
    cache = BaselineCache()
    assert cache.get("o/r", "base1") is None
    cache.put("o/r", "base1", report([]))
    assert cache.get("o/r", "base1") is not None
    # Keyed on the COMMIT: a branch name moves, and a stale baseline would report
    # every intervening commit's findings as introduced by this pull request.
    assert cache.get("o/r", "base2") is None
    assert cache.get("other/repo", "base1") is None

    small = BaselineCache(max_entries=2)
    for i in range(5):
        small.put("o/r", f"s{i}", report([]))
    assert len(small._by_key) <= 2, "the cache must not grow without bound"

    # ── a docs-only PR never starts a container ─────────────────────────────
    started = []

    def scan_never(**kw):
        started.append(kw)
        return report([])

    out = scan_pull_request(ref, token="t", fetch_files=files_docs, scan=scan_never,
                            baselines=BaselineCache())
    assert out.ok and out.verdict["exit_code"] == 0
    assert started == [], "a markdown PR must not spin up Docker"

    # ── a real PR: base scanned once, then cached ───────────────────────────
    calls: list = []

    def scan_ok(**kw):
        calls.append((kw["sha"], kw.get("triage_max")))
        if kw["sha"] == "base1":
            return report([finding("old")])
        return report([finding("old"), finding("new", verdict="exploitable")])

    cache = BaselineCache()
    out = scan_pull_request(ref, token="t", fetch_files=files_py, scan=scan_ok,
                            baselines=cache, triage_max=0)
    assert out.ok, out.error
    assert out.verdict["exit_code"] == 2, out.verdict["reason"]
    assert len(out.verdict["new"]) == 1
    assert ("base1", 0) in calls, "the baseline is scanned with triage OFF"

    # A second pull request against the SAME base does not rescan it.
    calls.clear()
    ref2 = PullRequestRef(repo="o/r", number=2, base_sha="base1", head_sha="head2",
                          base_ref="main")
    scan_pull_request(ref2, token="t", fetch_files=files_py, scan=scan_ok,
                      baselines=cache, triage_max=0)
    assert all(sha != "base1" for sha, _ in calls), "the baseline must come from cache"

    # ── failures are reported, never silently passed ────────────────────────
    def scan_dies(**kw):
        raise RuntimeError("docker is not running")

    broken = scan_pull_request(ref, token="t", fetch_files=files_py, scan=scan_dies,
                               baselines=BaselineCache())
    assert not broken.ok and "docker is not running" in broken.error

    def files_die(*_a):
        raise RuntimeError("404")

    nodiff = scan_pull_request(ref, token="t", fetch_files=files_die, scan=scan_ok,
                               baselines=BaselineCache())
    assert not nodiff.ok and "could not read the diff" in nodiff.error

    # ── the watch loop ──────────────────────────────────────────────────────
    seen = SeenStore(None)
    handled: list = []

    def list_one(repo):
        return ([{"number": 1, "base": {"sha": "base1", "ref": "main"},
                  "head": {"sha": "head1"}, "draft": False}], {})

    def handle_ok(r):
        handled.append(r.key)
        return PullRequestOutcome(r, {"exit_code": 0})

    # Counted on POLLS, not on should_stop calls: the loop checks the predicate
    # several times per cycle, so counting calls would stop it mid-cycle and the test
    # would pass for the wrong reason.
    polls = {"n": 0}

    def counted(repo):
        polls["n"] += 1
        return list_one(repo)

    def stop_after_two():
        return polls["n"] >= 2

    watch_forever(["o/r"], list_pulls=counted, handle=handle_ok, seen=seen,
                  sleep=lambda _s: None, should_stop=stop_after_two)
    assert handled == ["o/r#1"], handled  # scanned once, then not due again

    # A failed scan is NOT marked, so the next poll retries it.
    seen2 = SeenStore(None)
    polls["n"] = 0
    attempts: list = []

    def handle_fail(r):
        attempts.append(r.key)
        return PullRequestOutcome(r, {}, error="boom")

    # Three polls, so there is room for two attempts before the loop is asked to
    # stop — the loop re-checks should_stop before each handle, which is correct
    # behaviour and would otherwise cut the second attempt.
    watch_forever(["o/r"], list_pulls=counted, handle=handle_fail, seen=seen2,
                  sleep=lambda _s: None, should_stop=lambda: polls["n"] >= 3)
    assert len(attempts) == 2, "a failure must be retried, not skipped forever"

    # One unreachable repo must not stop the others.
    polls["n"] = 0
    reached: list = []

    def list_flaky(repo):
        polls["n"] += 1
        if repo == "bad/repo":
            raise RuntimeError("network")
        reached.append(repo)
        return ([], {})

    watch_forever(["bad/repo", "good/repo"], list_pulls=list_flaky,
                  handle=handle_ok, seen=SeenStore(None), sleep=lambda _s: None,
                  should_stop=stop_after_two)
    assert "good/repo" in reached

    print("core.pr_service: ok")


if __name__ == "__main__":
    demo()
