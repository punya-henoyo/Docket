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


def _report_on_disk(repo: str, sha: str,
                    needed_paths: list[str] | None = None) -> dict[str, Any] | None:
    """A previously written report.json for exactly this commit, or None.

    Never raises: a baseline that cannot be read is a baseline that gets re-scanned,
    which is slow but correct. Failing the pull request over a stale artifact would not be.
    """
    import json

    from docket.core.paths import runs_root

    try:
        root = runs_root()
        prefix = f"pr-{repo.replace('/', '-')}-{sha[:7]}"
        # Newest first: the same commit may have been scanned as a head AND as a base.
        candidates = sorted((p for p in root.glob(f"{prefix}*") if p.is_dir()),
                            key=lambda p: p.stat().st_mtime, reverse=True)
    except OSError:
        return None

    wanted = {str(p) for p in (needed_paths or [])}
    for directory in candidates:
        try:
            report = json.loads((directory / "report.json").read_text())
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(report, dict):
            continue
        # The 7-character prefix in the directory name is not proof of identity. The
        # target carries the FULL sha, and a baseline attributed to the wrong commit is
        # worse than no baseline: it reports someone else's findings as this change's.
        if not str(report.get("target", "")).endswith(f"@{sha}"):
            continue
        # An incomplete scan is not a baseline. Its missing findings would read as
        # "fixed" on one side and its absent coverage as "new" on the other.
        if report.get("success") is not True:
            continue
        covered = report.get("scanned_paths")
        # None = whole tree, covers anything. Otherwise it must be a superset.
        if covered is not None and not wanted.issubset({str(p) for p in covered}):
            continue
        logger.info("reusing the scan of %s@%s from %s", repo, sha[:7], directory.name)
        return report
    return None


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

    def get(self, repo: str, sha: str,
            needed_paths: list[str] | None = None) -> dict[str, Any] | None:
        """The cached baseline for this commit, from memory or from disk.

        The disk half is the point. This cache used to be memory-only, so every console
        restart threw away every baseline and the next pull request paid a full scan of a
        commit already sitting in docket_runs. Worse, a commit is routinely scanned twice
        for unrelated reasons — dd9fc5d was #26's HEAD and #27's BASE — and the second
        scan learned nothing the first had not already written down.

        A head report is reusable as a baseline: a baseline needs deterministic scanner
        findings, and a head report has those plus recon and triage on top.

        THE ONE THING THAT MAKES REUSE UNSAFE, AND THE CHECK FOR IT
        ----------------------------------------------------------
        Scope. A report written while scoped to app.py contains no utils.py findings, so
        standing it in for a pull request that touches utils.py would make every
        pre-existing finding there read as introduced by that change. A cached report is
        therefore only accepted when it covered AT LEAST the paths this caller needs
        (`scanned_paths is None` means the whole tree, which covers everything).
        """
        hit = self._by_key.get(self.key(repo, sha))
        if hit is not None:
            return hit
        found = _report_on_disk(repo, sha, needed_paths)
        if found is not None:
            # Promote to memory so a repeat within one process does not re-read the file.
            self.put(repo, sha, found)
        return found

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
    recon: bool = True,
) -> PullRequestOutcome:
    """Scan one pull request and, when `post` is given, publish the verdict.

    The callables are injected rather than imported so this is testable without a
    network or Docker — the interesting logic is the ordering and the short-circuits,
    and those are exactly what a live-only test would fail to cover.
    """
    from docket.core.pull_request import _touches_change, evaluate, plan_scan
    from docket.report.diff import finding_key

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
        # THE BASE COMES FIRST, AND THAT IS THE WHOLE POINT OF THIS ORDER.
        #
        # It used to run second, which forced a THIRD pass: scan head with triage off,
        # diff it, then scan head ALL OVER AGAIN — new container, semgrep, trivy and
        # recon — purely to attach triage verdicts. Measured on vulnshop#26: 204s + 128s
        # + 843s, where the third pass was 72% of a twenty-minute check.
        #
        # With the baseline in hand before the head runs, `triage_filter` below tells the
        # single head pass which of its own findings are new, so triage happens inside it.
        # One container, one fetch, one recon.
        base_report = baselines.get(ref.repo, ref.base_sha, plan.paths)
        # needed_paths, so a cached report is only reused when it actually covered the
        # files this pull request touches. Without it a baseline scoped to another PR's
        # files would report every pre-existing finding here as newly introduced.
        base_report = baselines.get(ref.repo, ref.base_sha, plan.paths)
        if base_report is None:
            # Triage is off for the baseline deliberately: nothing in it is reported,
            # it exists only to be subtracted, and judging it would double the bill.
            # Recon is NOT run on base. It doubled the wall clock — two agent runs
            # per pull request, six to ten minutes — and the comparison it bought was
            # non-deterministic anyway: recon phrases candidates afresh each run, so
            # the same code produced different candidates on the two sides and the
            # difference read as findings introduced by the change.
            #
            # Scoping candidates to the CHANGED FILES replaces it, and is a stronger
            # signal: "this is in a file you changed" is a fact, where "recon did not
            # mention it last time" is an agent's phrasing.
            # role="base": this commit may also be some pull request's HEAD, and the two
            # scans use different settings. Sharing one run directory meant the later
            # one silently destroyed the earlier one's report. See _scan_for_pr.
            base_report = scan(repo=ref.repo, sha=ref.base_sha, paths=plan.paths,
                               triage_max=0, budget_usd=budget_usd, recon=False,
                               role="base")
            if base_report is not None:
                baselines.put(ref.repo, ref.base_sha, base_report)

        # Triage still judges ONLY what this change introduced — the rule has not
        # changed, only where it is applied. A finding is worth paying to judge when it
        # is absent from the baseline AND sits on a line this pull request touched;
        # anything else the diff would discard afterwards, so judging it is money spent
        # on a verdict nobody reads. Both conditions come from the same helpers `evaluate`
        # uses, so the filter and the diff cannot drift apart.
        baseline_keys = {finding_key(f) for f in ((base_report or {}).get("findings") or [])}

        def is_new_here(finding: dict[str, Any]) -> bool:
            if finding_key(finding) in baseline_keys:
                return False
            if plan.scoped and plan.lines:
                return _touches_change(finding, plan.lines)
            return True

        head_report = scan(repo=ref.repo, sha=ref.head_sha, paths=plan.paths,
                           triage_max=triage_max, budget_usd=budget_usd, recon=recon,
                           triage_filter=is_new_here)
        if head_report is None:
            raise RuntimeError("the head scan produced no report")

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

    # ── recon runs on HEAD only ─────────────────────────────────────────────
    # Running it on both doubled the wall clock to six-plus minutes per pull request,
    # and bought a non-deterministic comparison: recon phrases candidates afresh, so
    # the same code yielded different candidates on the two sides. Scoping candidates
    # to the changed files replaces it — a fact rather than an agent's phrasing.
    sides: list = []

    def scan_sides(**kw):
        sides.append((kw["sha"], kw.get("recon")))
        return report([])

    scan_pull_request(ref, token="t", fetch_files=files_py, scan=scan_sides,
                      baselines=BaselineCache(), triage_max=0, recon=True)
    assert dict(sides) == {"head1": True, "base1": False}, sides

    sides.clear()
    scan_pull_request(ref, token="t", fetch_files=files_py, scan=scan_sides,
                      baselines=BaselineCache(), triage_max=0, recon=False)
    assert {r for _, r in sides} == {False}, sides

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

    # ── ONE head pass per pull request ─────────────────────────────────────────
    # The head used to be scanned twice: once with triage off to learn what was new,
    # then the whole pipeline again — container, semgrep, trivy, recon — to attach
    # verdicts. On vulnshop#26 that second head pass was 843s of a 1175s check.
    calls: list[dict[str, Any]] = []

    def counting_scan(**kw):
        calls.append(kw)
        sha = kw["sha"]
        return {"findings": [{"rule_id": "semgrep/sqli", "severity": "high",
                              "discovered_by": "semgrep",
                              "location": {"method": "STATIC", "path": "app.py",
                                           "parameter": None, "source_file": "app.py:7"},
                              "poc": {"request": "x"}}] if sha == "h" * 40 else [],
                "success": True, "coverage": {"semgrep": {"files_scanned": 1}}}

    ref = PullRequestRef(repo="o/r", number=1, head_sha="h" * 40, base_sha="b" * 40,
                         title="t", base_ref="main")
    out = scan_pull_request(
        ref, token="t",
        fetch_files=lambda *a, **k: [{"filename": "app.py", "status": "modified",
                                      "patch": "@@ -1,2 +1,3 @@\n+bad\n"}],
        scan=counting_scan, baselines=BaselineCache(), triage_max=5, post=None)
    heads = [c for c in calls if c["sha"] == "h" * 40]
    assert len(heads) == 1, f"the head must be scanned ONCE, got {len(heads)}"
    assert heads[0]["triage_max"] == 5, heads[0]["triage_max"]
    assert callable(heads[0].get("triage_filter")), "triage needs the new-finding filter"
    assert out.error is None, out.error

    # The filter is what keeps triage off the backlog. A finding already in the baseline
    # is not new here, whatever its severity.
    keep = heads[0]["triage_filter"]
    fresh = {"rule_id": "semgrep/sqli", "severity": "high", "discovered_by": "semgrep",
             "location": {"method": "STATIC", "path": "app.py", "parameter": None,
                          "source_file": "app.py:2"},
             "poc": {"request": "x"}}
    assert keep(fresh), "a finding on a changed line, absent from base, is new"
    old = dict(fresh, location=dict(fresh["location"], source_file="app.py:900"))
    assert not keep(old), "a finding outside the changed lines is not this change's"

    # ── reuse a scan already on disk instead of paying for it again ────────────
    import json as _json
    import tempfile

    from docket.core import paths as _paths

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        original = _paths.runs_root
        _paths.runs_root = lambda **_k: root  # type: ignore[assignment]
        try:
            sha = "c" * 40

            def write(dirname: str, *, target_sha: str, ok: bool,
                      paths: list[str] | None) -> None:
                d = root / dirname
                d.mkdir(parents=True, exist_ok=True)
                (d / "report.json").write_text(_json.dumps({
                    "target": f"github:o/r@{target_sha}", "success": ok,
                    "scanned_paths": paths, "findings": [],
                }))

            cache = BaselineCache()
            assert cache.get("o/r", sha, ["app.py"]) is None, "nothing on disk yet"

            # A head scan of this very commit, scoped to app.py, is a valid baseline for
            # a pull request that touches app.py. This is the #26-head / #27-base case.
            write("pr-o-r-ccccccc", target_sha=sha, ok=True, paths=["app.py"])
            assert cache.get("o/r", sha, ["app.py"]) is not None, "must reuse the scan"
            # ...and it is promoted to memory, so the file is read once.
            assert cache._by_key.get(BaselineCache.key("o/r", sha)) is not None

            # THE TRAP: narrower scope must NOT be reused. A report that only looked at
            # app.py has no utils.py findings, so standing it in for a pull request that
            # touches utils.py would report every pre-existing finding there as new.
            assert BaselineCache().get("o/r", sha, ["utils.py"]) is None, \
                "a baseline that never scanned utils.py cannot serve as one for it"

            # An unscoped report covers everything.
            write("pr-o-r-ccccccc-base", target_sha=sha, ok=True, paths=None)
            assert BaselineCache().get("o/r", sha, ["utils.py"]) is not None

            # A short-sha directory collision must not be trusted: the full sha in
            # `target` is the identity, and the wrong commit's findings would be
            # attributed to this change.
            other = "c" * 39 + "d"
            for d in root.glob("pr-o-r-*"):
                (d / "report.json").write_text(_json.dumps({
                    "target": f"github:o/r@{other}", "success": True,
                    "scanned_paths": None, "findings": [],
                }))
            assert BaselineCache().get("o/r", sha, ["app.py"]) is None, \
                "a 7-char prefix match is not proof of identity"

            # An incomplete scan is not a baseline.
            for d in root.glob("pr-o-r-*"):
                (d / "report.json").write_text(_json.dumps({
                    "target": f"github:o/r@{sha}", "success": False,
                    "scanned_paths": None, "findings": [],
                }))
            assert BaselineCache().get("o/r", sha, ["app.py"]) is None, \
                "a scan that did not complete cannot be subtracted from anything"

            # Unreadable JSON is skipped, never raised: a bad artifact costs a re-scan.
            for d in root.glob("pr-o-r-*"):
                (d / "report.json").write_text("{ not json")
            assert BaselineCache().get("o/r", sha, ["app.py"]) is None
        finally:
            _paths.runs_root = original  # type: ignore[assignment]

    print("core.pr_service: ok")


if __name__ == "__main__":
    demo()
