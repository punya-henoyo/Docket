"""GitHub connect: authorize -> pick a repo -> fetch source read-only -> scan it.

This is the hosted-product surface, not the CLI. A customer opens the console, clicks
Connect GitHub, authorizes, and picks repositories; docket pulls each one read-only and
runs the deterministic scanners (trivy + semgrep) against it.

AN OAUTH APP, AND WHAT THAT COSTS
---------------------------------
Register an OAuth App (Developer settings -> OAuth Apps), callback
http://127.0.0.1:8765/auth/callback.

The user authorizes once and docket can scan every repository they can reach,
INCLUDING ones they only collaborate on, with no repository owner installing
anything. That reach is the product requirement, and only an OAuth App delivers it.

The price is real: GitHub has NO read-only scope for private code. `repo` grants read
AND WRITE; there is no `repo:read`. Docket only ever reads — it clones nothing, pushes
nothing, opens no branches, and fetch_source() below pulls a tarball precisely so
there is no remote to push to — but the token it holds could write. A leaked token is
therefore worse than the access actually used, which raises the bar on the token
storage this module does not yet have.

A GitHub App would have been read-only (`contents: read`), at the cost of every
repository OWNER having to install it first; a collaborator cannot grant access to a
repo they do not own. That path was removed deliberately: it made onboarding depend on
someone other than the person connecting.

WHAT THIS IS NOT
----------------
Single-tenant and in-memory: one operator, on their own machine, holding one token.
There is no user table, no encryption at rest, no tenant isolation. Do not point this
at real customers as-is.
# ponytail: in-memory single-tenant session, ceiling is "one operator on localhost".
# Multi-tenant needs a real session store, per-tenant token encryption, and a job queue
# (a scan takes minutes and needs Docker, so it cannot run inside a request handler).
"""
from __future__ import annotations

import json
import logging
import os
import re
import secrets
import shutil
import tarfile
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

from docket.tools.scanners import read_coverage
from docket.utils.resource_paths import frontend_dir

logger = logging.getLogger(__name__)

GITHUB_AUTHORIZE = "https://github.com/login/oauth/authorize"
GITHUB_TOKEN = "https://github.com/login/oauth/access_token"
GITHUB_API = "https://api.github.com"

# "owner/repo" exactly. Anything else never reaches a URL or the filesystem: this value
# arrives from the browser and is interpolated into an api.github.com path, so a stray
# "../" or scheme here would be a path-traversal / SSRF primitive.
#
# The lookaheads reject a segment that is "." or "..", and they are load-bearing rather
# than belt-and-braces: the char class allows dots, because `owner/.github` is a real
# repository, and WITHOUT them "../evil" matched this pattern in full. It reached
# `/repos/../evil/pulls` — urllib sends a path literally, so what that resolves to is up
# to whatever normalises it next. The demo only tested three-segment traversals
# ("../../etc/passwd"), which the single slash already rejects, so the two-segment case
# went unnoticed. `..` in a REF has always been refused explicitly (valid_ref below);
# this is the same refusal on the other half of every URL built here.
_FULL_NAME = re.compile(r"^(?!\.\.?/)[A-Za-z0-9._-]+/(?!\.\.?$)[A-Za-z0-9._-]+$")

# A git ref: branch, tag or commit SHA. Slashes are legal and common ("feat/x"), which
# is exactly why this needs its own check rather than reusing _FULL_NAME — it is
# interpolated into the same API path, so "..", a leading "-" (which a shell or CLI
# could read as a flag) and empty segments are all rejected explicitly.
_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]*$")


# A run name is a directory name under docket_runs/ and arrives from the browser.
# sanitize_run_name() already restricts what gets written; this restricts what can be
# read back.
_RUN_NAME = re.compile(r"^[A-Za-z0-9._-]+$")


def valid_ref(ref: str) -> bool:
    return bool(_REF.match(ref)) and ".." not in ref and not ref.endswith("/") and "//" not in ref

# GitHub caps a tarball at a few hundred MB; refuse anything absurd rather than filling
# the disk of whoever runs this.
MAX_TARBALL_BYTES = 512 * 1024 * 1024

# No ceiling on triage count, deliberately. The operator chooses how many findings to
# triage; capping by COUNT here would only be a proxy for the thing actually worth
# bounding, which is money. DOCKET_MAX_COST_USD is the real stop, checked before every
# model turn (core/hooks.py) — and it stops mid-run rather than pre-emptively refusing
# a number that might have been affordable.
#
# That gate only became real once DOCKET_PRICE_*_PER_1M was set: LiteLLM cannot price
# an Azure deployment name, so an unpriced model reports $0.00 and the budget silently
# enforces nothing. Unpriced + unbounded count is genuinely unbounded spend.


# A scan in one of these has not finished. Used both to decide whether to refresh
# usage on read and to answer "is anything running", so the two can never disagree.
LIVE_STATUSES = ("queued", "fetching", "scanning")


def active_scans() -> list[dict[str, Any]]:
    """Scans still running, newest first.

    Exists so the console can find a live scan it has lost track of. The browser held
    the only reference to a running scan in React state, so opening a historical run
    replaced it and the scan became unreachable — still running, still spending, with
    no way back to it. A reload or a second tab had the same problem.
    """
    with SESSION.lock:
        return [
            {"id": scan_id, "repo": state.get("repo"), "ref": state.get("ref"),
             "status": state.get("status"), "started_at": state.get("started_at")}
            for scan_id, state in SESSION.scans.items()
            if state.get("status") in LIVE_STATUSES
        ]


# Verdicts kept in memory for the console. Enough to demonstrate a watcher running
# for hours without growing without bound; the durable record is report.json on disk.
MAX_WATCH_RESULTS = 50


def watch_state() -> dict[str, Any]:
    """A JSON-safe snapshot of the watcher for the console."""
    with SESSION.lock:
        state = dict(SESSION.watch)
        state["results"] = list(state.get("results") or [])
    return state


def record_watch_result(ref: Any, verdict: dict[str, Any], posted: dict[str, str],
                        error: str | None = None, scanning: bool = False) -> None:
    """Record a pull request's state: in progress, or the finished verdict.

    Called TWICE per pull request — once when the scan starts and once when it ends —
    because a scan takes minutes and a screen that shows nothing for minutes reads as
    broken. The second call replaces the first rather than appending.
    """
    entry = {
        "repo": getattr(ref, "repo", "?"),
        "number": getattr(ref, "number", 0),
        "title": getattr(ref, "title", ""),
        "head_sha": (getattr(ref, "head_sha", "") or "")[:7],
        "base_ref": getattr(ref, "base_ref", ""),
        "at": time.time(),
        "scanning": scanning,
        "error": error,
        "exit_code": verdict.get("exit_code"),
        "reason": verdict.get("reason", ""),
        "new": len(verdict.get("new") or []),
        "reachable": len(verdict.get("new_reachable") or []),
        "fixed": len(verdict.get("fixed") or []),
        "trustworthy": verdict.get("trustworthy", False),
        "posted": posted,
        # Enough of each finding to render a row without holding the whole report.
        "findings": [
            {"rule_id": f.get("rule_id"), "title": f.get("title"),
             "severity": f.get("severity"), "discovered_by": f.get("discovered_by"),
             "where": str((f.get("location") or {}).get("source_file") or "")
                      .replace("/work/source/", ""),
             "verdict": (f.get("triage") or {}).get("verdict")}
            for f in (verdict.get("new") or [])[:12]
        ],
    }
    with SESSION.lock:
        results = SESSION.watch.setdefault("results", [])
        for index, existing in enumerate(results):
            if (existing.get("repo"), existing.get("number"),
                    existing.get("head_sha")) == (entry["repo"], entry["number"],
                                                  entry["head_sha"]):
                results[index] = entry     # the in-progress row becomes the verdict
                return
        results.insert(0, entry)
        del results[MAX_WATCH_RESULTS:]


_WATCH_THREAD: threading.Thread | None = None
_WATCH_STOP = threading.Event()


def _scan_for_pr(*, repo: str, sha: str, paths: list[str], triage_max: int,
                 budget_usd: float | None = None, only: list | None = None,
                 recon: bool = False) -> dict[str, Any] | None:
    """Fetch a commit and scan it, returning report.json. Used for both sides of a diff.

    A pull request scan is a normal scan with two differences: it is pinned to a
    commit rather than a branch, and semgrep is scoped to the changed files.
    """
    from docket.core.paths import run_path
    from docket.core.runner import run_scan
    from docket.report.dedupe import FindingStore
    from docket.report.writer import write_report

    token = SESSION.token
    if not token:
        raise RuntimeError("GitHub is not connected")

    workdir = Path(tempfile.mkdtemp(prefix="docket-pr-"))
    run_name = f"pr-{repo.replace('/', '-')}-{sha[:7]}"
    store = FindingStore()
    try:
        source = fetch_source(repo, token, workdir, sha)
        result = run_scan(
            target_url=None, whitebox_path=str(source), run_name=run_name,
            use_sandbox=True, store=store, static_only=True,
            triage_max=triage_max, recon=recon, scope_paths=paths,
            budget_usd=budget_usd, on_finding=store.add,
        )
        out_dir = run_path(run_name)
        write_report(store, out_dir, run_name=run_name,
                     target=f"github:{repo}@{sha}",
                     coverage=read_coverage(out_dir / "sandbox"),
                     summary=result.summary, cost_usd=result.cost_usd,
                     agents_spawned=result.agents_spawned, success=result.success)
        return json.loads((out_dir / "report.json").read_text())
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def open_fix_pr(full_name: str, token: str, *, base_sha: str, base_ref: str,
                path: str, content: str, title: str, body: str,
                branch: str) -> dict[str, Any]:
    """Create a branch, commit one file, open a pull request. Returns the PR payload.

    Uses the contents API rather than git so no clone, no working tree and no
    credential helper are involved — docket already holds a token and this is three
    calls.
    """
    import base64

    if not _FULL_NAME.match(full_name):
        raise ValueError(f"refusing suspicious repository name: {full_name!r}")
    if not valid_ref(branch) or not valid_ref(base_ref):
        raise ValueError("refusing suspicious branch name")

    # Branch from the exact commit that was scanned and verified, never from the tip
    # of base — the tip may have moved since, and the proof applies to what was tested.
    _api(f"/repos/{full_name}/git/refs", token,
         body={"ref": f"refs/heads/{branch}", "sha": base_sha})

    existing = _api(f"/repos/{full_name}/contents/{path}?ref={branch}", token)
    _api(f"/repos/{full_name}/contents/{path}", token, method="PUT", body={
        "message": title,
        "content": base64.b64encode(content.encode()).decode(),
        "sha": (existing or {}).get("sha"),
        "branch": branch,
    })

    return _api(f"/repos/{full_name}/pulls", token, body={
        "title": title, "body": body, "head": branch, "base": base_ref,
    })


def _repo_relative(finding: dict[str, Any]) -> dict[str, Any]:
    """The same finding with container paths rebased to repo-relative.

    Semgrep runs inside the sandbox, so it reports `/work/source/app.py:66`.
    `report.writer.parse_source_file` rejects any path starting with "/" (it cannot tell a
    route from a file), so service/fix.py's `_fixable` saw no anchor and skipped EVERY
    finding a sandboxed scan produced — the autofix would report "nothing to fix" on a
    verdict full of patchable findings. core/remediation.py:attempt_fix already stripped
    this prefix inline; this is the same strip, hoisted so both paths share it.
    """
    location = dict(finding.get("location") or {})
    for field_name in ("source_file", "path"):
        if isinstance(location.get(field_name), str):
            location[field_name] = location[field_name].replace("/work/source/", "")
    return finding | {"location": location}


def autofix_target_key(finding: dict[str, Any]) -> tuple[str, str, int] | None:
    """`(rule_id, repo-relative file, line)` — what validate_patch calls a target key."""
    from docket.report.writer import parse_source_file

    parsed = parse_source_file((_repo_relative(finding).get("location") or {})
                               .get("source_file"))
    if not parsed or not finding.get("rule_id"):
        return None
    return (str(finding["rule_id"]), parsed[0], parsed[1])


def autofix_scope_keys(findings: list[dict[str, Any]]) -> list[tuple[str, str, int]]:
    """Every scanner key this pull request INTRODUCED — `validate_patch(in_scope_keys=)`.

    `merged_rules` is expanded, not ignored: `report/dedupe.merge_static` folds the several
    rules that match one line into a single Finding carrying one `rule_id` and the rest in
    `merged_rules`, and validate_patch compares against raw semgrep keys where all of them
    are separate. Without the expansion the four rules that fire on vulnshop#20's
    `cur.execute(... % code)` would arrive as one in-scope key, three of the four hits the
    fix legitimately clears would read as collateral, and gate 3 would refuse it.
    """
    keys: list[tuple[str, str, int]] = []
    for finding in findings:
        key = autofix_target_key(finding)
        if key is None:
            continue
        rules = [str(r) for r in (finding.get("merged_rules") or []) if r] or [key[0]]
        keys.extend((rule, key[1], key[2]) for rule in rules)
    return keys


def attempt_autofix(ref: Any, verdict: dict[str, Any], *,
                    dry_run: bool = False) -> dict[str, Any]:
    """Try to fix what a pull request introduced, and open a PR only if it is PROVEN.

    Only findings from a deterministic scanner are attempted. An agent candidate like
    "no authorization on /orders" has no single line to replace and its fix is a design
    decision; proposing a patch for it would be guessing at architecture.

    TWO THINGS CHANGED HERE, AND BOTH ARE THE POINT
    -----------------------------------------------
    1. THE PROOF IS `service/validate.py`, NOT A SECOND `run_scan`. What this used to do
       was call `core.remediation.attempt_fix` with a `rescan` closure that ran a full
       `run_scan(use_sandbox=True)` over the patched tree — TWICE per finding, each one a
       container start, a trivy pass and a semgrep pass, to answer one narrow question.
       `service/fix.fix_findings` already answers it: it copies the tree per finding so
       the pristine one is never written, routes every byte through
       `source_write.propose_edit` (which strips `NN: ` display prefixes, refuses an
       ambiguous anchor, denies `.github/`, `.env*`, `*.pem`, `*.key` and lockfiles,
       refuses a reformat-only change and refuses an added `# nosemgrep`), derives the
       diff by comparing the two trees rather than believing the model, and hands both
       trees to `validate_patch` — seven gates, semgrep host-side via uvx, no Docker.
       Fewer moving parts, no container, and the suppression refusal that no scanner
       comparison can ever catch by itself.
    2. THE PULL REQUEST IS OPENED BY `service/delivery.py:_fix_pr`, not by `open_fix_pr`
       below. `_fix_pr` READS FIRST — `GET /pulls?head=owner:branch&state=all` — so a
       re-run adopts its own branch instead of littering the repo, refuses
       `base_commit_stale` when the pull request has moved off the commit that was
       validated, and takes its base from the pull request's OWN head branch so the fix
       merges into it rather than competing with it against main. `open_fix_pr` does none
       of those three: it mints a random branch suffix every call, never re-reads the
       head sha, and falls back to `base_ref or "main"`.

    `dry_run=True` does everything except the write: same fetch, same agent, same seven
    gates, and it returns what WOULD have been opened. Nothing reaches GitHub.
    """
    from functools import partial

    from docket.config.settings import Config
    from docket.core.paths import run_path
    from docket.report.diff import DETERMINISTIC_SOURCES
    from docket.service.fix import VERIFIED, fix_findings
    from docket.service.validate import validate_patch

    token = SESSION.token
    if not token:
        return {"opened": False, "note": "GitHub is not connected"}

    fixable = [_repo_relative(f) for f in (verdict.get("new") or [])
               if str(f.get("discovered_by", "")) in DETERMINISTIC_SOURCES]
    if not fixable:
        return {"opened": False,
                "note": "nothing a patch can address — the new findings are design "
                        "issues, not single lines"}

    workdir = Path(tempfile.mkdtemp(prefix="docket-fix-"))
    try:
        source = fetch_source(ref.repo, token, workdir, ref.head_sha)
        run_dir = run_path(f"autofix-{ref.repo.replace('/', '-')}-{ref.number}-"
                           f"{ref.head_sha[:7]}")
        # THE SCOPE IS WHY THIS VERIFIES AT ALL — see validate_patch's docstring. Gate 2
        # is file-level by default, so on any file with a pre-existing finding of the same
        # rule (vulnshop's app.py has four) a CORRECT fix reports not_fixed and nothing
        # can ever ship. `verdict["new"]` is exactly the set the pull request introduced,
        # which is exactly the set the patch is allowed to clear. `validate` is already an
        # injectable seam in fix_findings, so this needs no change there.
        validate = partial(validate_patch, in_scope_keys=autofix_scope_keys(fixable))
        # max_fixes=1: one finding per pull request per pass. The watcher runs again on
        # the next push, and a reviewer reads one small diff sooner than three.
        patches = fix_findings({"findings": fixable}, source_root=source,
                               run_dir=run_dir, config=Config.from_env(), max_fixes=1,
                               validate=validate)
        if not patches:
            return {"opened": False,
                    "note": "no finding carried a file:line anchor to patch"}

        patch = patches[0]
        result: dict[str, Any] = {
            "opened": False, "status": patch.status, "key": patch.key,
            "outcome": patch.outcome, "validation": patch.validation,
            "note": patch.summary, "dry_run": dry_run,
            "files": [c["path"] for c in patch.files],
        }
        if patch.status != VERIFIED:
            # unverified_plausible is DISPLAY ONLY and is labelled as such here, at the
            # one place a caller reads: a pull request is the wrong vehicle for a patch
            # nobody re-tested, because a diff in a review queue reads as "this is the
            # fix" whatever the description says.
            result["note"] = f"{patch.status} (NOT verified): {patch.summary}"
            return result
        if dry_run:
            result["note"] = f"verified_fixed, not opened (dry run): {patch.summary}"
            return result

        from docket.interface.scm import GitHubApp
        from docket.service.delivery import _fix_pr

        # OAuth mode: everything _fix_pr needs — reads, a branch, a commit, a pull
        # request — is writable by a user-to-server token with the `repo` scope. Only
        # check runs are not, and _fix_pr creates none.
        opened = _fix_pr(GitHubApp(oauth_token=token), ref.repo, int(ref.number),
                         ref.head_sha, patch, patch.key)
        return result | {"opened": True, "url": opened.get("url"),
                         "number": opened.get("number"),
                         "adopted": opened.get("adopted"),
                         "branch": opened.get("branch"),
                         "note": ("adopted the existing fix PR" if opened.get("adopted")
                                  else patch.summary)}
    except Exception as exc:  # noqa: BLE001 — a failed fix must not sink the verdict
        return {"opened": False, "note": f"{type(exc).__name__}: {exc}"}
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def _post_for_pr(ref: Any, verdict: dict[str, Any]) -> dict[str, str]:
    if not SESSION.token:
        return {"status": "skipped: not connected"}
    return post_pr_result(
        ref.repo, SESSION.token, pr_number=ref.number, head_sha=ref.head_sha,
        verdict=verdict, run_url=None,
    )


def _watch_loop() -> None:
    """Poll watched repositories until stopped. Runs on its own thread."""
    from docket.core.paths import runs_root
    from docket.core.pr_service import BaselineCache, scan_pull_request, watch_forever
    from docket.core.pr_watcher import SeenStore

    baselines = BaselineCache()
    seen = SeenStore(runs_root() / ".pr-seen.json")

    def list_pulls(repo: str):
        # Stamped here, not in sleeper(): a cycle that starts a multi-minute scan does
        # not reach sleeper for minutes, so "last checked" sat at never while docket
        # was demonstrably working.
        with SESSION.lock:
            SESSION.watch["last_poll"] = time.time()
        payload = _api(f"/repos/{repo}/pulls?state=open&per_page=50", SESSION.token)
        # Reconcile the board against reality. A pull request closed or merged on GitHub
        # vanishes from this list, and nothing else ever writes its row again — so an
        # in-progress row for it sat at `scanning: true` forever, claiming to be working
        # on something that no longer exists. This is the only place the open set is
        # known, so it is the only place that can tell.
        open_numbers = {int(pr.get("number")) for pr in (payload or [])
                        if isinstance(pr, dict) and str(pr.get("number", "")).isdigit()}
        with SESSION.lock:
            for row in SESSION.watch.get("results") or []:
                if row.get("repo") != repo or not row.get("scanning"):
                    continue
                if int(row.get("number") or 0) in open_numbers:
                    continue
                # Not an error and not a verdict: nobody judged this code. Saying
                # "closed" is the honest record; calling it clean would be a lie, and
                # leaving it spinning was the bug.
                row["scanning"] = False
                row["reason"] = "the pull request was closed or merged before the scan finished"
                row["exit_code"] = None
        return payload, {}

    from docket.core.pr_service import PullRequestOutcome

    def handle(ref):
        record_watch_result(ref, {}, {}, scanning=True)
        # EVERYTHING between the two record_watch_result calls is guarded, because
        # `scanning` is cleared ONLY by the second one and nothing else ever writes it.
        # A raise in between left the row reading `scanning: true, error: null` forever —
        # a dead scan and a slow scan were indistinguishable on screen, which is the same
        # fail-open as a scanner whose crash reads as a clean result. Worse, watch_forever
        # has no handler around handle(), so the exception also killed the watcher thread
        # and every later pull request went unscanned in silence.
        try:
            outcome = scan_pull_request(
                ref, token=SESSION.token or "", fetch_files=changed_files,
                scan=_scan_for_pr, baselines=baselines, post=_post_for_pr,
                triage_max=int(SESSION.watch.get("triage_max") or 5),
            )
            posted = dict(outcome.posted)
            # Only on a blocking verdict. Opening a fix PR for a check that passed is
            # noise, and the whole point of blocking is that something needs doing.
            if (outcome.ok and outcome.verdict.get("exit_code") == 2
                    and SESSION.watch.get("autofix")):
                fix = attempt_autofix(ref, outcome.verdict)
                posted["autofix"] = (f"opened #{fix['number']}" if fix.get("opened")
                                     else f"not opened — {fix.get('note', '')}"[:120])
        except Exception as exc:  # noqa: BLE001 — one bad PR must not sink the watcher
            logger.exception("scan of %s#%s failed", getattr(ref, "repo", "?"),
                             getattr(ref, "number", "?"))
            detail = f"{type(exc).__name__}: {exc}"
            # exit_code 1 is ERROR, not 0/clean and not 2/findings. A scan that did not
            # finish has not cleared anything, and saying so is the whole point.
            record_watch_result(ref, {"exit_code": 1, "reason": f"scan failed: {detail}"},
                                {}, error=detail)
            # Returned, not raised: watch_forever leaves a not-ok outcome unmarked in
            # `seen`, so the next poll retries this pull request instead of skipping it
            # forever, and the loop lives on to scan the others.
            return PullRequestOutcome(ref, {}, error=detail)
        record_watch_result(ref, outcome.verdict, posted, outcome.error)
        return outcome

    def tick() -> None:
        with SESSION.lock:
            SESSION.watch["last_poll"] = time.time()
            SESSION.watch["next_poll"] = time.time() + SESSION.watch.get("interval_sec", 30)

    def sleeper(seconds: float) -> None:
        tick()
        # Event.wait rather than sleep: a Stop must take effect now, not in 30s.
        _WATCH_STOP.wait(seconds)

    try:
        while not _WATCH_STOP.is_set():
            repos = list(SESSION.watch.get("repos") or [])
            if not repos:
                _WATCH_STOP.wait(5)
                continue
            watch_forever(
                repos, list_pulls=list_pulls, handle=handle, seen=seen,
                interval_sec=int(SESSION.watch.get("interval_sec") or 30),
                should_stop=_WATCH_STOP.is_set, sleep=sleeper,
            )
    except Exception as exc:  # noqa: BLE001 — a dead thread must say why
        logger.warning("pull-request watcher stopped: %s", exc)
        with SESSION.lock:
            SESSION.watch["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        with SESSION.lock:
            SESSION.watch["enabled"] = False
            SESSION.watch["next_poll"] = None


def start_watching(repos: list[str], interval_sec: int = 30) -> dict[str, Any]:
    global _WATCH_THREAD
    with SESSION.lock:
        SESSION.watch.update({
            "enabled": True, "repos": repos, "error": None,
            "interval_sec": max(10, int(interval_sec)),
        })
    persist_session()
    if _WATCH_THREAD is None or not _WATCH_THREAD.is_alive():
        _WATCH_STOP.clear()
        _WATCH_THREAD = threading.Thread(target=_watch_loop, name="docket-pr-watch",
                                         daemon=True)
        _WATCH_THREAD.start()
    return watch_state()


def stop_watching() -> dict[str, Any]:
    _WATCH_STOP.set()
    with SESSION.lock:
        SESSION.watch["enabled"] = False
        SESSION.watch["next_poll"] = None
    persist_session()
    return watch_state()


def _merge_live_usage(state: dict[str, Any]) -> dict[str, Any]:
    """Refresh a scan state's per-agent turns and cost from the usage ledger.

    Called on every READ, not only when something happens to call snapshot(). During
    recon nothing calls snapshot() for minutes at a time — the runner's on_progress
    fires only after recon finishes — so the console sat on "Model turns 0, Spend
    $0.0000" for the entire run while the agent was demonstrably burning turns.
    Joining at read time means a poll can never show a stale number, whatever the
    callbacks do or do not do.
    """
    from docket.report.state import get_global_report_state

    ledger = get_global_report_state().usage
    totals = ledger.totals()
    state["cost_usd"] = round(totals.get("cost_usd", 0.0), 4)
    state["input_tokens"] = totals.get("input_tokens", 0)
    state["output_tokens"] = totals.get("output_tokens", 0)

    rows = {row["agent_id"]: row for row in ledger.per_agent()}
    for agent in state.get("agents", []):
        row = rows.get(agent["id"])
        if row:
            agent["turns"] = row["requests"]
            agent["cost_usd"] = round(row["cost_usd"], 4)
    return state


@dataclass
class Session:
    """One operator's connection. Module-level singleton — see the module docstring."""
    token: str | None = None
    login: str | None = None
    oauth_state: str | None = None
    scans: dict[str, dict[str, Any]] = field(default_factory=dict)
    # Kept out of `scans` deliberately: that dict is serialised straight to the
    # browser and a threading.Event is not JSON.
    cancels: dict[str, Any] = field(default_factory=dict)
    # The pull-request watcher: which repositories it polls, and what it has found.
    # Not persisted with the scans dict because a verdict outlives the scan that
    # produced it — it is the record the operator actually reads.
    watch: dict[str, Any] = field(default_factory=lambda: {
        "enabled": False,
        "autofix": False,
        "repos": [],
        "interval_sec": 30,
        "last_poll": None,
        "next_poll": None,
        "error": None,
        "results": [],      # newest first
    })
    lock: threading.Lock = field(default_factory=threading.Lock)


SESSION = Session()


def oauth_config() -> tuple[str, str, str] | None:
    """(client_id, client_secret, redirect_uri) or None when unconfigured.

    Reads .env on every call, for the same reason app/backend/scans.py and runs.py do.
    Nothing in this module's import chain loads it: `docket connect` got it for free
    because interface/main.py imports docket.config.settings (which calls load_dotenv at
    import), but the app console imports only this module — so credentials sat in .env
    while /api/session answered `configured: false` and /auth/start answered 503. The
    Connect GitHub button did nothing, with no error anywhere to explain why.
    """
    load_dotenv(override=True)
    client_id = os.environ.get("DOCKET_GITHUB_CLIENT_ID", "").strip()
    client_secret = os.environ.get("DOCKET_GITHUB_CLIENT_SECRET", "").strip()
    if not client_id or not client_secret:
        return None
    redirect = os.environ.get("DOCKET_GITHUB_REDIRECT_URI", "").strip()
    return client_id, client_secret, redirect


def oauth_scope() -> str:
    """OAuth scope to request. `repo` unless DOCKET_GITHUB_SCOPE overrides it.

    `repo` covers every repository the user can reach, including ones they only
    collaborate on. That reach is the point: anyone with access to a repo can connect
    it and scan it, with no repository owner having to install anything.

    The cost is unavoidable, not a choice made here: GitHub has NO read-only scope for
    private code. `repo` grants read AND WRITE; there is no `repo:read`. Docket only
    ever reads — it clones nothing, pushes nothing, opens no branches — but the token
    it holds could write, which makes a leaked token worse than the access we use.

    `public_repo` narrows this to public repositories (still write on those) and is
    the only meaningful alternative worth setting.
    """
    return os.environ.get("DOCKET_GITHUB_SCOPE", "").strip() or "repo"


def _api(path: str, token: str, *, timeout: float = 20.0,
         method: str | None = None, body: dict[str, Any] | None = None) -> Any:
    """One GitHub call. `body` makes it a write; `method` overrides the verb.

    Writes go through the same function as reads on purpose — one place holds the
    auth header, the API version and the user agent, so a new endpoint cannot
    accidentally ship without them.
    """
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(
        f"{GITHUB_API}{path}",
        data=data,
        method=method or ("POST" if data is not None else "GET"),
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "docket",
            **({"Content-Type": "application/json"} if data is not None else {}),
        },
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read() or b"null")


def changed_files(full_name: str, token: str, base: str, head: str) -> list[dict[str, Any]]:
    """The files a pull request touched, from GitHub's compare endpoint.

    Paginated at 300 files by GitHub itself, which is why plan_scan falls back to a
    whole-repo scan above that count rather than scanning a silently truncated list.
    """
    if not _FULL_NAME.match(full_name):
        raise ValueError(f"refusing suspicious repository name: {full_name!r}")
    for ref in (base, head):
        if not valid_ref(ref):
            raise ValueError(f"refusing suspicious ref: {ref!r}")
    payload = _api(f"/repos/{full_name}/compare/{base}...{head}", token)
    return (payload or {}).get("files") or []


def post_pr_result(full_name: str, token: str, *, pr_number: int, head_sha: str,
                   verdict: dict[str, Any], run_url: str | None = None) -> dict[str, str]:
    """Publish a verdict: commit status, then the summary comment.

    Ordered deliberately. The status is the merge gate and must land even if commenting
    fails — a PR blocked with no explanation is recoverable, a PR that merges because
    the comment API rate-limited is not.
    """
    from docket.report.pr_report import (
        COMMENT_MARKER, STATUS_CONTEXT, render_comment, should_comment, status_for,
    )

    outcome: dict[str, str] = {}
    state, description = status_for(verdict.get("exit_code", 1), verdict.get("reason", ""))
    try:
        _api(f"/repos/{full_name}/statuses/{head_sha}", token, body={
            "state": state,
            "context": STATUS_CONTEXT,
            "description": description,
            **({"target_url": run_url} if run_url else {}),
        })
        outcome["status"] = state
    except Exception as exc:  # noqa: BLE001 — report the failure, do not mask the verdict
        outcome["status"] = f"failed: {exc}"

    try:
        existing = None
        for comment in _api(f"/repos/{full_name}/issues/{pr_number}/comments", token) or []:
            if COMMENT_MARKER in (comment.get("body") or ""):
                existing = comment["id"]
                break

        if not should_comment(verdict, already_commented=existing is not None):
            outcome["comment"] = "skipped (clean, nothing said before)"
            return outcome

        body = {"body": render_comment(verdict, run_url=run_url)}
        if existing:
            # Edited in place. A check that appends a comment per push trains people
            # to collapse the whole conversation.
            _api(f"/repos/{full_name}/issues/comments/{existing}", token,
                 method="PATCH", body=body)
            outcome["comment"] = "updated"
        else:
            _api(f"/repos/{full_name}/issues/{pr_number}/comments", token, body=body)
            outcome["comment"] = "created"
    except Exception as exc:  # noqa: BLE001
        outcome["comment"] = f"failed: {exc}"
    return outcome


def exchange_code(code: str) -> tuple[str | None, str | None]:
    """Trade the callback's ?code for a user token. Returns (token, error)."""
    config = oauth_config()
    if config is None:
        return None, "DOCKET_GITHUB_CLIENT_ID / _SECRET are not set"
    client_id, client_secret, redirect = config
    form = {"client_id": client_id, "client_secret": client_secret, "code": code}
    if redirect:
        form["redirect_uri"] = redirect
    request = urllib.request.Request(
        GITHUB_TOKEN,
        data=urllib.parse.urlencode(form).encode(),
        headers={"Accept": "application/json", "User-Agent": "docket"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            payload = json.loads(response.read() or b"{}")
    except urllib.error.URLError as exc:
        return None, f"token exchange failed: {exc}"
    token = payload.get("access_token")
    if not token:
        # GitHub returns 200 with an error body on a bad/expired code.
        return None, payload.get("error_description") or payload.get("error") or "no access_token returned"
    return token, None


def list_repos(token: str) -> list[dict[str, Any]]:
    """Every repository this user can reach, newest first.

    affiliation is spelled out rather than left to GitHub's default: repos the user
    only COLLABORATES on are the entire reason this product uses OAuth, so a change
    in that default is the one thing that would quietly break it.
    """
    return _api(
        "/user/repos?per_page=100&sort=updated"
        "&affiliation=owner,collaborator,organization_member", token,
    ) or []


def _diagnose_404(full_name: str, token: str, ref: str | None) -> str:
    """Work out WHICH 404 this is, instead of listing the possibilities.

    GitHub returns 404 for a missing ref, a repository the token cannot see, and one
    that does not exist — and will not distinguish them, deliberately, so that nobody
    can probe for private repositories. But a second call to /repos/{full_name} does
    distinguish them, because it fails the same way ONLY for the no-access case:

        /repos 404s          -> no access, or no such repository
        /repos ok, size == 0 -> the repository exists and is EMPTY (no commits). This
                                one is easy to miss and looks identical to no access.
        /repos ok, has size  -> the ref is wrong, or points at nothing

    One extra request, made only on the failure path, turns three maybes into an
    answer.
    """
    try:
        meta = _api(f"/repos/{full_name}", token, timeout=10)
    except Exception:
        return (
            f"GitHub will not show docket {full_name}. Either the repository does not "
            "exist under that name, or your token cannot reach it — a private repo you "
            "lack access to returns 404, not 403, so the two look identical from here. "
            "If it belongs to an organisation, check that the OAuth app is approved "
            "for that organisation."
        )

    if not isinstance(meta, dict):
        return f"GitHub returned nothing usable for {full_name}."

    if meta.get("size", 0) == 0:
        return (
            f"{full_name} exists and docket can see it, but it is EMPTY — no commits, "
            "so there is no source to download. Push some code and scan again."
        )

    default = meta.get("default_branch") or "the default branch"
    if ref:
        return (
            f"{full_name} exists, but it has no branch, tag or commit called '{ref}'. "
            f"Its default branch is '{default}'. Leave the branch blank to use it."
        )
    return (
        f"{full_name} exists and is not empty, but GitHub served no tarball for its "
        f"default branch ('{default}'). That usually means the branch was just created "
        "and has no commits on it yet."
    )


def fetch_source(full_name: str, token: str, dest: Path, ref: str | None = None) -> Path:
    """Download a tarball of `full_name` at `ref` and extract it under `dest`.

    `ref` is a branch, tag or commit SHA; None means the repository's default branch,
    which is what GitHub returns when the path omits a ref. A PR branch is the point:
    scanning only ever the default branch cannot gate a change before it merges.

    Deliberately NOT `git clone`: a clone puts the token in the command line (visible
    to `ps`) or persists it in .git/config. The REST tarball carries the token in an
    Authorization header only, so it never touches the disk or the process table. It
    is also read-only by construction — there is no remote to push back to.
    """
    if not _FULL_NAME.match(full_name):
        raise ValueError(f"refusing suspicious repository name: {full_name!r}")
    if ref is not None and not valid_ref(ref):
        raise ValueError(f"refusing suspicious ref: {ref!r}")

    path = f"/repos/{full_name}/tarball" + (f"/{ref}" if ref else "")
    request = urllib.request.Request(
        f"{GITHUB_API}{path}",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "User-Agent": "docket",
        },
    )
    dest.mkdir(parents=True, exist_ok=True)
    archive = dest / "source.tar.gz"
    try:
        response_cm = urllib.request.urlopen(request, timeout=120)
    except urllib.error.HTTPError as exc:
        # "HTTP Error 404: Not Found" tells the operator nothing, and GitHub returns
        # 404 for three quite different situations — a missing ref, a repo the token
        # cannot see, and a repo that does not exist. It deliberately will not confirm
        # a private repo exists, so the status alone can never distinguish them. Say
        # what was requested and list the causes; the operator can tell which is which
        # instantly, and the raw status alone has them guessing.
        if exc.code == 404:
            raise RuntimeError(_diagnose_404(full_name, token, ref)) from exc
        if exc.code in (401, 403):
            raise RuntimeError(
                f"GitHub refused the request for {full_name} ({exc.code}). The token "
                "is expired, revoked, or lacks the `repo` scope. Reconnect GitHub."
            ) from exc
        raise
    with response_cm as response:
        size = 0
        with archive.open("wb") as out:
            while chunk := response.read(1 << 16):
                size += len(chunk)
                if size > MAX_TARBALL_BYTES:
                    raise ValueError(f"tarball exceeds {MAX_TARBALL_BYTES} bytes; refusing")
                out.write(chunk)

    extracted = dest / "src"
    extracted.mkdir(exist_ok=True)
    with tarfile.open(archive, "r:gz") as tar:
        # filter="data" (3.12+) blocks absolute paths, "..", symlinks and device files.
        # This archive is third-party content, so extractall without it is exactly the
        # traversal bug semgrep flags in this very repo.
        tar.extractall(extracted, filter="data")
    archive.unlink(missing_ok=True)

    # GitHub wraps everything in one "owner-repo-<sha>" directory; hand back the real root.
    entries = [p for p in extracted.iterdir() if p.is_dir()]
    return entries[0] if len(entries) == 1 else extracted


def run_repo_scan(full_name: str, token: str, scan_id: str, ref: str | None = None,
                  triage_max: int = 0, recon: bool = False, cancel: Any = None,
                  budget_usd: float | None = None) -> None:
    """Fetch + scan, updating SESSION.scans[scan_id] as it goes. Never raises: the
    status dict is how the browser learns something failed.

    Findings are published as each scanner finishes rather than in one lump at the
    end, so the console's radar fills in during the run instead of staying empty and
    then jumping. Sequential scanners make that ordering exact.
    """
    from docket.core.cancel import NEVER, ScanCancelled
    from docket.report.dedupe import FindingStore

    cancel = cancel if cancel is not None else NEVER

    def set_state(**fields: Any) -> None:
        with SESSION.lock:
            SESSION.scans[scan_id].update(fields)

    def stage(scanner: str, state: str) -> None:
        with SESSION.lock:
            SESSION.scans[scan_id]["stages"][scanner] = state

    store = FindingStore()
    try:
        from docket.config.settings import Config

        cfg_budget = budget_usd if budget_usd else Config.from_env().max_cost_usd
    except Exception:
        # static-only scans need no DOCKET_LLM; a missing budget just means nothing to
        # draw a meter against, not a failure.
        cfg_budget = 0.0

    def snapshot() -> None:
        """Push the store's CURRENT state, including any triage verdicts already
        attached. Called both as scanners produce findings and as triage judges them,
        so the console reflects work while it happens rather than only after."""
        from docket.report.state import get_global_report_state

        current = [f.model_dump(mode="json") for f in store.findings()]
        totals = get_global_report_state().usage.totals()
        with SESSION.lock:
            _merge_live_usage(SESSION.scans[scan_id])
        set_state(
            findings=current, finding_count=len(current),
            cost_usd=round(totals.get("cost_usd", 0.0), 4),
            input_tokens=totals.get("input_tokens", 0),
            output_tokens=totals.get("output_tokens", 0),
            budget_usd=cfg_budget,
        )

    def note_agent(record: dict[str, Any]) -> None:
        """Merge one agent's lifecycle update into the scan state.

        Merged rather than appended: an agent reports twice, once on start and once
        on finish, and the second must update the row the browser is already showing
        rather than adding a duplicate beneath it.
        """
        with SESSION.lock:
            agents = SESSION.scans[scan_id].setdefault("agents", [])
            for existing in agents:
                if existing["id"] == record["id"]:
                    existing.update({k: v for k, v in record.items() if v is not None})
                    break
            else:
                agents.append(dict(record))
        snapshot()

    def publish(finding: Any) -> None:
        store.add(finding)
        snapshot()

    workdir = Path(tempfile.mkdtemp(prefix="docket-connect-"))
    started = time.time()
    run_name = f"connect-{scan_id}"
    try:
        set_state(status="fetching")
        stage("fetch", "running")
        source = fetch_source(full_name, token, workdir, ref)
        stage("fetch", "done")
        cancel.check()

        set_state(status="scanning")
        from docket.core.runner import run_scan

        result = run_scan(
            target_url=None,
            whitebox_path=str(source),
            on_finding=publish,
            run_name=run_name,
            use_sandbox=True,
            store=store,
            static_only=True,
            on_stage=stage,
            triage_max=triage_max,
            on_progress=snapshot,
            recon=recon,
            on_surface=lambda surface: set_state(surface=surface),
            cancel=cancel,
            on_agent=note_agent,
            budget_usd=budget_usd,
        )
        # Persist the same artifacts `docket scan` writes, so a console scan is
        # visible to `docket view`, to the run-history panel, and to anything reading
        # report.sarif — rather than existing only in this process's memory.
        from docket.core.paths import run_path
        from docket.report.writer import write_report

        write_report(
            store, run_path(run_name), run_name=run_name,
            target=f"github:{full_name}" + (f"@{ref}" if ref else ""),
            coverage=read_coverage(run_path(run_name) / "sandbox"),
            surface=SESSION.scans[scan_id].get("surface"),
            agents=SESSION.scans[scan_id].get("agents"),
            summary=result.summary, cost_usd=result.cost_usd,
            agents_spawned=result.agents_spawned, success=result.success,
        )
        from docket.report.state import get_global_report_state

        totals = get_global_report_state().usage.totals()
        # Re-dump: `publish` snapshots each finding as it arrives, but the triage pass
        # mutates those same Finding objects AFTERWARDS. Without this the verdicts sit
        # in the store and in report.json while the console shows the pre-triage
        # snapshot — which is exactly how "triage ran, judged 0" looked.
        snapshot()
        # Coverage read from the scanners' own artifacts, which live under the
        # sandbox's bind mount, not the run dir the report goes to.
        set_state(coverage=read_coverage(run_path(run_name) / "sandbox"))
        set_state(
            status="done", summary=result.summary,
            elapsed_sec=round(time.time() - started, 1),
            cost_usd=round(totals.get("cost_usd", 0.0), 4),
            input_tokens=totals.get("input_tokens", 0),
            output_tokens=totals.get("output_tokens", 0),
            budget_usd=cfg_budget,
        )
    except ScanCancelled as exc:
        # A deliberate stop is not a failure, and the findings already produced are
        # real. Write them out and mark the stage that was interrupted "skipped"
        # rather than "error" — calling an operator's own stop an error trains people
        # to ignore errors.
        with SESSION.lock:
            stages = SESSION.scans[scan_id]["stages"]
            for name, value in stages.items():
                if value in ("running", "pending", ""):
                    stages[name] = "skipped"
        try:
            from docket.core.paths import run_path
            from docket.report.writer import write_report

            write_report(
                store, run_path(run_name), run_name=run_name,
                target=f"github:{full_name}" + (f"@{ref}" if ref else ""),
                coverage=read_coverage(run_path(run_name) / "sandbox"),
                surface=SESSION.scans[scan_id].get("surface"),
                summary=f"Stopped by the operator after {len(store)} finding(s). "
                        "This run is incomplete: what is here was measured, what is "
                        "missing was never looked at.",
                cost_usd=0.0, agents_spawned=0, success=False,
            )
        except Exception:  # noqa: BLE001 — a failed save must not mask the cancel
            logger.warning("could not write the partial report for %s", run_name)
        snapshot()
        set_state(status="cancelled", error=str(exc),
                  elapsed_sec=round(time.time() - started, 1))
    except Exception as exc:
        # Mark whichever stage was actually in flight. Blaming "fetch" unconditionally
        # reported a post-scan crash as a download failure, next to two scanners that
        # had plainly finished.
        with SESSION.lock:
            stages = SESSION.scans[scan_id]["stages"]
            in_flight = next((k for k, v in stages.items() if v == "running"), None)
            if in_flight:
                stages[in_flight] = "error"
        set_state(status="error", error=f"{type(exc).__name__}: {exc}",
                  elapsed_sec=round(time.time() - started, 1))
    finally:
        # The customer's source never outlives the scan.
        shutil.rmtree(workdir, ignore_errors=True)
        with SESSION.lock:
            SESSION.cancels.pop(scan_id, None)


def new_scan_state(scan_id: str, full_name: str, ref: str | None = None,
                   triage_max: int = 0, recon: bool = False,
                   budget_usd: float | None = None) -> dict[str, Any]:
    return {
        "id": scan_id,
        "repo": full_name,
        # None renders as "default branch" in the console; a real value is echoed back
        # so a finished scan says which code it actually looked at.
        "ref": ref,
        "status": "queued",
        "triage_max": triage_max,
        "recon": recon,
        # The attack surface an agent mapped: entry points, auth model, and candidates
        # no scanner rule encodes. None until recon runs, which is off by default.
        "surface": None,
        "coverage": {},
        "agents": [],
        "cost_usd": 0.0,
        # Shown as the denominator on the spend meter. 0 means "whatever
        # DOCKET_MAX_COST_USD says", resolved once the scan thread starts.
        "requested_budget_usd": budget_usd or 0.0,
        "input_tokens": 0,
        "output_tokens": 0,
        "budget_usd": 0.0,
        # Radar rings, outermost last. "skipped" is a real outcome, not a failure:
        # nuclei needs a live URL and a source-only scan has none, and triage is off
        # unless asked for because it costs LLM money per finding.
        "stages": {"fetch": "pending", "trivy": "pending", "semgrep": "pending",
                   "nuclei": "pending", "recon": "pending", "triage": "pending"},
        "findings": [],
        "finding_count": 0,
        "error": None,
    }


_MIME = {
    ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8", ".svg": "image/svg+xml",
    ".json": "application/json", ".woff2": "font/woff2", ".ico": "image/x-icon",
    ".png": "image/png", ".map": "application/json",
}

_NOT_BUILT = b"""<!doctype html><meta charset=utf-8>
<title>docket - not built</title>
<body style="background:#0b0b0b;color:#e8e6e1;font:15px/1.7 ui-monospace,monospace;padding:44px">
<h1 style="font-size:19px">Console not built</h1>
<p>The React app has not been compiled yet. From the repo root:</p>
<pre style="background:#1b1b1b;border:1px solid #333;border-radius:6px;padding:14px">cd frontend
npm install
npm run build</pre>
<p style="color:#8a8781">Then reload. For hot-reload development run <b>npm run dev</b> instead and use
the Vite URL it prints, which proxies /api and /auth back to this server.</p>"""


def frontend_dist() -> Path:
    return frontend_dir() / "dist"


def list_runs() -> list[dict[str, Any]]:
    """Past runs on disk, newest first. Read straight from the run directories the CLI
    already writes, so the console and `docket view` never disagree."""
    from docket.core.paths import runs_root

    root = runs_root()
    if not root.exists():
        return []
    runs: list[dict[str, Any]] = []
    for directory in root.iterdir():
        report = directory / "report.json"
        if not report.is_file():
            continue
        try:
            data = json.loads(report.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        runs.append({
            "run_name": data.get("run_name", directory.name),
            "target": data.get("target"),
            "generated_at": data.get("generated_at"),
            "finding_count": data.get("finding_count", 0),
            "severity_counts": data.get("severity_counts", {}),
            # usage.totals is where the writer records spend. The top-level cost_usd
            # key exists but is always 0.0, so reading it made every historical run
            # look free and the cost trend a flat line at zero.
            "cost_usd": round(
                ((data.get("usage") or {}).get("totals") or {}).get(
                    "cost_usd", data.get("cost_usd", 0.0)),
                4),
            "mtime": report.stat().st_mtime,
        })
    runs.sort(key=lambda r: r["mtime"], reverse=True)
    return runs


DOWNLOAD_FORMATS = {
    "json": ("report.json", "application/json"),
    "sarif": ("report.sarif", "application/json"),
    "md": (None, "text/markdown; charset=utf-8"),  # rendered, not stored
    # Written by a model, so CACHED on disk after the first request: a download button
    # must not bill the operator every time someone clicks it.
    "brief": ("brief.html", "text/html; charset=utf-8"),
}


def _download_brief(run_name: str) -> tuple[int, bytes, str, str]:
    """The LLM-written executive brief. Generated once, then served from disk.

    A failure here returns the reason as plain text rather than a broken download: the
    brief is a convenience over report.json, and the deterministic report.md is always
    available and always correct. Never silently substitute one for the other — a
    reader who asked for the brief must know they did not get it.
    """
    from docket.core.paths import runs_root

    if not _RUN_NAME.match(run_name):
        return 400, b"bad run name", "text/plain; charset=utf-8", "error.txt"
    root = runs_root().resolve()
    run_dir = (root / run_name).resolve()
    if not str(run_dir).startswith(str(root)) or not (run_dir / "report.json").is_file():
        return 404, b"no such run", "text/plain; charset=utf-8", "error.txt"

    cached = run_dir / "brief.html"
    if cached.is_file():
        return 200, cached.read_bytes(), "text/html; charset=utf-8", f"{run_name}-brief.html"

    try:
        report = json.loads((run_dir / "report.json").read_text())
    except (OSError, json.JSONDecodeError) as exc:
        return 500, f"unreadable report: {exc}".encode(), "text/plain; charset=utf-8", "error.txt"

    try:
        from docket.config.settings import Config

        config = Config.from_env()
    except Exception as exc:  # noqa: BLE001
        return 400, (f"An executive brief needs a model configured: {exc}\n"
                     "The .md and .json reports need no model and are ready now."
                     ).encode(), "text/plain; charset=utf-8", "error.txt"

    from docket.report.narrative import generate

    html, note = generate(report, config)
    if html is None:
        return 502, (f"No brief was produced: {note}\n"
                     "Nothing was written rather than something unverified."
                     ).encode(), "text/plain; charset=utf-8", "error.txt"
    try:
        cached.write_text(html)
    except OSError:
        logger.warning("could not cache the brief for %s", run_name)
    return 200, html.encode(), "text/html; charset=utf-8", f"{run_name}-brief.html"


def download_run(run_name: str, fmt: str) -> tuple[int, bytes, str, str]:
    """(status, body, content_type, filename) for one run in one format.

    json and sarif are served straight off disk — they are already written by the
    report writer, and re-generating them here would let the download drift from what
    the scan actually produced. Markdown is rendered on demand because nothing needs
    it until someone asks.
    """
    from docket.core.paths import runs_root
    from docket.report.markdown import render_markdown

    if fmt == "brief":
        return _download_brief(run_name)
    if fmt not in DOWNLOAD_FORMATS:
        return 400, b'{"error":"format must be json, sarif or md"}', "application/json", ""
    if not run_name or not _RUN_NAME.match(run_name):
        return 400, b'{"error":"bad run name"}', "application/json", ""

    root = runs_root().resolve()
    directory = (root / run_name).resolve()
    # Same containment check as load_run: the name comes from the browser and is
    # joined onto a filesystem path.
    # `in .parents`, NOT a string prefix: "<root>-other/x" shares a prefix with
    # "<root>" and is a different directory. Proven against the viewer already.
    if root not in directory.parents or not directory.is_dir():
        return 404, b'{"error":"no such run"}', "application/json", ""

    filename, content_type = DOWNLOAD_FORMATS[fmt]
    if filename:
        path = directory / filename
        if not path.is_file():
            return 404, b'{"error":"not written for this run"}', "application/json", ""
        return 200, path.read_bytes(), content_type, f"{run_name}-{filename}"

    report = directory / "report.json"
    if not report.is_file():
        return 404, b'{"error":"no report.json"}', "application/json", ""
    try:
        rendered = render_markdown(json.loads(report.read_text()))
    except (OSError, json.JSONDecodeError) as exc:
        return 500, f'{{"error":"unreadable report: {exc}"}}'.encode(), "application/json", ""
    return 200, rendered.encode(), content_type, f"{run_name}.md"


def load_run(run_name: str) -> tuple[int, dict[str, Any]]:
    """(status, payload) for one finished run, shaped like a ScanState so the console
    can render a reloaded run through exactly the same components as a live one."""
    from docket.core.paths import runs_root

    if not run_name or not _RUN_NAME.match(run_name):
        return 400, {"error": "bad run name"}
    # Resolved and containment-checked: run_name comes from the browser and is joined
    # onto a filesystem path, so a traversal here would read arbitrary files.
    root = runs_root().resolve()
    report = (root / run_name / "report.json").resolve()
    if root not in report.parents or not report.is_file():
        return 404, {"error": f"no run named {run_name}"}
    try:
        data = json.loads(report.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        return 500, {"error": f"unreadable report: {exc}"}

    target = str(data.get("target") or "")
    repo, _, ref = target.removeprefix("github:").partition("@")
    totals = (data.get("usage") or {}).get("totals") or {}
    return 200, {
        "id": run_name,
        "repo": repo or target or run_name,
        "ref": ref or None,
        "status": "done",
        # A finished run says nothing about which scanners were skipped, and inventing
        # stages would put lit rings on the radar that never ran. "done" everywhere is
        # the honest rendering of "this is history, not a live scan".
        "stages": {},
        "findings": data.get("findings", []),
        "finding_count": data.get("finding_count", 0),
        "error": None,
        "summary": data.get("summary", ""),
        "surface": data.get("surface") or None,
        # Coverage and spend are in the report and must survive a reload. Without them
        # the console showed "not recorded" and "$0.0000" for a run that recorded both,
        # which reads as "nothing was analysed and nothing was spent" — the two claims
        # a security report can least afford to get wrong.
        "coverage": data.get("coverage") or None,
        "agents": data.get("agents") or [],
        "cost_usd": round(totals.get("cost_usd", 0.0), 4),
        "input_tokens": totals.get("input_tokens", 0),
        "output_tokens": totals.get("output_tokens", 0),
        "budget_usd": 0.0,  # the live cap; a finished run was not bounded by today's
        "historical": True,
    }


def make_handler() -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _send(self, status: int, body: bytes, content_type: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _json(self, status: int, payload: Any) -> None:
            self._send(status, json.dumps(payload, default=str).encode(), "application/json")

        def _redirect(self, location: str) -> None:
            self.send_response(302)
            self.send_header("Location", location)
            self.send_header("Content-Length", "0")
            self.end_headers()

        # -- routes ----------------------------------------------------------------

        def do_GET(self) -> None:  # noqa: N802 — stdlib naming
            parsed = urllib.parse.urlparse(self.path)
            path, query = parsed.path, urllib.parse.parse_qs(parsed.query)

            if path.startswith("/assets/") or path in ("/favicon.ico", "/favicon.svg"):
                self._static(path)
            elif path == "/api/runs":
                self._json(200, {"runs": list_runs()})
            elif path.startswith("/api/download/"):
                rest = path[len("/api/download/"):]
                name, _, fmt = rest.rpartition(".")
                status, body, ctype, filename = download_run(name, fmt)
                self.send_response(status)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                if status == 200 and filename:
                    # Machine formats download; the brief opens in the tab. It is a
                    # document meant to be READ, and print-to-PDF from the browser is
                    # how it becomes something you send on — forcing a save first just
                    # adds a step before every one of those.
                    disposition = "inline" if fmt == "brief" else "attachment"
                    self.send_header("Content-Disposition",
                                     f'{disposition}; filename="{filename}"')
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(body)
            elif path.startswith("/api/run/"):
                # A finished run, rehydrated from disk. The console keeps its live scan
                # in memory only, so without this a reload loses everything — even
                # though report.json has been sitting there the whole time.
                self._json(*load_run(path[len("/api/run/"):]))
            elif path == "/api/session":
                self._json(200, {
                    "connected": SESSION.token is not None,
                    "login": SESSION.login,
                    "configured": oauth_config() is not None,
                    # Shown in the console so the granted scope is visible on screen
                    # rather than buried in a config file nobody rereads.
                    "scope": oauth_scope(),
                })
            elif path == "/auth/start":
                self._auth_start()
            elif path == "/auth/callback":
                self._auth_callback(query)
            elif path == "/api/repos":
                self._repos()
            elif path == "/api/watch":
                self._json(200, watch_state())
            elif path == "/api/scans/active":
                self._json(200, {"scans": active_scans()})
            elif path.startswith("/api/scan/"):
                scan_id = path.rsplit("/", 1)[-1]
                with SESSION.lock:
                    state = SESSION.scans.get(scan_id)
                    # Refreshed inside the lock: a live scan mutates this dict from
                    # its own thread while the handler serialises it.
                    if state is not None and state.get("status") in LIVE_STATUSES:
                        _merge_live_usage(state)
                    payload = dict(state) if state else None
                self._json(200 if payload else 404, payload or {"error": "unknown scan"})
            elif path.startswith("/api/") or path.startswith("/auth/"):
                self._json(404, {"error": "no such endpoint"})
            else:
                # Everything else is a client-side route: serve the SPA shell and let
                # the router decide, so a deep link or a refresh does not 404.
                self._static("/index.html")

        def do_POST(self) -> None:  # noqa: N802 — stdlib naming
            post_path = urllib.parse.urlparse(self.path).path
            if post_path == "/api/scan/cancel":
                self._cancel_scan()
                return
            if post_path == "/api/watch":
                self._set_watch()
                return
            if post_path != "/api/scan":
                self._send(404, b"not found", "text/plain")
                return
            if SESSION.token is None:
                self._json(401, {"error": "not connected to GitHub"})
                return
            length = int(self.headers.get("Content-Length", "0"))
            try:
                body = json.loads(self.rfile.read(length) or b"{}")
            except json.JSONDecodeError:
                self._json(400, {"error": "body must be JSON"})
                return
            full_name = str(body.get("repo", "")).strip()
            if not _FULL_NAME.match(full_name):
                self._json(400, {"error": "repo must look like owner/name"})
                return
            ref = str(body.get("ref", "")).strip() or None
            if ref is not None and not valid_ref(ref):
                self._json(400, {"error": f"not a usable branch/tag/sha: {ref}"})
                return
            # Validated, not capped: a non-number or a negative would break the loop
            # rather than cost money, so it is refused. How MANY is the operator's call.
            try:
                triage_max = int(body.get("triage_max") or 0)
            except (TypeError, ValueError):
                self._json(400, {"error": "triage_max must be a whole number"})
                return
            if triage_max < 0:
                self._json(400, {"error": "triage_max cannot be negative"})
                return
            # Triage spawns real LLM agents, so refuse early with a clear reason
            # rather than starting a scan that dies partway. Config.from_env() is what
            # loads .env, so asking it beats reading os.environ directly — an earlier
            # version did the latter and refused on a correctly-configured machine.
            # A ceiling in dollars, not a count. This is the only control that bounds
            # an AI phase by the thing actually worth bounding — triage_max caps how
            # many findings are judged, but says nothing about what each one costs.
            budget_usd: float | None = None
            if body.get("budget_usd") not in (None, ""):
                try:
                    budget_usd = float(body["budget_usd"])
                except (TypeError, ValueError):
                    self._json(400, {"error": "budget_usd must be a number"})
                    return
                if budget_usd <= 0:
                    self._json(400, {"error": "budget_usd must be greater than zero"})
                    return

            recon = bool(body.get("recon"))
            if triage_max or recon:
                try:
                    from docket.config.settings import Config

                    Config.from_env()
                except Exception as exc:
                    self._json(400, {"error": f"AI agents need a model configured: {exc}"})
                    return

            from docket.core.cancel import CancelToken

            scan_id = secrets.token_hex(8)
            token = CancelToken()
            with SESSION.lock:
                SESSION.scans[scan_id] = new_scan_state(scan_id, full_name, ref,
                                                        triage_max, recon, budget_usd)
                SESSION.cancels[scan_id] = token
            threading.Thread(
                target=run_repo_scan,
                args=(full_name, SESSION.token, scan_id, ref, triage_max, recon, token,
                      budget_usd),
                name=f"docket-scan-{scan_id}", daemon=True,
            ).start()
            self._json(202, {"id": scan_id, "status": "queued"})

        def _set_watch(self) -> None:
            """Start or stop the pull-request watcher."""
            if SESSION.token is None:
                self._json(401, {"error": "not connected to GitHub"})
                return
            length = int(self.headers.get("Content-Length", "0"))
            try:
                body = json.loads(self.rfile.read(length) or b"{}")
            except json.JSONDecodeError:
                self._json(400, {"error": "body must be JSON"})
                return

            if not body.get("enabled"):
                self._json(200, stop_watching())
                return

            repos = [r for r in (body.get("repos") or []) if isinstance(r, str)]
            bad = [r for r in repos if not _FULL_NAME.match(r)]
            if bad:
                self._json(400, {"error": f"not a repository name: {bad[0]}"})
                return
            if not repos:
                self._json(400, {"error": "pick at least one repository to watch"})
                return
            try:
                interval = int(body.get("interval_sec") or 30)
            except (TypeError, ValueError):
                self._json(400, {"error": "interval_sec must be a whole number"})
                return
            with SESSION.lock:
                SESSION.watch["triage_max"] = max(0, int(body.get("triage_max") or 5))
                # Opt-in. Opening pull requests on someone's repository is not a
                # thing to start doing because a checkbox defaulted on.
                SESSION.watch["autofix"] = bool(body.get("autofix"))
            self._json(200, start_watching(repos, interval))

        def _cancel_scan(self) -> None:
            """Ask the running scan to stop at its next checkpoint.

            202, not 200: the scan has not stopped when this returns, it has been
            asked to. Reporting a stop that has not happened yet is how a UI ends up
            showing "stopped" over a scanner that is still burning CPU.
            """
            length = int(self.headers.get("Content-Length", "0"))
            try:
                body = json.loads(self.rfile.read(length) or b"{}")
            except json.JSONDecodeError:
                body = {}
            scan_id = str(body.get("id", "")).strip()
            with SESSION.lock:
                # No id means "whatever is running", which is what the Stop button
                # sends: the console only ever shows one live scan.
                if not scan_id:
                    scan_id = next(
                        (k for k, v in SESSION.scans.items()
                         if v.get("status") in ("queued", "fetching", "scanning")),
                        "",
                    )
                token = SESSION.cancels.get(scan_id)
                state = SESSION.scans.get(scan_id)
            if token is None or state is None:
                self._json(404, {"error": "no scan is running"})
                return
            if state.get("status") in ("done", "error", "cancelled"):
                self._json(409, {"error": f"scan already {state['status']}"})
                return
            token.cancel("stopped by the operator")
            self._json(202, {"id": scan_id, "status": "cancelling"})

        # -- handlers --------------------------------------------------------------

        def _static(self, path: str) -> None:
            """Serve the Vite build. Resolved and containment-checked: this reads from
            a directory path derived from the URL, so a traversal here would hand out
            arbitrary files from the operator's machine."""
            dist = frontend_dist()
            index = dist / "index.html"
            if not index.is_file():
                self._send(200, _NOT_BUILT, "text/html; charset=utf-8")
                return
            target = (dist / path.lstrip("/")).resolve()
            if not str(target).startswith(str(dist.resolve())) or not target.is_file():
                if path == "/index.html":
                    self._send(200, _NOT_BUILT, "text/html; charset=utf-8")
                else:
                    self._send(404, b"not found", "text/plain")
                return
            self._send(200, target.read_bytes(),
                       _MIME.get(target.suffix, "application/octet-stream"))

        def _auth_start(self) -> None:
            config = oauth_config()
            if config is None:
                self._json(503, {
                    "error": "GitHub is not configured",
                    "detail": "Set DOCKET_GITHUB_CLIENT_ID and DOCKET_GITHUB_CLIENT_SECRET.",
                })
                return
            client_id, _, redirect = config
            # CSRF: an attacker who can make the browser hit /auth/callback with their
            # own code would otherwise bind THEIR GitHub account to this session.
            state = secrets.token_urlsafe(24)
            SESSION.oauth_state = state
            params = {"client_id": client_id, "state": state, "scope": oauth_scope()}
            if redirect:
                params["redirect_uri"] = redirect
            self._redirect(f"{GITHUB_AUTHORIZE}?{urllib.parse.urlencode(params)}")

        def _auth_callback(self, query: dict[str, list[str]]) -> None:
            expected, SESSION.oauth_state = SESSION.oauth_state, None
            state = (query.get("state") or [""])[0]
            if not expected or not secrets.compare_digest(state, expected):
                self._json(400, {"error": "state mismatch — restart the connection"})
                return
            code = (query.get("code") or [""])[0]
            if not code:
                self._json(400, {"error": "no code in callback"})
                return
            token, error = exchange_code(code)
            if error:
                self._json(502, {"error": error})
                return
            SESSION.token = token
            try:
                SESSION.login = (_api("/user", token) or {}).get("login")
            except urllib.error.URLError:
                SESSION.login = None
            persist_session()
            self._redirect("/?connected=1")

        def _repos(self) -> None:
            if SESSION.token is None:
                self._json(401, {"error": "not connected to GitHub"})
                return
            try:
                repos = list_repos(SESSION.token)
            except urllib.error.HTTPError as exc:
                self._json(502, {"error": f"GitHub API {exc.code}"})
                return
            self._json(200, {"repos": [
                {
                    "full_name": r.get("full_name"),
                    "private": r.get("private"),
                    "language": r.get("language"),
                    "updated_at": r.get("updated_at"),
                }
                for r in repos
            ]})

        def log_message(self, fmt: str, *args) -> None:
            pass

    return Handler


def persist_session() -> None:
    """Save the token and the operator's watch choices so a restart is not a reset."""
    from docket.interface import session_store

    with SESSION.lock:
        session_store.save(token=SESSION.token, login=SESSION.login,
                           watch=dict(SESSION.watch))


def restore_session() -> bool:
    """Reload a saved session and resume watching. True when something was restored.

    Called at startup. Without it every restart costs an OAuth round trip and a
    re-tick of every watched repository, which during development is constant and is
    most of what made the console feel unreliable.
    """
    from docket.interface import session_store

    saved = session_store.load()
    if not saved:
        return False

    with SESSION.lock:
        SESSION.token = saved.get("token")
        SESSION.login = saved.get("login")
        watch = saved.get("watch") or {}
        SESSION.watch.update({
            "repos": list(watch.get("repos") or []),
            "interval_sec": int(watch.get("interval_sec") or 30),
            "triage_max": int(watch.get("triage_max") or 5),
            "autofix": bool(watch.get("autofix")),
        })
        resume = bool(watch.get("enabled")) and bool(SESSION.watch["repos"])
        repos = list(SESSION.watch["repos"])
        interval = SESSION.watch["interval_sec"]

    if resume:
        # The watcher was on when the console stopped, so it is on again. An operator
        # who left it running did not ask for it to quietly stop.
        start_watching(repos, interval)
        logger.info("resumed watching %d repository(s)", len(repos))
    return True


def start_server(port: int = 8765) -> ThreadingHTTPServer:
    # Must happen on the main thread: signal.signal() refuses anywhere else, and a
    # console killed mid-scan is exactly when the sandbox needs reaping.
    try:
        if restore_session():
            logger.info("restored a saved GitHub session")
    except Exception:  # noqa: BLE001 — a bad session file must not stop the console
        logger.warning("could not restore the saved session", exc_info=True)

    try:
        from docket.runtime.sandbox import install_cleanup

        install_cleanup()
    except Exception:  # noqa: BLE001 — no docker is not a reason to refuse to serve
        logger.debug("sandbox cleanup hook not installed", exc_info=True)
    """Loopback only. The OAuth client secret lives in this process; binding it to a
    public interface would expose an unauthenticated scan trigger to the network."""
    return ThreadingHTTPServer(("127.0.0.1", port), make_handler())


def serve(port: int = 8765) -> int:
    from docket.interface.cli_args import EXIT_CLEAN

    server = start_server(port)
    actual = server.server_address[1]
    print(f"docket console: http://127.0.0.1:{actual}")
    if oauth_config() is None:
        print("warning: DOCKET_GITHUB_CLIENT_ID / DOCKET_GITHUB_CLIENT_SECRET are unset —")
        print("         the console loads but Connect GitHub will refuse. Register a GitHub App")
        print("         with 'Contents: read' + 'Metadata: read', callback")
        print(f"         http://127.0.0.1:{actual}/auth/callback, then export both values.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print()
    finally:
        server.shutdown()
    return EXIT_CLEAN


def demo() -> None:
    import threading as _threading

    # 1. Repo-name validation is the guard in front of every URL and path built below.
    for bad in ("../../etc/passwd", "owner/repo/../..", "https://evil.test/x",
                "owner", "", "owner/repo extra", "-flag/repo\nx",
                # Two segments, so the slash count alone does not reject them. These
                # DID match before the lookaheads were added.
                "../evil", "owner/..", "./evil", "owner/."):
        assert not _FULL_NAME.match(bad), bad
    # A repository legitimately named `.github` must still be accepted — the guard is
    # against a dot-only segment, not against dots.
    for good in ("punya-henoyo/Docket", "a/b", "org.name/repo_1.2-3", "owner/.github"):
        assert _FULL_NAME.match(good), good

    # 1b. Autofix keys. Semgrep runs INSIDE the sandbox, so it reports
    # `/work/source/app.py:66`; parse_source_file rejects anything starting with "/",
    # which made service/fix.py skip every finding a sandboxed scan produced and the
    # autofix report "nothing to fix" over a verdict full of patchable findings.
    sandboxed = {"rule_id": "semgrep/sqli", "discovered_by": "semgrep",
                 "location": {"method": "STATIC", "path": "/work/source/app.py",
                              "source_file": "/work/source/app.py:66"},
                 "merged_rules": ["semgrep/sqli", "semgrep/tainted-sql-string"]}
    assert autofix_target_key(sandboxed) == ("semgrep/sqli", "app.py", 66), \
        autofix_target_key(sandboxed)
    # merged_rules is EXPANDED: merge_static folds the several rules matching one line
    # into one Finding, while validate_patch compares raw semgrep keys where each is
    # separate. Collapse them and gate 3 reads the fix's own work as collateral.
    assert autofix_scope_keys([sandboxed]) == [("semgrep/sqli", "app.py", 66),
                                               ("semgrep/tainted-sql-string", "app.py", 66)]
    # A route is not a file, so it yields no key rather than a bogus one.
    assert autofix_target_key({"rule_id": "x", "location": {"source_file": "/"}}) is None
    assert autofix_scope_keys([{"rule_id": "x", "location": {}}]) == []

    state = new_scan_state("abc", "o/r")
    assert state["status"] == "queued" and state["finding_count"] == 0
    assert state["ref"] is None  # None means "whatever GitHub calls the default"
    assert set(state["stages"]) == {"fetch", "trivy", "semgrep", "nuclei", "recon", "triage"}
    # Both AI phases cost real money per run, so both are opt-in and neither can be
    # switched on by a caller that simply forgot to pass a flag.
    assert state["triage_max"] == 0, "triage costs money, so it must be opt-in"
    assert state["recon"] is False, "recon costs money, so it must be opt-in"
    assert state["surface"] is None, "no surface until an agent actually maps one"
    assert new_scan_state("abc", "o/r", None, 0, True)["recon"] is True
    assert new_scan_state("abc", "o/r", "feat/x")["ref"] == "feat/x"
    assert new_scan_state("abc", "o/r", None, 5)["triage_max"] == 5

    # Refs are interpolated into the same API path as the repo name, so they get the
    # same scrutiny. Slashes ARE legal here, which is why this is a separate check.
    for good in ("main", "feat/new-ui", "v1.2.3", "release/2026.08", "a1b2c3d4"):
        assert valid_ref(good), good
    for bad in ("../../etc/passwd", "-rf", "feat//x", "feat/", "", "a b",
                "main;rm -rf /", "..", "/abs"):
        assert not valid_ref(bad), bad

    # A reloaded run must carry coverage and spend. Dropping them showed "not recorded"
    # and "$0.0000" for a run that recorded both — silently, because a missing key
    # renders as a plausible zero rather than as an error.
    import tempfile as _tempfile
    with _tempfile.TemporaryDirectory() as tmp:
        from docket.core import paths as _paths
        _orig = _paths.runs_root
        _root = Path(tmp)
        _paths.runs_root = lambda: _root  # type: ignore[assignment]
        try:
            (_root / "connect-1").mkdir()
            (_root / "connect-1" / "report.json").write_text(json.dumps({
                "run_name": "connect-1", "target": "github:o/r@main", "finding_count": 1,
                "findings": [{"id": "f1"}],
                "coverage": {"semgrep": {"files_scanned": 3}},
                "usage": {"totals": {"input_tokens": 35773, "output_tokens": 2368,
                                     "cost_usd": 0.077928}},
            }))
            listed = list_runs()
            assert len(listed) == 1 and listed[0]["cost_usd"] == 0.0779, listed
            code, run = load_run("connect-1")
            assert code == 200, (code, run)
            assert run["repo"] == "o/r" and run["ref"] == "main", run
            assert run["coverage"]["semgrep"]["files_scanned"] == 3, run["coverage"]
            assert run["input_tokens"] == 35773 and run["output_tokens"] == 2368, run
            assert run["cost_usd"] == 0.0779, run["cost_usd"]
            # Traversal is rejected before any read.
            assert load_run("../../etc")[0] == 400
            assert load_run("connect-missing")[0] == 404
        finally:
            _paths.runs_root = _orig  # type: ignore[assignment]

    saved = {k: os.environ.pop(k, None)
             for k in ("DOCKET_GITHUB_CLIENT_ID", "DOCKET_GITHUB_CLIENT_SECRET")}
    # oauth_config() now reads .env on every call, so popping the keys is not enough: a
    # real developer .env puts them straight back and BOTH branches below would assert
    # against whatever happens to be on this machine. Stub the loader for the duration —
    # what is under test here is how the two variables are read, not where they came from.
    # Without this the self-check passed only on a machine with no GitHub App configured,
    # which is the one machine where it proves the least.
    real_load_dotenv = globals()["load_dotenv"]
    globals()["load_dotenv"] = lambda *a, **k: None
    try:
        assert oauth_config() is None
        token, error = exchange_code("irrelevant")
        assert token is None and "CLIENT_ID" in error, (token, error)

        os.environ["DOCKET_GITHUB_CLIENT_ID"] = "iv1.test"
        os.environ["DOCKET_GITHUB_CLIENT_SECRET"] = "shh"
        assert oauth_config()[:2] == ("iv1.test", "shh")

        server = start_server(port=0)
        base = f"http://127.0.0.1:{server.server_address[1]}"
        _threading.Thread(target=server.serve_forever, daemon=True).start()

        # "/" serves the built SPA, or a build-me page when dist/ is absent. Either
        # way it is HTML and mentions docket — never a 404.
        page = urllib.request.urlopen(base + "/", timeout=5).read().decode()
        assert "docket" in page.lower(), page[:200]
        # An unknown non-API path is a client-side route, not a 404.
        deep = urllib.request.urlopen(base + "/findings", timeout=5).read().decode()
        assert "docket" in deep.lower(), deep[:200]
        # ...but an unknown API path still 404s rather than returning HTML.
        try:
            urllib.request.urlopen(base + "/api/nonsense", timeout=5)
            raise AssertionError("unknown API path must 404")
        except urllib.error.HTTPError as exc:
            assert exc.code == 404, exc.code

        # ── live usage is joined on READ, not only on write ───────────────────
        # The bug this guards: during recon nothing calls snapshot() for minutes, so
        # a state written once at agent-start kept reporting 0 turns and $0.0000 for
        # the whole run while the agent was plainly spending money.
        from docket.report.state import get_global_report_state

        ledger = get_global_report_state().usage

        from agents.usage import Usage

        ledger.record(
            "recon",
            Usage(requests=4, input_tokens=900, output_tokens=60, total_tokens=960),
            cost_usd=0.05, role="recon", model="m",
        )
        live = {"status": "scanning", "agents": [{"id": "recon", "role": "recon"}]}
        merged = _merge_live_usage(live)
        assert merged["agents"][0]["turns"] == 4, merged
        assert merged["agents"][0]["cost_usd"] == 0.05, merged
        assert merged["cost_usd"] >= 0.05 and merged["input_tokens"] >= 900, merged
        # An agent the ledger has never seen keeps whatever it had rather than being
        # zeroed — absence of a row means "no turn charged yet", not "0 turns".
        untouched = _merge_live_usage({"agents": [{"id": "triage-9", "turns": 3}]})
        assert untouched["agents"][0]["turns"] == 3, untouched

        # ── cancel ────────────────────────────────────────────────────────────
        def post(path: str, payload: dict) -> tuple[int, dict]:
            request = urllib.request.Request(
                base + path, data=json.dumps(payload).encode(),
                headers={"Content-Type": "application/json"}, method="POST")
            try:
                with urllib.request.urlopen(request, timeout=5) as response:
                    return response.status, json.loads(response.read() or b"{}")
            except urllib.error.HTTPError as exc:
                return exc.code, json.loads(exc.read() or b"{}")

        # Nothing running: a 404, never a cheerful 202 for a stop that stopped nothing.
        code, payload = post("/api/scan/cancel", {})
        assert code == 404, (code, payload)

        from docket.core.cancel import CancelToken

        SESSION.scans["fake"] = new_scan_state("fake", "o/r")
        SESSION.scans["fake"]["status"] = "scanning"
        SESSION.cancels["fake"] = CancelToken()
        try:
            # No id means "whatever is running", which is what the Stop button sends.
            code, payload = post("/api/scan/cancel", {})
            assert code == 202 and payload["id"] == "fake", (code, payload)
            assert SESSION.cancels["fake"].cancelled
            # 202 is "asked to stop", not "stopped" — the status must NOT have been
            # flipped by the handler, only by the scan thread reaching a checkpoint.
            assert SESSION.scans["fake"]["status"] == "scanning", "handler must not lie"

            SESSION.scans["fake"]["status"] = "done"
            code, _ = post("/api/scan/cancel", {"id": "fake"})
            assert code == 409, code  # cannot stop what already finished
        finally:
            SESSION.scans.pop("fake", None)
            SESSION.cancels.pop("fake", None)

        # ── reporting a PR verdict ────────────────────────────────────────────
        # Recorded, not sent: the point is which calls are made and in what order.
        calls: list = []

        def _fake_api(path, tok, *, timeout=20.0, method=None, body=None):
            calls.append((method or ("POST" if body else "GET"), path, body))
            if path.endswith("/comments") and method is None and body is None:
                return _existing_comments
            return {}

        from docket.report.pr_report import COMMENT_MARKER, STATUS_CONTEXT

        _g2 = globals()
        _saved2 = _g2["_api"]
        _g2["_api"] = _fake_api
        try:
            blocked = {"exit_code": 2, "reason": "1 new finding blocks this merge",
                       "new": [{"rule_id": "r", "severity": "high",
                                "location": {"path": "a.py", "source_file": "a.py:1"}}],
                       "fixed": [], "new_reachable": [], "caveats": []}

            # Nothing said before: status posted, comment created.
            _existing_comments = []
            calls.clear()
            out = post_pr_result("o/r", "tok", pr_number=7, head_sha="sha1",
                                 verdict=blocked)
            assert out["status"] == "failure" and out["comment"] == "created", out
            assert calls[0][1] == "/repos/o/r/statuses/sha1", calls[0]
            assert calls[0][2]["context"] == STATUS_CONTEXT
            assert calls[-1][0] == "POST" and calls[-1][1].endswith("/issues/7/comments")

            # Said before: the SAME comment is edited, never a second one appended.
            _existing_comments = [{"id": 99, "body": f"{COMMENT_MARKER}\nold"}]
            calls.clear()
            out = post_pr_result("o/r", "tok", pr_number=7, head_sha="sha1",
                                 verdict=blocked)
            assert out["comment"] == "updated", out
            assert calls[-1][0] == "PATCH" and "issues/comments/99" in calls[-1][1]

            # Clean and never spoken on: status only. An unprompted "nothing to
            # report" on every PR is how a bot gets muted.
            _existing_comments = []
            calls.clear()
            clean = {"exit_code": 0, "reason": "No new findings", "new": [],
                     "fixed": [], "new_reachable": [], "caveats": []}
            out = post_pr_result("o/r", "tok", pr_number=7, head_sha="sha1",
                                 verdict=clean)
            assert out["status"] == "success" and "skipped" in out["comment"], out
            assert all("comments" not in c[1] or c[0] == "GET" for c in calls)

            # Clean but a stale failure is on the PR: it MUST be replaced.
            _existing_comments = [{"id": 99, "body": f"{COMMENT_MARKER}\n1 reachable"}]
            calls.clear()
            out = post_pr_result("o/r", "tok", pr_number=7, head_sha="sha1",
                                 verdict=clean)
            assert out["comment"] == "updated", "a stale failure must not be left up"

            # The status is the gate and must land even when commenting fails.
            def _status_ok_comment_dies(path, tok, *, timeout=20.0, method=None, body=None):
                if "statuses" in path:
                    return {}
                raise RuntimeError("rate limited")

            _g2["_api"] = _status_ok_comment_dies
            out = post_pr_result("o/r", "tok", pr_number=7, head_sha="sha1",
                                 verdict=blocked)
            assert out["status"] == "failure", "the gate must survive a comment failure"
            assert out["comment"].startswith("failed:"), out
        finally:
            _g2["_api"] = _saved2

        # ── a 404 from GitHub must say WHICH 404 ──────────────────────────────
        # GitHub returns 404 for a missing ref, a repo the token cannot see, and a
        # repo that does not exist, and deliberately will not distinguish them. The
        # raw "HTTP Error 404: Not Found" left the operator with no idea which.
        import urllib.error as _ue

        def _fetch_404(ref_value):
            def _raise(*_a, **_k):
                raise _ue.HTTPError("u", 404, "Not Found", {}, None)
            saved = urllib.request.urlopen
            urllib.request.urlopen = _raise
            try:
                fetch_source("o/r", "tok", Path(_tempfile.mkdtemp()), ref_value)
            except RuntimeError as exc:
                return str(exc)
            finally:
                urllib.request.urlopen = saved
            raise AssertionError("a 404 must not pass silently")

        # Patch THIS module's globals, not `import docket.interface.connect`. Run via
        # `python -m`, this file is __main__ and that import yields a SECOND module
        # object — patching it leaves the copy _diagnose_404 actually reads untouched.
        _g = globals()
        _saved_api = _g["_api"]
        try:
            # No access: the /repos probe fails the same way. This is the ONLY case
            # where it does, which is what makes the diagnosis possible at all.
            _g["_api"] = lambda *a, **k: (_ for _ in ()).throw(
                _ue.HTTPError("u", 404, "n", {}, None))
            no_access = _diagnose_404("o/r", "tok", None)
            assert "cannot reach it" in no_access, no_access
            assert "OAuth app is approved" in no_access, "the org case must be named"

            # Empty repository: exists, visible, no commits. Identical on the status
            # code alone, and the cause most easily missed.
            _g["_api"] = lambda *a, **k: {"size": 0, "default_branch": "main"}
            empty = _diagnose_404("o/r", "tok", None)
            assert "EMPTY" in empty and "no commits" in empty, empty

            # Has content: then it really is the ref, and the message names the
            # default branch so the fix is obvious.
            _g["_api"] = lambda *a, **k: {"size": 42, "default_branch": "main"}
            bad_ref = _diagnose_404("o/r", "tok", "nope")
            assert "no branch, tag or commit called 'nope'" in bad_ref, bad_ref
            assert "default branch is 'main'" in bad_ref, bad_ref
            assert "no branch, tag or commit" not in _diagnose_404("o/r", "tok", None)
        finally:
            _g["_api"] = _saved_api

        # ── per-scan budget ───────────────────────────────────────────────────
        # Validated, not clamped: the operator chooses the ceiling. Refusing a
        # nonsense value beats silently substituting one, because a budget the caller
        # did not set is a budget nobody is watching.
        assert new_scan_state("s", "o/r", None, 0, False, 0.5)["requested_budget_usd"] == 0.5
        assert new_scan_state("s", "o/r")["requested_budget_usd"] == 0.0

        # /api/scan refuses an unconnected session before it validates anything, so
        # a token has to exist for the validation path to be reachable at all.
        SESSION.token = "test-token"
        try:
            for bad in ("abc", -1, 0):
                code, payload = post("/api/scan", {"repo": "o/r", "budget_usd": bad})
                assert code == 400, (bad, code, payload)
                assert "budget_usd" in payload.get("error", ""), payload
        finally:
            SESSION.token = None

        # A per-scan ceiling must reach the config the pre-turn gate reads, or it is
        # a label on a dashboard rather than a control.
        from dataclasses import replace as _replace

        from docket.config.settings import Config as _Config

        _base = _Config(llm="m", llm_api_key=None, max_cost_usd=2.0,
                        max_child_cost_usd=0.75, max_agents=6)
        _capped = _replace(_base, max_cost_usd=0.25,
                           max_child_cost_usd=min(_base.max_child_cost_usd, 0.25))
        assert _capped.max_cost_usd == 0.25
        # A child reserve larger than the whole scan budget would let one agent
        # consume more than the operator allowed for everything.
        assert _capped.max_child_cost_usd <= _capped.max_cost_usd

        # ── a running scan must always be findable ────────────────────────────
        # The console held the only reference to a live scan in browser state, so
        # opening a historical run replaced it and the scan became unreachable while
        # still running and still spending.
        assert active_scans() == []
        SESSION.scans["live1"] = new_scan_state("live1", "o/r")
        SESSION.scans["live1"]["status"] = "scanning"
        SESSION.scans["old1"] = new_scan_state("old1", "o/r")
        SESSION.scans["old1"]["status"] = "done"
        try:
            listed = json.loads(
                urllib.request.urlopen(base + "/api/scans/active", timeout=5).read()
            )["scans"]
            assert [s["id"] for s in listed] == ["live1"], listed
            assert listed[0]["repo"] == "o/r"
            # Every non-terminal status counts, or a scan stuck in "queued" would be
            # just as unreachable as before.
            for status in LIVE_STATUSES:
                SESSION.scans["live1"]["status"] = status
                assert len(active_scans()) == 1, status
            for status in ("done", "error", "cancelled"):
                SESSION.scans["live1"]["status"] = status
                assert active_scans() == [], status
        finally:
            SESSION.scans.pop("live1", None)
            SESSION.scans.pop("old1", None)

        runs = json.loads(urllib.request.urlopen(base + "/api/runs", timeout=5).read())
        assert isinstance(runs.get("runs"), list), runs

        session = json.loads(urllib.request.urlopen(base + "/api/session", timeout=5).read())
        assert session["configured"] is True and session["connected"] is False, session
        assert session["scope"] == "repo", session

        # The scope MUST reach the authorize URL. Without it GitHub issues a token that
        # can read nothing private, and the failure looks identical to "this user has
        # no repositories" — which is exactly the dead end that killed the App path.
        opener = urllib.request.build_opener(_NoRedirect())
        try:
            opener.open(base + "/auth/start", timeout=5)
            raise AssertionError("expected a redirect")
        except urllib.error.HTTPError as exc:
            assert "scope=repo" in exc.headers["Location"], exc.headers["Location"]

        os.environ["DOCKET_GITHUB_SCOPE"] = "public_repo"
        try:
            assert oauth_scope() == "public_repo"
        finally:
            os.environ.pop("DOCKET_GITHUB_SCOPE", None)
        assert oauth_scope() == "repo", "unset must default to repo, not empty"

        # 2. /auth/start redirects to GitHub and plants a CSRF state.
        opener = urllib.request.build_opener(_NoRedirect())
        try:
            opener.open(base + "/auth/start", timeout=5)
            raise AssertionError("expected a redirect")
        except urllib.error.HTTPError as exc:
            assert exc.code == 302, exc.code
            location = exc.headers["Location"]
        assert location.startswith(GITHUB_AUTHORIZE), location
        assert SESSION.oauth_state and SESSION.oauth_state in location

        # 3. A callback whose state does not match is refused (CSRF).
        for bad_state in ("", "not-the-state"):
            try:
                urllib.request.urlopen(f"{base}/auth/callback?code=x&state={bad_state}", timeout=5)
                raise AssertionError("bad state must be refused")
            except urllib.error.HTTPError as exc:
                assert exc.code == 400, exc.code
        assert SESSION.oauth_state is None, "state must be single-use"

        # 4. Scanning without a connection is refused rather than half-attempted.
        for path, method in (("/api/repos", "GET"), ("/api/scan", "POST")):
            request = urllib.request.Request(
                base + path, method=method,
                data=b'{"repo":"a/b"}' if method == "POST" else None,
            )
            try:
                urllib.request.urlopen(request, timeout=5)
                raise AssertionError(f"{path} must require a connection")
            except urllib.error.HTTPError as exc:
                assert exc.code == 401, (path, exc.code)

        # 5. With a token present, a malformed repo name or ref never reaches the network.
        SESSION.token = "fake"
        try:
            urllib.request.urlopen(urllib.request.Request(
                base + "/api/scan", data=b'{"repo":"a/b","ref":"../../etc/passwd"}',
                method="POST"), timeout=5)
            raise AssertionError("bad ref must be rejected")
        except urllib.error.HTTPError as exc:
            assert exc.code == 400, exc.code
        try:
            urllib.request.urlopen(urllib.request.Request(
                base + "/api/scan", data=b'{"repo":"../../etc/passwd"}', method="POST"), timeout=5)
            raise AssertionError("bad repo name must be rejected")
        except urllib.error.HTTPError as exc:
            assert exc.code == 400, exc.code
        SESSION.token = None

        # 6. Polling an unknown scan id is a 404, not an empty "still running".
        try:
            urllib.request.urlopen(base + "/api/scan/nope", timeout=5)
            raise AssertionError("unknown scan id must 404")
        except urllib.error.HTTPError as exc:
            assert exc.code == 404, exc.code

        server.shutdown()
    finally:
        globals()["load_dotenv"] = real_load_dotenv
        for key, value in saved.items():
            if value is not None:
                os.environ[key] = value
            else:
                os.environ.pop(key, None)
        SESSION.token = SESSION.login = SESSION.oauth_state = None
    print("interface.connect: ok")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # noqa: ANN002, ANN003
        return None


if __name__ == "__main__":
    demo()
