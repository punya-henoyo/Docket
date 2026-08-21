"""Scan a pull request: what did this change introduce?

The economics are the design. A full scan of Mendor-lab was 48 findings, 17 minutes
and $2.00. Run that on every push and the check is unaffordable and too slow to gate a
merge. Three decisions bring it to seconds and cents:

  1. Scanners run only over the files the PR touched.
  2. The diff is scoped to those same files on BOTH sides. Without that, a base
     finding in an untouched file has no counterpart in the head scan and reports as
     FIXED — the PR would be credited with fixing everything it never opened.
  3. Triage runs ONLY on findings the diff calls new. A PR introduces nought to three,
     not forty-eight, and triage is the only phase that costs real money.

Recon runs on the HEAD commit only, in pull-request mode: it is handed the changed
files rather than grepping for routes, so the discovery phase is skipped and the turns
go into reading handlers. What it may READ is not restricted to the diff — a missing
guard is missing only relative to the guards around it, so comparing a changed handler
against its unchanged siblings is the whole technique. What it REPORTS is scoped to the
changed files, which is also what keeps a pre-existing candidate from being blamed on
this author.

WHAT THIS MODULE DOES NOT DO
Fetching the source and posting results are the caller's job (interface/connect.py
holds the GitHub token and the HTTP surface). This is the decision-making half, so it
is testable without a network.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from docket.report.diff import RunDiff, diff_runs, gate

# A pull request that rewrites this much is not a pull request docket can usefully
# scope. Past it, scanning everything is both cheaper and more honest than pretending
# a subset is representative.
MAX_CHANGED_FILES = 300

# Only files a static scanner can read. A PR full of images or lockfiles has nothing
# for semgrep, and scoping to them would scan nothing while reporting success.
SCANNABLE_SUFFIXES = (
    ".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".rb", ".java", ".php", ".rs",
    ".cs", ".kt", ".scala", ".swift", ".c", ".cc", ".cpp", ".h", ".hpp",
    ".sh", ".bash", ".yml", ".yaml", ".json", ".tf", ".tfvars",
    "dockerfile", ".dockerfile",
)


def scannable(files: list[dict[str, Any]] | None) -> list[str]:
    """Repo-relative paths worth scanning, from GitHub's compare/files payload.

    Removed files are dropped: they do not exist at head, and handing semgrep a path
    that is not there fails the whole invocation rather than skipping one entry.
    Renames are kept under their NEW name for the same reason.
    """
    if not files:
        return []
    out: list[str] = []
    for entry in files:
        if not isinstance(entry, dict):
            continue
        if entry.get("status") == "removed":
            continue
        name = entry.get("filename") or entry.get("path")
        if not isinstance(name, str) or not name.strip():
            continue
        lowered = name.lower()
        if not lowered.endswith(SCANNABLE_SUFFIXES) and "dockerfile" not in lowered:
            continue
        if name not in out:
            out.append(name)
    return out


@dataclass
class PullRequestPlan:
    """What to scan and how, decided before anything expensive runs."""

    paths: list[str] = field(default_factory=list)
    # The lines each changed file actually touched. Empty means "not known", and the
    # caller falls back to file-level scoping rather than discarding everything.
    lines: dict[str, set[int]] = field(default_factory=dict)
    # False when the change is too large to scope, or touches files no scanner reads.
    # The caller falls back to a full scan rather than scanning a misleading subset.
    scoped: bool = True
    notes: list[str] = field(default_factory=list)

    @property
    def worth_scanning(self) -> bool:
        """False when the PR contains nothing a static scanner can read at all.

        A documentation-only PR should pass instantly and silently, not spin up a
        container to prove that markdown has no SQL injection.
        """
        return bool(self.paths) or not self.scoped


_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@", re.M)


def changed_lines(files: list[dict[str, Any]] | None) -> dict[str, set[int]]:
    """{path: line numbers this change touched}, from GitHub's unified diff hunks.

    Scoping by FILE is not enough. A pull request that appends one route to app.py
    makes the whole of app.py "changed", so every finding anywhere in it — including
    ones that predate the author by months — reads as introduced. Measured on
    kaizenmantra/vulnshop#20: three findings reported, two of them about lines 36 and
    39 in a change that only touched 58-73.

    That is the exact failure this product exists to avoid: blame someone for code
    they did not write and the check gets muted.
    """
    out: dict[str, set[int]] = {}
    for entry in files or []:
        if not isinstance(entry, dict) or entry.get("status") == "removed":
            continue
        name = entry.get("filename") or entry.get("path")
        patch = entry.get("patch")
        if not isinstance(name, str) or not isinstance(patch, str):
            continue
        lines: set[int] = out.setdefault(name, set())
        for start, count in _HUNK.findall(patch):
            first = int(start)
            # A hunk with no count is a single line. GitHub omits ",1".
            span = int(count) if count else 1
            lines.update(range(first, first + span))
    return out


def plan_scan(files: list[dict[str, Any]] | None) -> PullRequestPlan:
    """Decide the scan scope for a pull request's changed files."""
    paths = scannable(files)
    total = len([f for f in (files or []) if isinstance(f, dict)])

    if total > MAX_CHANGED_FILES:
        return PullRequestPlan(
            paths=[], scoped=False,
            notes=[f"{total} files changed, over the {MAX_CHANGED_FILES} scoping "
                   "limit — scanned the whole repository instead, so findings may "
                   "predate this change"],
        )
    if not paths:
        return PullRequestPlan(
            paths=[], scoped=True,
            notes=["no files a static scanner reads were changed"],
        )
    return PullRequestPlan(paths=paths, lines=changed_lines(files))


def _touches_change(finding: dict[str, Any], lines: dict[str, set[int]]) -> bool:
    """Does this finding sit on a line the change touched?

    True when the finding cites no line at all — a candidate about a whole handler
    ("no authorization on /orders") legitimately spans a range, and refusing it for
    lacking a single line number would drop the findings recon is best at.
    """
    location = finding.get("location") or {}
    source = str(location.get("source_file") or "")
    path = str(location.get("path") or "").replace("/work/source/", "").lstrip("/")
    touched = lines.get(path)
    if not touched:
        return True                      # unknown scope: keep rather than guess

    numbers = [int(n) for n in re.findall(r"\d+", source.rsplit(":", 1)[-1])] \
        if ":" in source else []
    if not numbers:
        return True                      # no line cited: cannot be shown pre-existing
    # A candidate may cite a RANGE ("app.py:29-58"); any overlap counts.
    span = re.findall(r"(\d+)(?:\s*-\s*(\d+))?", source.rsplit(":", 1)[-1])
    for start, end in span:
        low, high = int(start), int(end or start)
        if any(low <= n <= high for n in touched):
            return True
    return False


def _provably_introduced(finding: dict[str, Any], lines: dict[str, set[int]]) -> bool:
    """Did this change PROVE it introduced this finding — a cited line inside a changed hunk?

    Stricter than `_touches_change`, which keeps a finding when it cannot be shown
    pre-existing (no line cited, file not in the change). Those are worth reporting but
    cannot carry a merge decision. This returns True only when a cited line overlaps a
    touched line, which is exactly the evidence `RunDiff.gating` needs to let an agent
    finding block a merge without re-opening the vulnshop#25 false-positive.
    """
    location = finding.get("location") or {}
    source = str(location.get("source_file") or "")
    path = str(location.get("path") or "").replace("/work/source/", "").lstrip("/")
    touched = lines.get(path)
    if not touched or ":" not in source:
        return False
    span = re.findall(r"(\d+)(?:\s*-\s*(\d+))?", source.rsplit(":", 1)[-1])
    for start, end in span:
        low, high = int(start), int(end or start)
        if any(low <= n <= high for n in touched):
            return True
    return False


def findings_to_triage(diff: RunDiff, limit: int) -> list[dict[str, Any]]:
    """The findings worth spending money on: the new ones, worst first, capped.

    Triage is the only phase that costs real money, and on a pull request the only
    findings that matter are the ones it introduced. Judging the pre-existing backlog
    on every push is how a $0.08 check becomes a $2.00 one.
    """
    if limit <= 0:
        return []
    return diff.new[:limit]


def evaluate(base_report: dict[str, Any] | None, head_report: dict[str, Any],
             plan: PullRequestPlan, *, block_on: str = "reachable") -> dict[str, Any]:
    """The verdict for a pull request: the diff, the exit code, and the reason.

    Scope is applied only when the head scan was actually scoped. Applying it to a
    full scan would discard real findings outside the changed files, which on a
    fallback run is exactly the coverage the fallback existed to get.
    """
    scope = plan.paths if (plan.scoped and plan.paths) else None
    diff = diff_runs(base_report, head_report, scope=scope)

    # Then narrow to the lines the change actually touched. Recon runs on head only,
    # so it has no base to be compared against and every candidate about the file
    # would otherwise read as introduced — including ones about code the author never
    # opened. A finding that cites no line is kept: it cannot be shown to be
    # pre-existing, and dropping it would hide something on a technicality.
    if plan.scoped and plan.lines:
        # Keep only findings on a changed line, and stamp `introduced` on each so the
        # gate can tell a finding this change PROVED it added (cited line inside a hunk)
        # from one merely kept because it could not be shown pre-existing (no line). Only
        # the former lets an agent finding block a merge — see RunDiff.gating.
        diff = RunDiff(
            new=[{**f, "introduced": _provably_introduced(f, plan.lines)}
                 for f in diff.new if _touches_change(f, plan.lines)],
            fixed=diff.fixed,
            unchanged=diff.unchanged,
            caveats=diff.caveats,
        )

    if not plan.scoped:
        diff = RunDiff(
            new=diff.new, fixed=diff.fixed, unchanged=diff.unchanged,
            caveats=[*diff.caveats, *plan.notes],
        )

    code, reason = gate(diff, block_on=block_on)
    return {
        "exit_code": code,
        "reason": reason,
        "summary": diff.summary(),
        "new": diff.new,
        # The same set split by whether it can carry a merge decision. `new` stays whole
        # so nothing downstream loses a finding; these two say which half it is in.
        # See RunDiff.gating — the base scan runs recon=False, so an agent finding is
        # `new` on every pull request and cannot mean "this change introduced it".
        "gating": diff.gating,
        "observations": diff.observations,
        "fixed": diff.fixed,
        "new_reachable": diff.new_reachable,
        "trustworthy": diff.trustworthy,
        "caveats": diff.caveats,
        "scoped_to": plan.paths,
        "notes": plan.notes,
    }


def demo() -> None:
    from docket.report.diff import EXIT_CLEAN, EXIT_FOUND, EXIT_INCONCLUSIVE

    def gh(name, status="modified"):
        return {"filename": name, "status": status}

    def finding(rule, path, severity="high", verdict=None):
        f = {"rule_id": rule, "severity": severity, "discovered_by": "semgrep",
             "location": {"method": "STATIC", "path": path, "parameter": None,
                          "source_file": f"{path}:1"}}
        if verdict:
            f["triage"] = {"verdict": verdict, "reasoning": "r", "evidence": "e"}
        return f

    def report(findings):
        return {"findings": findings, "success": True,
                "coverage": {"semgrep": {"files_scanned": 3}}}

    # ── what is worth scanning ──────────────────────────────────────────────
    assert scannable([gh("app/auth.py"), gh("README.md"), gh("logo.png")]) == ["app/auth.py"]
    assert scannable([gh("Dockerfile"), gh("infra/main.tf")]) == ["Dockerfile", "infra/main.tf"]
    # A removed file does not exist at head; handing it to semgrep fails the whole run.
    assert scannable([gh("gone.py", status="removed")]) == []
    assert scannable([gh("a.py"), gh("a.py")]) == ["a.py"]
    assert scannable(None) == [] and scannable([{"nonsense": 1}]) == []

    # ── the plan ────────────────────────────────────────────────────────────
    docs_only = plan_scan([gh("README.md")])
    assert docs_only.paths == [] and docs_only.scoped
    assert not docs_only.worth_scanning, "a docs PR must not start a container"

    huge = plan_scan([gh(f"f{i}.py") for i in range(MAX_CHANGED_FILES + 1)])
    assert not huge.scoped and huge.worth_scanning
    assert "over the" in huge.notes[0]

    normal = plan_scan([gh("app/auth.py"), gh("docs/x.md")])
    assert normal.paths == ["app/auth.py"] and normal.scoped

    # ── line scoping: the vulnshop#20 failure ───────────────────────────────
    # A pull request that appended one route to app.py made the WHOLE file "changed",
    # so recon candidates about lines 36 and 39 — code the author never opened — were
    # reported as introduced by it. Three findings, two of them someone else's.
    patch = ("@@ -58,5 +58,15 @@ def search():\n context\n+new line\n+another\n")
    touched = changed_lines([{"filename": "app.py", "status": "modified",
                              "patch": patch}])
    assert 58 in touched["app.py"] and 72 in touched["app.py"]
    assert 36 not in touched["app.py"], "a line the change never touched"

    def rec(title, at):
        return {"rule_id": f"recon/{title}", "title": title, "severity": "high",
                "discovered_by": "recon",
                "location": {"method": "STATIC", "path": "app.py", "parameter": None,
                             "source_file": f"app.py:{at}"},
                "poc": {"request": title, "response": "x"}}

    files20 = [{"filename": "app.py", "status": "modified", "patch": patch}]
    head20 = report([rec("pre-existing login sqli", 36),
                     rec("the injection this PR added", 66),
                     rec("pre-existing session bug", 39)])
    scoped20 = evaluate(report([]), head20, plan_scan(files20))
    assert len(scoped20["new"]) == 1, [f["title"] for f in scoped20["new"]]
    assert scoped20["new"][0]["title"] == "the injection this PR added"

    # An agent finding ON a changed line now BLOCKS — the fix for Mendor-lab#14, where a
    # recon-confirmed IDOR and a privilege escalation sat in a non-blocking fold. A
    # confirmed agent finding the change introduced must carry the merge decision.
    idor = {**rec("cross-tenant IDOR the PR added", 66),
            "triage": {"verdict": "exploitable"}}
    v = evaluate(report([]), report([idor]), plan_scan(files20))
    assert v["new"][0].get("introduced") is True, "cited line in a hunk ⇒ introduced"
    assert v["gating"] and v["new_reachable"], "an introduced agent finding must gate"
    assert v["exit_code"] == 2, f"must block (exit 2), got {v['exit_code']}"

    # ...but a line-less agent finding still cannot be shown introduced, so it stays an
    # observation and never gates — the vulnshop#25 false-positive stays closed.
    noline = {**rec("an authz smell with no line", 1),
              "triage": {"verdict": "exploitable"},
              "location": {"method": "STATIC", "path": "app.py", "parameter": None,
                           "source_file": "app.py"}}
    v2 = evaluate(report([]), report([noline]), plan_scan(files20))
    assert v2["observations"] and not v2["gating"], "no line ⇒ observation only"
    assert v2["exit_code"] == 0, f"line-less agent finding must not block, got {v2['exit_code']}"

    # A candidate spanning a RANGE counts if it overlaps the change at all — recon's
    # best findings are about whole handlers, not single lines.
    spanning = report([{**rec("no authorization on the new route", 1),
                        "location": {"method": "STATIC", "path": "app.py",
                                     "parameter": None,
                                     "source_file": "app.py:60-70"}}])
    assert len(evaluate(report([]), spanning, plan_scan(files20))["new"]) == 1

    # A range entirely outside the change is dropped.
    outside = report([{**rec("old handler", 1),
                       "location": {"method": "STATIC", "path": "app.py",
                                    "parameter": None,
                                    "source_file": "app.py:10-20"}}])
    assert evaluate(report([]), outside, plan_scan(files20))["new"] == []

    # No line cited at all: kept. It cannot be SHOWN pre-existing, and dropping it
    # would hide a finding on a technicality.
    noline = report([{**rec("something", 1),
                      "location": {"method": "STATIC", "path": "app.py",
                                   "parameter": None, "source_file": "app.py"}}])
    assert len(evaluate(report([]), noline, plan_scan(files20))["new"]) == 1

    # No patch text from GitHub means no line data; fall back to file scoping rather
    # than discarding everything.
    nopatch = [{"filename": "app.py", "status": "modified"}]
    assert changed_lines(nopatch) == {}
    assert len(evaluate(report([]), head20, plan_scan(nopatch))["new"]) == 3

    # ── the trap scoping closes ─────────────────────────────────────────────
    # Head only scanned app/auth.py. The base finding in legacy.py has no counterpart
    # and would report as FIXED, crediting the PR with work it never did.
    base = report([finding("old", "app/legacy.py"), finding("sqli", "app/auth.py")])
    head = report([finding("sqli", "app/auth.py")])
    verdict = evaluate(base, head, plan_scan([gh("app/auth.py")]))
    assert verdict["fixed"] == [], "must not credit a PR for untouched files"
    assert verdict["new"] == [] and verdict["exit_code"] == EXIT_CLEAN

    # A finding the PR actually introduced, judged reachable, blocks the merge.
    introduced = report([finding("sqli", "app/auth.py"), finding("rce", "app/auth.py",
                                                                verdict="exploitable")])
    blocked = evaluate(base, introduced, plan_scan([gh("app/auth.py")]))
    assert blocked["exit_code"] == EXIT_FOUND, blocked["reason"]
    assert len(blocked["new_reachable"]) == 1

    # ...and one that is NOT reachable does not. This is the whole thesis: quiet on a
    # clean PR is what keeps a check switched on.
    safe = report([finding("sqli", "app/auth.py"),
                   finding("x", "app/auth.py", verdict="not_reachable")])
    assert evaluate(base, safe, plan_scan([gh("app/auth.py")]))["exit_code"] == EXIT_CLEAN

    # ── the fallback must not silently narrow ───────────────────────────────
    # A whole-repo fallback scan carries no scope, and says why it cannot be trusted.
    fallback = evaluate(base, head, huge)
    assert not fallback["trustworthy"]
    assert any("over the" in c for c in fallback["caveats"])
    assert fallback["exit_code"] == EXIT_INCONCLUSIVE

    # ── triage only the delta ───────────────────────────────────────────────
    from docket.report.diff import diff_runs as _dr

    d = _dr(base, introduced, scope=["app/auth.py"])
    assert len(findings_to_triage(d, 10)) == 1, "only the new finding, not the backlog"
    assert findings_to_triage(d, 0) == [], "triage off means spend nothing"
    assert len(findings_to_triage(d, 1)) == 1

    print("core.pull_request: ok")


if __name__ == "__main__":
    demo()
