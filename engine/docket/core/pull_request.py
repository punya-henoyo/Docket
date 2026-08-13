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

Recon is deliberately not run per pull request. It maps the whole application, which a
three-line diff does not change, and it is the second most expensive phase. The base
branch's map is reused; refreshing it belongs on a schedule, not on a PR.

WHAT THIS MODULE DOES NOT DO
Fetching the source and posting results are the caller's job (interface/connect.py
holds the GitHub token and the HTTP surface). This is the decision-making half, so it
is testable without a network.
"""
from __future__ import annotations

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
    return PullRequestPlan(paths=paths)


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
