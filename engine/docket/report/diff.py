"""Compare two scans: what a change INTRODUCED, what it FIXED, what it left alone.

This is the primitive a pull-request check is built on, and it answers a different
question from a scan. A scan asks "how bad is this codebase". A PR asks "does this
change make it worse". Ship the first as the second and it dies in a week: forty
findings on a three-line diff blames a developer for code they did not write, and the
check gets muted.

WHY dedupe_key AND NOT LINE NUMBERS
-----------------------------------
The key is `rule_id|method|path|parameter` — the FILE, with no line number. That is
deliberate and it is the single most important decision here. Insert a comment at the
top of a file and every finding below it shifts a line; keyed on lines, a whitespace
commit reports twenty new vulnerabilities. Keyed on the file, it correctly reports
none.

The cost is real and worth stating: two matches of the same rule in one file share a
key, so removing one of them shows as no change. A line-noise generator would be worse.

WHY A DIFF CAN BE UNTRUSTWORTHY
-------------------------------
Learned from strix's CI guidance, which warns that a budget-exhausted scan still exits
zero and can report "no vulnerabilities" having analysed half the diff. They bolt a
status check onto the pipeline to compensate. Here it is structural: a diff computed
from an incomplete scan carries caveats, and `trustworthy` is False. A PR gate must
refuse to report "clean" when the truthful answer is "we did not finish looking".

The first scan of a repository has no baseline at all. Everything is "new", which is
true and useless — gating on it would block the first PR on the entire backlog. That
is a caveat too, not a pass.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any

# Worst first, so the caller can gate on the top of the list.
_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def finding_key(finding: dict[str, Any]) -> str:
    """The stable identity of a finding across runs.

    Recomputed here rather than read from the report because report.json does not
    carry it — `dedupe_key` is a property on the model and is serialised only into
    SARIF's partialFingerprints. Same formula, so the two agree by construction; if
    Finding.dedupe_key ever changes, this must change with it.
    """
    location = finding.get("location") or {}
    raw = "|".join([
        str(finding.get("rule_id", "")),
        str(location.get("method", "")),
        str(location.get("path", "")),
        str(location.get("parameter") or ""),
    ])
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _incomplete(report: dict[str, Any] | None, side: str) -> list[str]:
    """Reasons this side of the diff cannot be trusted. Empty means it can."""
    if report is None:
        return [f"no {side} scan to compare against"]
    reasons = []
    if report.get("success") is False:
        reasons.append(f"the {side} scan did not complete successfully")
    if (report.get("surface") or {}).get("partial"):
        reasons.append(f"the {side} scan's attack surface map is incomplete "
                       "(the agent ran out of turns)")
    if not report.get("coverage"):
        reasons.append(f"the {side} scan recorded no coverage, so there is no evidence "
                       "of how much was actually analysed")
    return reasons


@dataclass(frozen=True)
class RunDiff:
    """What changed between two scans. `new` is the only list a PR check should show."""

    new: list[dict[str, Any]] = field(default_factory=list)
    fixed: list[dict[str, Any]] = field(default_factory=list)
    unchanged: list[dict[str, Any]] = field(default_factory=list)
    # Why this comparison might be wrong. Empty means it can be relied on.
    caveats: list[str] = field(default_factory=list)

    @property
    def trustworthy(self) -> bool:
        return not self.caveats

    @property
    def new_reachable(self) -> list[dict[str, Any]]:
        """New findings an agent judged reachable by untrusted input.

        The subset worth blocking a merge over. A finding nobody triaged is NOT in
        here — absence of a verdict is not a verdict of safe.
        """
        return [f for f in self.new
                if (f.get("triage") or {}).get("verdict") == "exploitable"]

    def summary(self) -> str:
        """One line for a commit status description (GitHub truncates at 140)."""
        if self.caveats:
            return f"{len(self.new)} new, but the comparison is incomplete"
        if not self.new:
            fixed = f", {len(self.fixed)} fixed" if self.fixed else ""
            return f"No new findings{fixed}"
        reachable = len(self.new_reachable)
        detail = f" ({reachable} reachable)" if reachable else ""
        return f"{len(self.new)} new finding(s){detail}"


def diff_runs(base: dict[str, Any] | None, head: dict[str, Any]) -> RunDiff:
    """Compare two report.json documents. `base` is what the branch looked like before.

    Passing None for `base` is legitimate — it is the first scan of a repository — and
    produces every finding as `new` WITH a caveat, so a caller cannot mistake a
    backlog for a regression.
    """
    head_findings = head.get("findings", []) or []
    base_findings = (base or {}).get("findings", []) or []

    base_keys = {finding_key(f) for f in base_findings}
    head_keys = {finding_key(f) for f in head_findings}

    seen: set[str] = set()
    new, unchanged = [], []
    for finding in head_findings:
        key = finding_key(finding)
        # First occurrence only: two matches of one rule in one file share a key, and
        # listing the same key twice would double-count a single change.
        if key in seen:
            continue
        seen.add(key)
        (unchanged if key in base_keys else new).append(finding)

    fixed_seen: set[str] = set()
    fixed = []
    for finding in base_findings:
        key = finding_key(finding)
        if key not in head_keys and key not in fixed_seen:
            fixed_seen.add(key)
            fixed.append(finding)

    by_severity = lambda f: _ORDER.get(str(f.get("severity", "info")), 9)  # noqa: E731
    caveats = _incomplete(base, "base") + _incomplete(head, "head")

    return RunDiff(
        new=sorted(new, key=by_severity),
        fixed=sorted(fixed, key=by_severity),
        unchanged=unchanged,
        caveats=caveats,
    )


# Exit codes, matching the convention strix uses so a pipeline can switch between them
# without relearning: 0 clean, 1 could not tell, 2 found something.
EXIT_CLEAN = 0
EXIT_INCONCLUSIVE = 1
EXIT_FOUND = 2


def gate(diff: RunDiff, *, block_on: str = "reachable") -> tuple[int, str]:
    """(exit_code, reason) for a merge gate.

    `block_on`:
      "reachable"  block only on new findings an agent judged reachable. The default,
                   and the whole product thesis — a check that is quiet on a clean PR
                   is a check people leave enabled.
      "any"        block on any new finding, triaged or not. Noisier and it will be
                   turned off; offered because some teams are required to.

    An untrustworthy diff is INCONCLUSIVE, never clean. That is the failure strix
    warns about in their CI docs — a scan that ran out of budget exiting zero and
    being read as "no vulnerabilities" when it means "we stopped looking".
    """
    if diff.caveats:
        return EXIT_INCONCLUSIVE, "; ".join(diff.caveats)

    blocking = diff.new if block_on == "any" else diff.new_reachable
    if blocking:
        worst = blocking[0]
        location = (worst.get("location") or {}).get("source_file") or "?"
        return EXIT_FOUND, (
            f"{len(blocking)} new finding(s) block this merge. Worst: "
            f"{worst.get('rule_id', '?').rsplit('.', 1)[-1]} at "
            f"{str(location).replace('/work/source/', '')}"
        )

    if diff.new:
        # New findings exist but none are reachable. Say so rather than "clean" —
        # the reader should know something was added and judged, not overlooked.
        return EXIT_CLEAN, (
            f"{len(diff.new)} new finding(s), none judged reachable by untrusted input"
        )
    return EXIT_CLEAN, diff.summary()


def demo() -> None:
    def finding(rule, path, line=1, severity="high", verdict=None, by="semgrep"):
        f = {
            "rule_id": rule, "severity": severity, "discovered_by": by,
            "location": {"method": "STATIC", "path": path, "parameter": None,
                         "source_file": f"{path}:{line}"},
        }
        if verdict:
            f["triage"] = {"verdict": verdict, "reasoning": "r", "evidence": "e"}
        return f

    def report(findings, **kw):
        base = {"findings": findings, "success": True,
                "coverage": {"semgrep": {"files_scanned": 10}}}
        base.update(kw)
        return base

    sqli = finding("semgrep/sqli", "app/auth.py", line=41)
    xss = finding("semgrep/xss", "app/search.py", line=12, severity="medium")

    # ── the property the whole design rests on ──────────────────────────────
    # A comment inserted at the top shifts every line below it. Keyed on lines this
    # reports the file's findings as new; keyed on the file it reports none.
    moved = finding("semgrep/sqli", "app/auth.py", line=99)
    same = diff_runs(report([sqli]), report([moved]))
    assert same.new == [] and same.fixed == [], "a line shift must not look like a change"
    assert same.unchanged and same.trustworthy

    # Moving to a DIFFERENT file is a real change, and shows as both.
    relocated = diff_runs(report([sqli]), report([finding("semgrep/sqli", "app/db.py")]))
    assert len(relocated.new) == 1 and len(relocated.fixed) == 1

    # ── introduced and fixed ────────────────────────────────────────────────
    added = diff_runs(report([xss]), report([xss, sqli]))
    assert [f["rule_id"] for f in added.new] == ["semgrep/sqli"]
    assert added.fixed == [] and len(added.unchanged) == 1
    assert "1 new finding(s)" in added.summary()

    removed = diff_runs(report([xss, sqli]), report([xss]))
    assert [f["rule_id"] for f in removed.fixed] == ["semgrep/sqli"]
    assert removed.new == []
    assert removed.summary() == "No new findings, 1 fixed"

    # Worst first, so a gate can read the head of the list.
    ordered = diff_runs(report([]), report([
        finding("a", "x.py", severity="low"),
        finding("b", "y.py", severity="critical"),
    ], coverage={"semgrep": {}}))
    assert ordered.new[0]["severity"] == "critical", [f["severity"] for f in ordered.new]

    # Two matches of one rule in one file share a key and must not double-count.
    twice = diff_runs(report([]), report([
        finding("semgrep/sqli", "app/auth.py", line=10),
        finding("semgrep/sqli", "app/auth.py", line=20),
    ], coverage={"semgrep": {}}))
    assert len(twice.new) == 1, twice.new

    # ── the gate ────────────────────────────────────────────────────────────
    reachable = finding("semgrep/sqli", "app/auth.py", verdict="exploitable")
    unreachable = finding("semgrep/x", "tests/fixture.py", verdict="not_reachable")

    code, why = gate(diff_runs(report([]), report([reachable])))
    assert code == EXIT_FOUND and "block this merge" in why and "app/auth.py" in why

    # Not reachable -> not a blocker. This is the product thesis: quiet on a clean PR.
    code, why = gate(diff_runs(report([]), report([unreachable])))
    assert code == EXIT_CLEAN and "none judged reachable" in why, why

    # ...but an untriaged finding is NOT safe. Absence of a verdict is not a verdict.
    untriaged = diff_runs(report([]), report([finding("semgrep/sqli", "a.py")]))
    assert untriaged.new_reachable == [], "no verdict must never count as reachable"
    assert gate(untriaged)[0] == EXIT_CLEAN
    assert gate(untriaged, block_on="any")[0] == EXIT_FOUND

    code, why = gate(diff_runs(report([]), report([])))
    assert code == EXIT_CLEAN and why == "No new findings"

    # ── never fail open ─────────────────────────────────────────────────────
    # The failure strix's CI docs warn about: a scan that stopped early exiting 0 and
    # being read as "no vulnerabilities" when it means "we stopped looking".
    stopped = diff_runs(report([xss]), report([xss], success=False))
    assert not stopped.trustworthy
    assert gate(stopped)[0] == EXIT_INCONCLUSIVE, "an incomplete scan is never clean"
    assert "did not complete" in gate(stopped)[1]

    # A partial recon map taints it too.
    partial = diff_runs(report([]), report([], surface={"partial": True}))
    assert not partial.trustworthy and "ran out of turns" in " ".join(partial.caveats)

    # No coverage recorded means no evidence anything was examined.
    blind = diff_runs(report([]), {"findings": [], "success": True})
    assert not blind.trustworthy and any("no coverage" in c for c in blind.caveats)

    # First scan of a repository: everything is new, which is TRUE and useless. It
    # must not read as a regression, or the first PR blocks on the whole backlog.
    first = diff_runs(None, report([sqli, xss]))
    assert len(first.new) == 2
    assert not first.trustworthy and "no base scan" in " ".join(first.caveats)
    assert gate(first)[0] == EXIT_INCONCLUSIVE, "a backlog is not a regression"
    assert "incomplete" in first.summary()

    print("report.diff: ok")


if __name__ == "__main__":
    demo()
