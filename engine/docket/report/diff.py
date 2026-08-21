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

# Sources that return the same findings for the same code every time. Only these can
# support a claim that something was FIXED, because only for these does absence mean
# the code changed.
DETERMINISTIC_SOURCES = frozenset({"semgrep", "trivy", "nuclei"})


def _snippet(finding: dict[str, Any]) -> str:
    """The matched code, whitespace-normalised. Empty when the finding carries none.

    Normalised so reindenting a block is not mistaken for new code: only the tokens
    matter, not the spacing between them.
    """
    request = ((finding.get("poc") or {}).get("request") or "")
    return " ".join(str(request).split())


def finding_key(finding: dict[str, Any]) -> str:
    """The identity of a finding across runs, for DIFFING.

    DELIBERATELY NOT Finding.dedupe_key, and this is the correction to a real false
    negative. dedupe_key is rule|method|file|param with no line and no content, which
    is right for its job — collapsing several agents reporting one issue into one
    finding. Reused for diffing it hides the commonest regression there is:

        main            f-string SQL in /login          app.py
        pull request    f-string SQL in /admin/users     app.py   <- same rule, same file

    Same key, so the new one classified as `unchanged` and the check reported "No new
    findings" on a pull request that plainly introduced one. GitHub's own Semgrep
    action flagged it in the same run, which is how it was caught.

    The matched CODE is the anchor instead. It distinguishes two instances in one file,
    and unlike a line number it survives a comment being inserted above them — the
    line-noise problem that made line numbers unusable in the first place. Findings
    with no snippet fall back to the location, which is all they have.
    """
    location = finding.get("location") or {}
    parts = [
        str(finding.get("rule_id", "")),
        str(location.get("method", "")),
        str(location.get("path", "")),
        str(location.get("parameter") or ""),
    ]
    snippet = _snippet(finding)
    if snippet:
        parts.append(snippet)
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]


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
    coverage = report.get("coverage") or {}
    if not coverage:
        reasons.append(f"the {side} scan recorded no coverage, so there is no evidence "
                       "of how much was actually analysed")
    # COVERAGE THAT CONTRADICTS THE FINDINGS. `rules_fired` is derived from semgrep's own
    # results (tools/scanners/semgrep.py:87 reads `check_id` off each hit), so a non-empty
    # value is proof semgrep MATCHED something. If none of those matches is in findings[],
    # the pipeline dropped them between the scanner and the report, and every downstream
    # number is computed from a set that is missing its deterministic half.
    #
    # Measured on kaizenmantra/vulnshop#20 and #23. `_run_scanner_prescans` binned all 17
    # semgrep hits at `if on_finding is not None` (fixed in core/runner.py:308), yet
    # coverage still read `files_scanned: 1, rules_fired: ["python"], error_count: 0` — a
    # clean-looking scanner run next to an empty findings list. The check passed a live
    # SQL injection, and later blocked the fix PR for it, for a whole day, because
    # nothing compared these two numbers against each other.
    #
    # Deliberately one-directional: findings without coverage is normal (trivy and recon
    # report neither), coverage without findings is not.
    elif (coverage.get("semgrep") or {}).get("rules_fired"):
        findings = report.get("findings") or []
        if not any(str(f.get("discovered_by", "")) == "semgrep" for f in findings):
            reasons.append(
                f"the {side} scan's semgrep matched rules but not one of its findings "
                "reached the report, so the scanner half of this comparison is missing")
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
    def gating(self) -> list[dict[str, Any]]:
        """New findings a merge may be blocked on: deterministic findings, PLUS agent
        findings proven to sit on a line this change actually touched.

        WHY AN AGENT FINDING CAN NOW GATE — AND WHY IT ONCE COULD NOT
        ------------------------------------------------------------
        The BASE scan runs with `recon=False` (core/pr_service.py, deliberately: running
        the agent on both sides doubled the wall clock). So the baseline contains NO
        agent findings, and every agent finding in the head is `new` by construction.
        "New" alone therefore never meant "this change introduced it" — it meant "there
        was nothing to compare against". That is why this used to block on deterministic
        findings only. Measured on kaizenmantra/vulnshop#25: a one-line fix PR blocked on
        an IDOR that was already in the branch it targeted.

        What closes the gap is the git diff. `core/pull_request.evaluate` now stamps
        `introduced` on each finding from the actual changed-line hunks
        (`_provably_introduced`): an agent finding that cites a line inside a changed hunk
        provably came from this change, and vulnshop#25's IDOR — on a line the fix never
        touched — would not be stamped and would not gate. So an agent finding is here
        ONLY when the diff proves it new; a line-less candidate, or an unscoped fallback
        scan with no diff to check, is never stamped and stays in `observations`.

        This is the product's whole point: the vulnerabilities only the agent can find
        (IDOR, privilege escalation, cross-tenant authz) block a merge when the change
        introduced them, instead of sitting in a fold nobody expands.
        """
        return [f for f in self.new
                if str(f.get("discovered_by", "")) in DETERMINISTIC_SOURCES
                or f.get("introduced")]

    @property
    def observations(self) -> list[dict[str, Any]]:
        """New findings that cannot carry a merge decision: agent findings NOT proven to
        sit on a changed line (no line cited, or an unscoped fallback with no diff). The
        complement of `gating`, so every new finding appears in exactly one of the two."""
        return [f for f in self.new
                if str(f.get("discovered_by", "")) not in DETERMINISTIC_SOURCES
                and not f.get("introduced")]

    @property
    def new_reachable(self) -> list[dict[str, Any]]:
        """Gating findings an agent judged reachable by untrusted input.

        The subset worth blocking a merge over. A finding nobody triaged is NOT in
        here — absence of a verdict is not a verdict of safe.
        """
        return [f for f in self.gating
                if (f.get("triage") or {}).get("verdict") == "exploitable"]

    @property
    def new_unresolved(self) -> list[dict[str, Any]]:
        """New findings on which NOBODY established anything.

        `not_reachable` is the only verdict that clears a finding. Missing means no agent
        judged it; `uncertain` means one tried and could not — and core/triage.py:198
        records `uncertain` when the budget runs out, so it is also what "we stopped
        paying" looks like. Neither is safety.

        This exists because `new_reachable` being empty has two very different causes and
        the gate could not tell them apart. Measured on kaizenmantra/vulnshop#23: triage
        spent its budget on two PRE-EXISTING semgrep findings at app.py:36-37 (out of the
        diff scope, correctly excluded from `new`), so the two in-scope findings at
        app.py:61-68 were never judged at all. `new_reachable` was empty, the check went
        green, and the comment said "none judged reachable" over two high-severity
        findings nobody had judged. The same pull request had been BLOCKED an hour
        earlier, when the scanner was broken and triage's budget happened to land on
        those same findings instead.

        Scoped to `gating` for the same reason `new_reachable` is. An agent finding is
        never blocking, so an agent finding nobody triaged cannot make the check
        inconclusive either — otherwise every pull request goes yellow forever, since
        triage is capped and agent findings are always the ones left over.
        """
        return [f for f in self.gating
                if (f.get("triage") or {}).get("verdict") != "not_reachable"
                and (f.get("triage") or {}).get("verdict") != "exploitable"]

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


def _in_scope(finding: dict[str, Any], scope: set[str]) -> bool:
    location = (finding.get("location") or {})
    path = str(location.get("path") or "").replace("/work/source/", "").lstrip("/")
    return path in scope


def diff_runs(base: dict[str, Any] | None, head: dict[str, Any],
              scope: list[str] | None = None) -> RunDiff:
    """Compare two report.json documents. `base` is what the branch looked like before.

    `scope` restricts BOTH sides to a set of repo-relative paths, and exists for the
    pull-request case where the head scan only covered the changed files. Without it
    the comparison is silently wrong in the most damaging direction: a base finding in
    a file the head scan never looked at has no counterpart, so it reports as FIXED.
    A PR would be credited with fixing everything it did not touch.

    Scoping both sides makes "fixed" mean "fixed among the files this change touched",
    which is the only claim the evidence supports.

    Passing None for `base` is legitimate — it is the first scan of a repository — and
    produces every finding as `new` WITH a caveat, so a caller cannot mistake a
    backlog for a regression.
    """
    head_findings = head.get("findings", []) or []
    base_findings = (base or {}).get("findings", []) or []

    if scope is not None:
        wanted = {str(p).strip().lstrip("/") for p in scope if isinstance(p, str)}
        head_findings = [f for f in head_findings if _in_scope(f, wanted)]
        base_findings = [f for f in base_findings if _in_scope(f, wanted)]

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
        # An agent's candidate vanishing is NOT evidence it was fixed. Recon phrases
        # each candidate afresh and is free to mention different ones on two runs of
        # the same code, so its absence means "not mentioned this time", not "gone".
        # Measured on kaizenmantra/vulnshop#19: a pull request that fixed nothing was
        # credited with "4 finding(s) fixed", purely from candidates churning between
        # the base and head runs.
        #
        # The asymmetry is deliberate and correct: a NEW candidate is a real
        # observation an agent made against real code and is reported, while a missing
        # one is the absence of an observation and proves nothing. Presence is
        # evidence; absence is not.
        if str(finding.get("discovered_by", "")) not in DETERMINISTIC_SOURCES:
            continue
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
      "any"        block on any new DETERMINISTIC finding, triaged or not. Noisier and
                   it will be turned off; offered because some teams are required to.

    Both settings can block on an agent finding, but ONLY one the git diff proved this
    change introduced (`RunDiff.gating`, via the `introduced` stamp). An agent finding
    that is merely `new` — line-less, or an unscoped fallback with no diff — still cannot
    gate, which is what keeps "any" from meaning "never merge anything".

    An untrustworthy diff is INCONCLUSIVE, never clean. That is the failure strix
    warns about in their CI docs — a scan that ran out of budget exiting zero and
    being read as "no vulnerabilities" when it means "we stopped looking".
    """
    # A CONFIRMED finding blocks BEFORE caveats are considered. Triage judged it
    # reachable by reading the source, which is independent of whatever else in the scan
    # failed — an incomplete scan cannot un-prove a reproduction. Checking caveats first
    # (as this used to) let one agent's crash downgrade a proven, exploitable finding to
    # "inconclusive". Measured on punya-henoyo/Mendor-lab#7: semgrep found a SQL
    # injection at app/profiles.py:48, triage confirmed it exploitable, and because recon
    # failed to record a surface the whole verdict went inconclusive (exit 1) instead of
    # blocked (exit 2) — softening a real block into "we could not tell".
    blocking = diff.gating if block_on == "any" else diff.new_reachable
    if blocking:
        worst = blocking[0]
        location = str((worst.get("location") or {}).get("source_file") or "?")
        # A recon candidate's rule_id is a slug of its own title; the title reads.
        name = (worst.get("title") if worst.get("discovered_by") == "recon"
                else str(worst.get("rule_id", "?")).rsplit(".", 1)[-1]) or "?"
        reason = (f"{len(blocking)} new finding(s) block this merge. Worst: {name} at "
                  f"{location.replace('/work/source/', '')}")
        if diff.caveats:
            # Still blocked, but say the scan was also incomplete so the reader knows the
            # count may be a floor, not the whole picture.
            reason += " (the scan was also incomplete — this may not be all of it)"
        return EXIT_FOUND, reason

    # No confirmed block. NOW an incomplete scan is decisive: we cannot call it clean.
    if diff.caveats:
        return EXIT_INCONCLUSIVE, "; ".join(diff.caveats)

    # "Nobody judged it" must never render as "nothing to worry about". Only reached
    # when nothing is exploitable, so this is the branch that used to go green on
    # findings no agent had looked at — see RunDiff.new_unresolved for the measurement.
    # INCONCLUSIVE rather than FOUND: docket did not find these unsafe, it failed to
    # find out, and the reader has to be able to tell those apart.
    if block_on != "any" and diff.new_unresolved:
        unresolved = diff.new_unresolved
        worst = unresolved[0]
        location = str((worst.get("location") or {}).get("source_file") or "?")
        return EXIT_INCONCLUSIVE, (
            f"{len(unresolved)} of {len(diff.gating)} scanner finding(s) were never "
            f"judged reachable or not — no verdict on "
            f"{location.replace('/work/source/', '')}"
        )

    # Passing, so the only job left is to not overstate it. An agent observation is
    # mentioned by count and never called safe: nobody established that it is.
    noted = (f", {len(diff.observations)} agent observation(s) to review"
             if diff.observations else "")
    if diff.gating:
        # Scanner findings exist, every one was judged, none is reachable. Say so rather
        # than "clean" — the reader should know something was added and judged.
        return EXIT_CLEAN, (
            f"{len(diff.gating)} new finding(s), all judged not reachable by untrusted "
            f"input{noted}"
        )
    if noted:
        return EXIT_CLEAN, f"No new scanner findings{noted}"
    return EXIT_CLEAN, diff.summary()


def demo() -> None:
    def finding(rule, path, line=1, severity="high", verdict=None, by="semgrep",
                code=None):
        f = {
            "rule_id": rule, "severity": severity, "discovered_by": by,
            "location": {"method": "STATIC", "path": path, "parameter": None,
                         "source_file": f"{path}:{line}"},
            "poc": {"request": code or f"line {line} of {path}", "response": "match"},
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

    # ── "fixed" must be provable ────────────────────────────────────────────
    # A recon candidate absent from the head run was not necessarily fixed — the agent
    # simply did not mention it this time. vulnshop#19 fixed nothing and was credited
    # with 4 fixes purely from that churn.
    candidate = finding("recon/no-authz", "app.py", by="recon", code="/orders route")
    scanner = finding("semgrep/sqli", "app.py", by="semgrep", code="execute(q)")
    churn = diff_runs(report([candidate, scanner]), report([scanner]))
    assert churn.fixed == [], "an agent candidate vanishing is not a fix"

    real = diff_runs(report([candidate, scanner]), report([candidate]))
    assert [f["rule_id"] for f in real.fixed] == ["semgrep/sqli"], real.fixed

    # ...but a NEW candidate IS reported. Presence is an observation an agent made
    # against real code; absence is the lack of one.
    appeared = diff_runs(report([scanner]), report([scanner, candidate]))
    assert len(appeared.new) == 1 and appeared.new[0]["discovered_by"] == "recon"

    # ── the false negative that shipped, and must never come back ───────────
    # A pull request adding a SECOND SQL injection to a file that already had one.
    # Keyed on rule|file alone the two collide, the new one reads as `unchanged`, and
    # the check reports "No new findings" on a PR that plainly introduced one. That
    # happened on kaizenmantra/vulnshop#18; GitHub's own Semgrep action flagged it in
    # the same run, which is how it was caught.
    RULE = "semgrep/python.lang.security.audit.tainted-sql-string"
    existing = finding(RULE, "app.py", 36, code='query = f"SELECT id FROM users WHERE u = {u}"')
    introduced = finding(RULE, "app.py", 80, code='cur.execute(f"SELECT id FROM users LIKE {t}")')
    assert finding_key(existing) != finding_key(introduced), \
        "two instances of one rule in one file must be distinguishable"
    regression = diff_runs(report([existing]), report([existing, introduced]),
                           scope=["app.py"])
    assert len(regression.new) == 1, regression.summary()

    # A finding with no snippet still keys on its location rather than vanishing.
    bare = {"rule_id": "r", "severity": "high",
            "location": {"method": "STATIC", "path": "a.py", "parameter": None}}
    assert finding_key(bare)

    # ── the property the whole design rests on ──────────────────────────────
    # A comment inserted at the top shifts every line below it. Keyed on lines this
    # reports the file's findings as new; keyed on the file it reports none.
    # Same code, different line: a comment inserted above must not report the whole
    # file as new. This is why the anchor is the CODE and not the line number.
    moved = finding("semgrep/sqli", "app/auth.py", line=99, code="db.execute(q)")
    sqli_anchored = finding("semgrep/sqli", "app/auth.py", line=41, code="db.execute(q)")
    same = diff_runs(report([sqli_anchored]), report([moved]))
    assert same.new == [] and same.fixed == [], "a line shift must not look like a change"
    assert same.unchanged and same.trustworthy

    # Reindenting is not a change either — the snippet is whitespace-normalised.
    reindented = finding("semgrep/sqli", "app/auth.py", line=41, code="   db.execute(q)  ")
    assert diff_runs(report([sqli_anchored]), report([reindented])).new == []

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

    # Two DIFFERENT matches of one rule in one file are two findings. This is the
    # behaviour the vulnshop#18 false negative forced: collapsing them is right when
    # deduping one issue reported twice, and wrong when diffing, where the second
    # instance is exactly the regression being looked for.
    twice = diff_runs(report([]), report([
        finding("semgrep/sqli", "app/auth.py", line=10, code="execute(a)"),
        finding("semgrep/sqli", "app/auth.py", line=20, code="execute(b)"),
    ], coverage={"semgrep": {}}))
    assert len(twice.new) == 2, twice.new

    # ...but genuinely identical code at two places still collapses, because there is
    # nothing to tell the two apart and reporting one change twice is noise.
    identical = diff_runs(report([]), report([
        finding("semgrep/sqli", "app/auth.py", line=10, code="execute(q)"),
        finding("semgrep/sqli", "app/auth.py", line=20, code="execute(q)"),
    ], coverage={"semgrep": {}}))
    assert len(identical.new) == 1, identical.new

    # ── the gate ────────────────────────────────────────────────────────────
    reachable = finding("semgrep/sqli", "app/auth.py", verdict="exploitable")
    unreachable = finding("semgrep/x", "tests/fixture.py", verdict="not_reachable")

    code, why = gate(diff_runs(report([]), report([reachable])))
    assert code == EXIT_FOUND and "block this merge" in why and "app/auth.py" in why

    # Not reachable -> not a blocker. This is the product thesis: quiet on a clean PR.
    code, why = gate(diff_runs(report([]), report([unreachable])))
    assert code == EXIT_CLEAN and "all judged not reachable" in why, why

    # ...but an untriaged finding is NOT safe. Absence of a verdict is not a verdict.
    # This block asserted EXIT_CLEAN until vulnshop#23 showed what that means in
    # practice: the comment below was already right, and the assertion under it
    # contradicted the comment, so the fail-open was locked in by its own test.
    untriaged = diff_runs(report([]), report([finding("semgrep/sqli", "a.py")]))
    assert untriaged.new_reachable == [], "no verdict must never count as reachable"
    assert gate(untriaged)[0] == EXIT_INCONCLUSIVE, "no verdict must never be clean"
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

    # Coverage that contradicts the findings — the vulnshop#20 regression. semgrep says
    # it matched python rules; not one semgrep finding is in the report. That is a
    # dropped scanner, and it must never read as clean.
    fired = {"semgrep": {"files_scanned": 1, "rules_fired": ["python"], "error_count": 0}}
    dropped = diff_runs(report([]), {"findings": [], "success": True, "coverage": fired})
    assert not dropped.trustworthy, "semgrep matched but reported nothing — not clean"
    assert any("not one of its findings" in c for c in dropped.caveats), dropped.caveats
    assert gate(dropped)[0] == EXIT_INCONCLUSIVE, "a dropped scanner is never a pass"

    # ...and the same coverage WITH a semgrep finding present is fine. Without this the
    # check above could be satisfied by a rule that just distrusts all coverage.
    kept = diff_runs(report([]), {"findings": [finding("semgrep/sqli", "app.py")],
                                  "success": True, "coverage": fired})
    assert kept.trustworthy, kept.caveats

    # Recon-only is NOT penalised: no rules_fired means semgrep never claimed a match,
    # which is a scan without SAST rather than a scan that lost its SAST.
    quiet = {"semgrep": {"files_scanned": 1, "rules_fired": [], "error_count": 0}}
    recon_only = diff_runs(report([]), {"findings": [], "success": True,
                                        "coverage": quiet})
    assert recon_only.trustworthy, recon_only.caveats

    # ── a CONFIRMED block beats an incomplete scan — the Mendor-lab#7 fail-open ─
    # semgrep found it, triage confirmed exploitable, but recon failed so the scan
    # carried a caveat. The proven finding must still BLOCK, not soften to inconclusive.
    confirmed = diff_runs(report([]), report([finding("semgrep/sqli", "app.py",
                                                      verdict="exploitable")], success=False))
    assert confirmed.caveats, "an incomplete scan carries a caveat"
    assert confirmed.new_reachable, "the confirmed finding is still reachable"
    code, why = gate(confirmed)
    assert code == EXIT_FOUND, f"a confirmed block must beat a caveat, got {code}: {why}"
    assert "block this merge" in why and "incomplete" in why, why
    # ...but with NO confirmed block, the same caveat is decisive: inconclusive.
    caveat_only = diff_runs(report([]), report([finding("semgrep/sqli", "app.py")],
                                               success=False))
    assert gate(caveat_only)[0] == EXIT_INCONCLUSIVE, "an incomplete scan with nothing proven is not clean"

    # ── an agent finding reports, it does not gate — the vulnshop#25 block ──────
    # The base scan runs with recon=False, so an agent finding is `new` on EVERY pull
    # request by construction. #25 changed one line and was blocked on a missing
    # ownership check that was already in the branch it targeted.
    agent_only = diff_runs(report([]), report([
        finding("recon/idor", "app.py", by="recon", verdict="exploitable")]))
    assert agent_only.observations and not agent_only.gating, agent_only.gating
    assert agent_only.new_reachable == [], "an agent finding must never gate"
    code, why = gate(agent_only)
    assert code == EXIT_CLEAN, f"agent-only findings must not block, got {code}: {why}"
    assert "observation" in why, why
    # ...and it must not make the check inconclusive either, or every PR goes yellow.
    assert agent_only.new_unresolved == [], agent_only.new_unresolved
    # block_on="any" must not smuggle it back in through the other door.
    assert gate(agent_only, block_on="any")[0] == EXIT_CLEAN, gate(agent_only, "any")

    # A scanner finding in the same diff still blocks, and the observation rides along
    # in the message rather than being silently dropped.
    mixed_src = diff_runs(report([]), report([
        finding("recon/idor", "app.py", by="recon", verdict="exploitable"),
        finding("semgrep/sqli", "app.py", verdict="exploitable"),
    ]))
    assert gate(mixed_src)[0] == EXIT_FOUND, gate(mixed_src)
    assert "semgrep" in str(gate(mixed_src)[1]) or "sqli" in str(gate(mixed_src)[1])

    # Every new finding lands in exactly one of the two lists — no finding disappears.
    for d in (agent_only, mixed_src):
        assert len(d.gating) + len(d.observations) == len(d.new), d.new

    # ── an unjudged finding is not a safe one — the vulnshop#23 fail-open ───────
    # `uncertain` is NOT a clearance. core/triage.py records it when the budget runs
    # out, so treating it as safe is the fail-open service/gate.py warns about.
    unsure = diff_runs(report([]), report([finding("semgrep/sqli", "app.py",
                                                   verdict="uncertain")]))
    assert gate(unsure)[0] == EXIT_INCONCLUSIVE, "uncertain is not safe"

    # A reachable finding still reports FOUND, not INCONCLUSIVE: an unjudged sibling
    # must not downgrade a proven one into "we could not tell".
    mixed = diff_runs(report([]), report([
        finding("semgrep/sqli", "app.py", verdict="exploitable"),
        finding("semgrep/xss", "views.py"),
    ]))
    assert gate(mixed)[0] == EXIT_FOUND, gate(mixed)

    # block_on="any" already blocks on everything, judged or not — the unresolved
    # branch must not steal those from EXIT_FOUND and report them as inconclusive.
    assert gate(unsure, block_on="any")[0] == EXIT_FOUND, gate(unsure, block_on="any")

    # ── scoped to a pull request's changed files ────────────────────────────
    # The trap this closes: the head scan only covered changed files, so a base
    # finding in an untouched file has no counterpart and reports as FIXED. The PR
    # gets credit for fixing everything it did not touch.
    untouched = finding("semgrep/old", "app/legacy.py")
    touched = finding("semgrep/sqli", "app/auth.py")
    base_report = report([untouched, touched])
    head_report = report([touched])          # head only scanned app/auth.py

    unscoped = diff_runs(base_report, head_report)
    assert len(unscoped.fixed) == 1, "without scope the untouched file looks fixed"

    scoped = diff_runs(base_report, head_report, scope=["app/auth.py"])
    assert scoped.fixed == [], "scoping must not credit a PR for untouched files"
    assert scoped.new == [] and len(scoped.unchanged) == 1

    # A genuine fix INSIDE the scope is still reported.
    real_fix = diff_runs(report([untouched, touched]), report([untouched]),
                         scope=["app/auth.py"])
    assert len(real_fix.fixed) == 1 and real_fix.fixed[0]["rule_id"] == "semgrep/sqli"

    # A leading slash or mount prefix on either side must not defeat the match.
    prefixed = dict(touched)
    prefixed["location"] = dict(touched["location"], path="/work/source/app/auth.py")
    assert diff_runs(report([prefixed]), report([prefixed]),
                     scope=["app/auth.py"]).unchanged, "mount prefix must be stripped"

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
