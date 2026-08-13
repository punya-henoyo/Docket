"""The fix-report tool: the only way a fix agent can end its turn.

Mirrors the `triage_verdict` tool's stance. That one refuses a verdict with no cited code;
this one refuses a fix report with no evidence, because a patch whose justification is
"looks fixed to me" is worse than no patch at all — somebody merges it on the strength of
the AI stamp.

THE VOCABULARY IS THE POINT. The agent reports `patched`: a claim about what it CHANGED.
It may not report `verified_fixed`, because whether the change worked is decided by a
scanner re-run over the patched tree (docket.service.validate), and that status is what
reaches report.json and the pull request. The prompt says so; this refuses it by
construction, because a prompt is a request and a gate is a guarantee. A model told to
self-certify will self-certify.

AND THE REFUSALS ARE SUCCESSES. Four of the five outcomes are "I did not patch this", and
skills/fix/workflow.md:168 says plainly that none of them is a failure. Each has a gate
that makes it cost something to say — a quoted guard, a named file, a stated reason — so
that "I could not fix this safely" stays an honest answer rather than the cheap exit.
"""
from __future__ import annotations

import re
from typing import Literal

from agents import RunContextWrapper, function_tool

from docket.core.execution import ScanContext

Outcome = Literal["patched", "not_a_bug", "no_safe_fix", "needs_wider_scope",
                  "not_reproducible"]

OUTCOMES: tuple[str, ...] = ("patched", "not_a_bug", "no_safe_fix", "needs_wider_scope",
                             "not_reproducible")

# Verification statuses. NOT outcomes, and listed here only so the refusal below can
# recognise an agent reaching for one and tell it whose job that is.
_NOT_THE_AGENTS_TO_GIVE = ("verified_fixed", "unverified_plausible", "not_fixed",
                           "validation_inconclusive", "fixed", "verified")

# Enough to name a file and a line. Anything shorter is not evidence. Same constant, same
# reason, as tools/triage/tool.py.
_MIN_EVIDENCE = 12

# "app/views.py:31". A `not_a_bug` is the one outcome that leaves a real bug in place if
# the agent is wrong, so it has to point at the guard it is relying on — the same reason
# triage's FALSE_POSITIVE has to quote one.
_CITATION = re.compile(r"[\w./\\-]+\.\w{1,10}:\d+")

# A path with an extension, anywhere in the text: `needs_wider_scope` is worthless without
# the file it needs, because the operator's next move is to widen the scope to that file.
_FILENAME = re.compile(r"[\w./\\-]+\.\w{1,10}")


def build_fix_report(outcome: str, root_cause: str, invariant: str, evidence: str) -> dict:
    """The gate itself, separate from the SDK wrapper so it is testable without a live run
    context — and so every rule is readable in one place."""
    outcome = (outcome or "").strip().lower()
    root_cause, invariant, evidence = root_cause.strip(), invariant.strip(), evidence.strip()

    if outcome not in OUTCOMES:
        extra = ""
        if outcome in _NOT_THE_AGENTS_TO_GIVE:
            extra = (
                f" `{outcome}` is a VERIFICATION status, and it is not yours to give: a "
                "scanner re-run over your patched tree decides that, and you cannot see "
                "it. If you edited the source, the outcome is `patched` — describe what "
                "you changed and why, and let the re-scan rule on it."
            )
        return {
            "ok": False,
            "error": (f"report refused — {outcome!r} is not an outcome. Use one of: "
                      f"{', '.join(OUTCOMES)}.{extra}"),
        }

    if not root_cause:
        return {
            "ok": False,
            "error": ("report refused — `root_cause` must not be empty. Say why the code "
                      "was wrong (or why it was not), in your own words, not what the "
                      "scanner said."),
        }

    if len(evidence) < _MIN_EVIDENCE:
        return {
            "ok": False,
            "error": ("report refused — no evidence. Quote the `file:line` you read and "
                      "the lines that decide it, plus anything a reviewer should "
                      "double-check."),
        }

    if outcome == "patched" and not invariant:
        return {
            "ok": False,
            "error": ("report refused — a patch needs the `invariant` it now enforces. "
                      "\"Untrusted input can no longer reach the query as syntax\" beats "
                      "\"added parameterisation\": name the property that now holds, not "
                      "the edit you made."),
        }

    if outcome == "not_a_bug" and not _CITATION.search(evidence):
        return {
            "ok": False,
            "error": ("report refused — `not_a_bug` must QUOTE the guard that makes it "
                      "safe, as `file:line` plus the line itself. This is the one outcome "
                      "that leaves a real bug in place if you are wrong. If you cannot "
                      "point at a guard, you have not established this."),
        }

    if outcome == "needs_wider_scope" and not _FILENAME.search(evidence):
        return {
            "ok": False,
            "error": ("report refused — `needs_wider_scope` must NAME the file the fix "
                      "needs, in `evidence`. Without it nobody can widen the scope, so "
                      "the report is unactionable."),
        }

    if outcome == "no_safe_fix" and len(evidence.split()) < 5:
        return {
            "ok": False,
            "error": ("report refused — `no_safe_fix` must give the REASON: what you "
                      "considered and what it would break. It is a respected answer, and "
                      "it is only useful with the reason attached."),
        }

    return {"ok": True, "outcome": outcome, "root_cause": root_cause,
            "invariant": invariant, "evidence": evidence}


@function_tool
async def fix_report(
    ctx: RunContextWrapper[ScanContext],
    outcome: Outcome,
    root_cause: str,
    invariant: str,
    evidence: str,
) -> dict:
    """Record what you changed and why, and finish.

    Args:
        outcome: patched | not_a_bug | no_safe_fix | needs_wider_scope | not_reproducible.
            `patched` is a claim about what you CHANGED, not that it works — a scanner
            re-run decides that. The other four are refusals, and each is a successful
            outcome of your work.
        root_cause: one paragraph on why the code was wrong, in your own words. Required
            for every outcome, including the refusals.
        invariant: what your fix now makes true. Required for `patched`. Name the property
            that holds ("untrusted input can no longer reach the query as syntax"), not
            the edit you made.
        evidence: the file:line references you actually read with the lines that matter,
            and what a reviewer should double-check. `not_a_bug` must quote the guard;
            `needs_wider_scope` must name the file; `no_safe_fix` must give the reason.
            Never put a live secret here — say what must be rotated instead.
    """
    return build_fix_report(outcome, root_cause, invariant, evidence)


def demo() -> None:
    good_evidence = "app/views.py:34  cursor.execute(SQL, (username,))  — no behaviour change"

    # THE LOAD-BEARING REFUSAL: the agent may not certify its own fix. `verified_fixed` is
    # decided by a scanner re-run, and a model told to self-certify will self-certify.
    for claim in ("verified_fixed", "fixed", "unverified_plausible", "not_fixed"):
        refused = build_fix_report(claim, "interpolated user input", "parameterised",
                                  good_evidence)
        assert refused["ok"] is False, claim
        assert "not yours to give" in refused["error"], refused
        assert "`patched`" in refused["error"], refused
    # ...and a typo is refused too, rather than becoming a silent default.
    assert build_fix_report("PATCHED_MAYBE", "r", "i", good_evidence)["ok"] is False

    # Every outcome needs a root cause and real evidence.
    assert build_fix_report("patched", "", "i", good_evidence)["ok"] is False
    assert build_fix_report("not_reproducible", "the anchor is gone", "", "a.py")["ok"] is False

    # `patched` without an invariant is a diff with no claim attached.
    thin = build_fix_report("patched", "interpolated user input", "", good_evidence)
    assert thin["ok"] is False and "invariant" in thin["error"], thin

    # `not_a_bug` must quote the guard: it is the one outcome that leaves a real bug in
    # place if the agent is wrong.
    uncited = build_fix_report("not_a_bug", "the value is a constant",
                              "", "there is a guard above it, it looked fine to me")
    assert uncited["ok"] is False and "QUOTE the guard" in uncited["error"], uncited
    cited = build_fix_report("not_a_bug", "the value is a constant", "",
                            "config.py:12  ROLE = 'admin'  — never user-controlled")
    assert cited["ok"] is True, cited

    # `needs_wider_scope` without the file is unactionable.
    vague = build_fix_report("needs_wider_scope", "the sink is here, the taint is upstream",
                            "", "the fix belongs in the caller, somewhere upstream")
    assert vague["ok"] is False and "NAME the file" in vague["error"], vague
    named = build_fix_report("needs_wider_scope", "the sink is here, the taint is upstream",
                            "", "the guard belongs in app/routes.py:88 where the value enters")
    assert named["ok"] is True, named

    # `no_safe_fix` is respected — with the reason, not without it.
    assert build_fix_report("no_safe_fix", "raw SQL by design", "", "app/db.py:9 no")["ok"] is False
    reasoned = build_fix_report(
        "no_safe_fix", "the query shape is chosen by the caller",
        "", "app/db.py:9 — parameterising it would change the public API of query()")
    assert reasoned["ok"] is True, reasoned

    # The happy path, and the fields survive verbatim.
    ok = build_fix_report("patched", "The login query interpolated request.form['user'].",
                          "Untrusted input can no longer reach the query as syntax.",
                          good_evidence)
    assert ok["ok"] is True and ok["outcome"] == "patched", ok
    assert ok["invariant"].startswith("Untrusted input"), ok
    assert ok["evidence"] == good_evidence, ok
    # `verified_fixed` must not be reachable as a value even on the happy path.
    assert ok["outcome"] != "verified_fixed"
    assert "verified_fixed" not in OUTCOMES
    print("tools.fix: ok")


if __name__ == "__main__":
    demo()
