"""The verdict tool: the only way a triage agent can end its turn.

Mirrors the `finding` tool's stance. That one refuses a claim with no reproduced
evidence; this one refuses a verdict with no cited code, because a triage pass whose
output is "looks real to me" is worse than no triage at all — it puts an AI stamp on
the scanner's guess and makes it harder to question later.
"""
from __future__ import annotations

from typing import Literal

from agents import RunContextWrapper, function_tool

from docket.core.execution import ScanContext

Verdict = Literal["exploitable", "not_reachable", "uncertain"]

# Enough to name a file and a line. Anything shorter is not a citation.
_MIN_EVIDENCE = 12


def build_verdict(verdict: str, reasoning: str, evidence: str) -> dict:
    """The gate itself, separate from the SDK wrapper so it is testable without a live
    run context — and so the rule is readable in one place."""
    reasoning, evidence = reasoning.strip(), evidence.strip()
    if len(evidence) < _MIN_EVIDENCE:
        return {
            "ok": False,
            "error": (
                "verdict refused — no code cited. Quote the file:line you read and the "
                "lines that decide it. If you did not read any code, the honest verdict "
                "is `uncertain` and the evidence is what you tried."
            ),
        }
    if not reasoning:
        return {"ok": False, "error": "verdict refused — reasoning must not be empty."}
    return {"ok": True, "verdict": verdict, "reasoning": reasoning, "evidence": evidence}


@function_tool
async def triage_verdict(
    ctx: RunContextWrapper[ScanContext],
    verdict: Verdict,
    reasoning: str,
    evidence: str,
) -> dict:
    """Record whether untrusted input can reach the flagged line, and finish.

    Args:
        verdict: exploitable | not_reachable | uncertain
        reasoning: two or three sentences on the data flow you traced.
        evidence: the file:line references you actually read, with the lines that
            settle it. Required for every verdict including `uncertain`, where it
            records what you looked at before giving up.
    """
    return build_verdict(verdict, reasoning, evidence)


def demo() -> None:
    # An uncited verdict is the failure this tool exists to prevent: it would put an
    # AI stamp on the scanner's guess and make it harder to question later.
    refused = build_verdict("exploitable", "looks bad to me", "")
    assert refused["ok"] is False and "no code cited" in refused["error"], refused
    assert build_verdict("not_reachable", "fine", "app.py")["ok"] is False  # too thin
    assert build_verdict("uncertain", "", "tests/conftest.py:14 seed()")["ok"] is False

    ok = build_verdict(
        "not_reachable",
        "Only called from tests/conftest.py with a literal.",
        "tests/conftest.py:14  seed_db('admin')",
    )
    assert ok["ok"] is True and ok["verdict"] == "not_reachable", ok
    # `uncertain` still has to say what was looked at — it is a real answer, not a
    # way to skip the work.
    assert build_verdict("uncertain", "Entry point is in another repo.",
                         "routes.py:1-40 has no caller")["ok"] is True
    print("tools.triage: ok")


if __name__ == "__main__":
    demo()
