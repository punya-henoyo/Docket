"""End-to-end compliance pass through the REAL agent pipeline, with a scripted model.

Run: uv run python tests/test_compliance.py

Same harness as test_agent_loop_mock.py: only "which tool to call next" is faked, and
every tool actually executes — the source reads really read the temp repo, and
`record_controls` really runs its gate. That makes this the one check that covers the
whole path (driver -> agent loop -> finish tool -> gate -> PackResult) without Docker, an
API key, or a dollar.

The cases worth having a test for are the ones where being wrong is expensive:

  1. an honest audit produces the statuses the code actually read, with citations;
  2. a model that claims `pass` on a file that is not in the repository does NOT get a
     pass — it gets an unknown, and the report says the claim was not accepted;
  3. a control nobody reached is `unjudged`, distinguishable from one that was judged
     inconclusive, because a coverage number that cannot tell those apart is worthless;
  4. a control no repository can answer is never sent to the model at all.
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "engine"))

from mock_model import ScriptedModel  # noqa: E402

from docket.compliance.models import ControlStatus, Observability  # noqa: E402
from docket.compliance.packs import load_pack  # noqa: E402
from docket.config.settings import Config  # noqa: E402
from docket.core.compliance import run_compliance  # noqa: E402
from docket.core.triage import UNJUDGED_PREFIX  # noqa: E402

PACK = load_pack("twelve-factor")
CONFIG = Config(llm="mock/model", llm_api_key="k", max_cost_usd=5.0,
                max_child_cost_usd=2.0, max_agents=2)
SENTINEL = object()  # stands in for a Sandbox; the source tools are host-side


def make_repo(directory: Path) -> None:
    """A tiny app that is genuinely wrong in one way and right in another, so a correct
    audit has something real to both fail and pass."""
    (directory / "settings.py").write_text(
        "import os\n"
        "DEBUG = True\n"
        "SECRET_KEY = 'hunter2'          # hardcoded, not from the environment\n"
        "DATABASE_URL = os.environ['DATABASE_URL']\n"
    )
    (directory / "requirements.txt").write_text("flask==3.0.0\nrequests==2.32.3\n")
    (directory / "app.py").write_text(
        "import logging, sys\n"
        "logging.basicConfig(stream=sys.stdout)   # logs are an event stream\n"
    )


def run(script, source: Path, deep: int = 0):
    """Drive run_compliance with a scripted model instead of a live one."""
    model = ScriptedModel(script)
    return run_compliance(
        "acme/api", [PACK], run_dir=source / "_run", config=CONFIG, sandbox=SENTINEL,
        source_root=str(source), deep=deep, model_override=lambda role: model,
    )


def answer(control_id: str, status: str, **extra) -> dict:
    row = {"control_id": control_id, "status": status,
           "rationale": extra.pop("rationale", "read the code and this is what it says")}
    row.update(extra)
    return row


def test_an_honest_audit_records_what_it_read() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        source = Path(tmp)
        make_repo(source)
        cite = [{"file": "settings.py", "line": 3, "quote": "SECRET_KEY = 'hunter2'"}]
        pinned = [{"file": "requirements.txt", "line": 1, "quote": "flask==3.0.0"}]

        # The agent reads a file for real, then records. Both really execute.
        packs = run([
            ("read_source", {"path": "settings.py"}),
            ("record_controls", {"results": [
                answer("twelve-factor:III", "fail", citations=cite,
                       rationale="SECRET_KEY is a literal in settings.py, not read from "
                                 "the environment."),
                answer("twelve-factor:II", "pass", citations=pinned,
                       rationale="requirements.txt pins every dependency exactly."),
                answer("twelve-factor:VI", "unknown",
                       rationale="Could not find where session state is kept.",
                       looked_at="grepped for session, cache, global dict"),
            ]}),
        ], source)

    assert len(packs) == 1, packs
    result = packs[0]
    by_id = {r.control_id: r for r in result.results}
    assert by_id["twelve-factor:III"].status is ControlStatus.FAIL
    assert str(by_id["twelve-factor:III"].citations[0]) == "settings.py:3"
    assert by_id["twelve-factor:II"].status is ControlStatus.PASS
    assert by_id["twelve-factor:VI"].status is ControlStatus.UNKNOWN
    assert by_id["twelve-factor:VI"].downgraded_from is None

    # Only pass+fail count as assessed: an unknown is not a satisfied control and an
    # unanswerable one was never in scope.
    assert result.assessed == 2, result.counts
    assert result.judged == 3, result.judged
    # THE HEADLINE. 2 of 12, and it never says the word.
    assert "1 of 2 source-checkable controls satisfied" in result.label, result.label
    assert "compliant" not in result.label.lower(), result.label


def test_a_fabricated_citation_does_not_become_a_pass() -> None:
    """The failure this whole feature is built to prevent: a model asserting a control is
    satisfied while pointing at a file that is not in the repository."""
    with tempfile.TemporaryDirectory() as tmp:
        source = Path(tmp)
        make_repo(source)
        packs = run([
            ("record_controls", {"results": [
                # Plausible path, real-sounding quote, does not exist here.
                answer("twelve-factor:III", "pass",
                       rationale="Config is loaded from the environment in config/env.py.",
                       citations=[{"file": "config/env.py", "line": 12,
                                   "quote": "SECRET_KEY = os.environ['SECRET_KEY']"}]),
                # ...and one that does exist, so the batch is not refused wholesale.
                answer("twelve-factor:XI", "pass",
                       rationale="logging writes to stdout.",
                       citations=[{"file": "app.py", "line": 2}]),
            ]}),
        ], source)

    by_id = {r.control_id: r for r in packs[0].results}
    claimed = by_id["twelve-factor:III"]
    assert claimed.status is ControlStatus.UNKNOWN, claimed
    assert claimed.downgraded_from is ControlStatus.PASS, claimed
    assert "no citation resolved" in claimed.rationale, claimed.rationale
    # The model's own words are kept, so a human can see what was claimed and rejected.
    assert "config/env.py" in claimed.rationale, claimed.rationale
    # The good row in the same batch survives — refusing it to punish the bad one would
    # throw away real work.
    assert by_id["twelve-factor:XI"].status is ControlStatus.PASS
    # And the fabricated claim contributes nothing to the score.
    assert packs[0].assessed == 1, packs[0].counts


def test_unreached_controls_are_unjudged_not_inconclusive() -> None:
    """A control the agent skipped and a control it could not settle are different facts,
    and a coverage number that cannot tell them apart is worthless."""
    with tempfile.TemporaryDirectory() as tmp:
        source = Path(tmp)
        make_repo(source)
        packs = run([
            ("record_controls", {"results": [
                answer("twelve-factor:III", "fail",
                       citations=[{"file": "settings.py", "line": 3}]),
                answer("twelve-factor:VI", "unknown", looked_at="grepped for globals"),
            ]}),
        ], source)

    result = packs[0]
    by_id = {r.control_id: r for r in result.results}
    # Answered inconclusively: a real verdict, no prefix.
    assert by_id["twelve-factor:VI"].status is ControlStatus.UNKNOWN
    assert not by_id["twelve-factor:VI"].rationale.startswith(UNJUDGED_PREFIX)
    # Never reached: marked so no consumer can mistake it for one.
    skipped = by_id["twelve-factor:I"]
    assert skipped.status is ControlStatus.UNKNOWN
    assert skipped.rationale.startswith(UNJUDGED_PREFIX), skipped.rationale
    assert result.unjudged == 9, result.unjudged   # 11 source controls, 2 answered
    assert result.judged == 2, result.judged
    # Every control in the pack appears exactly once, always.
    assert len(result.results) == result.total_controls == len(PACK.controls)
    assert len({r.control_id for r in result.results}) == len(result.results)


def test_an_unanswerable_control_never_reaches_the_model() -> None:
    """Factor VIII is a property of how the app is deployed. Most of RBI's and SEBI's
    frameworks are the same shape, and asking a model a question with no code in it is
    asking it to invent one."""
    runtime = [c for c in PACK.controls if c.observability is not Observability.SOURCE]
    assert [c.id for c in runtime] == ["twelve-factor:VIII"], runtime

    with tempfile.TemporaryDirectory() as tmp:
        source = Path(tmp)
        make_repo(source)
        packs = run([
            ("record_controls", {"results": [
                answer("twelve-factor:III", "fail",
                       citations=[{"file": "settings.py", "line": 3}]),
                # The model volunteers a verdict on it anyway. It must not be recorded.
                answer("twelve-factor:VIII", "pass",
                       rationale="It scales horizontally.",
                       citations=[{"file": "app.py", "line": 1}]),
            ]}),
        ], source)

    written = {r.control_id: r for r in packs[0].results}["twelve-factor:VIII"]
    assert written.status is ControlStatus.NOT_OBSERVABLE, written
    assert "does not count it as satisfied" in written.rationale
    assert written.citations == [], written   # no citation, because nothing was assessed
    # It is in the pack total but not in the denominator.
    assert packs[0].total_controls == 12 and packs[0].requested == 11
    assert packs[0].counts["not_observable"] == 1
    assert packs[0].assessed == 1, packs[0].counts


def test_escalation_replaces_only_a_better_answer() -> None:
    """A second look that also came back empty must leave the first answer standing,
    rather than erasing a real finding with a worse one."""
    with tempfile.TemporaryDirectory() as tmp:
        source = Path(tmp)
        make_repo(source)
        packs = run([
            # Batched pass: one fail, cited.
            ("record_controls", {"results": [
                answer("twelve-factor:III", "fail",
                       rationale="SECRET_KEY is a literal.",
                       citations=[{"file": "settings.py", "line": 3}]),
            ]}),
            # Escalation on it: the second agent reads more, and confirms with a better
            # citation rather than overturning.
            ("read_around", {"path": "settings.py", "line": 3}),
            ("record_controls", {"results": [
                answer("twelve-factor:III", "fail",
                       rationale="Confirmed: SECRET_KEY and DEBUG are both literals, and "
                                 "only DATABASE_URL comes from os.environ.",
                       citations=[{"file": "settings.py", "line": 2},
                                  {"file": "settings.py", "line": 3}]),
            ]}),
        ], source, deep=1)

    escalated = {r.control_id: r for r in packs[0].results}["twelve-factor:III"]
    assert escalated.status is ControlStatus.FAIL
    assert escalated.escalated is True, escalated
    assert len(escalated.citations) == 2, escalated.citations
    assert "Confirmed" in escalated.rationale


def test_escalation_keeps_the_first_answer_when_the_second_fails() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        source = Path(tmp)
        make_repo(source)
        packs = run([
            ("record_controls", {"results": [
                answer("twelve-factor:III", "fail",
                       rationale="SECRET_KEY is a literal.",
                       citations=[{"file": "settings.py", "line": 3}]),
            ]}),
            # The second look claims a pass it cannot cite. The gate refuses it, and the
            # original cited fail must survive untouched.
            ("record_controls", {"results": [
                answer("twelve-factor:III", "pass", rationale="Actually it is fine.",
                       citations=[{"file": "nope.py", "line": 1}]),
            ]}),
        ], source, deep=1)

    kept = {r.control_id: r for r in packs[0].results}["twelve-factor:III"]
    assert kept.status is ControlStatus.FAIL, kept
    assert kept.rationale == "SECRET_KEY is a literal.", kept.rationale
    assert kept.escalated is True, kept   # it was looked at again, and nothing changed


if __name__ == "__main__":
    test_an_honest_audit_records_what_it_read()
    test_a_fabricated_citation_does_not_become_a_pass()
    test_unreached_controls_are_unjudged_not_inconclusive()
    test_an_unanswerable_control_never_reaches_the_model()
    test_escalation_replaces_only_a_better_answer()
    test_escalation_keeps_the_first_answer_when_the_second_fails()
    print("test_compliance: ok")
