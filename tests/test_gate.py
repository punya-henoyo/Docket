"""Plain-assert smoke checks for the PR gate. Run: uv run python tests/test_gate.py

Fixture reports, not real runs: the gate is a pure function of report.json, so the whole
contract is testable with dicts and there is nothing to mock.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from docket.service.gate import annotations_for, evaluate


def report(**overrides) -> dict:
    base = {
        "run_name": "fixture",
        "status": "completed",
        "stages": {"semgrep": "done"},
        "findings": [],
        "triaged": [],
        "triage_requested": 0,
        "triage_judged": 0,
        "triage_unjudged": 0,
    }
    return base | overrides


def finding(rule_id, source_file="app.py:10", verdict=None, **extra) -> dict:
    out = {
        "rule_id": rule_id,
        "discovered_by": "semgrep",
        "severity": "high",
        "description": "static analysis match",
        "location": {"method": "STATIC", "path": "app.py", "source_file": source_file},
    }
    if verdict:
        out["triage"] = {"verdict": verdict, "reasoning": "reasoned", "evidence": "app.py:1"}
    return out | extra


CMDI = "semgrep/python.flask.security.injection.os-system-injection.os-system-injection"
SQLI = "semgrep/python.django.security.injection.tainted-sql-string.tainted-sql-string"
BENIGN = "semgrep/yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag"


def test_floor_survives_a_false_positive_verdict() -> None:
    """The load-bearing case: a model verdict may de-escalate, never lift the floor."""
    result = evaluate(report(
        findings=[finding(CMDI, verdict="not_reachable")],
        triaged=[{"rule_id": CMDI, "file": "app.py", "line": 10,
                   "verdict": "FALSE_POSITIVE", "reasoning": "r", "evidence": "e"}],
        triage_requested=1, triage_judged=1,
    ))
    assert (result.conclusion, result.exit_code) == ("failure", 2), result
    assert any("OS command injection" in r for r in result.reasons), result.reasons
    # ...and the annotation stays a failure rather than following the verdict.
    assert [a["annotation_level"] for a in result.annotations] == ["failure"], result.annotations


def test_confirmed_verdict_fails() -> None:
    result = evaluate(report(
        findings=[finding(BENIGN, verdict="exploitable")],
        triage_requested=1, triage_judged=1,
    ))
    assert (result.conclusion, result.exit_code) == ("failure", 2), result
    assert any("confirmed" in r.lower() for r in result.reasons), result.reasons


def test_errored_stage_needs_a_human() -> None:
    result = evaluate(report(stages={"semgrep": "error", "trivy": "done"}))
    assert (result.conclusion, result.exit_code) == ("action_required", 1), result
    assert "semgrep" in result.reasons[0], result.reasons


def test_truncated_triage_fails() -> None:
    result = evaluate(report(triage_requested=15, triage_judged=3))
    assert (result.conclusion, result.exit_code) == ("failure", 2), result
    assert any("3 of 15" in r for r in result.reasons), result.reasons


def test_unjudged_verdicts_fail() -> None:
    result = evaluate(report(triage_requested=2, triage_judged=2, triage_unjudged=1))
    assert (result.conclusion, result.exit_code) == ("failure", 2), result
    assert any("synthesised" in r for r in result.reasons), result.reasons


def test_all_false_positive_and_no_floor_passes() -> None:
    result = evaluate(report(
        findings=[finding(BENIGN, source_file=".github/workflows/semgrep.yml:21",
                           verdict="not_reachable"),
                   finding(BENIGN, source_file="app.py:61", verdict="not_reachable")],
        triage_requested=2, triage_judged=2,
    ))
    assert (result.conclusion, result.exit_code) == ("success", 0), result
    assert result.annotations == [], result.annotations


def test_empty_report_needs_a_human() -> None:
    for junk in ({}, None, [], "not a report"):
        result = evaluate(junk)
        assert (result.conclusion, result.exit_code) == ("action_required", 1), junk
        assert result.annotations == []


def test_a_route_is_not_a_file() -> None:
    """A route renders as an annotation against nothing, so it is dropped."""
    for route in ("/", "login", "/search", None, ""):
        assert annotations_for({"findings": [finding(CMDI, source_file=route)]}) == [], route


def test_a_range_annotates_the_range() -> None:
    got = annotations_for({"findings": [finding(SQLI, source_file="app.py:52-58")]})
    assert len(got) == 1, got
    assert (got[0]["path"], got[0]["start_line"], got[0]["end_line"]) == ("app.py", 52, 58), got
    assert got[0]["annotation_level"] == "failure"  # tainted-sql-string is on the floor
    assert got[0]["title"] == "docket: tainted-sql-string", got[0]


def test_one_rule_twice_in_one_file_annotates_twice() -> None:
    got = annotations_for({"findings": [
        finding(SQLI, source_file="app.py:36"),
        finding(SQLI, source_file="app.py:37"),
    ]})
    assert [(a["start_line"], a["end_line"]) for a in got] == [(36, 36), (37, 37)], got


def test_untriaged_findings_warn_but_do_not_block() -> None:
    result = evaluate(report(findings=[finding(BENIGN, source_file="app.py:61")]))
    assert (result.conclusion, result.exit_code) == ("success", 0), result
    assert [a["annotation_level"] for a in result.annotations] == ["warning"], result.annotations


def test_trivy_cvss_floor() -> None:
    critical = finding("trivy/CVE-2026-1", source_file="requirements.txt",
                        discovered_by="trivy", cvss={"score": 9.8, "source": "nvd"})
    moderate = finding("trivy/CVE-2026-2", source_file="requirements.txt",
                        discovered_by="trivy", cvss={"score": 4.3, "source": "nvd"})
    assert evaluate(report(findings=[critical])).exit_code == 2
    assert evaluate(report(findings=[moderate])).exit_code == 0
    # No CVSS at all must not crash or block: semgrep matches carry none by design.
    assert evaluate(report(findings=[finding(BENIGN)])).exit_code == 0


def test_real_run_reports() -> None:
    """The gate must survive the report shapes actually on disk, old fields and all."""
    import json

    # CI has no docket_runs/ (and `make clean` deletes it), so this is a bonus pass over
    # whatever real reports happen to be on this machine, never a requirement.
    for path in sorted(Path(__file__).resolve().parent.parent.glob("docket_runs/*/report.json")):
        try:
            data = json.loads(path.read_text())
        except json.JSONDecodeError:
            continue  # an unparseable report is the caller's problem, not the gate's
        result = evaluate(data)
        assert result.conclusion in ("success", "failure", "action_required"), path
        assert result.exit_code in (0, 1, 2), path
        for annotation in result.annotations:
            assert annotation["start_line"] >= 1, (path, annotation)
            assert annotation["end_line"] >= annotation["start_line"], (path, annotation)
            assert not annotation["path"].startswith("/"), (path, annotation)


if __name__ == "__main__":
    test_floor_survives_a_false_positive_verdict()
    test_confirmed_verdict_fails()
    test_errored_stage_needs_a_human()
    test_truncated_triage_fails()
    test_unjudged_verdicts_fail()
    test_all_false_positive_and_no_floor_passes()
    test_empty_report_needs_a_human()
    test_a_route_is_not_a_file()
    test_a_range_annotates_the_range()
    test_one_rule_twice_in_one_file_annotates_twice()
    test_untriaged_findings_warn_but_do_not_block()
    test_trivy_cvss_floor()
    test_real_run_reports()
    print("test_gate: ok")
