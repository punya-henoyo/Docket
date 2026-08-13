"""Turn a report.json into a pull-request verdict: pass, fail, or "a human must look".

`evaluate(report)` is PURE — a dict in, a GateResult out. No file reads, no network, no
model. That is what makes the decision reproducible and testable: the same report always
produces the same conclusion, and the whole contract fits in the table below.

    report missing/unparseable, or any stages value == "error"   -> action_required, exit 1
    hits the DETERMINISTIC_FLOOR                                 -> failure, exit 2
    any triage verdict CONFIRMED (== core vocabulary exploitable) -> failure, exit 2
    triage truncated (judged < requested, or unjudged > 0)        -> failure, exit 2
    otherwise                                                    -> success, exit 0

WHY THE FLOOR COMES FIRST, AND WHY A MODEL CAN NEVER RAISE A FINDING TO IT
-------------------------------------------------------------------------
An LLM verdict may only DE-ESCALATE a finding below the bar. It may never be what puts a
finding at the bar, and it may never lift a floor rule off it. Two concrete reasons, both
measured in this repository, not hypothetical:

1. A verified fail-open. `Config.static_only()` sets `max_cost_usd=0.0`
   (config/settings.py:69) and `AgentCoordinator.over_budget` is `spent >= budget`
   (core/agents.py:106). `0.0 >= 0.0` is TRUE, so every triage agent raises
   BudgetExceeded before its first turn and is recorded `uncertain`. A gate that decided
   on triage alone would therefore pass 100% of pull requests on that config — silently,
   with a green check, having judged nothing.

2. A pull request from a fork gets no LLM key at all (secrets are withheld from fork
   workflows by design). A model-dependent gate gates on nothing there, which is exactly
   the case where an untrusted contributor is proposing the code.

So the floor is a hand-listed constant, reviewable in one screen, matched on the rule_id
leaf, and it NEVER consults a model. A FALSE_POSITIVE verdict on a floor rule still fails
the check; the verdict is published alongside so a human can override it deliberately,
which is a decision a person makes and not one an agent makes on their behalf.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from docket.report.writer import TRIAGE_VERDICT_MAP, parse_source_file

# THE DETERMINISTIC FLOOR. Substring match on the rule_id's last dotted segment,
# case-insensitive, `_` and `-` treated alike — so it catches semgrep's long ids
# ("python.django.security.injection.command.command-injection-os-system.command-injection-os-system"),
# docket's own short ones ("command-injection"), and either spelling of the same rule.
# The value is the phrase that ends up in the reason a human reads.
#
# Hand-listed on purpose: every entry is a class where a match on the source line is
# already enough to block a merge, with no reachability argument needed. Add to it
# deliberately; do not generate it, and never widen it to "everything semgrep says".
FLOOR_RULES: dict[str, str] = {
    "command-injection": "OS command injection",
    "os-system-injection": "OS command injection",
    "os-system": "call to os.system with untrusted input",
    "subprocess-shell-true": "subprocess with shell=True",
    "dangerous-system-call": "dangerous system call",
    "dangerous-subprocess-use": "dangerous subprocess call",
    "sql-injection": "SQL injection",
    "tainted-sql-string": "tainted SQL string",
    # semgrep's commonest f-string-SQL id; 6 real occurrences in docket_runs/ and it
    # was missing from the floor entirely.
    "formatted-sql-query": "SQL query built by string formatting",
    "sql-string-concat": "SQL string concatenation",
    "sqlalchemy-execute-raw-query": "raw SQL query built as a string",
    "pickle": "pickle deserialisation of untrusted data",
    "yaml-load": "yaml.load without a safe loader",
    "pyyaml-load": "yaml.load without a safe loader",
    "hardcoded-secret": "hardcoded secret",
    "hardcoded-password": "hardcoded credential",
    "hardcoded-credential": "hardcoded credential",
    "hardcoded-token": "hardcoded token",
    "generic-api-key": "hardcoded API key",
}

# A dependency CVE this severe blocks on the published score alone. `trivy` only, because
# only trivy findings carry a CVSS docket RECEIVED from a scoring body — semgrep matches
# have none and must never be given an invented one (see report/models.py:Cvss).
TRIVY_CVSS_FLOOR = 9.0

_FAIL_LEVEL = "failure"
_WARN_LEVEL = "warning"


@dataclass(frozen=True, slots=True)
class GateResult:
    conclusion: str  # "success" | "failure" | "action_required"
    exit_code: int  # 0 pass | 1 a human must look | 2 blocked
    reasons: list[str] = field(default_factory=list)
    annotations: list[dict] = field(default_factory=list)


def rule_leaf(rule_id: object) -> str:
    """The comparable tail of a rule id: last dotted segment, lowercased, `_` -> `-`."""
    return str(rule_id or "").rsplit(".", 1)[-1].lower().replace("_", "-")


def normalise_verdict(verdict: object) -> str:
    """Either triage vocabulary in, the reported one out. Unknown text stays unknown."""
    text = str(verdict or "").strip()
    return TRIAGE_VERDICT_MAP.get(text.lower(), text.upper())


def floor_reason(finding: dict) -> str | None:
    """Why this finding is on the floor, or None. Reads only the rule id and the CVSS."""
    leaf = rule_leaf(finding.get("rule_id"))
    for token, label in FLOOR_RULES.items():
        if token in leaf:
            return label
    cvss = finding.get("cvss") or {}
    score = cvss.get("score") if isinstance(cvss, dict) else None
    if str(finding.get("discovered_by") or "").lower() == "trivy" and score is not None:
        if float(score) >= TRIVY_CVSS_FLOOR:
            return (f"dependency CVE scored {float(score)} by "
                    f"{cvss.get('source') or 'a scoring body'}")
    return None


def _where(finding: dict) -> tuple[str, int, int] | None:
    return parse_source_file((finding.get("location") or {}).get("source_file"))


def _at(finding: dict) -> str:
    where = _where(finding)
    return f"{where[0]}:{where[1]}" if where else (
        (finding.get("location") or {}).get("path") or "an unmapped location")


def _finding_verdict(finding: dict) -> str:
    return normalise_verdict((finding.get("triage") or {}).get("verdict"))


def _all_rows(report: dict) -> list[dict]:
    """Every row the gate must judge: proven findings AND unproven candidates.

    Reading only `findings` was a TOTAL fail-open, measured on the exact command a PR check
    runs. Under --static-only there is no sandbox, so core/runner.py never runs the scanner
    prescans and no Finding is ever constructed — every semgrep hit is written to
    `flagged_not_proven` instead. The floor therefore scanned an empty list:

        docket scan --static-only --no-sandbox --sarif ci.sarif --changed-files changed.txt
        flagged: python.flask...os-system-injection at app.py:47   <- inside the diff
        GATE -> success / 0

    A gate is worthless if the one invocation shape it exists to serve bypasses it.

    Rows are normalised because the two lists differ: a candidate carries `file`/`line`
    and its engine, a finding carries `location.source_file` and `discovered_by`. Note this
    does NOT make a candidate a finding — AGENTS.md rule 10 keeps them out of
    `finding_count`, and they stay out. It makes them GATEABLE, which is a different claim:
    an unproven command injection in a changed file is exactly what a PR check exists to
    stop, and the floor never consults a verdict anyway.
    """
    rows: list[dict] = []
    for row in report.get("findings") or []:
        if isinstance(row, dict):
            rows.append(row)
    for cand in report.get("flagged_not_proven") or []:
        if not isinstance(cand, dict):
            continue
        path, line = cand.get("file"), cand.get("line")
        rows.append({
            "rule_id": cand.get("rule_id"),
            "discovered_by": cand.get("engine") or "semgrep",
            "severity": cand.get("severity"),
            "cvss": cand.get("cvss"),
            "triage": cand.get("triage"),
            "location": {"method": "STATIC", "path": path,
                          "source_file": f"{path}:{line}" if path and line else path},
            "_candidate": True,
        })
    return rows


def annotations_for(report: dict) -> list[dict]:
    """GitHub check-run annotations, one per locatable finding.

    Anything whose location is not a file with a line is SKIPPED: a route ("/", "login") is
    not a path, and GitHub renders it as an annotation against nothing.

    ponytail: built from `findings[]` only. A verdict that exists solely as a `triaged[]`
    row (the unwired static path) still drives the conclusion but gets no inline comment —
    wire it up here if that path is ever turned on.
    """
    out: list[dict] = []
    for finding in _all_rows(report):
        where = _where(finding)
        if where is None:
            continue
        path, start, end = where
        floor = floor_reason(finding)
        verdict = _finding_verdict(finding)
        if floor:
            level, why = _FAIL_LEVEL, f"Blocked: {floor}."
        elif verdict == "CONFIRMED":
            level, why = _FAIL_LEVEL, "Blocked: triage confirmed this is reachable."
        elif verdict == "FALSE_POSITIVE":
            continue  # judged not reachable and not on the floor: nothing to say to a reviewer
        else:
            level, why = _WARN_LEVEL, (
                "Not judged." if verdict != "UNCERTAIN" else "Triage could not settle this.")
        detail = ((finding.get("triage") or {}).get("reasoning")
                  or finding.get("description") or "")
        out.append({
            "path": path,
            "start_line": start,
            "end_line": end,
            "annotation_level": level,
            # GitHub caps title at 255 chars and silently rejects longer ones.
            "title": f"docket: {rule_leaf(finding.get('rule_id'))}"[:255],
            "message": f"{why} {detail}".strip()[:2000],
        })
    return out


def evaluate(report: dict) -> GateResult:
    """Total by construction: a malformed report is action_required, never an exception.

    Nine of twenty malformed shapes used to raise here — `stages` as a list, a non-numeric
    cvss score, a non-dict inside `findings`. A gate that raises hands the decision to a
    caller, and "the report was unreadable" must never be able to read as green.
    """
    try:
        return _evaluate(report)
    except Exception as exc:                      # noqa: BLE001 - deliberately total
        return GateResult("action_required", 1,
                          [f"The report could not be evaluated ({type(exc).__name__}: "
                           f"{exc}), so nothing was verified."], [])


def _evaluate(report: dict) -> GateResult:
    """The whole contract, in order. Pure: same report in, same verdict out."""
    if not isinstance(report, dict) or not report:
        return GateResult("action_required", 1, [
            "No readable report.json, so there is nothing to gate on — the scan did not "
            "produce a result rather than producing a clean one."
        ])

    annotations = annotations_for(report)

    # 1. Did the scan actually run? "semgrep found nothing" and "semgrep never started" are
    #    the same silence in a report that does not record stages.
    errored = sorted(k for k, v in (report.get("stages") or {}).items()
                      if str(v).lower() == "error")
    if errored:
        return GateResult("action_required", 1, [
            f"Stage {name} errored, so this pull request was not fully scanned."
            for name in errored
        ], annotations)

    reasons: list[str] = []

    # 2. The floor, before any verdict is read. A model cannot lift a finding off it.
    for finding in _all_rows(report):
        floor = floor_reason(finding)
        if floor:
            note = ("" if _finding_verdict(finding) != "FALSE_POSITIVE"
                    else " (triage called it a false positive; the floor does not defer "
                          "to a model verdict)")
            reasons.append(
                f"{floor} at {_at(finding)} [{rule_leaf(finding.get('rule_id'))}]{note}."
            )

    # 3. Confirmed verdicts. `triaged[]` is authoritative — report/writer.py derives it from
    #    `findings[].triage` when that is where the verdicts landed — so reading the findings
    #    is a fallback for reports written before that, not a second source of truth.
    rows = report.get("triaged") or []
    judged = [(normalise_verdict(r.get("verdict")),
               f"{r.get('file') or 'unknown'}:{r.get('line') or '?'}",
               rule_leaf(r.get("rule_id"))) for r in rows]
    if not judged:
        judged = [(_finding_verdict(f), _at(f), rule_leaf(f.get("rule_id")))
                  for f in _all_rows(report) if f.get("triage")]
    for verdict, at, leaf in judged:
        if verdict == "CONFIRMED":
            reasons.append(f"Triage confirmed {leaf} at {at} is reachable.")

    # 4. Completeness. "Judged everything and it was fine" and "ran out of money after three"
    #    are different answers, and only one of them is a pass.
    requested = int(report.get("triage_requested") or 0)
    done = int(report.get("triage_judged") or len(rows))
    unjudged = int(report.get("triage_unjudged") or 0)
    if requested and done < requested:
        reasons.append(
            f"Triage was truncated: {done} of {requested} findings were judged, so "
            f"{requested - done} were never looked at."
        )
    if unjudged:
        reasons.append(
            f"{unjudged} triage verdict(s) were synthesised by the runner rather than "
            f"produced by an agent, so those findings are unresolved, not cleared."
        )

    if reasons:
        return GateResult("failure", 2, reasons, annotations)
    return GateResult("success", 0, ["Nothing hit the deterministic floor and no finding "
                                      "was confirmed reachable."], annotations)


def demo() -> None:
    # Contract order, one case each. The full matrix lives in tests/test_gate.py.
    assert evaluate({}).conclusion == "action_required"
    assert evaluate(None).exit_code == 1

    floor_fp = {
        "stages": {"semgrep": "done"},
        "findings": [{
            "rule_id": "semgrep/python.flask.security.injection.os-system-injection.os-system-injection",
            "discovered_by": "semgrep",
            "location": {"method": "STATIC", "path": "app.py", "source_file": "app.py:47"},
            "triage": {"verdict": "not_reachable", "reasoning": "only reached from tests",
                        "evidence": "t.py:1"},
        }],
        "triaged": [{"rule_id": "os-system-injection", "file": "app.py", "line": 47,
                      "verdict": "FALSE_POSITIVE"}],
    }
    # THE POINT OF THIS MODULE: a model verdict cannot de-escalate a floor rule.
    result = evaluate(floor_fp)
    assert (result.conclusion, result.exit_code) == ("failure", 2), result
    assert "does not defer" in result.reasons[0], result.reasons
    assert result.annotations[0]["annotation_level"] == "failure", result.annotations

    # A stage that errored is not a clean scan; it is an unfinished one.
    errored = evaluate({"stages": {"semgrep": "error"}, "findings": []})
    assert (errored.conclusion, errored.exit_code) == ("action_required", 1), errored

    # Truncated triage fails: nobody looked at 12 of the 15.
    short = evaluate({"triage_requested": 15, "triage_judged": 3, "findings": []})
    assert (short.conclusion, short.exit_code) == ("failure", 2), short

    # Nothing on the floor, everything judged not reachable -> green.
    clean = evaluate({
        "stages": {"semgrep": "done"},
        "findings": [{"rule_id": "semgrep/python.flask.security.audit.debug-enabled.debug-enabled",
                      "discovered_by": "semgrep",
                      "location": {"path": "app.py", "source_file": "app.py:61"},
                      "triage": {"verdict": "not_reachable", "reasoning": "r", "evidence": "e"}}],
    })
    assert (clean.conclusion, clean.exit_code) == ("success", 0), clean
    assert clean.annotations == []  # a false positive earns no inline comment

    # A route is not a file: annotating it would point a reviewer at nothing.
    assert annotations_for({"findings": [
        {"rule_id": "command-injection", "location": {"path": "/", "source_file": "/"}},
        {"rule_id": "command-injection", "location": {"path": "/x", "source_file": None}},
    ]}) == []

    # Ranges survive as ranges, and the CVSS floor reads the score trivy was GIVEN.
    ranged = annotations_for({"findings": [
        {"rule_id": "x.tainted-sql-string", "location": {"source_file": "app.py:52-58"}}]})
    assert (ranged[0]["start_line"], ranged[0]["end_line"]) == (52, 58), ranged
    assert floor_reason({"discovered_by": "trivy", "rule_id": "trivy/CVE-1",
                          "cvss": {"score": 9.8, "source": "nvd"}}), "9.8 must be on the floor"
    assert floor_reason({"discovered_by": "trivy", "rule_id": "trivy/CVE-2",
                          "cvss": {"score": 4.3, "source": "nvd"}}) is None
    print("service.gate: ok")


if __name__ == "__main__":
    demo()
