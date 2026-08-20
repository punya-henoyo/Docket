"""Plain-assert checks for the seven gates. Run: uv run python tests/test_validate.py

The gates are a pure function of two scan outcomes, so the whole contract is testable with
a fake scanner and no semgrep installed — which is the point of `validate_patch(scan=...)`.

What is actually under test is one property: **absence of the finding is not evidence.** A
patch that breaks a file's syntax makes the scanner emit zero findings for it, and gate 2
alone reads that as a perfect fix. Every check below that says NOT verified_fixed is a
check that the remaining gates caught what gate 2 could not.

No pytest: plain asserts, like every other script in tests/.
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from docket.service.validate import (
    INCONCLUSIVE,
    NOT_FIXED,
    PLAUSIBLE,
    VERIFIED,
    ScanOutcome,
    parse_scan_json,
    validate_patch,
)

TARGET = ("python.django.security.injection.sqli", "app/db.py", 5)
SAME_FILE = ("python.lang.security.audit.eval-detected", "app/db.py", 22)
ELSEWHERE = ("python.lang.security.audit.subprocess-shell", "app/tasks.py", 40)


def scanner(pristine: ScanOutcome, patched: ScanOutcome):
    """A fake scan, plus the record of how it was called. Both trees must be scanned with
    the SAME timeout — a comparison of two differently-configured runs is not evidence."""
    calls: list[tuple[str, int]] = []

    def scan(root, *, timeout_sec: int = 0) -> ScanOutcome:
        calls.append((str(root), timeout_sec))
        return (pristine, patched)[len(calls) - 1]

    scan.calls = calls
    return scan


def run(pristine: ScanOutcome, patched: ScanOutcome, target=TARGET, **kwargs):
    scan = scanner(pristine, patched)
    result = validate_patch(base_root="/pristine", patched_root="/patched",
                            target_key=target, scan=scan, **kwargs)
    # Both trees, one function, one config: nothing in the API lets a caller scan the
    # pristine tree with one setup and the patched tree with another.
    assert [call[0] for call in scan.calls] == ["/pristine", "/patched"], scan.calls
    assert len({call[1] for call in scan.calls}) == 1, scan.calls
    return result


def outcome(*keys, files=120, errors=0) -> ScanOutcome:
    return ScanOutcome(keys=frozenset(keys), files_scanned=files, parse_errors=errors)


def test_a_genuine_fix_is_verified() -> None:
    result = run(outcome(TARGET, ELSEWHERE), outcome(ELSEWHERE))
    assert result.status == VERIFIED, result
    assert result.failed_gate is None, result
    assert result.gates["positive_control"] is True
    assert result.gates["target_absent"] is True
    assert result.gates["nothing_else_vanished"] is True
    assert result.gates["no_new_findings"] is True
    assert result.gates["parse_errors_not_increased"] is True
    assert result.gates["files_scanned_not_dropped"] is True
    # Gate 7 is recorded honestly as not established, and does not block the verdict.
    assert result.gates["tests_pass"] is None, result.gates
    assert "not run" in result.evidence["tests"], result.evidence["tests"]
    assert result.evidence["findings_before"] == 2
    assert result.evidence["findings_after"] == 1
    # Pair level, with the number of hits lost — see the module docstring for why the line
    # number is not part of the collateral comparison.
    assert result.evidence["vanished"] == [[TARGET[0], TARGET[1], 1]], result.evidence
    assert result.evidence["vanished_unexpected"] == [], result.evidence
    # Seven gates, in the workflow's order, every time.
    assert list(result.gates) == [
        "positive_control", "target_absent", "nothing_else_vanished", "no_new_findings",
        "parse_errors_not_increased", "files_scanned_not_dropped", "callers_consistent", "tests_pass"]


def test_the_syntax_error_trap_is_not_verified_fixed() -> None:
    """THE trap, three ways. A broken file emits ZERO findings, so gate 2 passes. Each
    variant leaves a different one of gates 3, 5, 6 as the only net, and each must hold
    on its own."""
    # 1. The file held another finding too, and it vanished with the target.
    both_gone = run(outcome(TARGET, SAME_FILE, ELSEWHERE), outcome(ELSEWHERE))
    assert both_gone.status == NOT_FIXED, both_gone
    assert both_gone.failed_gate == "nothing_else_vanished", both_gone.failed_gate
    assert both_gone.gates["target_absent"] is True, "gate 2 alone would have passed this"

    # 2. The file held ONLY the target, so nothing else could vanish — but semgrep now
    #    reports a parse error it did not report before.
    parse_broke = run(outcome(TARGET, ELSEWHERE, errors=0),
                      outcome(ELSEWHERE, errors=1))
    assert parse_broke.status == NOT_FIXED, parse_broke
    assert parse_broke.failed_gate == "parse_errors_not_increased", parse_broke.failed_gate

    # 3. No error reported at all: the file simply fell out of coverage.
    dropped = run(outcome(TARGET, ELSEWHERE, files=120),
                  outcome(ELSEWHERE, files=119))
    assert dropped.status == NOT_FIXED, dropped
    assert dropped.failed_gate == "files_scanned_not_dropped", dropped.failed_gate
    assert dropped.evidence["files_scanned_before"] == 120
    assert dropped.evidence["files_scanned_after"] == 119

    # 4. The live shape: a syntax error trips gate 3 AND gate 5 at once. The diagnosis must
    #    be "you broke the file", which explains the vanishing — not "you deleted other
    #    code", which is the wrong story told about the same numbers.
    both = run(outcome(TARGET, SAME_FILE, ELSEWHERE, errors=0),
               outcome(ELSEWHERE, errors=1))
    assert both.gates["nothing_else_vanished"] is False, both.gates
    assert both.gates["parse_errors_not_increased"] is False, both.gates
    assert both.failed_gate == "parse_errors_not_increased", both.failed_gate

    # In none of the four may the string delivery.py branches on appear.
    for result in (both_gone, parse_broke, dropped, both):
        assert result.status != VERIFIED
        assert result.failed_gate is not None


def test_the_finding_surviving_is_not_fixed() -> None:
    result = run(outcome(TARGET, ELSEWHERE), outcome(TARGET, ELSEWHERE))
    assert result.status == NOT_FIXED, result
    assert result.failed_gate == "target_absent", result.failed_gate


def test_a_fix_that_removes_an_unrelated_finding_fails_gate_three() -> None:
    """Deleting the vulnerable code rather than fixing it, or breaking a whole module,
    looks like an extra-good fix. It is the opposite."""
    result = run(outcome(TARGET, ELSEWHERE), outcome())
    assert result.status == NOT_FIXED, result
    assert result.failed_gate == "nothing_else_vanished", result.failed_gate
    assert result.evidence["vanished_count"] == 2, result.evidence
    assert result.gates["no_new_findings"] is True


def test_a_patch_that_introduces_a_finding_fails_gate_four() -> None:
    introduced = ("python.lang.security.audit.exec-detected", "app/db.py", 6)
    result = run(outcome(TARGET, ELSEWHERE), outcome(ELSEWHERE, introduced))
    assert result.status == NOT_FIXED, result
    assert result.failed_gate == "no_new_findings", result.failed_gate
    assert result.evidence["appeared"] == [[introduced[0], introduced[1], 1]], result.evidence
    # A SECOND hit of a rule that already fired in that file is new too — the count is
    # compared, not just the set, so a patch cannot hide one behind an existing finding.
    second = run(outcome(TARGET, ELSEWHERE),
                 outcome(ELSEWHERE, (ELSEWHERE[0], ELSEWHERE[1], 41)))
    assert second.failed_gate == "no_new_findings", second.failed_gate
    assert second.evidence["appeared"] == [[ELSEWHERE[0], ELSEWHERE[1], 1]], second.evidence


def test_two_rules_on_the_target_line_are_one_defect_seen_twice() -> None:
    """Live-verified against `p/default`: `os.system("ping " + host)` fires BOTH
    `os-system-injection` and `dangerous-system-call` on the same line. A correct fix
    clears both, and a key-level gate 3 called the second one collateral damage. Overlapping
    rules are `p/default`'s design, so this is the common case, not a corner."""
    twin = ("python.lang.security.audit.dangerous-system-call", TARGET[1], TARGET[2])
    result = run(outcome(TARGET, twin, ELSEWHERE), outcome(ELSEWHERE))
    assert result.status == VERIFIED, result
    assert result.gates["nothing_else_vanished"] is True, result.gates
    assert result.evidence["colocated_exempt"] == [[twin[0], twin[1]]], result.evidence

    # The exemption is that ONE line and nothing else in the file. The same rule also
    # firing at line 99: losing only the co-located hit is fine ...
    far = (twin[0], twin[1], 99)
    partial = run(outcome(TARGET, twin, far), outcome(far))
    assert partial.status == VERIFIED, partial

    # ... and losing BOTH is a real disappearance that dropping the line must not hide.
    total = run(outcome(TARGET, twin, far), outcome())
    assert total.status == NOT_FIXED, total
    assert total.failed_gate == "nothing_else_vanished", total.failed_gate
    assert total.evidence["vanished_unexpected"] == [[twin[0], twin[1], 2]], total.evidence


def test_a_fix_that_adds_an_import_shifts_lines_and_still_verifies() -> None:
    """`import subprocess` / `import shlex` / `from markupsafe import escape` is the most
    common shape a security fix takes, and it pushes every finding below it down a line. A
    key-level comparison counted one untouched finding as BOTH vanished at its old line and
    new at its new one, failing gates 3 and 4 together."""
    shifted = (SAME_FILE[0], SAME_FILE[1], SAME_FILE[2] + 1)      # same file, moved down
    moved_elsewhere = (ELSEWHERE[0], ELSEWHERE[1], ELSEWHERE[2] + 1)
    result = run(outcome(TARGET, SAME_FILE, ELSEWHERE),
                 outcome(shifted, moved_elsewhere))
    assert result.status == VERIFIED, result
    assert result.gates["nothing_else_vanished"] is True, result.gates
    assert result.gates["no_new_findings"] is True, result.gates
    assert result.evidence["appeared_count"] == 0, result.evidence
    assert result.evidence["vanished_count"] == 1, result.evidence   # the target, and only it


def test_moving_the_sink_without_fixing_it_is_not_fixed() -> None:
    """The fail-open that comparing `(rule_id, file)` in gates 3 and 4 would otherwise
    open: a patch that shifts the vulnerable call to another line satisfies an exact-key
    gate 2, and once gates 3 and 4 stop reading line numbers nothing else notices. Gate 2
    is the only thing standing here, which is why it is file-level."""
    moved = (TARGET[0], TARGET[1], TARGET[2] + 1)
    result = run(outcome(TARGET, ELSEWHERE), outcome(moved, ELSEWHERE))
    assert result.status == NOT_FIXED, result
    assert result.failed_gate == "target_absent", result.failed_gate
    assert result.evidence["target_still_firing_at"] == [TARGET[2] + 1], result.evidence
    # Proof that nothing else would have caught it: every other gate passes.
    assert result.gates["nothing_else_vanished"] is True, result.gates
    assert result.gates["no_new_findings"] is True, result.gates
    assert result.gates["parse_errors_not_increased"] is True, result.gates
    assert result.gates["files_scanned_not_dropped"] is True, result.gates

    # Same rule, same file, left behind at another line: "a patch that fixes the flagged
    # line and leaves its three siblings closes a ticket without closing a hole."
    sibling = (TARGET[0], TARGET[1], 40)
    partial = run(outcome(TARGET, sibling), outcome(sibling))
    assert partial.status == NOT_FIXED, partial
    assert partial.failed_gate == "target_absent", partial.failed_gate
    assert partial.evidence["target_still_firing_at"] == [40], partial.evidence


def test_failed_gate_names_the_most_diagnostic_failure() -> None:
    """A broken file trips several gates at once. "You broke the file" explains "other
    findings vanished"; the reverse is not true, so the coverage gates are named first."""
    coverage = run(outcome(TARGET, SAME_FILE, ELSEWHERE, files=120),
                   outcome(ELSEWHERE, files=119))
    assert coverage.gates["nothing_else_vanished"] is False, coverage.gates
    assert coverage.failed_gate == "files_scanned_not_dropped", coverage.failed_gate

    # A surviving target with an otherwise clean scan is diagnosed as itself.
    alive = run(outcome(TARGET, ELSEWHERE), outcome(TARGET, ELSEWHERE))
    assert alive.failed_gate == "target_absent", alive.failed_gate

    # The gates dict itself stays in the workflow's order whatever is named.
    assert list(coverage.gates)[:2] == ["positive_control", "target_absent"]


def test_no_positive_control_is_inconclusive_never_not_fixed() -> None:
    """You cannot say a fix failed if the bug was never measurable. The pristine scan is
    the control, and without it the comparison proves nothing in either direction."""
    result = run(outcome(ELSEWHERE), outcome(ELSEWHERE))
    assert result.status == INCONCLUSIVE, result
    assert result.status != NOT_FIXED
    assert result.failed_gate == "positive_control", result.failed_gate
    assert result.gates["positive_control"] is False
    # Nothing downstream of a failed control may be claimed as established.
    assert all(value is None for name, value in result.gates.items()
               if name != "positive_control"), result.gates
    assert "PRISTINE" in result.evidence["why"], result.evidence

    # A clean pristine scan with a clean patched scan is the same story: no control.
    assert run(outcome(), outcome()).status == INCONCLUSIVE


def test_a_scanner_that_could_not_run_is_inconclusive() -> None:
    """"A scanner that cannot fail loudly cannot supply a proof." An empty report from a
    crashed scanner is indistinguishable from a clean one, so it is never a verdict."""
    for pristine, patched in (
        (ScanOutcome(error="semgrep is not installed"), outcome(ELSEWHERE)),
        (outcome(TARGET, ELSEWHERE), ScanOutcome(error="semgrep timed out after 600s")),
        (ScanOutcome(error="could not start semgrep"), ScanOutcome(error="x")),
        # The worst case: the patched scan crashed and returned nothing, which without
        # the error would sail through every gate as a flawless fix.
        (outcome(TARGET), ScanOutcome(error="semgrep output was not valid JSON")),
    ):
        result = run(pristine, patched)
        assert result.status == INCONCLUSIVE, result
        assert result.status not in (VERIFIED, NOT_FIXED)
        assert set(result.gates.values()) == {None}, result.gates
        assert result.evidence["scanner_error"], result.evidence


def test_unknown_coverage_caps_at_unverified_plausible() -> None:
    """A gate that could not be ESTABLISHED (None) is the absence of evidence, which is
    unverified_plausible — delivery.py opens no pull request for it. A gate that FAILED is
    evidence against, which is not_fixed. False outranks None."""
    unknown = ScanOutcome(keys=frozenset({TARGET, ELSEWHERE}))       # no coverage numbers
    result = run(unknown, ScanOutcome(keys=frozenset({ELSEWHERE})))
    assert result.status == PLAUSIBLE, result
    assert result.status != VERIFIED
    assert result.failed_gate == "parse_errors_not_increased", result.failed_gate
    assert result.gates["target_absent"] is True

    # ... and a real failure alongside an unknown still reports the failure.
    both = run(ScanOutcome(keys=frozenset({TARGET, ELSEWHERE})),
               ScanOutcome(keys=frozenset()))
    assert both.status == NOT_FIXED, both
    assert both.failed_gate == "nothing_else_vanished", both.failed_gate


def test_key_vocabularies_both_produce_a_control() -> None:
    """StaticFinding.key carries semgrep's bare check_id; report.models.Finding prefixes
    it with "semgrep/". A caller holding either shape must still get a positive control,
    or every validation silently comes back inconclusive."""
    prefixed = (f"semgrep/{TARGET[0]}", "./app/db.py", 5)
    result = run(outcome(TARGET, ELSEWHERE), outcome(ELSEWHERE), target=prefixed)
    assert result.status == VERIFIED, result


def test_parse_scan_json_reads_findings_and_coverage_from_one_run() -> None:
    """Gates 5 and 6 need coverage, gates 1-4 need findings, and one --json invocation
    carries both — so the numbers can never come from two different scans."""
    document = json.dumps({
        "results": [
            {"check_id": TARGET[0], "path": "/tmp/tree/app/db.py", "start": {"line": 5}},
            {"check_id": ELSEWHERE[0], "path": "/tmp/tree/app/tasks.py",
             "start": {"line": 40}},
            {"check_id": "no.line.reported", "path": "/tmp/tree/app/x.py"},
        ],
        "paths": {"scanned": ["app/db.py", "app/tasks.py", "app/x.py"]},
        "errors": [{"message": "Syntax error"}, {"message": "timeout"}],
    })
    parsed = parse_scan_json(document, "/tmp/tree")
    assert parsed.error is None, parsed.error
    assert parsed.keys == frozenset({TARGET, ELSEWHERE}), parsed.keys
    assert parsed.files_scanned == 3 and parsed.parse_errors == 2, parsed

    # Every way the output can be unusable must surface as an error, never as "clean".
    for bad in ("", "not json", "[]", "null", "semgrep: command not found"):
        assert parse_scan_json(bad, "/tmp").error, bad
    # Coverage the scanner did not report is UNKNOWN, not zero — which is what turns
    # gates 5 and 6 into None rather than a passing comparison of two zeroes.
    silent = parse_scan_json('{"results": []}', "/tmp")
    assert silent.error is None
    assert silent.files_scanned is None and silent.parse_errors is None, silent


def test_the_verified_string_is_the_one_delivery_gates_on() -> None:
    """delivery.py:41 branches on exactly this string, and this module is the only place
    it may come from."""
    from docket.service.delivery import VERIFIED as DELIVERY_VERIFIED

    assert VERIFIED == DELIVERY_VERIFIED == "verified_fixed"
    assert PLAUSIBLE != DELIVERY_VERIFIED and NOT_FIXED != DELIVERY_VERIFIED
    assert INCONCLUSIVE != DELIVERY_VERIFIED


if __name__ == "__main__":
    test_a_genuine_fix_is_verified()
    test_the_syntax_error_trap_is_not_verified_fixed()
    test_the_finding_surviving_is_not_fixed()
    test_a_fix_that_removes_an_unrelated_finding_fails_gate_three()
    test_a_patch_that_introduces_a_finding_fails_gate_four()
    test_two_rules_on_the_target_line_are_one_defect_seen_twice()
    test_a_fix_that_adds_an_import_shifts_lines_and_still_verifies()
    test_moving_the_sink_without_fixing_it_is_not_fixed()
    test_failed_gate_names_the_most_diagnostic_failure()
    test_no_positive_control_is_inconclusive_never_not_fixed()
    test_a_scanner_that_could_not_run_is_inconclusive()
    test_unknown_coverage_caps_at_unverified_plausible()
    test_key_vocabularies_both_produce_a_control()
    test_parse_scan_json_reads_findings_and_coverage_from_one_run()
    test_the_verified_string_is_the_one_delivery_gates_on()
    print("test_validate: ok")
