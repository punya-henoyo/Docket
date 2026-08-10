"""Plain-assert smoke checks. Run: uv run python tests/test_report.py"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from docket.interface.main import exit_code
from docket.report.dedupe import FindingStore
from docket.report.models import Finding, Location, PoC, Severity


def make(rule="sql-injection", path="/login", param="username", severity=Severity.HIGH) -> Finding:
    return Finding(
        rule_id=rule,
        title=f"{rule} at {path}",
        severity=severity,
        location=Location(method="POST", path=path, parameter=param),
        description="test",
        poc=PoC(request="req", response="resp"),
        discovered_by="test",
    )


def test_exit_codes() -> None:
    empty = FindingStore()
    assert exit_code(empty, scan_ok=True) == 0
    assert exit_code(empty, scan_ok=False) == 1

    nonempty = FindingStore()
    nonempty.add(make())
    assert exit_code(nonempty, scan_ok=True) == 2


def test_dedupe_collapses_same_route_finding() -> None:
    store = FindingStore()
    store.add(make())
    store.add(make())  # a 2nd agent/payload hitting the same bug
    assert len(store) == 1
    assert len(store.findings()[0].corroborating_evidence) == 1


if __name__ == "__main__":
    test_exit_codes()
    test_dedupe_collapses_same_route_finding()
    print("test_report: ok")
