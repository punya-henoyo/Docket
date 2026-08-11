"""FindingStore: the whole de-dupe engine. Two agents (or two payloads) hitting the
same rule/route/param collapse to one Finding with corroborating evidence appended,
keeping the more severe verdict.
"""
from __future__ import annotations

from docket.report.models import Finding


class FindingStore:
    def __init__(self) -> None:
        self._by_key: dict[str, Finding] = {}

    def add(self, finding: Finding) -> None:
        existing = self._by_key.get(finding.dedupe_key)
        if existing is None:
            self._by_key[finding.dedupe_key] = finding
            return
        existing.corroborating_evidence.append(finding.poc)
        # Severity is an ordered str Enum by declaration order (CRITICAL first) — lower
        # index in the enum members list is more severe.
        order = list(type(existing.severity))
        if order.index(finding.severity) < order.index(existing.severity):
            existing.severity = finding.severity

    def findings(self) -> list[Finding]:
        return list(self._by_key.values())

    def __len__(self) -> int:
        return len(self._by_key)


def demo() -> None:
    from docket.report.models import Location, PoC, Severity

    def make(rule: str, path: str, param: str, severity: Severity = Severity.HIGH) -> Finding:
        return Finding(
            rule_id=rule,
            title=f"{rule} at {path}",
            severity=severity,
            location=Location(method="POST", path=path, parameter=param),
            description="...",
            poc=PoC(request="req", response="resp"),
            discovered_by="test-agent",
        )

    store = FindingStore()
    store.add(make("sql-injection", "/login", "username"))
    store.add(make("sql-injection", "/login", "username", severity=Severity.CRITICAL))
    assert len(store) == 1
    only = store.findings()[0]
    assert len(only.corroborating_evidence) == 1
    assert only.severity == Severity.CRITICAL  # more severe verdict won

    store.add(make("command-injection", "/export", "file"))
    assert len(store) == 2
    print("dedupe: ok")


if __name__ == "__main__":
    demo()
