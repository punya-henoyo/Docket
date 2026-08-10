"""The one seam between CLI, orchestration, sandbox, and reporting.

docket.interface.main calls run_scan() exactly once. Everything after this stub is
built milestone-by-milestone (see /Users/punya07/.claude/plans/snug-greeting-dolphin.md):
M3 replaces the hardcoded findings with a real single-agent LLM loop, M4 adds the
multi-agent coordinator. The signature and on_finding contract are final now so CLI
and reporting don't have to change shape later.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from docket.config import Config
from docket.report.models import Finding, Location, PoC, Severity


@dataclass(slots=True)
class ScanResult:
    success: bool
    summary: str
    finding_count: int
    cost_usd: float = 0.0
    agents_spawned: int = 0


def run_scan(
    target_url: str,
    *,
    instruction: str | None = None,
    whitebox_path: str | None = None,
    on_finding: Callable[[Finding], None] | None = None,
    config: Config | None = None,
) -> ScanResult:
    """STUB (milestone 1): reports 2 hardcoded findings so the CLI/report plumbing is
    provably correct before any LLM or sandbox exists. Real implementation lands in
    M3 (single-agent) and M4 (multi-agent)."""
    stub_findings = [
        Finding(
            rule_id="sql-injection",
            cwe="CWE-89",
            title="SQL injection in POST /login",
            severity=Severity.HIGH,
            location=Location(method="POST", path="/login", parameter="username"),
            description="STUB finding — replaced by a real agent-discovered result in M3.",
            poc=PoC(request="stub", response="stub"),
            discovered_by="stub",
        ),
        Finding(
            rule_id="command-injection",
            cwe="CWE-78",
            title="Command injection in GET /export",
            severity=Severity.CRITICAL,
            location=Location(method="GET", path="/export", parameter="file"),
            description="STUB finding — replaced by a real agent-discovered result in M3.",
            poc=PoC(request="stub", response="stub"),
            discovered_by="stub",
        ),
    ]
    for f in stub_findings:
        if on_finding is not None:
            on_finding(f)

    return ScanResult(
        success=True,
        summary=f"stub scan against {target_url}: {len(stub_findings)} finding(s)",
        finding_count=len(stub_findings),
    )
