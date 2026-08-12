"""Turns a FindingStore into the run's artifacts: report.json, report.sarif, and the
terminal summary a human actually reads.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from docket import __version__
from docket.report.dedupe import FindingStore
from docket.report.models import Finding, Severity
from docket.report.sarif import write_sarif
from docket.report.state import get_global_report_state
from docket.utils.secret_files import redact

_SEVERITY_ORDER = list(Severity)  # CRITICAL first, per declaration order in models.py


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (_SEVERITY_ORDER.index(f.severity), f.location.path))


def severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts = {s.value: 0 for s in Severity}
    for finding in findings:
        counts[finding.severity.value] += 1
    return counts


def build_report(
    store: FindingStore,
    *,
    run_name: str,
    target: str,
    summary: str = "",
    cost_usd: float = 0.0,
    agents_spawned: int = 0,
    success: bool = True,
    coverage: dict | None = None,
) -> dict:
    findings = sort_findings(store.findings())
    return {
        "run_name": run_name,
        "docket_version": __version__,
        "target": target,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "success": success,
        "summary": summary,
        "cost_usd": cost_usd,
        "agents_spawned": agents_spawned,
        "finding_count": len(findings),
        # What was actually analysed. Without it, "0 findings" and "nothing was
        # scanned" are the same number.
        "coverage": coverage or {},
        "severity_counts": severity_counts(findings),
        # Per-agent token accounting: explains where the run's cost actually went.
        "usage": get_global_report_state().usage.to_dict(),
        "findings": [f.model_dump(mode="json") for f in findings],
    }


def write_report(
    store: FindingStore,
    out_dir: Path,
    *,
    run_name: str,
    target: str,
    summary: str = "",
    cost_usd: float = 0.0,
    agents_spawned: int = 0,
    success: bool = True,
    coverage: dict | None = None,
) -> dict[str, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    report = build_report(
        store, run_name=run_name, target=target, summary=summary,
        cost_usd=cost_usd, agents_spawned=agents_spawned, success=success,
        coverage=coverage,
    )
    json_path = out_dir / "report.json"
    # Same redaction boundary as SARIF — see write_sarif. This also catches the raw
    # exception strings folded into `summary`, which are the one realistic way our OWN
    # key could reach an artifact (a LiteLLM auth error echoing what it was given).
    json_path.write_text(redact(json.dumps(report, indent=2)))
    sarif_path = write_sarif(out_dir / "report.sarif", sort_findings(store.findings()), target=target)
    return {"json": json_path, "sarif": sarif_path}


def format_summary(report: dict, *, paths: dict[str, Path] | None = None, full: bool = False) -> str:
    findings = report["findings"]
    counts = report["severity_counts"]
    present = ", ".join(
        f"{counts[s]} {s.upper()}" for s in (x.value for x in Severity) if counts.get(s)
    ) or "none"

    lines = [
        f"docket scan complete — target {report['target']}",
        f"{report['finding_count']} finding(s) ({present})",
    ]
    for finding in findings:
        param = f" ({finding['location']['parameter']})" if finding["location"].get("parameter") else ""
        lines.append(
            f"  [{finding['severity'].upper():<8}] {finding['rule_id']:<18} "
            f"{finding['location']['method']:<5} {finding['location']['path']}{param}"
        )
        if full:
            lines.append(f"      request:  {finding['poc']['request']}")
            lines.append(f"      response: {finding['poc']['response']}")
            if finding["poc"].get("notes"):
                lines.append(f"      steps:    {finding['poc']['notes']}")
    if report.get("cost_usd"):
        lines.append(f"cost: ${report['cost_usd']:.4f} across {report['agents_spawned']} agent(s)")
    if paths:
        lines.append(f"report: {paths['json']}")
        lines.append(f"sarif:  {paths['sarif']}")
    return "\n".join(lines)


def demo() -> None:
    import shutil
    import tempfile

    from docket.report.models import Location, PoC

    def make(rule, sev, path, param) -> Finding:
        return Finding(
            rule_id=rule, title=f"{rule} at {path}", severity=sev,
            location=Location(method="GET", path=path, parameter=param),
            description="desc", poc=PoC(request="req", response="resp"),
            discovered_by="test",
        )

    store = FindingStore()
    store.add(make("reflected-xss", Severity.MEDIUM, "/search", "q"))
    store.add(make("command-injection", Severity.CRITICAL, "/export", "file"))
    store.add(make("sql-injection", Severity.HIGH, "/login", "username"))

    tmp = Path(tempfile.mkdtemp())
    try:
        paths = write_report(
            store, tmp, run_name="selftest", target="http://127.0.0.1:5000",
            summary="ok", cost_usd=0.0123, agents_spawned=4,
        )
        assert paths["json"].exists() and paths["sarif"].exists()
        report = json.loads(paths["json"].read_text())
        # Sorted most-severe first.
        assert [f["severity"] for f in report["findings"]] == ["critical", "high", "medium"]
        assert report["severity_counts"]["critical"] == 1
        assert report["finding_count"] == 3
        sarif = json.loads(paths["sarif"].read_text())
        assert len(sarif["runs"][0]["results"]) == 3

        text = format_summary(report, paths=paths)
        assert "3 finding(s) (1 CRITICAL, 1 HIGH, 1 MEDIUM)" in text, text
        assert "command-injection" in text and "0.0123" in text
        assert "request:" not in text
        assert "request:" in format_summary(report, full=True)
    finally:
        shutil.rmtree(tmp)
    print("writer: ok")


if __name__ == "__main__":
    demo()
