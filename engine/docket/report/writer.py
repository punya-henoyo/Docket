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
from docket.utils.secret_files import redact_document

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
    leads: list | None = None,
    triage: object | None = None,
) -> dict:
    """`leads` are static-analysis candidates (docket.static.correlate.Lead). They are
    reported in a SEPARATE list from `findings` and never merged into it.

    A Finding is a reproduction: its PoC request and response are validated non-empty at
    construction, which is the guarantee the whole tool rests on. A static candidate has
    neither and never will. Merging them would force the validator to accept blanks and
    delete that guarantee for every finding, not just these. Keeping two lists also means
    nothing downstream can accidentally present a lead as a confirmed exploit — the
    structure enforces the distinction, not a naming convention.

    Note `finding_count` and the exit code stay driven by proven findings only. A wall of
    unproven candidates must never turn a clean scan red.
    """
    findings = sort_findings(store.findings())
    # Cross-link static leads to proven findings by CWE, which is the finest granularity
    # actually available. A Finding records the ROUTE it exploited, not the source line —
    # `location.source_file` is optional and usually null, because an agent works from the
    # outside and has no reason to know which line it reached. So this answers "was a
    # vulnerability of this class proven exploitable on this target", not "was this exact
    # line proven". The field name says so, rather than implying line-level proof.
    proven_cwes = {f.cwe for f in findings if getattr(f, "cwe", None)}
    flagged = []
    for lead in leads or []:
        finding = lead.finding
        flagged.append({
            "rule_id": finding.rule_id,
            "engine": finding.engine,
            "severity": finding.severity,
            "cwe": finding.cwe,
            "message": finding.message,
            "file": finding.file,
            "line": finding.line,
            "snippet": finding.snippet,
            "status": "flagged_not_proven",
            "endpoint": (f"{lead.endpoint.method} {lead.endpoint.path}"
                          if lead.endpoint else None),
            "reachable": lead.reachable,
            "correlation_confidence": lead.confidence,
            "correlation_reason": lead.why,
            # Did an agent prove this CWE exploitable on this target? Turns two unrelated
            # lists into a hand-off a reader can follow: a flagged CWE-89 next to a proven
            # CWE-89 says "the pattern matcher was right about this class here".
            "cwe_proven_dynamically": bool(finding.cwe and finding.cwe in proven_cwes),
        })
    # When triage ran, a candidate carries a verdict from an agent that READ the code.
    # That row supersedes the bare candidate: "flagged, and here is why an engineer thinks
    # it is real" is a different artifact from "flagged".
    triage_rows = [v.to_dict() for v in getattr(triage, "verdicts", []) or []]
    triage_counts = triage.counts() if hasattr(triage, "counts") else {}
    triaged_keys = {(r["file"], r["line"], r["rule_id"]) for r in triage_rows}
    if triage_rows:
        flagged = [f for f in flagged
                    if (f["file"], f["line"], f["rule_id"]) not in triaged_keys]

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
        "severity_counts": severity_counts(findings),
        # Static candidates: leads, not results. Explicitly unproven, counted separately,
        # and deliberately NOT part of finding_count or the exit code.
        "flagged_count": len(flagged),
        "flagged_not_proven": flagged,
        # Triaged candidates: a verdict from an agent that read the surrounding source,
        # with its reasoning. Still NOT `findings` — the evidence is a read of the code,
        # not a reproduction, and the two must stay distinguishable.
        "triage_counts": triage_counts,
        "triaged": triage_rows,
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
    leads: list | None = None,
    triage: object | None = None,
) -> dict[str, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    report = build_report(
        store, run_name=run_name, target=target, summary=summary,
        cost_usd=cost_usd, agents_spawned=agents_spawned, success=success, leads=leads,
        triage=triage,
    )
    json_path = out_dir / "report.json"
    # Same redaction boundary as SARIF — see write_sarif. This also catches the raw
    # exception strings folded into `summary`, which are the one realistic way our OWN
    # key could reach an artifact (a LiteLLM auth error echoing what it was given).
    # redact_document, NOT redact(json.dumps(...)): the latter runs the patterns over
    # escaped JSON and can eat a backslash, leaving a bare quote and an unparseable
    # report. See redact_document's docstring for the exact input that did it.
    json_path.write_text(json.dumps(redact_document(report), indent=2))
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
    if report.get("triage_counts"):
        c = report["triage_counts"]
        lines.append(
            f"{sum(c.values())} static candidate(s) triaged by an agent that read the "
            f"code: {c.get('CONFIRMED', 0)} confirmed, "
            f"{c.get('FALSE_POSITIVE', 0)} false positive, "
            f"{c.get('UNCERTAIN', 0)} uncertain"
        )
    if report.get("flagged_count"):
        # Stated separately and labelled unproven, so a reader cannot read the two
        # numbers as one total. Silence here would hide the static coverage entirely.
        flagged = report.get("flagged_not_proven", [])
        reachable = sum(1 for f in flagged if f.get("reachable"))
        confirmed = sum(1 for f in flagged if f.get("cwe_proven_dynamically"))
        lines.append(
            f"{report['flagged_count']} static candidate(s) NOT proven "
            f"({reachable} mapped to an endpoint, {confirmed} whose CWE was proven "
            f"elsewhere on this target) — leads only, see flagged_not_proven"
        )
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
