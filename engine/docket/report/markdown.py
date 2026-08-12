"""Human-readable report.

report.json is for machines and report.sarif is for GitHub. This is the one someone
actually reads: pastes into a ticket, sends to the developer who owns the file, attaches
to an email.

Two rules shape it. Coverage goes near the TOP, not buried at the end, because "48
findings" means nothing without "26 files analysed, 3 could not be" — a reader who
sees only the count cannot tell a clean repository from an unscanned one. And a
static match is never presented as a proven vulnerability: the wording distinguishes
what a scanner matched, what an agent judged, and what was actually exploited, because
this document will outlive the conversation that produced it.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

_ORDER = ["critical", "high", "medium", "low", "info"]

_VERDICT_LABEL = {
    "exploitable": "REACHABLE",
    "not_reachable": "NOT REACHABLE",
    "uncertain": "UNCERTAIN",
}


def _location(finding: dict[str, Any]) -> str:
    loc = finding.get("location") or {}
    source = loc.get("source_file")
    if source:
        return str(source).replace("/work/source/", "")
    method, path = loc.get("method", ""), loc.get("path", "")
    param = loc.get("parameter")
    return f"{method} {path}".strip() + (f" ({param})" if param else "")


def _coverage_section(coverage: dict[str, Any]) -> list[str]:
    if not coverage:
        return [
            "## Coverage",
            "",
            "**Not recorded for this run.** Treat the finding count below as a lower "
            "bound: there is no record of how much of the repository was analysed.",
            "",
        ]
    lines = ["## Coverage", ""]
    semgrep = coverage.get("semgrep") or {}
    if semgrep.get("files_scanned") is not None:
        lines.append(f"- **{semgrep['files_scanned']:,} files analysed** by semgrep")
        if semgrep.get("rules_fired"):
            lines.append(f"- Languages matched: {', '.join(semgrep['rules_fired'])}")
        if semgrep.get("error_count"):
            lines += [
                f"- **{semgrep['error_count']} file(s) could not be analysed.** These are "
                "coverage holes, not clean passes:",
                *(f"  - `{e}`" for e in (semgrep.get("errors") or [])[:5]),
            ]
    trivy = coverage.get("trivy") or {}
    if trivy.get("manifest_count"):
        manifests = ", ".join(f"`{m}`" for m in (trivy.get("manifests") or [])[:6])
        lines.append(f"- **{trivy['manifest_count']} dependency manifest(s)**: {manifests}")
    if not coverage.get("nuclei"):
        lines.append("- No live target was scanned, so nothing runtime-only was tested.")
    lines.append("")
    return lines


def _finding_block(finding: dict[str, Any], index: int) -> list[str]:
    severity = str(finding.get("severity", "info")).upper()
    lines = [
        f"### {index}. {finding.get('title', 'Untitled')}",
        "",
        f"| | |",
        f"|---|---|",
        f"| Severity | **{severity}** |",
        f"| Rule | `{finding.get('rule_id', '?')}` |",
    ]
    if finding.get("cwe"):
        lines.append(f"| Weakness | {finding['cwe']} |")
    lines += [
        f"| Location | `{_location(finding)}` |",
        f"| Found by | {finding.get('discovered_by', '?')} |",
    ]

    triage = finding.get("triage")
    if triage:
        lines.append(f"| Triage | **{_VERDICT_LABEL.get(triage.get('verdict',''), '?')}** |")
    lines += ["", finding.get("description", "").strip(), ""]

    poc = finding.get("poc") or {}
    if poc.get("request"):
        lines += ["**Matched code**", "", "```", poc["request"].strip(), "```", ""]

    if triage:
        lines += [
            "**Agent triage** — read the source, ran nothing. A verdict is reasoning "
            "about reachability, not a reproduction.",
            "",
            f"> {triage.get('reasoning', '').strip()}",
            "",
        ]
        if triage.get("evidence"):
            lines += ["```", triage["evidence"].strip(), "```", ""]
    return lines


def render_markdown(report: dict[str, Any]) -> str:
    findings = report.get("findings", [])
    counts = report.get("severity_counts", {})
    target = str(report.get("target", "unknown")).removeprefix("github:")

    generated = str(report.get("generated_at", ""))[:19].replace("T", " ")
    lines = [
        f"# Security report — {target}",
        "",
        f"`{report.get('run_name','')}` · generated {generated} UTC · "
        f"docket {report.get('docket_version','')}",
        "",
        "## Summary",
        "",
        f"**{report.get('finding_count', len(findings))} finding(s)**"
        + (" — " + ", ".join(f"{counts[s]} {s}" for s in _ORDER if counts.get(s))
           if any(counts.get(s) for s in _ORDER) else ""),
        "",
    ]

    triaged = [f for f in findings if f.get("triage")]
    if triaged:
        reachable = sum(1 for f in triaged if f["triage"].get("verdict") == "exploitable")
        lines += [
            f"{len(triaged)} were triaged by an agent that read the source; "
            f"**{reachable}** judged reachable by untrusted input.",
            "",
        ]

    lines += _coverage_section(report.get("coverage") or {})

    lines += [
        "## What this report is, and is not",
        "",
        "- Findings marked `semgrep` or `trivy` are **pattern and advisory matches**, "
        "not exploited vulnerabilities. They say a line looks dangerous or a dependency "
        "has a published CVE.",
        "- An agent **triage** verdict is reasoning over source about whether untrusted "
        "input can reach the line. Nothing was executed.",
        "- Nothing here was proven by exploitation unless a finding explicitly carries a "
        "reproduced request and response.",
        "",
        "---",
        "",
        "## Findings",
        "",
    ]

    if not findings:
        lines += ["None reported. Read the coverage section above before concluding the "
                  "repository is clean.", ""]
    else:
        ordered = sorted(
            findings,
            key=lambda f: _ORDER.index(str(f.get("severity", "info")))
            if str(f.get("severity", "info")) in _ORDER else 99,
        )
        for i, finding in enumerate(ordered, 1):
            lines += _finding_block(finding, i)
            lines.append("---")
            lines.append("")

    usage = (report.get("usage") or {}).get("totals") or {}
    if usage.get("total_tokens"):
        lines += [
            "## Run cost",
            "",
            f"- {usage.get('input_tokens', 0):,} input / "
            f"{usage.get('output_tokens', 0):,} output tokens",
            f"- ${usage.get('cost_usd', 0):.4f}",
            "",
        ]
    return "\n".join(lines)


def demo() -> None:
    report = {
        "run_name": "connect-abc", "target": "github:acme/api",
        "generated_at": datetime(2026, 8, 12, 9, 0).isoformat(),
        "docket_version": "0.1.0", "finding_count": 2,
        "severity_counts": {"high": 1, "medium": 1},
        "coverage": {"semgrep": {"files_scanned": 26, "rules_fired": ["python"],
                                 "error_count": 3, "errors": ["parse failed x.py"]}},
        "findings": [
            {"title": "SQLi", "severity": "high", "rule_id": "semgrep/sqli",
             "cwe": "CWE-89", "discovered_by": "semgrep",
             "location": {"source_file": "/work/source/app.py:42"},
             "description": "raw query", "poc": {"request": "db.execute(q)"},
             "triage": {"verdict": "exploitable", "reasoning": "reached from /login",
                        "evidence": "app.py:30"}},
            {"title": "debug on", "severity": "medium", "rule_id": "semgrep/debug",
             "discovered_by": "semgrep", "location": {"method": "STATIC", "path": "s.py"},
             "description": "DEBUG=True", "poc": {"request": "DEBUG=True"}},
        ],
        "usage": {"totals": {"input_tokens": 1000, "output_tokens": 50, "cost_usd": 0.01,
                             "total_tokens": 1050}},
    }
    out = render_markdown(report)
    assert "# Security report — acme/api" in out
    # Coverage must appear BEFORE the findings, and the holes must be stated.
    assert out.index("## Coverage") < out.index("## Findings")
    assert "3 file(s) could not be analysed" in out
    # Severity order, worst first.
    assert out.index("1. SQLi") < out.index("2. debug on")
    # A static match must never read as a proven exploit.
    assert "not exploited vulnerabilities" in out
    assert "REACHABLE" in out and "ran nothing" in out
    # The mount prefix is an implementation detail, never a location a reader sees.
    assert "/work/source/" not in out
    assert "$0.0100" in out

    # No coverage recorded is stated, not silently omitted.
    bare = render_markdown({"findings": [], "finding_count": 0})
    assert "Not recorded for this run" in bare
    assert "before concluding the repository is clean" in bare
    print("report.markdown: ok")


if __name__ == "__main__":
    demo()
