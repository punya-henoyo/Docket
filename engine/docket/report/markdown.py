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


def _compliance_section(packs: list[dict[str, Any]]) -> list[str]:
    """Control-pack results, as a section a person reads rather than a table of numbers.

    Two numbers per pack and never one, for the reason stated in
    compliance/models.py: pass-rate and coverage move in opposite directions, so a single
    percentage rewards an agent that gives up on the hard controls. A pack that assessed
    nothing says so in words.

    Every failed control prints its citation. A control marked satisfied with nothing a
    reader can open is exactly what this feature exists not to produce.
    """
    if not packs:
        return []
    lines = ["## Compliance", ""]
    for pack in packs:
        if not isinstance(pack, dict):
            continue
        results = [r for r in (pack.get("results") or []) if isinstance(r, dict)]
        counts: dict[str, int] = {}
        for result in results:
            key = str(result.get("status", "unknown"))
            counts[key] = counts.get(key, 0) + 1
        assessed = counts.get("pass", 0) + counts.get("fail", 0)
        total = pack.get("total_controls", len(results))

        lines.append(f"### {pack.get('pack_title', pack.get('pack_id', 'pack'))}")
        lines.append("")
        if assessed:
            lines.append(
                f"**{counts.get('pass', 0)} of {assessed} source-checkable controls "
                f"satisfied**, {counts.get('fail', 0)} not. {total} control(s) in the pack."
            )
        else:
            lines.append(
                f"**No control could be assessed from source.** {total} control(s) in the "
                "pack. This is not a pass: nothing here was checked."
            )
        detail = []
        if counts.get("not_observable"):
            detail.append(f"{counts['not_observable']} cannot be answered by reading a "
                          "repository (organisational or deployment controls)")
        if counts.get("unknown"):
            detail.append(f"{counts['unknown']} inconclusive")
        if counts.get("not_applicable"):
            detail.append(f"{counts['not_applicable']} do not apply here")
        if pack.get("unjudged"):
            detail.append(f"{pack['unjudged']} were never reached by an agent")
        if detail:
            lines.append("")
            lines.append("- " + "\n- ".join(detail))
        lines.append("")

        failed = [r for r in results if r.get("status") == "fail"]
        if failed:
            lines.append("**Not satisfied:**")
            lines.append("")
            for result in failed:
                where = ", ".join(
                    f"`{c.get('file')}" + (f":{c['line']}`" if c.get("line") else "`")
                    for c in (result.get("citations") or [])[:3]
                    if isinstance(c, dict) and c.get("file")
                )
                proven = (" **A reproduced finding corroborates this.**"
                          if result.get("proven_findings") else "")
                lines.append(f"- **{result.get('control_id')}** — "
                             f"{str(result.get('rationale', '')).strip()}{proven}"
                             + (f" ({where})" if where else ""))
            lines.append("")

        contradicted = [r for r in results if r.get("contradicted_by")]
        if contradicted:
            lines += [
                f"**{len(contradicted)} control(s) were marked satisfied while a "
                "reproduced finding of the same weakness class exists in this scan.** "
                "Treat those passes with suspicion:",
                "",
                *(f"- `{r.get('control_id')}`" for r in contradicted),
                "",
            ]
    lines += [
        "> This is an evidence-based review of source code, not an attestation of "
        "compliance. Controls that no repository can answer are reported as unassessed "
        "and are never counted as satisfied.",
        "",
    ]
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
    cvss = finding.get("cvss")
    if cvss:
        # Source and vector travel with the number. Scoring bodies disagree, and a bare
        # "8.8" in a report that outlives this conversation is not checkable.
        vector = cvss.get("vector") or "no vector published"
        lines.append(
            f"| CVSS | **{cvss.get('score')}** (v{cvss.get('version','?')}, "
            f"{str(cvss.get('source','?')).upper()}) — `{vector}` |"
        )
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
    lines += _compliance_section(report.get("compliance") or [])

    lines += [
        "## What this report is, and is not",
        "",
        "- Findings marked `semgrep` or `trivy` are **pattern and advisory matches**, "
        "not exploited vulnerabilities. They say a line looks dangerous or a dependency "
        "has a published CVE.",
        "- A **CVSS** score is published by a scoring body (NVD, GHSA, a distro vendor) "
        "or by a nuclei template, and rates the vulnerability CLASS. It does not know "
        "whether this codebase reaches the vulnerable code. Findings with no CVSS were "
        "not scored by anyone — that is not a score of zero.",
        "- An agent **triage** verdict is reasoning over source about whether untrusted "
        "input can reach the line. Nothing was executed.",
        "- A **compliance** control result is an agent's reading of whether a written "
        "requirement is met, evidenced by a file and line it opened. It is weaker than a "
        "triage verdict and far weaker than a reproduction, it is counted separately from "
        "findings, and it never affects the pass/fail of this scan.",
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


def _compliance_demo() -> None:
    """The three shapes that must not be confused with one another."""
    # A pack that assessed nothing must SAY so. Silence here reads as a clean sheet.
    nothing = "\n".join(_compliance_section([{
        "pack_id": "sebi-cscrf", "pack_title": "SEBI CSCRF", "total_controls": 43,
        "unjudged": 14,
        "results": [{"status": "not_observable"}] * 29 + [{"status": "unknown"}] * 14,
    }]))
    assert "No control could be assessed" in nothing, nothing
    assert "This is not a pass" in nothing, nothing
    assert "29 cannot be answered" in nothing, nothing
    assert "14 were never reached" in nothing, nothing
    # The word that must never appear next to a regulator's name.
    assert "compliant" not in nothing.lower(), nothing

    mixed = "\n".join(_compliance_section([{
        "pack_id": "twelve-factor", "pack_title": "The Twelve-Factor App",
        "total_controls": 12, "unjudged": 0,
        "results": [
            {"control_id": "twelve-factor:II", "status": "pass",
             "contradicted_by": ["abc1"]},
            {"control_id": "twelve-factor:III", "status": "fail",
             "rationale": "SECRET_KEY is a literal in settings.py.",
             "proven_findings": ["deadbeef"],
             "citations": [{"file": "settings.py", "line": 3}]},
            {"control_id": "twelve-factor:VIII", "status": "not_observable"},
        ],
    }]))
    # Two numbers, and the denominator is what was ASSESSED, not the pack size.
    assert "1 of 2 source-checkable controls satisfied" in mixed, mixed
    assert "12 control(s) in the pack" in mixed, mixed
    # A failure prints the line a reader can open. Without it this is just an opinion.
    assert "`settings.py:3`" in mixed, mixed
    # ...and says when it is more than an opinion.
    assert "A reproduced finding corroborates this." in mixed, mixed
    # A pass sitting next to a reproduced exploit of the same class is the signal that
    # says how far to trust the whole run, so it gets its own paragraph.
    assert "marked satisfied while a reproduced finding" in mixed, mixed
    assert "compliant" not in mixed.lower(), mixed

    # No pack requested means no section at all, not an empty heading.
    assert _compliance_section([]) == []
    # Malformed rows must not raise: this renders at the end of a scan that already cost
    # money, and a crash here loses the whole brief.
    for junk in ([None], [{"results": "no"}], [{"results": [None]}], [{}]):
        _compliance_section(junk)


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
             "cvss": {"score": 8.8, "version": "3.1", "source": "nvd",
                      "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"},
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
    # A CVSS number must never appear without its source and vector.
    assert "**8.8** (v3.1, NVD)" in out, out[out.index("| CVSS"):][:120]
    assert "CVSS:3.1/AV:N/AC:L" in out
    assert "rates the vulnerability CLASS" in out
    # The unscored finding gets no CVSS row at all, rather than a zero.
    assert out.count("| CVSS |") == 1, "only the scored finding may show a CVSS row"

    # No coverage recorded is stated, not silently omitted.
    bare = render_markdown({"findings": [], "finding_count": 0})
    assert "Not recorded for this run" in bare
    assert "before concluding the repository is clean" in bare
    _compliance_demo()
    # And the caveat that keeps a reader from over-reading a control result.
    audited = render_markdown({"findings": [], "severity_counts": {}, "compliance": [{
        "pack_id": "p", "pack_title": "Pack", "total_controls": 1,
        "results": [{"control_id": "p:1", "status": "fail", "rationale": "x",
                     "citations": [{"file": "a.py", "line": 1}]}]}]})
    assert "## Compliance" in audited, audited
    assert "never affects the pass/fail of this scan" in audited, audited
    # A run with no pack renders exactly as it did before this feature existed.
    assert "## Compliance" not in render_markdown({"findings": [], "severity_counts": {}})
    print("report.markdown: ok")


if __name__ == "__main__":
    demo()
