"""SARIF 2.1.0 export. Hand-rolled dict -> JSON: the format is ~15 fields for our
purposes, which doesn't justify a dependency.

Local artifact only, by design. vulnshop's existing Semgrep workflow already owns the
default code-scanning category for that repo, so auto-uploading here would intermix or
clobber its alerts; and a developer running docket against localhost has no
GITHUB_TOKEN/Actions context to upload from anyway. To wire this into CI later, add a
step running `docket scan -n` against a CI-started app, then
github/codeql-action/upload-sarif@v3 with an explicit `category: docket` so it lands
beside Semgrep as a distinct tool rather than colliding with it.
"""
from __future__ import annotations

import json
from pathlib import Path

from docket import __version__
from docket.report.models import Finding, Severity

SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

# SARIF has three result levels; map our five severities onto them, and carry the
# nuance separately in security-severity (which is what GitHub's severity badge reads).
_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}
_SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "7.5",
    Severity.MEDIUM: "5.0",
    Severity.LOW: "2.5",
    Severity.INFO: "0.0",
}


def _cwe_tag(cwe: str | None) -> str | None:
    """"CWE-89" -> "external/cwe/cwe-089". GitHub's UI parses exactly this tag shape
    to render its CWE badge, including the zero-padding to three digits."""
    if not cwe:
        return None
    digits = cwe.upper().removeprefix("CWE-").strip()
    if not digits.isdigit():
        return None
    return f"external/cwe/cwe-{int(digits):03d}"


def _location(finding: Finding) -> dict:
    """Best-effort physical location. This is DAST against a live endpoint, not SAST,
    so there is often no source file to point at — fall back to the route, the same
    approach ZAP's SARIF export takes. A finding whose agent mapped the route back to
    source (location.source_file) anchors properly in code scanning; one without will
    show up unanchored."""
    source = finding.location.source_file
    if source:
        file_part, _, line_part = source.partition(":")
        physical: dict = {"artifactLocation": {"uri": file_part}}
        if line_part.isdigit():
            physical["region"] = {"startLine": int(line_part)}
        return {"physicalLocation": physical}
    route = finding.location.path.lstrip("/") or "/"
    return {"physicalLocation": {"artifactLocation": {"uri": route}}}


def _rule(finding: Finding) -> dict:
    tags = ["security"]
    tag = _cwe_tag(finding.cwe)
    if tag:
        tags.append(tag)
    return {
        "id": finding.rule_id,
        "name": finding.rule_id,
        "shortDescription": {"text": finding.title},
        "fullDescription": {"text": finding.description},
        "properties": {
            "tags": tags,
            "security-severity": _SECURITY_SEVERITY[finding.severity],
        },
    }


def _message(finding: Finding) -> str:
    parts = [finding.description.strip()]
    if finding.location.parameter:
        parts.append(f"Parameter: {finding.location.parameter}.")
    parts.append(f"Reproduced with: {finding.poc.request.strip()}")
    parts.append(f"Observed: {finding.poc.response.strip()[:500]}")
    return " ".join(p for p in parts if p)


def to_sarif(findings: list[Finding], *, target: str | None = None) -> dict:
    # One rule per distinct rule_id, in first-seen order, so results can reference it
    # by ruleIndex.
    rules: list[dict] = []
    rule_index: dict[str, int] = {}
    for finding in findings:
        if finding.rule_id not in rule_index:
            rule_index[finding.rule_id] = len(rules)
            rules.append(_rule(finding))

    results = [
        {
            "ruleId": finding.rule_id,
            "ruleIndex": rule_index[finding.rule_id],
            "level": _LEVEL[finding.severity],
            "message": {"text": _message(finding)},
            "locations": [_location(finding)],
            # Same key the FindingStore dedupes on, so two runs of docket are diffable:
            # a fingerprint present in run A and absent in run B is a closed finding.
            "partialFingerprints": {"docketDedupeKey/v1": finding.dedupe_key},
            "properties": {
                "security-severity": _SECURITY_SEVERITY[finding.severity],
                "docket-severity": finding.severity.value,
                "discovered-by": finding.discovered_by,
                "http-method": finding.location.method,
                "route": finding.location.path,
            },
        }
        for finding in findings
    ]

    run: dict = {
        "tool": {
            "driver": {
                "name": "docket",
                "version": __version__,
                # No informationUri: docket has no canonical published URL, and pointing
                # it at the upstream project docket is modeled on would misattribute
                # these findings to a tool that did not produce them.
                "rules": rules,
            }
        },
        "results": results,
    }
    if target:
        run["properties"] = {"target": target}
    return {"$schema": SARIF_SCHEMA, "version": "2.1.0", "runs": [run]}


def write_sarif(path: Path, findings: list[Finding], *, target: str | None = None) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(to_sarif(findings, target=target), indent=2))
    return path


def demo() -> None:
    from docket.report.models import Location, PoC

    findings = [
        Finding(
            rule_id="sql-injection", cwe="CWE-89", title="SQLi in /login",
            severity=Severity.HIGH,
            location=Location(method="POST", path="/login", parameter="username", source_file="app.py:34"),
            description="username is f-string'd into the query.",
            poc=PoC(request="curl -d ...", response="200 Welcome"),
            discovered_by="sqli-agent",
        ),
        Finding(
            rule_id="reflected-xss", cwe="CWE-79", title="XSS in /search",
            severity=Severity.MEDIUM,
            location=Location(method="GET", path="/search", parameter="q"),
            description="q is rendered unescaped.",
            poc=PoC(request="GET /search?q=<script>", response="alert fired"),
            discovered_by="xss-agent",
        ),
    ]
    doc = to_sarif(findings, target="http://127.0.0.1:5000")
    assert doc["version"] == "2.1.0"
    assert len(doc["runs"][0]["tool"]["driver"]["rules"]) == 2
    assert doc["runs"][0]["results"][0]["level"] == "error"
    assert doc["runs"][0]["results"][1]["level"] == "warning"
    assert "external/cwe/cwe-089" in doc["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["tags"]
    # source_file anchors to a real file+line; the other falls back to the route.
    loc0 = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    assert loc0["artifactLocation"]["uri"] == "app.py" and loc0["region"]["startLine"] == 34
    loc1 = doc["runs"][0]["results"][1]["locations"][0]["physicalLocation"]
    assert loc1["artifactLocation"]["uri"] == "search"
    assert doc["runs"][0]["results"][0]["partialFingerprints"]["docketDedupeKey/v1"] == findings[0].dedupe_key
    assert _cwe_tag("CWE-79") == "external/cwe/cwe-079"
    assert _cwe_tag(None) is None and _cwe_tag("nonsense") is None
    # Two findings sharing a rule_id collapse to one rule entry.
    doc2 = to_sarif([findings[0], findings[0]])
    assert len(doc2["runs"][0]["tool"]["driver"]["rules"]) == 1
    assert [r["ruleIndex"] for r in doc2["runs"][0]["results"]] == [0, 0]
    print("sarif: ok")


if __name__ == "__main__":
    demo()
