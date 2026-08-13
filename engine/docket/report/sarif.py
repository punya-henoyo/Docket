"""SARIF 2.1.0 export. Hand-rolled dict -> JSON: the format is ~15 fields for our
purposes, which doesn't justify a dependency.

Local artifact only, by design. A developer running docket against localhost has no
GITHUB_TOKEN/Actions context to upload from, and auto-uploading would claim a repo's
default code-scanning category, intermixing docket's alerts with whatever static
analysis already publishes there. To wire this into CI later, add a
step running `docket scan -n` against a CI-started app, then
github/codeql-action/upload-sarif@v3 with an explicit `category: docket` so it lands
beside Semgrep as a distinct tool rather than colliding with it.
"""
from __future__ import annotations

import json
from pathlib import Path

from docket import __version__
from docket.report.models import Finding, Severity
from docket.utils.secret_files import redact_document

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


def _region(line_part: str) -> dict | None:
    """"12" -> startLine 12. "52-58" -> startLine 52, endLine 58. Anything else -> None.

    Ranges are not a hypothetical: the recon agent writes location.source_file as
    "app/admin.py:52-58" for a whole handler. The previous `line_part.isdigit()` test is
    False for "52-58", so NO region was emitted at all — GitHub accepts a region-less
    result and pins it to line 1, which made every ranged finding land on the same line,
    indistinguishable from each other. Verified against
    docket_runs/connect-b9744ecf3c78/report.sarif before this fix.
    """
    start, _, end = line_part.strip().partition("-")
    if not start.isdigit() or int(start) < 1:
        return None
    region: dict = {"startLine": int(start)}
    # An endLine below startLine is invalid SARIF, so a garbled range degrades to the
    # single line it starts on rather than emitting a document a consumer rejects.
    if end.isdigit() and int(end) >= int(start):
        region["endLine"] = int(end)
    return region


def _location(finding: Finding) -> dict | None:
    """Physical location, or None when there is nothing in the tree to point at.

    None means the result is DROPPED (see to_sarif). This is DAST against a live
    endpoint, so a finding often has no source file — but the old fallback pointed at the
    ROUTE (`route.lstrip("/")`, yielding uri="/" or uri="login"), and those are not paths
    in the repository. GitHub resolves them to nothing and shows the alert against line 1
    of a file that does not exist. An alert nobody can navigate to is worse than an absent
    one, because it looks reviewed. report.json still carries every finding either way.
    """
    source = finding.location.source_file
    if not source or not source.partition(":")[0].strip():
        return None
    file_part, _, line_part = source.partition(":")
    physical: dict = {"artifactLocation": {"uri": file_part.strip()}}
    region = _region(line_part)
    if region:
        physical["region"] = region
    return {"physicalLocation": physical}


def _security_severity(finding: Finding) -> str:
    """The number GitHub's code-scanning badge ranks by.

    A published CVSS wins over our bucketed approximation whenever one exists: the
    bucket is derived from a scanner's severity LABEL, and those labels disagree with
    CVSS often. Real example from trivy output: CVE-2024-56201 is labelled MEDIUM by
    the distro advisory but scores 8.8 (high) at NVD. Ranking by the label buries it.
    """
    if finding.cvss:
        return f"{finding.cvss.score:.1f}"
    return _SECURITY_SEVERITY[finding.severity]


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
            "security-severity": _security_severity(finding),
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
    # A finding with no source file has no location a code-scanning UI can resolve, so it
    # is dropped rather than anchored to a route that is not a file. Dropped, not hidden:
    # the count goes into run properties below, and report.json keeps all of them.
    located = [(f, loc) for f in findings if (loc := _location(f)) is not None]
    omitted = len(findings) - len(located)

    # One rule per distinct rule_id, in first-seen order, so results can reference it
    # by ruleIndex. Built from the KEPT findings only — a rule with no result is noise in
    # the tool listing.
    rules: list[dict] = []
    rule_index: dict[str, int] = {}
    for finding, _ in located:
        if finding.rule_id not in rule_index:
            rule_index[finding.rule_id] = len(rules)
            rules.append(_rule(finding))

    results = [
        {
            "ruleId": finding.rule_id,
            "ruleIndex": rule_index[finding.rule_id],
            "level": _LEVEL[finding.severity],
            "message": {"text": _message(finding)},
            "locations": [location],
            # Same key the FindingStore dedupes on, so two runs of docket are diffable:
            # a fingerprint present in run A and absent in run B is a closed finding.
            "partialFingerprints": {"docketDedupeKey/v1": finding.dedupe_key},
            "properties": {
                "security-severity": _security_severity(finding),
                "docket-severity": finding.severity.value,
                # Attribution travels with the number. Consumers that show a score
                # without saying who published it cannot be checked.
                **({"cvss-score": finding.cvss.score,
                    "cvss-vector": finding.cvss.vector or "",
                    "cvss-version": finding.cvss.version,
                    "cvss-source": finding.cvss.source} if finding.cvss else {}),
                "discovered-by": finding.discovered_by,
                "http-method": finding.location.method,
                "route": finding.location.path,
            },
        }
        for finding, location in located
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
        # Countable, not silent: a reader comparing report.json's finding_count against
        # this document's result count needs to see WHY they differ.
        "properties": {"omitted-no-source-file": omitted},
    }
    if target:
        run["properties"]["target"] = target
    return {"$schema": SARIF_SCHEMA, "version": "2.1.0", "runs": [run]}


def leads_to_sarif(leads: list, verdicts: dict | None = None) -> dict:
    """SARIF for STATIC candidates — one result per (rule_id, file, line).

    Separate from to_sarif() because the two key differently and must. Finding.dedupe_key
    deliberately omits the line, so two hits of one rule in one file collapse inside
    FindingStore.add and only ONE alert can ever exist for them. StaticFinding.key is
    per-line. Emitting candidates as their own document keeps every flagged line
    addressable as its own annotation without touching dedupe_key, which report/dedupe.py
    pins with its own asserts.

    `leads` accepts docket.static.correlate.Lead objects or bare StaticFindings.
    `verdicts` optionally maps StaticFinding.key -> a verdict string, or a dict carrying
    "verdict"/"reasoning". It only annotates the message; it never suppresses a result,
    because "an agent thought this was a false positive" is not the same as "this line was
    never flagged".

    driver.name is "docket-static", not "docket": these are candidates, not reproductions,
    and uploading them under the same tool name would let a lead close a proven finding's
    alert on the next run.
    """
    rules: list[dict] = []
    rule_index: dict[str, int] = {}
    results: list[dict] = []

    for lead in leads:
        finding = getattr(lead, "finding", lead)
        severity = _static_severity(finding.severity)
        message = (finding.message or finding.rule_id).strip()
        if finding.rule_id not in rule_index:
            tags = ["security"]
            tag = _cwe_tag(finding.cwe)
            if tag:
                tags.append(tag)
            rule_index[finding.rule_id] = len(rules)
            rules.append({
                "id": finding.rule_id,
                "name": finding.rule_id,
                "shortDescription": {"text": message.splitlines()[0][:200] or finding.rule_id},
                "fullDescription": {"text": message or finding.rule_id},
                "properties": {"tags": tags,
                                "security-severity": _SECURITY_SEVERITY[severity]},
            })

        region: dict = {"startLine": max(1, int(finding.line or 1))}
        if finding.end_line and finding.end_line >= region["startLine"]:
            region["endLine"] = int(finding.end_line)

        endpoint = getattr(lead, "endpoint", None)
        parts = [message]
        if endpoint is not None:
            parts.append(f"Reachable via {endpoint.method} {endpoint.path} "
                          f"(correlation confidence {getattr(lead, 'confidence', 'none')}).")
        raw = (verdicts or {}).get(finding.key)
        if raw is not None:
            verdict = raw.get("verdict", "") if isinstance(raw, dict) else str(raw)
            reasoning = raw.get("reasoning", "") if isinstance(raw, dict) else ""
            parts.append(f"Agent triage: {verdict}. {reasoning}".strip())
        parts.append("UNPROVEN static candidate — no request was sent and no response "
                      "observed.")

        results.append({
            "ruleId": finding.rule_id,
            "ruleIndex": rule_index[finding.rule_id],
            "level": _LEVEL[severity],
            "message": {"text": " ".join(p for p in parts if p)},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": finding.file}, "region": region}}],
            # Per-LINE on purpose — this is the whole reason this emitter exists.
            "partialFingerprints": {
                "docketStaticKey/v1": f"{finding.rule_id}|{finding.file}|{finding.line}"},
            "properties": {
                "security-severity": _SECURITY_SEVERITY[severity],
                "docket-severity": severity.value,
                "discovered-by": getattr(finding, "engine", "static"),
                "unproven": True,
            },
        })

    return {"$schema": SARIF_SCHEMA, "version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": "docket-static", "version": __version__,
                             "rules": rules}},
        "results": results,
    }]}


def _static_severity(raw: object) -> Severity:
    """StaticFinding.severity is a plain string ("high"), Finding's is the enum. Unknown
    values become MEDIUM rather than raising a scan's report away."""
    try:
        return Severity(str(raw).lower())
    except ValueError:
        return Severity.MEDIUM


def write_sarif(path: Path, findings: list[Finding], *, target: str | None = None) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    # Redact at the write boundary, on the serialized text, so every field is covered
    # rather than the handful someone remembered to wrap. SARIF is the artifact built for
    # upload, and a PoC quotes the request verbatim — including the target's Authorization
    # and Cookie headers. redact() replaces the VALUE and keeps the header name, so
    # "Authorization: [REDACTED]" still shows the operator what to substitute; the repro
    # stays reproducible. [REDACTED] contains no quotes or backslashes, so substituting it
    # inside serialized JSON cannot corrupt the document.
    path.write_text(json.dumps(
        redact_document(to_sarif(findings, target=target)), indent=2))
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
        # A RANGE, exactly as the recon agent writes it ("app/admin.py:52-58").
        Finding(
            rule_id="missing-authz", cwe="CWE-862", title="Unguarded admin handler",
            severity=Severity.MEDIUM,
            location=Location(method="GET", path="/admin", source_file="app/admin.py:52-58"),
            description="the whole handler runs with no auth check.",
            poc=PoC(request="GET /admin", response="200 admin panel"),
            discovered_by="recon",
        ),
        # Route only, no source file anywhere: must be OMITTED, not given uri="search".
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
    run = doc["runs"][0]
    assert doc["version"] == "2.1.0"
    assert run["properties"]["target"] == "http://127.0.0.1:5000"
    # 3 findings in, 2 results out: the route-only one has no location a code-scanning UI
    # can resolve, and the count of drops is published rather than left to be inferred.
    assert len(run["results"]) == 2, run["results"]
    assert run["properties"]["omitted-no-source-file"] == 1
    assert "reflected-xss" not in [r["ruleId"] for r in run["results"]]
    assert len(run["tool"]["driver"]["rules"]) == 2      # dropped result drops its rule
    assert run["results"][0]["level"] == "error"
    assert run["results"][1]["level"] == "warning"
    assert "external/cwe/cwe-089" in run["tool"]["driver"]["rules"][0]["properties"]["tags"]
    # Every remaining uri is a path in the tree — never "/" and never a bare route name.
    for result in run["results"]:
        uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert uri.endswith(".py"), uri
    loc0 = run["results"][0]["locations"][0]["physicalLocation"]
    assert loc0["artifactLocation"]["uri"] == "app.py" and loc0["region"]["startLine"] == 34
    assert "endLine" not in loc0["region"]
    # The range fix: "52-58" used to emit NO region at all, pinning the alert to line 1.
    loc1 = run["results"][1]["locations"][0]["physicalLocation"]
    assert loc1["artifactLocation"]["uri"] == "app/admin.py"
    assert loc1["region"] == {"startLine": 52, "endLine": 58}, loc1["region"]
    assert _region("12") == {"startLine": 12}
    assert _region("52-58") == {"startLine": 52, "endLine": 58}
    assert _region("58-52") == {"startLine": 58}          # invalid range degrades, not raises
    assert _region("") is None and _region("nonsense") is None and _region("0") is None
    assert _location(findings[2]) is None                 # no source file -> no location
    assert run["results"][0]["partialFingerprints"]["docketDedupeKey/v1"] == findings[0].dedupe_key
    assert run["results"][0]["properties"]["security-severity"] == "7.5"
    assert _cwe_tag("CWE-79") == "external/cwe/cwe-079"
    assert _cwe_tag(None) is None and _cwe_tag("nonsense") is None
    # Two findings sharing a rule_id collapse to one rule entry.
    doc2 = to_sarif([findings[0], findings[0]])
    assert len(doc2["runs"][0]["tool"]["driver"]["rules"]) == 1
    assert [r["ruleIndex"] for r in doc2["runs"][0]["results"]] == [0, 0]

    # --- static candidates: per-LINE, where Finding.dedupe_key is per-route ------------
    from docket.static.models import StaticFinding

    a = StaticFinding("sqli", "user input in query", "app.py", 31, "high", "CWE-89")
    b = StaticFinding("sqli", "user input in query", "app.py", 37, "high", "CWE-89")
    spans = StaticFinding("authz", "handler has no guard", "app.py", 52, "medium",
                           end_line=58)
    static_doc = leads_to_sarif([a, b, spans],
                                verdicts={a.key: {"verdict": "CONFIRMED",
                                                   "reasoning": "reaches sqlite3.execute"}})
    static_run = static_doc["runs"][0]
    assert static_run["tool"]["driver"]["name"] == "docket-static"
    # THE point: same rule, same file, two lines -> TWO results with distinct startLines.
    assert len(static_run["results"]) == 3
    starts = [r["locations"][0]["physicalLocation"]["region"]["startLine"]
              for r in static_run["results"]]
    assert starts == [31, 37, 52], starts
    assert len({r["partialFingerprints"]["docketStaticKey/v1"]
                for r in static_run["results"]}) == 3
    # ...while the one shared rule_id still collapses to a single rule entry.
    assert len(static_run["tool"]["driver"]["rules"]) == 2
    assert [r["ruleIndex"] for r in static_run["results"]] == [0, 0, 1]
    assert static_run["results"][2]["locations"][0]["physicalLocation"]["region"]["endLine"] == 58
    assert "external/cwe/cwe-089" in static_run["tool"]["driver"]["rules"][0]["properties"]["tags"]
    assert static_run["results"][0]["level"] == "error"          # high -> error
    assert static_run["results"][0]["properties"]["security-severity"] == "7.5"
    assert static_run["results"][2]["level"] == "warning"        # medium -> warning
    assert all(r["properties"]["unproven"] is True for r in static_run["results"])
    assert "CONFIRMED" in static_run["results"][0]["message"]["text"]
    assert "UNPROVEN" in static_run["results"][1]["message"]["text"]
    assert _static_severity("high") is Severity.HIGH
    assert _static_severity("bogus") is Severity.MEDIUM
    # A Lead wrapping a finding works the same, and carries its endpoint into the message.
    from docket.discovery.models import Endpoint
    from docket.static.correlate import Lead

    lead = Lead(a, Endpoint("POST", "/login"), "high", "'/login' appears 2 line(s) above")
    lead_doc = leads_to_sarif([lead])
    assert "POST /login" in lead_doc["runs"][0]["results"][0]["message"]["text"]
    assert lead_doc["runs"][0]["results"][0][
        "locations"][0]["physicalLocation"]["region"]["startLine"] == 31
    assert leads_to_sarif([])["runs"][0]["results"] == []
    print("sarif: ok")


if __name__ == "__main__":
    demo()
