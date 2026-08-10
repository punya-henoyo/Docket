"""The `finding` tool: the interface agents call to register a validated vulnerability.
Params are the rich, LLM-facing shape (steps/proxy_flow_id/screenshot_path/
dialog_message); this maps them down into docket.report.models.Finding — the report
layer's stricter, validated shape — and persists one JSON file per finding so results
survive a crashed/killed agent, matching the sandbox's runs/<id>/findings/ convention.
"""
from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Literal
from urllib.parse import urlparse

from docket.report.models import Finding, Location, PoC, Severity

FindingType = Literal[
    "sqli", "command_injection", "xss_reflected", "xss_stored",
    "ssrf", "idor", "auth_bypass", "other",
]

_TYPE_TO_RULE_ID: dict[str, str] = {
    "sqli": "sql-injection",
    "command_injection": "command-injection",
    "xss_reflected": "reflected-xss",
    "xss_stored": "stored-xss",
    "ssrf": "ssrf",
    "idor": "idor",
    "auth_bypass": "auth-bypass",
    "other": "other",
}

_TYPE_TO_CWE: dict[str, str] = {
    "sqli": "CWE-89",
    "command_injection": "CWE-78",
    "xss_reflected": "CWE-79",
    "xss_stored": "CWE-79",
    "ssrf": "CWE-918",
    "idor": "CWE-639",
}


def _render_request(request: dict) -> str:
    method = request.get("method", "GET")
    url = request.get("url", "")
    parts = [f"{method} {url}"]
    for k, v in (request.get("headers") or {}).items():
        parts.append(f"{k}: {v}")
    if request.get("body"):
        parts.append("")
        parts.append(str(request["body"]))
    return "\n".join(parts)


def register_finding(
    *,
    rule_type: FindingType,
    severity: str,
    title: str,
    description: str,
    location: dict,
    poc: dict,
    discovered_by: str,
    run_dir: Path,
    on_finding: Callable[[Finding], None] | None = None,
    confidence: Literal["confirmed", "likely", "suspected"] = "confirmed",
) -> dict:
    path = urlparse(location.get("url", "")).path or location.get("path", "")
    finding = Finding(
        rule_id=_TYPE_TO_RULE_ID[rule_type],
        cwe=_TYPE_TO_CWE.get(rule_type),
        title=title,
        severity=Severity(severity),
        location=Location(
            method=location.get("method", "GET"),
            path=path,
            parameter=location.get("parameter"),
            source_file=location.get("file"),
        ),
        description=description,
        poc=PoC(
            request=_render_request(poc["request"]) if isinstance(poc.get("request"), dict) else str(poc.get("request", "")),
            response=str(poc.get("response_excerpt", "")),
            notes="; ".join(poc.get("steps", [])) or None,
        ),
        discovered_by=discovered_by,
    )
    # `confidence` is accepted for schema parity with the tool contract but not yet
    # modeled on Finding — every finding that reaches here already carries validated
    # non-empty PoC evidence (enforced by PoC's own validator), which is what
    # "confirmed" means in practice. Add a real confidence field if a caller needs to
    # distinguish "confirmed" from "likely"/"suspected" mid-investigation.

    findings_dir = run_dir / "findings"
    findings_dir.mkdir(parents=True, exist_ok=True)
    stored_at = findings_dir / f"{finding.id}.json"
    stored_at.write_text(finding.model_dump_json(indent=2))

    if on_finding is not None:
        on_finding(finding)

    return {"finding_id": finding.id, "ok": True, "stored_at": str(stored_at)}


def demo() -> None:
    import shutil
    import tempfile

    from docket.report.dedupe import FindingStore

    tmp = Path(tempfile.mkdtemp())
    try:
        store = FindingStore()
        result = register_finding(
            rule_type="sqli",
            severity="high",
            title="SQL injection in POST /login",
            description="username is f-string'd into the SQL query, allowing auth bypass.",
            location={"url": "http://127.0.0.1:5000/login", "method": "POST", "parameter": "username"},
            poc={
                "steps": ["send username=admin' -- with any password"],
                "request": {"method": "POST", "url": "http://127.0.0.1:5000/login", "body": "username=admin'+--+&password=x"},
                "response_excerpt": "200 Welcome",
            },
            discovered_by="sqli-agent",
            run_dir=tmp,
            on_finding=store.add,
        )
        assert result["ok"] is True
        assert Path(result["stored_at"]).exists()
        assert len(store) == 1
        f = store.findings()[0]
        assert f.rule_id == "sql-injection"
        assert f.cwe == "CWE-89"
        assert f.location.path == "/login"
        assert "admin" in f.poc.request
        assert f.poc.response == "200 Welcome"
        # persisted JSON round-trips
        reloaded = json.loads(Path(result["stored_at"]).read_text())
        assert reloaded["rule_id"] == "sql-injection"
    finally:
        shutil.rmtree(tmp)
    print("finding: ok")


if __name__ == "__main__":
    demo()
