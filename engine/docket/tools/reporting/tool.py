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


def _evidence(value: object, *, dict_ok: bool = False) -> str:
    """Coerce model-supplied evidence to text WITHOUT manufacturing content.

    PoC's validator rejects blank strings, but it only ever saw the output of `str()`,
    and `str()` is happy to invent something non-blank out of nothing:

        str(None)              -> "None"    4 chars, not blank, ACCEPTED
        _render_request({})    -> "GET "    4 chars, not blank, ACCEPTED

    So a JSON `null` from the model was enough to file a finding with zero reproduced
    output — the one thing this tool must never emit. Absent or structurally empty
    evidence now becomes "", which the validator refuses.

    A request dict counts as evidence only if it carries a url; a method alone is a
    shape, not a repro. `dict_ok` is False for response bodies because there is no
    sensible rendering of a dict as observed output.
    """
    if value is None:
        return ""
    if isinstance(value, dict):
        if not dict_ok or not str(value.get("url", "")).strip():
            return ""
        return _render_request(value)
    if isinstance(value, (list, tuple)):
        return "\n".join(str(v) for v in value if str(v).strip())
    return str(value)


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

    # Refuse before constructing, and say why. PoC's validator would raise a
    # ValidationError here, which the SDK renders to the model as an opaque tool crash —
    # the model then has no idea it needs to go and actually reproduce the bug. An
    # explicit refusal is actionable: it names the missing field and what would satisfy it.
    request_text = _evidence(poc.get("request"), dict_ok=True)
    response_text = _evidence(poc.get("response_excerpt"))
    missing = [
        field for field, value in (("request", request_text), ("response_excerpt", response_text))
        if not value.strip()
    ]
    if missing:
        return {
            "ok": False,
            "error": (
                f"finding refused — no reproduced evidence in: {', '.join(missing)}. "
                "Send the literal request you issued and the literal output you observed. "
                "A description of what you believe happens is not evidence. Go run the "
                "exploit, capture the real request/response, then call this again."
            ),
            "missing": missing,
        }

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
            # Still routed through PoC's validator, not trusted from the check above:
            # the model's guarantee is the type's, and the refusal path is only there to
            # make the failure legible to the agent.
            request=request_text,
            response=response_text,
            notes="; ".join(poc.get("steps") or []) or None,
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

        # An evidence-free finding must be REFUSED. Every shape below used to be accepted,
        # because str() manufactures something non-blank from nothing: str(None) is "None"
        # and rendering an empty request dict is "GET ". A finding without reproduced
        # output is the one thing this tool must never emit, so these stay asserted.
        def _rejected(poc: dict) -> bool:
            outcome = register_finding(
                rule_type="sqli", severity="critical", title="claimed, not proven",
                description="no evidence attached",
                location={"url": "http://127.0.0.1:5000/x", "method": "GET", "parameter": "u"},
                poc=poc, discovered_by="test", run_dir=tmp, on_finding=store.add,
            )
            return outcome.get("ok") is not True

        assert _rejected({"request": "GET /x", "response_excerpt": None}), "null response accepted"
        assert _rejected({"request": {}, "response_excerpt": "body"}), "empty request dict accepted"
        assert _rejected({}), "wholly absent PoC accepted"
        assert _rejected({"request": None, "response_excerpt": None}), "explicit nulls accepted"
        assert _rejected({"request": "GET /x", "response_excerpt": "   "}), "whitespace accepted"
        # ...while a dict request carrying a real url is still valid evidence.
        assert len(store) == 1, "a refused finding must not reach the store"
    finally:
        shutil.rmtree(tmp)
    print("finding: ok")


if __name__ == "__main__":
    demo()
