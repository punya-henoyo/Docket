"""Semgrep: deterministic static-analysis (SAST) scanning against mounted source.

Same shape as trivy.py: requires `--source <path>` (mounted read-only at
/work/source, see docket/runtime/sandbox.py); does not run without it.

Honesty note, same as trivy.py: a pattern match is not an exploited proof. The
PoC here is real (the literal matched source line + semgrep's own finding message,
both taken verbatim from semgrep's output) but it is static evidence, not a
reproduced dynamic exploit — rule_id is prefixed `semgrep/` so it reads distinctly
from an agent-confirmed finding in the report.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from docket.report.models import Finding, Location, PoC, Severity

_SEVERITY_MAP = {"ERROR": Severity.HIGH, "WARNING": Severity.MEDIUM, "INFO": Severity.LOW}
_CWE_RE = re.compile(r"CWE-\d+")

# Where the source is mounted inside the sandbox (runtime/sandbox.py). Stripped so a
# report says "app.py", not "/work/source/app.py" — the container's layout is an
# implementation detail, and a repo-relative path is what a reader can act on.
_MOUNT = "/work/source/"


def _relative(path: str) -> str:
    return path[len(_MOUNT):] if path.startswith(_MOUNT) else path.removeprefix("/work/source")


def _cwe(metadata: dict[str, Any]) -> str | None:
    for entry in metadata.get("cwe") or []:
        match = _CWE_RE.search(str(entry))
        if match:
            return match.group(0)
    return None


def parse_semgrep_json(text: str) -> list[Finding]:
    try:
        doc = json.loads(text)
    except json.JSONDecodeError:
        return []

    findings: list[Finding] = []
    for result in doc.get("results") or []:
        check_id = result.get("check_id", "unknown")
        path = _relative(result.get("path", "unknown"))
        line = (result.get("start") or {}).get("line")
        extra = result.get("extra") or {}
        metadata = extra.get("metadata") or {}
        snippet = (extra.get("lines") or "").strip()
        message = (extra.get("message") or "").strip()
        if not snippet or not message:
            # No real matched code / explanation to build a PoC from.
            continue

        findings.append(Finding(
            rule_id=f"semgrep/{check_id}",
            cwe=_cwe(metadata),
            title=f"{check_id.rsplit('.', 1)[-1]} in {path}",
            severity=_SEVERITY_MAP.get((extra.get("severity") or "INFO").upper(), Severity.LOW),
            location=Location(
                method="STATIC", path=path, source_file=f"{path}:{line}" if line else path,
            ),
            description=f"Static analysis (semgrep) — not dynamically exploited. {message}",
            poc=PoC(request=snippet, response=message),
            discovered_by="semgrep",
        ))
    return findings


def run_semgrep(sandbox: Any, run_dir: Path, *, timeout_sec: int = 120) -> list[Finding]:
    """Requires the sandbox to have been started with a source_dir mounted at
    /work/source — callers gate on that before invoking this. Never raises."""
    out_path = run_dir / "artifacts" / "scanners" / "semgrep.json"
    command = (
        "mkdir -p /work/run/artifacts/scanners && "
        "semgrep scan --config auto --json --quiet "
        "--output /work/run/artifacts/scanners/semgrep.json /work/source"
    )
    try:
        result = sandbox.call("shell", command=command, timeout_sec=timeout_sec)
    except Exception:
        return []
    if "error" in result:
        return []
    if not out_path.exists():
        return []
    return parse_semgrep_json(out_path.read_text())


def demo() -> None:
    sample = json.dumps({
        "results": [{
            "check_id": "python.django.security.injection.sqli.sqli-raw-query",
            "path": "app/views.py",
            "start": {"line": 42},
            "extra": {
                "message": "Detected a raw SQL query.",
                "severity": "ERROR",
                "lines": 'cursor.execute(f"SELECT * FROM users WHERE id={uid}")',
                "metadata": {"cwe": ["CWE-89: SQL Injection"]},
            },
        }],
    })
    findings = parse_semgrep_json(sample)
    assert len(findings) == 1, findings
    f = findings[0]
    assert f.rule_id.startswith("semgrep/")
    assert f.cwe == "CWE-89"
    assert f.severity == Severity.HIGH
    assert f.location.source_file == "app/views.py:42"

    # The sandbox mount prefix must never reach a report.
    mounted = json.loads(sample)
    mounted["results"][0]["path"] = "/work/source/app/views.py"
    only = parse_semgrep_json(json.dumps(mounted))[0]
    assert only.location.path == "app/views.py", only.location.path
    assert only.location.source_file == "app/views.py:42", only.location.source_file
    assert "/work/source" not in only.title, only.title
    assert "not dynamically exploited" in f.description
    assert "cursor.execute" in f.poc.request
    assert parse_semgrep_json("not json") == []
    print("scanners.semgrep: ok")


if __name__ == "__main__":
    demo()
