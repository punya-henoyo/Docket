"""Trivy: deterministic dependency (SCA) scanning against mounted source.

Same shape as nuclei.py — a pre-scan, not an agent tool, parsing trivy's own JSON
straight into a Finding. Requires `--source <path>` (docket/interface/cli_args.py),
which docket mounts read-only into the sandbox at /work/source
(docket/runtime/sandbox.py); with no source path this scanner does not run.

Honesty note: unlike a dynamic finding, this is NOT an exploited proof — it is "this
advisory applies to this pinned version." rule_id is prefixed `trivy/` and the
description says so explicitly, so a report reader can't mistake it for something an
agent reproduced.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from docket.report.models import Finding, Location, PoC, Severity

_SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW, "UNKNOWN": Severity.INFO,
}


def _cwe(vuln: dict[str, Any]) -> str | None:
    ids = vuln.get("CweIDs") or []
    return ids[0].upper() if ids else None


def parse_trivy_json(text: str) -> list[Finding]:
    try:
        doc = json.loads(text)
    except json.JSONDecodeError:
        return []

    findings: list[Finding] = []
    for result in doc.get("Results") or []:
        target = result.get("Target", "unknown")
        for vuln in result.get("Vulnerabilities") or []:
            vuln_id = vuln.get("VulnerabilityID", "unknown")
            package = vuln.get("PkgName", "unknown")
            installed = vuln.get("InstalledVersion", "?")
            fixed = vuln.get("FixedVersion")
            findings.append(Finding(
                rule_id=f"trivy/{vuln_id}",
                cwe=_cwe(vuln),
                title=f"{vuln_id} in {package}@{installed}",
                severity=_SEVERITY_MAP.get((vuln.get("Severity") or "UNKNOWN").upper(), Severity.INFO),
                location=Location(method="DEPENDENCY", path=target, parameter=package, source_file=target),
                description=(
                    f"Dependency scan (trivy) — not dynamically exploited. "
                    f"{(vuln.get('Title') or vuln.get('Description') or '').strip()}"
                ).strip(),
                poc=PoC(
                    request=f"{package}@{installed} pinned in {target}",
                    response=(
                        f"Advisory {vuln_id}: {(vuln.get('Title') or 'no title').strip()}. "
                        f"Fixed in {fixed or 'no fix available yet'}."
                    ),
                ),
                discovered_by="trivy",
            ))
    return findings


def run_trivy(sandbox: Any, run_dir: Path, *, timeout_sec: int = 120) -> list[Finding]:
    """Requires the sandbox to have been started with a source_dir (mounted read-only
    at /work/source) — callers gate on that before invoking this. Never raises."""
    out_path = run_dir / "artifacts" / "scanners" / "trivy.json"
    command = (
        "mkdir -p /work/run/artifacts/scanners && "
        "trivy fs --scanners vuln --format json --quiet "
        "--output /work/run/artifacts/scanners/trivy.json /work/source"
    )
    try:
        result = sandbox.call("shell", command=command, timeout_sec=timeout_sec)
    except Exception:
        return []
    if "error" in result:
        return []
    if not out_path.exists():
        return []
    return parse_trivy_json(out_path.read_text())


def demo() -> None:
    sample = json.dumps({
        "Results": [{
            "Target": "package-lock.json",
            "Vulnerabilities": [{
                "VulnerabilityID": "CVE-2021-23337",
                "PkgName": "lodash",
                "InstalledVersion": "4.17.15",
                "FixedVersion": "4.17.21",
                "Severity": "HIGH",
                "Title": "lodash: command injection",
                "CweIDs": ["CWE-78"],
            }],
        }],
    })
    findings = parse_trivy_json(sample)
    assert len(findings) == 1, findings
    f = findings[0]
    assert f.rule_id == "trivy/CVE-2021-23337"
    assert f.cwe == "CWE-78"
    assert f.severity == Severity.HIGH
    assert f.location.parameter == "lodash" and f.location.path == "package-lock.json"
    assert "not dynamically exploited" in f.description
    assert "4.17.21" in f.poc.response
    assert parse_trivy_json("not json") == []
    print("scanners.trivy: ok")


if __name__ == "__main__":
    demo()
