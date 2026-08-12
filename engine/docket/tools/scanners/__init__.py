"""Deterministic scanner pre-scans (nuclei, trivy, semgrep) — see nuclei.py's module
docstring for why these are plain functions run before the agent loop, not agent tools.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def read_coverage(run_dir: Path) -> dict[str, Any]:
    """What each scanner actually looked at, read back from its own artifact.

    Separate from the findings path on purpose: a report that says "12 findings" and
    nothing else cannot distinguish a clean repository from one where the scanner
    errored on every file, and only one of those is safe to act on.
    """
    from docket.tools.scanners.semgrep import parse_coverage

    artifacts = run_dir / "artifacts" / "scanners"
    coverage: dict[str, Any] = {}

    semgrep_json = artifacts / "semgrep.json"
    if semgrep_json.is_file():
        coverage["semgrep"] = parse_coverage(semgrep_json.read_text())

    trivy_json = artifacts / "trivy.json"
    if trivy_json.is_file():
        try:
            doc = json.loads(trivy_json.read_text())
            results = doc.get("Results") or []
            coverage["trivy"] = {
                "manifests": [r.get("Target") for r in results if r.get("Target")],
                "manifest_count": len(results),
            }
        except (OSError, json.JSONDecodeError):
            coverage["trivy"] = {}

    nuclei_jsonl = artifacts / "nuclei.jsonl"
    if nuclei_jsonl.is_file():
        coverage["nuclei"] = {"ran": True}

    return coverage
