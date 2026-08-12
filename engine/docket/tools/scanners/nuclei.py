"""Nuclei: deterministic, template-matched black-box scanning.

Runs as a pre-scan step BEFORE any LLM sees the target — not an agent tool. Nuclei's
own JSON output is already structured; routing it through an LLM to re-type as a
`finding` tool call would only add latency and transcription risk for data that's
already exact. `parse_nuclei_jsonl` is pure and container-free, so it's testable
without Docker; `run_nuclei` is the thin part that actually shells out.

-irr (include request/response) is required — without it nuclei's JSON has no
request/response fields, and docket's PoC model rejects a Finding built from a claim
instead of real reproduced evidence (see report/models.py).

# ponytail: a scan run is bounded by the shared shell timeout
# (tools/shell/tools.py::MAX_TIMEOUT_SEC, 120s) since run_nuclei goes through the same
# `shell` RPC an agent uses. Fine for a small target; raise that constant (or give
# scanners their own longer-lived RPC verb) if a real target needs more.
"""
from __future__ import annotations

import json
import re
import shlex
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from docket.report.models import Cvss, Finding, Location, PoC, Severity

_METHOD_RE = re.compile(r"^([A-Z]+)\s+\S+\s+HTTP/")
_EVIDENCE_CHARS = 4000  # generous single-response cap; the verdict is what matters


def _method_from_raw_request(raw: str) -> str:
    match = _METHOD_RE.match(raw.strip())
    return match.group(1) if match else "GET"


def _severity(raw: str | None) -> Severity:
    try:
        return Severity[(raw or "info").strip().upper()]
    except KeyError:
        return Severity.INFO


def _cwe(info: dict[str, Any]) -> str | None:
    ids = (info.get("classification") or {}).get("cwe-id") or []
    return ids[0].upper() if ids else None


def _cvss(info: dict[str, Any]) -> Cvss | None:
    """The template author's own CVSS classification, when the template carries one.

    Attributed to the template rather than to a scoring body, because that is what it
    is: a community template's assessment, not an NVD record. Templates commonly ship
    a score with no vector, so the vector stays None rather than being reconstructed."""
    classification = (info.get("classification") or {})
    raw = classification.get("cvss-score")
    if not isinstance(raw, (int, float)) or not 0.0 <= float(raw) <= 10.0:
        return None
    vector = classification.get("cvss-metrics")
    version = "3.1"
    if isinstance(vector, str) and vector.startswith("CVSS:"):
        version = vector.split("/")[0].removeprefix("CVSS:") or version
    return Cvss(score=float(raw), vector=vector if isinstance(vector, str) else None,
                version=version, source="nuclei-template")


def parse_nuclei_jsonl(text: str) -> list[Finding]:
    """One JSON object per line (`nuclei -jsonl`). Blank/malformed lines are skipped —
    nuclei's stdout can carry a trailing non-JSON status line."""
    findings: list[Finding] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            result = json.loads(line)
        except json.JSONDecodeError:
            continue

        raw_request = (result.get("request") or "").strip()
        raw_response = (result.get("response") or "").strip()
        if not raw_request or not raw_response:
            # No captured request/response (ran without -irr, or a non-HTTP protocol
            # template) — nothing real to build a PoC from, so skip rather than fake it.
            continue

        info = result.get("info") or {}
        matched_at = result.get("matched-at") or result.get("host") or ""
        template_id = result.get("template-id", "unknown")

        findings.append(Finding(
            rule_id=f"nuclei/{template_id}",
            cwe=_cwe(info),
            title=info.get("name") or template_id,
            severity=_severity(info.get("severity")),
            location=Location(
                method=_method_from_raw_request(raw_request),
                path=urlparse(matched_at).path or "/",
            ),
            description=(info.get("description") or "").strip()
            or f"nuclei template {template_id} matched.",
            poc=PoC(
                request=raw_request[:_EVIDENCE_CHARS],
                response=raw_response[:_EVIDENCE_CHARS],
            ),
            discovered_by="nuclei",
            cvss=_cvss(info),
        ))
    return findings


def run_nuclei(sandbox: Any, target_url: str, run_dir: Path, *, timeout_sec: int = 120) -> list[Finding]:
    """Shell out to nuclei inside the sandbox, via the same RPC path an agent's `shell`
    tool uses — deterministic input, deterministic parse, no LLM in the loop. Output is
    written straight to the bind-mounted run dir (not returned over the RPC channel,
    which head+tail-truncates large stdout) so an oversized scan can't silently lose
    findings in the middle. Never raises: a missing/broken scanner degrades to "no
    scanner findings," not a failed scan.

    -duc (disable update check) is load-bearing, not cosmetic: without it, nuclei
    phones home to api.pdtm.sh on every invocation and — confirmed by an end-to-end
    run against the test fixture — that check can retry for 15-30s+ before the actual
    scan starts, eating most of the shared shell timeout for nothing.
    """
    out_path = run_dir / "artifacts" / "scanners" / "nuclei.jsonl"
    command = (
        "mkdir -p /work/run/artifacts/scanners && "
        f"nuclei -u {shlex.quote(target_url)} -jsonl -irr -silent -duc "
        "-severity low,medium,high,critical "
        "-o /work/run/artifacts/scanners/nuclei.jsonl"
    )
    try:
        result = sandbox.call("shell", command=command, timeout_sec=timeout_sec)
    except Exception:
        return []
    if "error" in result:
        return []
    if not out_path.exists():
        return []
    return parse_nuclei_jsonl(out_path.read_text())


def demo() -> None:
    sample = "\n".join([
        json.dumps({
            "template-id": "exposed-.git",
            "info": {
                "name": "Exposed .git Repository",
                "severity": "high",
                "description": "A .git repository is exposed.",
                "classification": {"cwe-id": ["CWE-538"]},
            },
            "matched-at": "http://target/.git/config",
            "request": "GET /.git/config HTTP/1.1\nHost: target",
            "response": "HTTP/1.1 200 OK\n\n[core]\n",
        }),
        "",  # blank line, must be skipped
        "not json at all",  # malformed, must be skipped
        json.dumps({  # no -irr evidence -> must be skipped, not fabricated
            "template-id": "tech-detect",
            "info": {"name": "Tech", "severity": "info"},
            "matched-at": "http://target/",
        }),
    ])
    findings = parse_nuclei_jsonl(sample)
    assert len(findings) == 1, findings
    f = findings[0]
    assert f.rule_id == "nuclei/exposed-.git"
    assert f.cwe == "CWE-538"
    assert f.severity == Severity.HIGH
    assert f.location.method == "GET" and f.location.path == "/.git/config"
    assert f.discovered_by == "nuclei"
    assert "core" in f.poc.response
    # ── CVSS from the template's own classification ────────────────────────
    scored = json.dumps({
        "template-id": "CVE-2021-44228", "matched-at": "http://t/api",
        "request": "GET /api HTTP/1.1", "response": "HTTP/1.1 200 OK",
        "info": {"name": "Log4Shell", "severity": "critical", "classification": {
            "cwe-id": ["CWE-502"], "cvss-score": 10.0,
            "cvss-metrics": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}},
    })
    f = parse_nuclei_jsonl(scored)[0]
    assert f.cvss.score == 10.0 and f.cvss.source == "nuclei-template"
    assert f.cvss.rating == "critical" and f.cvss.version == "3.1"

    # A template with no cvss-score gets no score. Severity alone is not a CVSS.
    plain = json.dumps({
        "template-id": "tech-detect", "matched-at": "http://t/",
        "request": "GET / HTTP/1.1", "response": "HTTP/1.1 200 OK",
        "info": {"name": "Tech", "severity": "high"},
    })
    assert parse_nuclei_jsonl(plain)[0].cvss is None

    print("scanners.nuclei: ok")


if __name__ == "__main__":
    demo()
