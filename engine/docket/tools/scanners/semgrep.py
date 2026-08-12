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
import os
import re
import shlex
from pathlib import Path
from typing import Any

from docket.report.models import Finding, Location, PoC, Severity

_SEVERITY_MAP = {"ERROR": Severity.HIGH, "WARNING": Severity.MEDIUM, "INFO": Severity.LOW}
_CWE_RE = re.compile(r"CWE-\d+")

# Where the source is mounted inside the sandbox (runtime/sandbox.py). Stripped so a
# report says "app.py", not "/work/source/app.py" — the container's layout is an
# implementation detail, and a repo-relative path is what a reader can act on.
_MOUNT = "/work/source/"

# Paths excluded from scanning. Tuned for NOISE, not coverage: every entry here is
# either not the customer's code (vendored, installed dependencies) or not code at all
# (docs, lockfiles). Measured on a real repo: 655 of its 1254 files were markdown, and
# every top-severity finding the triage agent judged turned out to be semgrep matching
# prose or JSON config — a `ws://` inside a detection-pattern string, a JWT inside a
# fenced bash block. Excluding those is free; filtering them with an LLM afterwards
# costs ~$0.04 each.
#
# Deliberately NOT excluded: test files. Test code is real code, runs in CI with real
# credentials, and a hardcoded secret there is still a leaked secret. The triage agent
# is the right place to judge whether a test finding matters.
SEMGREP_EXCLUDES = (
    "*.md", "*.rst", "*.txt", "docs", "site-packages", "node_modules",
    "vendor", "third_party", "*.lock", "*.min.js", "dist", "build", ".git",
)

# NOT `auto`, for two reasons that turn out to be the same reason.
#
# 1. `auto` is incompatible with --metrics=off. Semgrep refuses outright:
#      "Cannot create auto config when metrics are off."
#    Docket's stated position is that nothing leaves your machine except calls to the
#    target and your model provider, so metrics stay off and `auto` cannot be used.
#    Shipping both silently produced NO output while the stage still read "done".
# 2. `auto` is not reproducible — it resolves rules from the registry at scan time, so
#    the same commit can yield different findings next month with nothing recording
#    which rules ran.
#
# A named pack is pinned, defensible, and does not phone home. Override with
# DOCKET_SEMGREP_CONFIG (e.g. "p/owasp-top-ten", "p/secrets").
DEFAULT_CONFIG = "p/default"


def semgrep_config() -> str:
    return os.environ.get("DOCKET_SEMGREP_CONFIG", "").strip() or DEFAULT_CONFIG


def parse_coverage(text: str) -> dict:
    """What the scan actually looked at.

    Reported because a finding count alone cannot distinguish "your code is clean"
    from "we had no rules for your language" — and the second is the one that gets
    someone owned. semgrep already emits all of this; nothing read it until now.
    """
    try:
        doc = json.loads(text)
    except json.JSONDecodeError:
        return {}
    scanned = doc.get("paths", {}).get("scanned", []) or []
    by_ext: dict[str, int] = {}
    for path in scanned:
        ext = str(path).rsplit(".", 1)[-1] if "." in str(path) else "(none)"
        by_ext[ext] = by_ext.get(ext, 0) + 1
    errors = doc.get("errors", []) or []
    return {
        "files_scanned": len(scanned),
        "file_types": dict(sorted(by_ext.items(), key=lambda kv: -kv[1])[:8]),
        "rules_fired": sorted({
            str(r.get("check_id", "")).split(".")[0]
            for r in doc.get("results", []) if r.get("check_id")
        }),
        # Surfaced, not swallowed: a parse error means a file was NOT analysed, which
        # is a coverage hole the operator should see rather than a silent pass.
        "error_count": len(errors),
        "errors": [str(e.get("message", e))[:200] for e in errors[:5]],
    }


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


class ScannerError(RuntimeError):
    """A scanner did not run. Distinct from "ran and found nothing", which is a
    result; this is the absence of one, and reporting it as a clean pass is how a
    tool tells someone their code is fine when it was never analysed."""


def run_semgrep(sandbox: Any, run_dir: Path, *, timeout_sec: int = 120) -> list[Finding]:
    """Requires the sandbox to have been started with a source_dir mounted at
    /work/source — callers gate on that before invoking this.

    Raises ScannerError when semgrep did not produce output. It used to return [] for
    both "clean" and "crashed", which hid a broken --config/--metrics combination
    behind a green stage and 0 findings."""
    out_path = run_dir / "artifacts" / "scanners" / "semgrep.json"
    excludes = " ".join(f"--exclude={shlex.quote(e)}" for e in SEMGREP_EXCLUDES)
    command = (
        "mkdir -p /work/run/artifacts/scanners && "
        f"semgrep scan --config {shlex.quote(semgrep_config())} --json --quiet "
        f"--metrics=off {excludes} "
        "--output /work/run/artifacts/scanners/semgrep.json /work/source"
    )
    try:
        result = sandbox.call("shell", command=command, timeout_sec=timeout_sec)
    except Exception as exc:
        raise ScannerError(f"semgrep could not be started: {exc}") from exc
    if "error" in result:
        raise ScannerError(f"semgrep failed: {result['error']}")
    if not out_path.exists():
        stderr = (result.get("stderr") or result.get("stdout") or "").strip()
        raise ScannerError(f"semgrep wrote no output: {stderr[:300] or 'no diagnostics'}")
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

    # Coverage is reported so "0 findings" can be told apart from "nothing analysed".
    cov = parse_coverage(json.dumps({
        "paths": {"scanned": ["a.py", "b.py", "c.go"]},
        "results": [{"check_id": "python.lang.x"}, {"check_id": "go.lang.y"}],
        "errors": [{"message": "parse failure in c.go"}],
    }))
    assert cov["files_scanned"] == 3, cov
    assert cov["file_types"] == {"py": 2, "go": 1}, cov
    assert cov["rules_fired"] == ["go", "python"], cov
    # An error means a file was NOT analysed. Silently dropping it would report a
    # coverage hole as a clean pass.
    assert cov["error_count"] == 1 and "parse failure" in cov["errors"][0], cov
    assert parse_coverage("not json") == {}

    # Excludes must not quietly drop real code: tests are code, and a secret in a
    # test file is still a leaked secret.
    assert not any(e.startswith("test") for e in SEMGREP_EXCLUDES), SEMGREP_EXCLUDES
    assert "*.md" in SEMGREP_EXCLUDES and "node_modules" in SEMGREP_EXCLUDES
    print("scanners.semgrep: ok")


if __name__ == "__main__":
    demo()
