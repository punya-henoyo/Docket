"""Getting static findings in: ingest first, run second.

Same ladder logic as discovery. The cheapest and most authoritative source is a SARIF
file the team's CI already produces — no engine to install, no version to pin, and it
works with whatever they standardised on (Semgrep, CodeQL, Bandit, gosec). Running
Semgrep ourselves is the fallback for a laptop with no CI artifact to hand.

Semgrep is NOT a project dependency. It is heavy, it is not needed by anything else here,
and a team that wants SAST almost always has it already. If it is absent we say so
plainly rather than silently producing zero findings, which would read as "your code is
clean".
"""
from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import replace
from pathlib import Path

from docket.static.models import StaticReport, parse_sarif

# p/default is Semgrep's curated cross-language ruleset. NOT --config=auto, which refuses
# to run with metrics off ("Cannot create auto config when metrics are off") — and metrics
# stay off because docket does not ship telemetry and will not add someone else's (see
# AGENTS.md rule 6). Fetching rules is an outbound call the operator opted into by passing
# --source; reporting usage back is not.
#
# Not p/security-audit either: measured on the bundled fixture's source, security-audit
# found 1 candidate where p/default found 12 and covered all three vulnerability classes.
SEMGREP_ARGS = ("--config=p/default", "--sarif", "--quiet", "--no-git-ignore",
                "--timeout", "0", "--metrics=off")


def ingest_sarif_file(path: str | Path) -> StaticReport:
    """Read a SARIF document produced by any SAST tool."""
    try:
        document = json.loads(Path(path).read_text())
    except (OSError, json.JSONDecodeError) as exc:
        report = StaticReport()
        report.notes.append(f"could not read SARIF from {path}: {type(exc).__name__}")
        return report
    if not isinstance(document, dict):
        report = StaticReport()
        report.notes.append(f"{path} is not a SARIF document")
        return report
    report = parse_sarif(document)
    report.notes.append(f"ingested {len(report)} finding(s) from {path}")
    return report


def semgrep_available() -> str | None:
    """Path to a usable semgrep, or None. Checks a real binary first, then uvx, which can
    run it without installing anything into this project."""
    if (found := shutil.which("semgrep")):
        return found
    if shutil.which("uvx"):
        return "uvx"
    return None


def run_semgrep(source_root: str | Path, *, timeout_sec: int = 600) -> StaticReport:
    """Run Semgrep over a source tree and parse its SARIF.

    Emits nothing to the network beyond Semgrep's own rule fetch (`--metrics=off` stops
    its telemetry). Non-zero exit is normal: Semgrep exits 1 when it finds something.
    """
    report = StaticReport()
    root = Path(source_root)
    if not root.is_dir():
        report.notes.append(f"source path is not a directory: {source_root}")
        return report

    binary = semgrep_available()
    if binary is None:
        report.notes.append(
            "semgrep is not installed, so no static analysis ran. This is NOT a clean "
            "result. Install it (`uv tool install semgrep`) or pass --sarif with a "
            "report from your CI."
        )
        return report

    argv = ([binary, *SEMGREP_ARGS, str(root)] if binary != "uvx"
            else ["uvx", "semgrep", *SEMGREP_ARGS, str(root)])
    try:
        completed = subprocess.run(argv, capture_output=True, text=True, timeout=timeout_sec)
    except subprocess.TimeoutExpired:
        report.notes.append(f"semgrep timed out after {timeout_sec}s; no static findings")
        return report
    except OSError as exc:
        report.notes.append(f"could not start semgrep: {exc}")
        return report

    if not completed.stdout.strip():
        tail = (completed.stderr or "").strip().splitlines()[-1:] or ["no output"]
        report.notes.append(f"semgrep produced no SARIF: {tail[0][:200]}")
        return report
    try:
        document = json.loads(completed.stdout)
    except json.JSONDecodeError:
        report.notes.append("semgrep output was not valid JSON")
        return report

    parsed = parse_sarif(document, engine="semgrep")
    # Semgrep reports paths absolute or relative to cwd. Rebase onto the source root so
    # they match what correlate.py opens and what a human recognises in a report.
    rebased = StaticReport(engines=parsed.engines)
    for finding in parsed.findings:
        rebased.add(replace(finding, file=_relative_to(finding.file, root)))
    rebased.notes.append(f"semgrep found {len(rebased)} candidate(s) in {root}")
    return rebased


def _relative_to(file: str, root: Path) -> str:
    """Best-effort rebase. parse_sarif strips the leading "/" off a file:// URI, so try
    both the stripped and restored forms before giving up and keeping what we were given."""
    resolved_root = root.resolve()
    for candidate in (Path(file), Path("/" + file)):
        try:
            return str(candidate.resolve().relative_to(resolved_root))
        except (ValueError, OSError):
            continue
    return file


def collect(
    *, sarif_path: str | Path | None = None, source_root: str | Path | None = None,
) -> StaticReport:
    """The ladder: a supplied SARIF wins; otherwise run Semgrep if we have a source tree."""
    if sarif_path:
        report = ingest_sarif_file(sarif_path)
        if len(report):
            return report
        if not source_root:
            return report
    if source_root:
        return run_semgrep(source_root)
    return StaticReport(notes=["no --sarif and no --source, so no static analysis ran"])


def demo() -> None:
    import shutil as sh
    import tempfile

    tmp = Path(tempfile.mkdtemp())
    try:
        # --- ingest -------------------------------------------------------------------
        sarif = tmp / "semgrep.sarif"
        sarif.write_text(json.dumps({"runs": [{
            "tool": {"driver": {"name": "semgrep", "rules": [
                {"id": "sqli", "properties": {"tags": ["cwe-89"]}}]}},
            "results": [{"ruleId": "sqli", "level": "error",
                          "message": {"text": "sqli"},
                          "locations": [{"physicalLocation": {
                              "artifactLocation": {"uri": "app.py"},
                              "region": {"startLine": 34}}}]}]}]}))
        report = ingest_sarif_file(sarif)
        assert len(report) == 1 and report.findings[0].cwe == "CWE-89"
        assert any("ingested 1" in n for n in report.notes)

        # A missing or corrupt file is REPORTED, never silently zero — "no findings" and
        # "we could not look" must not be indistinguishable in a security report.
        missing = ingest_sarif_file(tmp / "nope.sarif")
        assert len(missing) == 0 and any("could not read" in n for n in missing.notes)
        (tmp / "bad.sarif").write_text("{not json")
        assert any("could not read" in n for n in ingest_sarif_file(tmp / "bad.sarif").notes)
        (tmp / "list.sarif").write_text("[]")
        assert any("not a SARIF" in n for n in ingest_sarif_file(tmp / "list.sarif").notes)

        # --- run ----------------------------------------------------------------------
        bad_root = run_semgrep(tmp / "does-not-exist")
        assert any("not a directory" in n for n in bad_root.notes)

        # --- the ladder ---------------------------------------------------------------
        assert len(collect(sarif_path=sarif)) == 1
        none_at_all = collect()
        assert len(none_at_all) == 0
        assert any("no --sarif and no --source" in n for n in none_at_all.notes)
        # An empty SARIF plus a source root falls through to running an engine.
        (tmp / "empty.sarif").write_text(json.dumps({"runs": []}))
        fell_through = collect(sarif_path=tmp / "empty.sarif", source_root=tmp)
        assert fell_through.notes, "falling through must leave a trace of why"
    finally:
        sh.rmtree(tmp, ignore_errors=True)
    print("static.engines: ok")


if __name__ == "__main__":
    demo()
