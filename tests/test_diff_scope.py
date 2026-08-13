"""Diff scoping: --changed-files narrows what a PR check reports, and never widens it.

The rule under test is strix's, quoted in its CI skill: "Fail loudly rather than silently
narrowing scope". The inverse is just as important here — an unreadable scope file that got
treated as "no scope" would quietly report a whole-repo scan as a PR result.

No pytest: plain asserts. Run: uv run python tests/test_diff_scope.py
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from docket.core.runner import apply_diff_scope, load_diff_scope, run_scan
from docket.static.engines import collect as collect_static
from docket.static.models import StaticFinding, StaticReport


def three_findings() -> StaticReport:
    """One candidate each in three different files. Only app.py is ever "changed"."""
    report = StaticReport()
    report.add(StaticFinding("sqli", "user input in query", "app.py", 31, "high", "CWE-89"))
    report.add(StaticFinding("cmdi", "os.system", "legacy/old.py", 12, "high", "CWE-78"))
    report.add(StaticFinding("xss", "unescaped render", "vendor/lib.py", 88, "medium"))
    return report


def test_scope_of_one_file_suppresses_the_other_two() -> None:
    static = three_findings()
    suppressed = apply_diff_scope(static, {"app.py"})
    assert len(static.findings) == 1, [f.key for f in static.findings]
    assert static.findings[0].file == "app.py"
    assert suppressed == 2
    # The count is stated in the report's notes, not just returned: a filtered lead list
    # that does not say it was filtered reads as a clean scan of the whole repo.
    assert any("2 suppressed" in note for note in static.notes), static.notes


def test_missing_scope_file_raises() -> None:
    tmp = Path(tempfile.mkdtemp())
    try:
        try:
            load_diff_scope(tmp / "no-such-file.txt")
            raise AssertionError("a missing --changed-files must RAISE, never widen scope")
        except OSError:
            pass
        # A directory is unreadable in the same way, and must fail the same way.
        try:
            load_diff_scope(tmp)
            raise AssertionError("an unreadable --changed-files must RAISE")
        except OSError:
            pass
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_empty_scope_file_yields_zero_not_everything() -> None:
    tmp = Path(tempfile.mkdtemp())
    try:
        empty = tmp / "changed.txt"
        empty.write_text("")
        assert load_diff_scope(empty) == set()
        static = three_findings()
        suppressed = apply_diff_scope(static, load_diff_scope(empty))
        # "The PR changed nothing scannable" means ZERO leads. Falling back to all three
        # would report findings the PR did not touch as though it introduced them.
        assert static.findings == [] and suppressed == 3

        # Blank lines and "./" prefixes are noise, not scope entries.
        whitespace = tmp / "ws.txt"
        whitespace.write_text("\n  \n./app.py\n/legacy/old.py\n\n")
        assert load_diff_scope(whitespace) == {"app.py", "legacy/old.py"}
        scoped = three_findings()
        assert apply_diff_scope(scoped, load_diff_scope(whitespace)) == 1
        assert {f.file for f in scoped.findings} == {"app.py", "legacy/old.py"}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_filter_still_applies_after_the_empty_sarif_fall_through() -> None:
    """static/engines.py:collect() falls through to a WHOLE-TREE semgrep run when a
    supplied --sarif parses to zero findings. That is verified here, because it is the
    path that could turn a PR check into a full-repo scan — and the filter has to bite
    after it, which is exactly why it is post-hoc rather than in semgrep's argv."""
    tmp = Path(tempfile.mkdtemp())
    try:
        (tmp / "empty.sarif").write_text(json.dumps({"runs": []}))
        (tmp / "app.py").write_text("import os\nos.system(input())\n")
        report = collect_static(sarif_path=tmp / "empty.sarif", source_root=tmp)
        # The fall-through happened: the report is talking about semgrep, not about the
        # SARIF it was handed. (Whether semgrep is installed only changes the note.)
        assert report.notes and any("semgrep" in n for n in report.notes), report.notes
        # Whatever came back out of the whole-tree run, only in-scope files survive.
        report.add(StaticFinding("planted", "outside the diff", "vendor/lib.py", 3, "high"))
        suppressed = apply_diff_scope(report, {"app.py"})
        assert suppressed >= 1
        assert all(f.file == "app.py" for f in report.findings), [f.file for f in report.findings]
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_run_scan_reports_the_suppressed_count() -> None:
    """End to end through run_scan, with no Docker, no LLM key and no live target:
    --static-only + --sarif exercises the real code path a PR gate uses."""
    tmp = Path(tempfile.mkdtemp())
    cwd = Path.cwd()
    try:
        os.chdir(tmp)                     # docket_runs/ lands in the temp dir, not the repo
        sarif = tmp / "ci.sarif"
        sarif.write_text(json.dumps({"runs": [{
            "tool": {"driver": {"name": "semgrep", "rules": [{"id": "sqli"}]}},
            "results": [
                {"ruleId": "sqli", "level": "error", "message": {"text": "in the diff"},
                 "locations": [{"physicalLocation": {
                     "artifactLocation": {"uri": "app.py"}, "region": {"startLine": 31}}}]},
                {"ruleId": "sqli", "level": "error", "message": {"text": "not in the diff"},
                 "locations": [{"physicalLocation": {
                     "artifactLocation": {"uri": "legacy/old.py"},
                     "region": {"startLine": 12}}}]},
            ]}]}))
        changed = tmp / "changed.txt"
        changed.write_text("app.py\n")

        result = run_scan(
            None, run_name="diff-scope-test", use_sandbox=False, static_only=True,
            discovery=False, sarif_path=str(sarif), changed_files=str(changed),
        )
        assert result.suppressed_outside_diff == 1
        assert len(result.leads) == 1
        assert result.leads[0].finding.file == "app.py"
        static_json = json.loads((tmp / "docket_runs" / "diff-scope-test"
                                  / "static.json").read_text())
        assert static_json["finding_count"] == 1
        assert any("suppressed" in n for n in static_json["notes"]), static_json["notes"]

        # And the raising case survives the trip through run_scan: no partial run, no
        # report, no exit code that could be read as a pass.
        try:
            run_scan(None, run_name="diff-scope-missing", use_sandbox=False,
                     static_only=True, discovery=False, sarif_path=str(sarif),
                     changed_files=str(tmp / "gone.txt"))
            raise AssertionError("run_scan must raise on an unreadable --changed-files")
        except OSError:
            pass
    finally:
        os.chdir(cwd)
        shutil.rmtree(tmp, ignore_errors=True)


def test_a_store_with_no_sink_never_silently_swallows_findings() -> None:
    """A scan handed a store must not report zero findings when the scanner found some.

    THE BUG THIS EXISTS TO CATCH, measured on kaizenmantra/vulnshop#20:
    connect.py:_scan_for_pr called run_scan with `store=store` and `on_finding=None`.
    Semgrep ran inside the container and found 17 hits including the SQL injection the
    pull request introduced (app.py:64 and app.py:66); `_run_scanner_prescans` dropped
    every one of them at `if on_finding is not None`. report.json said finding_count 0,
    report/diff.diff_runs reads `findings[]`, and the verdict came back "No new findings",
    exit_code 0 — a green PR check over a live SQL injection docket had already found.
    It fails SILENTLY, which is what makes it worth a test: the coverage block still said
    one file scanned and zero errors, so nothing on screen looked wrong.

    Docker-free: the Sandbox is replaced with a stub, so this exercises the wiring
    (does what the scanner produced reach the store?) and nothing else.
    """
    from docket.core import runner
    from docket.report.dedupe import FindingStore
    from docket.report.models import Finding, Location, PoC, Severity

    def lead(rule: str, line: int) -> Finding:
        return Finding(
            rule_id=f"semgrep/{rule}", title=f"{rule} in app.py", severity=Severity.HIGH,
            location=Location(method="STATIC", path="app.py", source_file=f"app.py:{line}"),
            description="static", poc=PoC(request=f"line {line}", response="match"),
            discovered_by="semgrep",
        )

    class StubSandbox:
        """Enough of runtime.Sandbox for run_scan; starts no container."""

        def __init__(self, run_dir, source_dir=None):
            self.run_dir, self.source_dir = Path(run_dir), source_dir

        def start(self):
            self.run_dir.mkdir(parents=True, exist_ok=True)

        def stop(self):
            pass

    def fake_prescans(sandbox, target_url, run_dir_, on_finding, on_stage=None, **kw):
        # Exactly what the real one does with what a scanner produced.
        for finding in (lead("sqli", 64), lead("tainted-sql-string", 66)):
            if on_finding is not None:
                on_finding(finding)

    tmp = Path(tempfile.mkdtemp())
    cwd = Path.cwd()
    real_sandbox, real_prescans = runner.Sandbox, runner._run_scanner_prescans
    try:
        os.chdir(tmp)
        (tmp / "src").mkdir()
        (tmp / "src" / "app.py").write_text("x = 1\n")
        runner.Sandbox, runner._run_scanner_prescans = StubSandbox, fake_prescans

        # on_finding OMITTED — the exact shape _scan_for_pr used.
        store = FindingStore()
        runner.run_scan(None, run_name="sink-default", use_sandbox=True, static_only=True,
                        discovery=False, store=store, whitebox_path=str(tmp / "src"))
        assert len(store.findings()) == 2, (
            "a store passed to run_scan must receive scanner findings even when the "
            f"caller omits on_finding; got {len(store.findings())}"
        )

        # An EXPLICIT sink still wins, and is not called twice.
        seen: list = []
        store2 = FindingStore()
        runner.run_scan(None, run_name="sink-explicit", use_sandbox=True, static_only=True,
                        discovery=False, store=store2, whitebox_path=str(tmp / "src"),
                        on_finding=lambda f: (seen.append(f), store2.add(f))[0])
        assert len(seen) == 2, seen
        assert len(store2.findings()) == 2, store2.findings()
        # Nothing corroborates itself: a double add would append a finding's own PoC to
        # its own corroborating_evidence, which is what the removed recon store.add did.
        assert all(not f.corroborating_evidence for f in store2.findings()), \
            "a finding was added to the store twice"
    finally:
        runner.Sandbox, runner._run_scanner_prescans = real_sandbox, real_prescans
        os.chdir(cwd)
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    test_scope_of_one_file_suppresses_the_other_two()
    test_missing_scope_file_raises()
    test_empty_scope_file_yields_zero_not_everything()
    test_filter_still_applies_after_the_empty_sarif_fall_through()
    test_run_scan_reports_the_suppressed_count()
    test_a_store_with_no_sink_never_silently_swallows_findings()
    print("test_diff_scope: ok")
