"""R8 check: the web viewer renders a REAL scan's data.

Runs a scripted 4-agent scan (no LLM key needed), then serves the resulting run
directory and asserts the dashboard's API returns the agent graph, findings with PoC
evidence, transcript, and SARIF — the same data the TUI projects, proving both
front-ends read one source.

Run: uv run python tests/test_viewer.py
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import threading
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_multiagent_mock import _model_override  # noqa: E402
from test_multiagent_mock import TARGET  # noqa: E402

from docket.config.settings import Config, run_dir
from docket.core.runner import run_scan
from docket.interface.viewer.server import start_server
from docket.report.dedupe import FindingStore
from docket.report.writer import write_report

RUN_NAME = "r8-viewer-test"


def test_viewer_serves_a_real_run() -> None:
    os.environ.setdefault("DOCKET_LLM", "anthropic/claude-sonnet-4-5-20250929")
    directory = run_dir(RUN_NAME)
    store = FindingStore()
    try:
        result = run_scan(
            TARGET, on_finding=store.add, config=Config.from_env(), run_name=RUN_NAME,
            model_override=_model_override, use_sandbox=False, store=store,
        )
        write_report(store, directory, run_name=RUN_NAME, target=TARGET,
                     summary=result.summary, cost_usd=result.cost_usd,
                     agents_spawned=result.agents_spawned, success=result.success)

        server = start_server(directory, port=0)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        base = f"http://127.0.0.1:{server.server_address[1]}"
        try:
            page = urllib.request.urlopen(base + "/", timeout=5).read().decode()
            assert "<title>docket" in page
            # No pricing / upgrade / account funnel anywhere in the UI.
            lowered = page.lower()
            for banned in ("pricing", "upgrade", "subscribe", "sign in", "log in", "free trial"):
                assert banned not in lowered, f"found commercial UI text: {banned!r}"

            data = json.loads(urllib.request.urlopen(base + "/api/run", timeout=5).read())
            assert data["run_name"] == RUN_NAME
            assert data["finished"] is True
            assert data["finding_count"] == 3, data["finding_count"]
            assert data["severity_counts"] == {
                "critical": 1, "high": 1, "medium": 1, "low": 0, "info": 0,
            }, data["severity_counts"]

            # Agent graph: root plus three specialists, root first and nested.
            agents = data["agents"]
            assert len(agents) == 4, agents
            assert agents[0]["agent_id"] == "root" and agents[0]["depth"] == 0
            assert {a["role"] for a in agents} == {"root", "sqli", "cmdi", "xss"}
            assert all(a["depth"] == 1 for a in agents[1:]), agents

            # Findings carry the validated PoC evidence, not just a label.
            rules = {f["rule_id"] for f in data["findings"]}
            assert rules == {"sql-injection", "command-injection", "reflected-xss"}, rules
            for finding in data["findings"]:
                assert finding["poc"]["request"].strip()
                assert finding["poc"]["response"].strip()

            assert len(data["transcript"]) > 0
            assert data["has_sarif"] is True
            sarif = json.loads(urllib.request.urlopen(base + "/report.sarif", timeout=5).read())
            assert sarif["version"] == "2.1.0"
            assert len(sarif["runs"][0]["results"]) == 3

            # Traversal out of the run directory must not be possible.
            try:
                urllib.request.urlopen(base + "/artifacts/../../../../etc/passwd", timeout=5)
                raise AssertionError("traversal should 404")
            except urllib.error.HTTPError as exc:
                assert exc.code == 404
        finally:
            server.shutdown()
    finally:
        shutil.rmtree(directory, ignore_errors=True)


if __name__ == "__main__":
    test_viewer_serves_a_real_run()
    print("test_viewer: ok — dashboard serves a real run's graph, findings, PoCs and SARIF")
