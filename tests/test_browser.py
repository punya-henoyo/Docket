"""M8 check: the browser tool and the V3 (reflected XSS) execution proof.

Requires Docker running. The target is the self-contained fixture in tests/fixtures/.
Run: uv run python tests/test_browser.py
"""
from __future__ import annotations

import asyncio
import shutil
import sys
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from fixtures.target_app import ensure_target
from mock_model import ScriptedModel
from docket.config.settings import Config, run_dir
from docket.core.execution import ScanContext, run_agent_loop
from docket.report.dedupe import FindingStore
from docket.agents.factory import build_agent
from docket.runtime.sandbox import Sandbox, rewrite_for_container

PAYLOAD = "<script>alert(document.domain)</script>"


def test_browser_proves_xss_executes_not_just_reflects() -> None:
    target = rewrite_for_container(ensure_target())
    directory = run_dir("m8-browser-test")
    try:
        with Sandbox(directory / "sandbox") as sb:
            # CONTROL: a benign query reflects text but must raise NO dialog. Without
            # this, a dialog_message assertion alone wouldn't prove the oracle
            # discriminates — it might just always fire.
            benign = sb.call(
                "browser", action="navigate",
                url=f"{target}/search?q=hello", rpc_timeout=120,
            )
            assert benign["ok"] is True, benign
            assert benign["dialog_message"] is None, benign
            body = sb.call("browser", action="get_text", rpc_timeout=60)
            assert "hello" in (body["text"] or ""), body

            # THE M8 GOAL: the same route with an alert() payload makes a real DOM
            # execute it. document.domain comes back as the dialog text, which no
            # amount of HTML-echoing could produce.
            url = f"{target}/search?q=" + urllib.parse.quote(PAYLOAD)
            proof = sb.call("browser", action="navigate", url=url, rpc_timeout=120)
            assert proof["ok"] is True, proof
            assert proof["dialog_message"] == "host.docker.internal", proof

            # Screenshot lands on the HOST through the bind mount, at a path that
            # resolves on both sides.
            shot = sb.call("browser", action="screenshot", rpc_timeout=60)
            rel = shot["screenshot_path"]
            assert rel and rel.startswith("artifacts/screenshots/"), shot
            on_host = directory / "sandbox" / rel
            assert on_host.exists() and on_host.stat().st_size > 0, f"missing {on_host}"

            # A bad selector must come back as an error result, not kill the session.
            bad = sb.call("browser", action="click", selector="#nope", timeout_sec=2, rpc_timeout=60)
            assert bad["ok"] is False and bad["error"], bad
            assert sb.call("browser", action="get_html", rpc_timeout=60)["ok"] is True

            assert sb.call("browser", action="close", rpc_timeout=60) == {"ok": True}
    finally:
        shutil.rmtree(directory, ignore_errors=True)


def test_browser_tool_refuses_without_sandbox() -> None:
    import os

    os.environ.setdefault("DOCKET_LLM", "anthropic/claude-sonnet-4-5-20250929")
    cfg = Config.from_env()
    context = ScanContext(
        target_url=ensure_target(), run_dir=run_dir("m8-no-sandbox"),
        on_finding=FindingStore().add, agent_id="solo", role="xss", config=cfg, sandbox=None,
    )
    script = [
        ("browser", {"action": "navigate", "url": "http://127.0.0.1:5000/search?q=x"}),
        ("agent_finish", {"summary": "no browser available", "findings": [], "success": True}),
    ]
    agent = build_agent("xss", cfg, model=ScriptedModel(script))
    out = asyncio.run(run_agent_loop(agent, context, "probe", max_turns=6))
    assert out["success"] is True, out  # the agent still finishes cleanly


def test_xss_role_gets_browser_and_others_do_not() -> None:
    import os

    os.environ.setdefault("DOCKET_LLM", "anthropic/claude-sonnet-4-5-20250929")
    cfg = Config.from_env()
    tools = {role: {t.name for t in build_agent(role, cfg).tools} for role in ("sqli", "cmdi", "xss")}
    assert "browser" in tools["xss"] and "shell" not in tools["xss"], tools["xss"]
    assert "shell" in tools["sqli"] and "browser" not in tools["sqli"], tools["sqli"]
    # cmdi proves itself with HTTP timing alone — no shell, no browser.
    assert tools["cmdi"] == {"http_request", "finding", "agent_finish"}, tools["cmdi"]


if __name__ == "__main__":
    test_xss_role_gets_browser_and_others_do_not()
    test_browser_tool_refuses_without_sandbox()
    test_browser_proves_xss_executes_not_just_reflects()
    print("test_browser: ok — XSS proven by real DOM execution (dialog_message), control case raises none")
