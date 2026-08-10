"""M3 harness check WITHOUT a live LLM: a ScriptedModel plays back a fixed tool-call
sequence through the REAL Runner / tool_use_behavior / tool-execution pipeline (only
the model's next-tool-call *decision* is faked — every tool call it makes actually
executes: real HTTP requests against a live vulnshop, real Finding registration).

This proves the SDK integration itself is wired correctly: multi-turn tool-calling
loop, conversation-history threading (a later step reads an earlier tool's real
output), and the tool_use_behavior gate stopping only on finish_scan. It does NOT
prove a real model can reason its way to these tool calls unprompted — that half
needs a live LLM_API_KEY (see docket/.env / README).

Run: uv run python tests/test_agent_loop_mock.py  (vulnshop must be running at :5000)
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from agents import Agent

from mock_model import ScriptedModel
from docket.roles.factory import _finish_tool_use_behavior, finding, http_request
from docket.roles.lifecycle import AgentFinalOutput, finish_scan
from docket.roles.prompts.root import SYSTEM_PROMPT
from docket.core.execution import ScanContext, run_agent_loop
from docket.report.dedupe import FindingStore

TARGET = "http://127.0.0.1:5000"


def _script() -> list[tuple[str, dict]]:
    """V1 (SQLi auth-bypass) + V2 (blind command-injection via timing) end-to-end,
    then finish_scan referencing the real finding_ids the `finding` tool returned."""
    return [
        ("http_request", {
            "method": "POST", "url": f"{TARGET}/login",
            "data": {"username": "admin' -- ", "password": "wrong"},
        }),
        ("http_request", {"method": "GET", "url": f"{TARGET}/export", "params": {"file": "report.csv"}}),
        ("http_request", {"method": "GET", "url": f"{TARGET}/export", "params": {"file": "report.csv; sleep 3"}}),
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
        ("finish_scan", lambda outputs: {
            "summary": "Confirmed SQLi on /login and blind command injection on /export.",
            "findings": [o["finding_id"] for o in outputs.values() if isinstance(o, dict) and "finding_id" in o],
            "success": True,
        }),
    ]


def test_scripted_agent_loop_end_to_end() -> None:
    store = FindingStore()
    context = ScanContext(target_url=TARGET, run_dir=Path("docket_runs") / "mock-test", on_finding=store.add)
    agent = Agent[ScanContext](
        name="docket-root-mock",
        instructions=SYSTEM_PROMPT,
        tools=[http_request, finding, finish_scan],
        model=ScriptedModel(_script()),
        tool_use_behavior=_finish_tool_use_behavior,
        output_type=AgentFinalOutput,
    )

    output = asyncio.run(run_agent_loop(agent, context, "Begin testing.", max_turns=10))

    assert output["success"] is True
    assert len(output["findings"]) == 2, output  # both finding_ids landed in finish_scan
    assert len(store) == 2
    assert {f.rule_id for f in store.findings()} == {"sql-injection", "command-injection"}
    for f in store.findings():
        assert f.poc.request.strip() and f.poc.response.strip()


if __name__ == "__main__":
    test_scripted_agent_loop_end_to_end()
    print("test_agent_loop_mock: ok — Runner/tool_use_behavior/tool-execution harness verified (model reasoning still unverified, needs a live key)")
