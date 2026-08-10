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

import ast
import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agents import Agent, ModelResponse, Usage
from agents.models.interface import Model
from openai.types.responses import ResponseFunctionToolCall

from docket.roles.factory import _finish_tool_use_behavior, finding, http_request
from docket.roles.lifecycle import AgentFinalOutput, finish_scan
from docket.roles.prompts.root import SYSTEM_PROMPT
from docket.core.execution import ScanContext, run_agent_loop
from docket.report.dedupe import FindingStore

TARGET = "http://127.0.0.1:5000"


class ScriptedModel(Model):
    """Plays back a fixed list of (tool_name, args_or_args_fn) calls. `args_fn`, if
    callable, receives {call_id: parsed_tool_output} collected from the conversation
    so far — lets a later step (finish_scan) reference an earlier step's real result
    (e.g. the finding_id a `finding` call actually returned)."""

    def __init__(self, script: list[tuple[str, dict | callable]]) -> None:
        self._script = script
        self._step = 0

    @staticmethod
    def _tool_outputs(input_items) -> dict[str, dict]:
        """The SDK stores each tool's raw Python return value in conversation history
        as `repr(value)` (single-quoted, `True`/`None`), not JSON — confirmed by
        inspecting live `function_call_output` items. `ast.literal_eval` parses that;
        `json.loads` silently fails on every one of them."""
        outputs: dict[str, dict] = {}
        if not isinstance(input_items, list):
            return outputs
        for item in input_items:
            if isinstance(item, dict) and item.get("type") == "function_call_output":
                try:
                    outputs[item["call_id"]] = ast.literal_eval(item["output"])
                except (KeyError, TypeError, ValueError, SyntaxError):
                    pass
        return outputs

    async def get_response(self, system_instructions, input, model_settings, tools,
                            output_schema, handoffs, tracing, *, previous_response_id,
                            conversation_id, prompt) -> ModelResponse:
        if self._step >= len(self._script):
            raise RuntimeError(f"ScriptedModel: script exhausted at step {self._step}")
        name, args_or_fn = self._script[self._step]
        outputs = self._tool_outputs(input)
        args = args_or_fn(outputs) if callable(args_or_fn) else args_or_fn
        self._step += 1
        call = ResponseFunctionToolCall(
            type="function_call", call_id=f"call_{self._step}", name=name,
            arguments=json.dumps(args), id=f"fc_{self._step}",
        )
        return ModelResponse(output=[call], usage=Usage(), response_id=f"resp_{self._step}", request_id=None)

    async def stream_response(self, *args, **kwargs):
        raise NotImplementedError("ScriptedModel is non-streaming only")
        yield  # pragma: no cover — makes this a valid async generator signature

    def get_retry_advice(self, request):
        return None

    async def close(self) -> None:
        return None


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
