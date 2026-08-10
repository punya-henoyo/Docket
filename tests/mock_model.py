"""Shared test helper: a Model that plays back a scripted tool-call sequence through
the REAL Runner/tool_use_behavior/tool-execution pipeline. Only the "which tool to
call next" decision is faked — every tool call actually executes. Lets M3+/M4+ prove
the SDK harness is wired correctly without a live LLM_API_KEY. Not a test itself
(no test_ prefix) — imported by test_agent_loop_mock.py and test_multiagent_mock.py.
"""
from __future__ import annotations

import ast
import json

from agents import ModelResponse, Usage
from agents.models.interface import Model
from openai.types.responses import ResponseFunctionToolCall


class ScriptedModel(Model):
    """Plays back a fixed list of (tool_name, args_or_args_fn) calls. `args_fn`, if
    callable, receives {call_id: parsed_tool_output} collected from the conversation
    so far — lets a later step reference an earlier step's real result (e.g.
    finish_scan referencing the finding_id a `finding` call actually returned)."""

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
