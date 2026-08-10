"""Builds SDK Agent objects: LiteLLM model wiring, per-role tool list, and the
tool_use_behavior gate that stops the loop only via a dedicated finish tool.

M3 scope: only the "root" role exists (single generalist agent, tests every route
itself). M4 adds sqli/cmdi/xss specialist roles with narrower tool lists and swaps
`finish_scan` for `agent_finish` on non-root agents.
"""
from __future__ import annotations

from typing import Literal

from agents import Agent, FunctionToolResult, RunContextWrapper, ToolsToFinalOutputResult, function_tool
from agents.extensions.models.litellm_model import LitellmModel

from docket.roles.lifecycle import AgentFinalOutput, finish_scan
from docket.roles.prompts.root import SYSTEM_PROMPT
from docket.config import Config
from docket.core.execution import ScanContext
from docket.tools.finding import FindingType, register_finding
from docket.tools.http_request import do_http_request

Role = Literal["root"]

_FINISH_TOOL_NAMES = {"finish_scan", "agent_finish"}


@function_tool(strict_mode=False)  # headers/params/data are open-ended dicts — strict
# JSON schema mode can't represent those (it requires enumerated properties).
async def http_request(
    ctx: RunContextWrapper[ScanContext],
    method: str,
    url: str,
    headers: dict | None = None,
    params: dict | None = None,
    data: dict | None = None,
    timeout_sec: int = 15,
) -> dict:
    """Send a raw HTTP request to the target and return status/headers/body/timing.
    `data` as an object is form-urlencoded, matching how Flask reads request.form."""
    return do_http_request(
        method, url, ctx.context.run_dir,
        headers=headers, params=params, data=data, timeout_sec=timeout_sec,
    )


@function_tool(strict_mode=False)  # location/poc are open-ended dicts, same reason
async def finding(
    ctx: RunContextWrapper[ScanContext],
    rule_type: FindingType,
    severity: Literal["critical", "high", "medium", "low", "info"],
    title: str,
    description: str,
    location: dict,
    poc: dict,
) -> dict:
    """Register a CONFIRMED vulnerability. poc.request and poc.response_excerpt must
    contain real, reproduced evidence you actually observed — never call this on a
    hunch or before you've tried the exploit."""
    return register_finding(
        rule_type=rule_type, severity=severity, title=title, description=description,
        location=location, poc=poc, discovered_by=ctx.context.role,
        run_dir=ctx.context.run_dir, on_finding=ctx.context.on_finding,
    )


async def _finish_tool_use_behavior(
    ctx: RunContextWrapper[ScanContext], results: list[FunctionToolResult],
) -> ToolsToFinalOutputResult:
    """The loop only ends when the model calls a dedicated finish tool — enforced
    structurally here, not by asking nicely in the prompt."""
    last = results[-1]
    if last.tool.name in _FINISH_TOOL_NAMES and isinstance(last.output, dict):
        return ToolsToFinalOutputResult(is_final_output=True, final_output=last.output)
    return ToolsToFinalOutputResult(is_final_output=False, final_output=None)


def build_agent(role: Role, config: Config) -> Agent[ScanContext]:
    if role != "root":
        raise NotImplementedError(f"role={role!r} lands in M4 (sqli/cmdi/xss specialists)")
    return Agent[ScanContext](
        name="docket-root",
        instructions=SYSTEM_PROMPT,
        tools=[http_request, finding, finish_scan],
        model=LitellmModel(model=config.llm, api_key=config.llm_api_key),
        tool_use_behavior=_finish_tool_use_behavior,
        output_type=AgentFinalOutput,  # non-str output_type — see AgentFinalOutput's docstring
    )
