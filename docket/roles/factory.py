"""Builds SDK Agent objects: LiteLLM model wiring, per-role tool list, and the
tool_use_behavior gate that stops the loop only via a dedicated finish tool.

Root's coordination tools (create_agent/wait_for_agents/view_agent_graph, in
graph_tools.py) are NOT imported here — graph_tools.py imports build_agent (to
construct the children it spawns), so importing it back here would cycle. The caller
(scan.py) passes those tools in via extra_tools instead.
"""
from __future__ import annotations

import asyncio
from typing import Literal

from agents import Agent, FunctionToolResult, RunContextWrapper, Tool, ToolsToFinalOutputResult, function_tool
from agents.extensions.models.litellm_model import LitellmModel
from agents.models.interface import Model

from docket.config import Config
from docket.core.execution import ScanContext
from docket.roles.lifecycle import AgentFinalOutput, agent_finish, finish_scan
from docket.roles.prompts.root import SYSTEM_PROMPT as ROOT_SYSTEM_PROMPT
from docket.roles.prompts.specialist import SYSTEM_PROMPT as SPECIALIST_SYSTEM_PROMPT
from docket.tools.finding import FindingType, register_finding
from docket.tools.http_request import do_http_request

Role = Literal["root", "sqli", "cmdi", "xss"]
SpecialistRole = Literal["sqli", "cmdi", "xss"]

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
    # do_http_request is synchronous urllib — run it off-thread so one agent's
    # blocking call (e.g. the deliberate 3s timing probe for blind command
    # injection) can't freeze the event loop for every other concurrently running
    # agent. Without this, "multi-agent" would be multi-agent in name only.
    return await asyncio.to_thread(
        do_http_request, method, url, ctx.context.run_dir,
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


def build_agent(
    role: Role,
    config: Config,
    *,
    extra_tools: list[Tool] | None = None,
    model: Model | None = None,
) -> Agent[ScanContext]:
    """`model`, if given, overrides the real LitellmModel — used by tests to script a
    child agent's decisions (see ScanContext.model_override in core/execution.py)."""
    if role == "root":
        instructions = ROOT_SYSTEM_PROMPT
        finish_tool = finish_scan
        name = "docket-root"
        base_tools: list[Tool] = [http_request]  # root delegates; it doesn't call `finding` itself
    elif role in ("sqli", "cmdi", "xss"):
        instructions = SPECIALIST_SYSTEM_PROMPT
        finish_tool = agent_finish
        name = f"docket-{role}"
        base_tools = [http_request, finding]
    else:
        raise ValueError(f"unknown role: {role!r}")

    return Agent[ScanContext](
        name=name,
        instructions=instructions,
        tools=[*base_tools, *(extra_tools or []), finish_tool],
        model=model or LitellmModel(model=config.llm, api_key=config.llm_api_key),
        tool_use_behavior=_finish_tool_use_behavior,
        output_type=AgentFinalOutput,
    )
