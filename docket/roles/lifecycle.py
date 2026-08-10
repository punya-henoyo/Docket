"""The only tools that can end an agent's turn (enforced by the tool_use_behavior gate
in factory.py, not by prompt discipline) — no free-form stopping.
"""
from __future__ import annotations

from agents import RunContextWrapper, function_tool
from pydantic import BaseModel

from docket.core.execution import ScanContext


class AgentFinalOutput(BaseModel):
    """Shape returned by finish_scan/agent_finish. Also declared as Agent.output_type
    in factory.py — without a non-str output_type, the SDK force-stringifies whatever
    a tool_use_behavior hands back as final_output (see the framework's
    `if not agent.output_type or agent.output_type is str: final_output = str(...)`),
    which would turn this dict into an unparseable repr string. Confirmed by tracing
    agents/run_internal/turn_resolution.py in the installed 0.19.4 package."""

    summary: str
    findings: list[str]
    success: bool


@function_tool
async def agent_finish(
    ctx: RunContextWrapper[ScanContext],
    summary: str,
    findings: list[str],
    success: bool,
) -> dict:
    """Terminate THIS agent (non-root specialists only). Findings must already be
    filed via the `finding` tool before calling this — pass their returned IDs here,
    not their content."""
    return {"summary": summary, "findings": findings, "success": success}


@function_tool
async def finish_scan(
    ctx: RunContextWrapper[ScanContext],
    summary: str,
    findings: list[str],
    success: bool,
) -> dict:
    """Terminate the scan (root agent only). Aggregates the run's findings into the
    final result."""
    return {"summary": summary, "findings": findings, "success": success}
