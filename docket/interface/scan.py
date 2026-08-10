"""The one seam between CLI, orchestration, sandbox, and reporting.

docket.interface.main calls run_scan() exactly once. Root spawns sqli/cmdi/xss
specialists through AgentCoordinator — the signature and on_finding contract are
final now so CLI and reporting don't have to change shape later.
"""
from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass

from agents.models.interface import Model

from docket.config import Config, run_dir
from docket.core.agents import AgentCoordinator
from docket.core.execution import ScanContext, run_agent_loop
from docket.report.models import Finding
from docket.roles.factory import build_agent
from docket.roles.graph_tools import create_agent, view_agent_graph, wait_for_agents
from docket.roles.prompts.root import build_root_task


@dataclass(slots=True)
class ScanResult:
    success: bool
    summary: str
    finding_count: int
    cost_usd: float = 0.0
    agents_spawned: int = 1


def run_scan(
    target_url: str,
    *,
    instruction: str | None = None,
    whitebox_path: str | None = None,
    on_finding: Callable[[Finding], None] | None = None,
    config: Config | None = None,
    run_name: str = "scan",
    max_turns: int = 20,
    model_override: Callable[[str], Model] | None = None,
) -> ScanResult:
    """`model_override`, if given, is threaded through every agent (root and any
    child it spawns) instead of building a real LitellmModel — the hook tests use to
    script a whole multi-agent run without a live LLM_API_KEY."""
    cfg = config or Config.from_env()
    coordinator = AgentCoordinator(max_agents=cfg.max_agents)
    context = ScanContext(
        target_url=target_url,
        run_dir=run_dir(run_name),
        on_finding=on_finding,
        agent_id="root",
        role="root",
        coordinator=coordinator,
        config=cfg,
        model_override=model_override,
    )
    root_model = model_override("root") if model_override else None
    agent = build_agent(
        "root", cfg,
        extra_tools=[create_agent, wait_for_agents, view_agent_graph],
        model=root_model,
    )
    task = build_root_task(target_url, instruction)

    output = asyncio.run(run_agent_loop(agent, context, task, max_turns=max_turns))
    findings = output.get("findings", [])
    return ScanResult(
        success=bool(output.get("success", True)),
        summary=output.get("summary", ""),
        finding_count=len(findings),
        agents_spawned=len(coordinator.agents) + 1,  # +1 for root itself
    )
