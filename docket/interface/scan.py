"""The one seam between CLI, orchestration, sandbox, and reporting.

docket.interface.main calls run_scan() exactly once. M3: a single agent does
everything (see docket/roles/factory.py). M4 replaces this with root spawning
sqli/cmdi/xss specialists through AgentCoordinator — the signature and on_finding
contract are final now so CLI and reporting don't have to change shape later.
"""
from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass

from docket.roles.factory import build_agent
from docket.roles.prompts.root import build_root_task
from docket.config import Config, run_dir
from docket.core.execution import ScanContext, run_agent_loop
from docket.report.models import Finding


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
    max_turns: int = 15,
) -> ScanResult:
    cfg = config or Config.from_env()
    context = ScanContext(
        target_url=target_url,
        run_dir=run_dir(run_name),
        on_finding=on_finding,
        agent_id="root",
        role="root",
    )
    agent = build_agent("root", cfg)
    task = build_root_task(target_url, instruction)

    output = asyncio.run(run_agent_loop(agent, context, task, max_turns=max_turns))
    findings = output.get("findings", [])
    return ScanResult(
        success=bool(output.get("success", True)),
        summary=output.get("summary", ""),
        finding_count=len(findings),
    )
