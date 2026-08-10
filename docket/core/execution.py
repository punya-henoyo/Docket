"""The agent run loop. M3 scope: a single agent, no coordinator/children yet (that's
M4's core/agents.py + spawn_child_agent). ScanContext gains a `coordinator` field when
M4 lands — this shape doesn't change, only what's added to it.
"""
from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from agents import Agent, Runner

from docket.report.models import Finding


@dataclass(slots=True)
class ScanContext:
    target_url: str
    run_dir: Path
    on_finding: Callable[[Finding], None] | None = None
    agent_id: str = "root"
    role: str = "root"


async def run_agent_loop(
    agent: Agent[ScanContext],
    context: ScanContext,
    task: str,
    max_turns: int = 15,
) -> dict:
    """Runs one agent to completion, returns its finish tool's output dict.

    Recovery here is a flat retry (2 attempts, 3s apart), not upstream Docket's full
    image-strip/compaction/backoff pipeline — vulnshop's 3 known routes will never
    approach a context-window limit or a real rate-limit wall.
    # ponytail: flat retry(2) not full backoff/compaction — upgrade if a real
    # (non-toy) target starts overflowing context or hammering rate limits.
    """
    last_exc: Exception | None = None
    for attempt in range(2):
        try:
            result = await Runner.run(agent, task, context=context, max_turns=max_turns)
            output = result.final_output
            if not isinstance(output, dict):
                # tool_use_behavior guarantees the run only ends via finish_scan/
                # agent_finish, both of which return a dict — this is a defensive
                # fallback, not the expected path.
                output = {"summary": str(output), "findings": [], "success": False}
            return output
        except Exception as exc:  # transient model/network error
            last_exc = exc
            if attempt == 0:
                await asyncio.sleep(3)
                continue
    raise last_exc  # pragma: no cover — only reached if both attempts fail
