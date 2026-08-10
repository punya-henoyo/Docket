"""M4 harness check WITHOUT any LLM/Agent machinery: AgentCoordinator +
spawn_child_agent directly, proving registration/status/wake plumbing works before
layering real agents on top. Run: uv run python tests/test_coordinator.py
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from docket.core.agents import AgentCoordinator
from docket.core.execution import spawn_child_agent


async def _echo_child() -> dict:
    """A dummy child that does no real work — just reports success immediately."""
    await asyncio.sleep(0.05)
    return {"summary": "echo", "findings": [], "success": True}


async def _crashing_child() -> dict:
    raise RuntimeError("boom")


async def test_dummy_echo_child_completes() -> None:
    coordinator = AgentCoordinator(max_agents=6)
    task = spawn_child_agent(coordinator, "c1", "echo-child", "sqli", "root", _echo_child)
    await task  # in production the root agent awaits via wait_for_agents, not this directly
    assert coordinator.statuses["c1"] == "completed"
    assert coordinator.results["c1"]["success"] is True
    assert coordinator.agents["c1"].wake.is_set()


async def test_crashed_child_still_reports_terminal_status() -> None:
    """The load-bearing guarantee: a child that raises still flips to a terminal
    status via spawn_child_agent's `finally:` — a parent in wait_for_agents cannot
    hang on a task that silently died."""
    coordinator = AgentCoordinator(max_agents=6)
    task = spawn_child_agent(coordinator, "c2", "crash-child", "cmdi", "root", _crashing_child)
    await asyncio.gather(task, return_exceptions=True)
    assert coordinator.statuses["c2"] == "crashed"
    assert "boom" in coordinator.errors["c2"]
    assert coordinator.agents["c2"].wake.is_set()


async def test_cancelled_child_reports_stopped() -> None:
    async def _slow_child() -> dict:
        await asyncio.sleep(30)
        return {"summary": "never", "findings": [], "success": True}

    coordinator = AgentCoordinator(max_agents=6)
    task = spawn_child_agent(coordinator, "c3", "slow-child", "xss", "root", _slow_child)
    await asyncio.sleep(0.05)
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)
    assert coordinator.statuses["c3"] == "stopped"


def main() -> None:
    asyncio.run(test_dummy_echo_child_completes())
    asyncio.run(test_crashed_child_still_reports_terminal_status())
    asyncio.run(test_cancelled_child_reports_stopped())
    print("test_coordinator: ok — echo/crash/cancel all reach a terminal status via spawn_child_agent")


if __name__ == "__main__":
    main()
