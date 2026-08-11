"""Harness check WITHOUT any LLM/Agent machinery: AgentCoordinator + spawn_child_agent
directly, proving registration/status/wake plumbing works before layering real agents on
top. Run: uv run python tests/test_coordinator.py
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


async def _spawn(coordinator: AgentCoordinator, agent_id: str, name: str, role: str, factory):
    """register-then-spawn, the same order create_agent uses. Registration is the
    caller's job precisely so a child is visible before the spawning tool returns."""
    await coordinator.register(agent_id, name=name, role=role, parent_id="root")
    return spawn_child_agent(coordinator, agent_id, name, role, "root", factory)


async def test_dummy_echo_child_completes() -> None:
    coordinator = AgentCoordinator(max_agents=6)
    task = await _spawn(coordinator, "c1", "echo-child", "sqli", _echo_child)
    await task  # in production the root agent awaits via wait_for_agents, not this directly
    assert coordinator.statuses["c1"] == "completed"
    assert coordinator.results["c1"]["success"] is True
    assert coordinator.agents["c1"].wake.is_set()


async def test_crashed_child_still_reports_terminal_status() -> None:
    """The load-bearing guarantee: a child that raises still flips to a terminal
    status via spawn_child_agent's `finally:` — a parent in wait_for_agents cannot
    hang on a task that silently died."""
    coordinator = AgentCoordinator(max_agents=6)
    task = await _spawn(coordinator, "c2", "crash-child", "cmdi", _crashing_child)
    await asyncio.gather(task, return_exceptions=True)
    assert coordinator.statuses["c2"] == "crashed"
    assert "boom" in coordinator.errors["c2"]
    assert coordinator.agents["c2"].wake.is_set()


async def test_cancelled_child_reports_stopped() -> None:
    async def _slow_child() -> dict:
        await asyncio.sleep(30)
        return {"summary": "never", "findings": [], "success": True}

    coordinator = AgentCoordinator(max_agents=6)
    task = await _spawn(coordinator, "c3", "slow-child", "xss", _slow_child)
    await asyncio.sleep(0.05)
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)
    assert coordinator.statuses["c3"] == "stopped"


async def test_child_is_visible_before_its_task_runs() -> None:
    """Regression: a root that spawns and waits in the SAME model turn used to be told
    nothing was pending, because register() ran inside the spawned task and the wait tool
    skips ids absent from coordinator.agents. Root then called finish_scan and the loop
    teardown cancelled its children mid-exploit — a scan exiting success=True with zero
    findings and no error anywhere. Models emit parallel tool calls by default, so this is
    the normal path, not an edge case.

    The assertion is deliberately made with NO await between spawn and check: that is what
    "same turn" means.
    """
    coordinator = AgentCoordinator(max_agents=6)
    await coordinator.register("c4", name="visible", role="sqli", parent_id="root")
    task = spawn_child_agent(coordinator, "c4", "visible", "sqli", "root", _echo_child)
    assert "c4" in coordinator.agents, "child invisible to a same-turn wait_for_agents"
    assert coordinator.statuses["c4"] == "pending"
    assert not coordinator.agents["c4"].wake.is_set(), "not-yet-run child must not look done"
    await task
    assert coordinator.statuses["c4"] == "completed"


async def test_refused_spawn_is_not_silently_dropped() -> None:
    """Regression: register() used to sit outside _run_child's try, so hitting max_agents
    escaped the finally that guarantees a terminal status. The refusal surfaced only as an
    unretrieved asyncio exception while create_agent still returned "spawned", leaving root
    convinced a route was covered by an agent that never existed.

    Registration is now the caller's job, so the refusal is raised where it can be caught
    and reported to the model.
    """
    coordinator = AgentCoordinator(max_agents=1)
    await coordinator.register("c5", name="first", role="sqli", parent_id="root")
    spawn_child_agent(coordinator, "c5", "first", "sqli", "root", _echo_child)

    refused = False
    try:
        await coordinator.register("c6", name="second", role="cmdi", parent_id="root")
    except RuntimeError as exc:
        refused = True
        assert "max_agents" in str(exc)
    assert refused, "second registration should be refused at max_agents=1"
    assert "c6" not in coordinator.agents

    # And spawning without registering is a loud error, not a half-alive ghost agent.
    unguarded = False
    try:
        spawn_child_agent(coordinator, "c6", "second", "cmdi", "root", _echo_child)
    except RuntimeError as exc:
        unguarded = True
        assert "register" in str(exc)
    assert unguarded, "spawn_child_agent must refuse an unregistered agent_id"


def main() -> None:
    asyncio.run(test_dummy_echo_child_completes())
    asyncio.run(test_crashed_child_still_reports_terminal_status())
    asyncio.run(test_cancelled_child_reports_stopped())
    asyncio.run(test_child_is_visible_before_its_task_runs())
    asyncio.run(test_refused_spawn_is_not_silently_dropped())
    print("test_coordinator: ok — terminal status on echo/crash/cancel, "
          "same-turn visibility, and refused spawns surface")


if __name__ == "__main__":
    main()
