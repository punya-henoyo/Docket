"""The agent run loop and the multi-agent spawn wrapper that guarantees a dead child
still reports a terminal status back to its parent. Mirrors docket/core/execution.py.

Cost/budget hooks live in docket/core/hooks.py.
"""
from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agents import Agent, MaxTurnsExceeded, Runner, UserError
from agents.models.interface import Model

from docket.config.settings import Config
from docket.core.agents import AgentCoordinator, AgentStatus
from docket.core.hooks import BudgetExceeded, BudgetHooks
from docket.report.models import Finding


@dataclass(slots=True)
class ScanContext:
    target_url: str
    run_dir: Path
    on_finding: Callable[[Finding], None] | None = None
    agent_id: str = "root"
    role: str = "root"
    coordinator: AgentCoordinator | None = None
    config: Config | None = None
    # When set, sandboxed tools (shell/http_request) execute inside the container
    # instead of the host process. `shell` REFUSES to run without it — see
    # docket/agents/factory.py; running LLM-authored shell commands on the host is
    # exactly what the sandbox exists to prevent.
    sandbox: Any | None = None
    # Test-only hook: if set, create_agent (docket/tools/agents_graph/tools.py) uses
    # model_override(role) instead of building a real LitellmModel — lets a mock
    # harness script every spawned agent's decisions without touching production code.
    model_override: Callable[[str], Model] | None = None


# Errors that mean "this run is over", not "the network hiccuped". Retrying any of
# these just burns a second full run to reach the same conclusion.
_TERMINAL_EXCEPTIONS = (BudgetExceeded, MaxTurnsExceeded, UserError)


async def run_agent_loop(
    agent: Agent[ScanContext],
    context: ScanContext,
    task: str,
    max_turns: int = 15,
) -> dict:
    """Runs one agent to completion, returns its finish tool's output dict.

    Transient-error recovery is a flat retry (2 attempts, 3s apart), not upstream
    Docket's full image-strip/compaction/backoff pipeline — vulnshop's known routes
    will never approach a context-window limit or a real rate-limit wall.
    # ponytail: flat retry(2) not full backoff/compaction — upgrade if a real
    # (non-toy) target starts overflowing context or hammering rate limits.
    """
    last_exc: Exception | None = None
    for attempt in range(2):
        try:
            result = await Runner.run(
                agent, task, context=context, max_turns=max_turns, hooks=BudgetHooks(max_turns=max_turns),
            )
            output = result.final_output
            if not isinstance(output, dict):
                # tool_use_behavior + Agent.output_type guarantee the run only ends
                # via finish_scan/agent_finish with a dict — this is a defensive
                # fallback, not the expected path.
                output = {"summary": str(output), "findings": [], "success": False}
            return output
        except _TERMINAL_EXCEPTIONS as exc:
            # Report it as a failed-but-clean result rather than raising: findings
            # already registered by this agent are on disk and in the FindingStore,
            # and its parent still deserves a status it can aggregate.
            return {"summary": f"stopped: {type(exc).__name__}: {exc}", "findings": [], "success": False}
        except Exception as exc:  # transient model/network error
            last_exc = exc
            if attempt == 0:
                await asyncio.sleep(3)
                continue
    raise last_exc  # pragma: no cover — only reached if both attempts fail


async def _run_child(
    coordinator: AgentCoordinator,
    agent_id: str,
    name: str,
    role: str,
    parent_id: str,
    run_coro_factory: Callable[[], Awaitable[dict]],
) -> None:
    """The load-bearing guarantee: whatever happens to the child's own run — it
    finishes, raises, or gets cancelled — `finally:` unconditionally reports a
    terminal status. A parent blocked in wait_for_agents cannot hang on a task that
    silently died; asyncio.create_task() otherwise swallows exceptions unless the
    task is awaited or a done-callback checks it.
    """
    await coordinator.register(agent_id, name=name, role=role, parent_id=parent_id)
    await coordinator.attach_task(agent_id, asyncio.current_task())

    status: AgentStatus = "crashed"
    result: dict = {"success": False, "summary": "no terminal report produced", "findings": []}
    try:
        await coordinator.mark_running(agent_id)
        result = await run_coro_factory()
        status = "completed" if result.get("success") else "failed"
    except asyncio.CancelledError:
        status = "stopped"
        raise
    except Exception as exc:
        coordinator.errors[agent_id] = repr(exc)
        status = "crashed"
    finally:
        await coordinator.mark_terminal(agent_id, status, result)


def spawn_child_agent(
    coordinator: AgentCoordinator,
    agent_id: str,
    name: str,
    role: str,
    parent_id: str,
    run_coro_factory: Callable[[], Awaitable[dict]],
) -> asyncio.Task:
    """Fire-and-forget: returns immediately with the Task; the caller (create_agent)
    does not await it — that's what makes this "spawn a child", not "run inline"."""
    return asyncio.create_task(
        _run_child(coordinator, agent_id, name, role, parent_id, run_coro_factory)
    )
