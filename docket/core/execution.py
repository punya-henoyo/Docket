"""The agent run loop, the cost/budget hooks, and the multi-agent spawn wrapper that
guarantees a dead child still reports a terminal status back to its parent.
"""
from __future__ import annotations

import asyncio
import sys
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agents import Agent, MaxTurnsExceeded, ModelResponse, RunContextWrapper, RunHooks, Runner, UserError
from agents.models.interface import Model

from docket.config.settings import Config
from docket.core.agents import AgentCoordinator, AgentStatus
from docket.report.models import Finding


class BudgetExceeded(Exception):
    """Raised by the pre-turn budget check. Terminal, never retried — a retry would
    just hit the same wall and bill another turn for the privilege."""


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
    # docket/roles/factory.py; running LLM-authored shell commands on the host is
    # exactly what the sandbox exists to prevent.
    sandbox: Any | None = None
    # Test-only hook: if set, create_agent (docket/roles/graph_tools.py) uses
    # model_override(role) instead of building a real LitellmModel — lets a mock
    # harness script every spawned agent's decisions without touching production code.
    model_override: Callable[[str], Model] | None = None


_warned_unpriced: set[str] = set()


def estimate_cost(model: str, usage: Any) -> float:
    """Dollar cost of one model turn, via LiteLLM's pricing tables.

    Returns 0.0 for a model LiteLLM has no pricing data for (it raises rather than
    guessing). That means budget enforcement silently becomes a no-op for unpriced
    models — max_turns is then the only ceiling — so warn once per model rather than
    swallowing it, and never crash a scan over missing pricing metadata.
    """
    if usage is None:
        return 0.0
    try:
        import litellm

        prompt_cost, completion_cost = litellm.cost_per_token(
            model=model,
            prompt_tokens=getattr(usage, "input_tokens", 0) or 0,
            completion_tokens=getattr(usage, "output_tokens", 0) or 0,
        )
        return prompt_cost + completion_cost
    except Exception:
        if model not in _warned_unpriced:
            _warned_unpriced.add(model)
            print(
                f"warning: no LiteLLM pricing data for {model!r} — cost budget cannot be "
                f"enforced for this model; --max-steps/max_turns is the only ceiling.",
                file=sys.stderr,
            )
        return 0.0


class BudgetHooks(RunHooks[ScanContext]):
    """Charges each model turn to the coordinator and refuses to start a turn once
    the caller is out of budget. Lives in hooks rather than inside the model wrapper
    so it applies to any Model implementation — including the ScriptedModel the tests
    use, which is what makes budget enforcement testable without a live provider."""

    async def on_llm_start(self, context, agent, system_prompt, input_items) -> None:
        ctx = context.context
        if ctx.coordinator is None:
            return
        reason = ctx.coordinator.over_budget(ctx.agent_id)
        if reason:
            raise BudgetExceeded(reason)

    async def on_llm_end(self, context, agent, response: ModelResponse) -> None:
        ctx = context.context
        if ctx.coordinator is None or ctx.config is None:
            return
        usd = estimate_cost(ctx.config.llm, response.usage)
        if usd:
            await ctx.coordinator.record_spend(ctx.agent_id, usd)


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
                agent, task, context=context, max_turns=max_turns, hooks=BudgetHooks(),
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
