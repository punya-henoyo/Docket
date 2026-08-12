"""The agent run loop and the multi-agent spawn wrapper that guarantees a dead child
still reports a terminal status back to its parent. Cost/budget hooks live in docket/core/hooks.py.
"""
from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agents import Agent, MaxTurnsExceeded, RunConfig, Runner, UserError
from agents.models.interface import Model

from docket.config.settings import Config
from docket.core.agents import AgentCoordinator, AgentStatus
from docket.core.hooks import BudgetExceeded, BudgetHooks
from docket.core.sessions import make_session
from docket.interface.tui.backend.messages import get_emitter
from docket.llm.compaction import compact
from docket.report.models import Finding

logger = logging.getLogger(__name__)


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
    # Where the finish tool parks its result, so reading it never depends on how the
    # SDK chose to shape `final_output`. Agent.output_type used to carry that job, but
    # declaring it makes the SDK send response_format=json_schema, and some providers
    # (confirmed: DeepSeek V4 Pro on Azure AI Foundry) then stop emitting tool calls
    # entirely — the agent loop spins until MaxTurnsExceeded having done nothing. See
    # factory._finish_tool_use_behavior.
    final_result: dict | None = None


# Errors that mean "this run is over", not "the network hiccuped". Retrying any of
# these just burns a second full run to reach the same conclusion.
_TERMINAL_EXCEPTIONS = (BudgetExceeded, MaxTurnsExceeded, UserError)


SALVAGE_INSTRUCTION = (
    "You have run out of turns. Do not read, search or think any further — every "
    "additional tool call is refused from here.\n\n"
    "Call your finish tool NOW, using only what is already in this conversation. "
    "Report exactly what you established and nothing you did not: an incomplete "
    "result that says what it covered is useful, an invented one is worse than "
    "silence. State what you did not get to in the notes."
)


async def _salvage(agent: Any, context: "ScanContext", session: Any,
                   run_config: Any) -> dict | None:
    """One last turn whose only job is to call the finish tool. None if that fails.

    Deliberately max_turns=2, not 1: the SDK counts the finish tool call itself as a
    turn, so a ceiling of 1 raises MaxTurnsExceeded again before the result lands.
    """
    try:
        result = await Runner.run(
            agent, SALVAGE_INSTRUCTION, context=context, max_turns=2,
            hooks=BudgetHooks(max_turns=2), session=session, run_config=run_config,
        )
    except Exception:  # noqa: BLE001 — a failed rescue must not mask the original stop
        logger.debug("salvage turn failed", exc_info=True)
        return None
    output = context.final_result
    if not isinstance(output, dict):
        output = getattr(result, "final_output", None)
    return output if isinstance(output, dict) else None


def _is_context_overflow(exc: BaseException) -> bool:
    try:
        from litellm.exceptions import ContextWindowExceededError

        if isinstance(exc, ContextWindowExceededError):
            return True
    except ImportError:  # pragma: no cover
        pass
    # Providers vary in how they surface it, and LiteLLM doesn't always normalise a
    # passthrough route's error into its own class.
    text = str(exc).lower()
    return "context" in text and ("length" in text or "window" in text or "too long" in text)


async def run_agent_loop(
    agent: Agent[ScanContext],
    context: ScanContext,
    task: str,
    max_turns: int = 15,
) -> dict:
    """Runs one agent to completion, returns its finish tool's output dict.

    Three recovery paths, in order of specificity:
      - context overflow -> compact the session's history and retry (the retry is
        pointless without compaction: an unchanged history overflows identically)
      - terminal errors (budget/max-turns/user error) -> report a clean failure
      - anything else transient -> one flat retry, 3s later
    """
    session = make_session(context.run_dir, context.agent_id)
    model_name = context.config.llm if context.config else ""

    # A SandboxAgent's native Filesystem/Shell tools need the session handed to the
    # RUN as well as to the agent — the SDK refuses to execute one otherwise
    # ("SandboxAgent execution requires RunConfig(sandbox=...)").
    run_config = None
    if context.sandbox is not None:
        from agents.sandbox import SandboxRunConfig

        from docket.runtime.sdk_session import DocketSandboxSession

        run_config = RunConfig(sandbox=SandboxRunConfig(session=DocketSandboxSession(context.sandbox)))
    last_exc: Exception | None = None
    compacted_already = False

    for attempt in range(3):
        try:
            result = await Runner.run(
                agent, task, context=context, max_turns=max_turns,
                hooks=BudgetHooks(max_turns=max_turns), session=session,
                run_config=run_config,
            )
            # context.final_result first: the finish tool parks the real dict there,
            # which survives regardless of how the SDK shapes final_output. Without
            # an Agent.output_type (see factory.build_agent for why declaring one
            # breaks tool calling on some providers) final_output arrives stringified.
            output = context.final_result
            if not isinstance(output, dict):
                output = result.final_output
            if not isinstance(output, dict):
                # The finish-tool gate should make this unreachable; treat a run that
                # ended some other way as failed rather than silently "successful".
                output = {"summary": str(output), "findings": [], "success": False}
            return output
        except MaxTurnsExceeded as exc:
            # Hitting the ceiling used to discard everything. Measured on a real
            # codebase: recon spent all 24 turns reading 29 files and recorded NO
            # map at all — the full budget spent for nothing, which is strictly worse
            # than a shallow map produced cheaply.
            #
            # The session still holds every file it read, so one more tightly-scoped
            # turn can usually convert that reading into a result. Costs one turn to
            # avoid losing all of them.
            salvaged = await _salvage(agent, context, session, run_config)
            if salvaged is not None:
                logger.info("recovered a result on the salvage turn after %s", type(exc).__name__)
                return salvaged
            return {"summary": f"stopped: {type(exc).__name__}: {exc}", "findings": [], "success": False}
        except _TERMINAL_EXCEPTIONS as exc:
            # Report it as a failed-but-clean result rather than raising: findings
            # already registered by this agent are on disk and in the FindingStore,
            # and its parent still deserves a status it can aggregate.
            return {"summary": f"stopped: {type(exc).__name__}: {exc}", "findings": [], "success": False}
        except Exception as exc:
            last_exc = exc
            if _is_context_overflow(exc) and not compacted_already:
                items = await session.get_items()
                compacted, did = compact(items, model_name)
                if did:
                    await session.clear_session()
                    await session.add_items(compacted)
                    compacted_already = True
                    logger.info("compacted history after context overflow; retrying")
                    continue
                return {
                    "summary": f"stopped: context window exceeded and history could not be compacted: {exc}",
                    "findings": [], "success": False,
                }
            if attempt < 2:
                await asyncio.sleep(3)
                continue
    raise last_exc  # pragma: no cover — only reached if every attempt fails


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
    # register() deliberately happens in create_agent, BEFORE this task is created, for
    # two reasons. It makes the child visible in coordinator.agents the instant the tool
    # returns, so a root that spawns and waits in the SAME turn (the norm, since models
    # emit parallel tool calls) cannot be told "nothing is pending" and end the scan out
    # from under its children. And it puts a max_agents refusal on create_agent's own
    # error path instead of in here, outside the try, where it escaped the finally below
    # and left root believing a route was covered by an agent that never existed.
    status: AgentStatus = "crashed"
    result: dict = {"success": False, "summary": "no terminal report produced", "findings": []}
    try:
        await coordinator.attach_task(agent_id, asyncio.current_task())
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
        get_emitter().agent_finished(agent_id, role, status, result.get("summary", ""))


def spawn_child_agent(
    coordinator: AgentCoordinator,
    agent_id: str,
    name: str,
    role: str,
    parent_id: str,
    run_coro_factory: Callable[[], Awaitable[dict]],
) -> asyncio.Task:
    """Fire-and-forget: returns immediately with the Task; the caller (create_agent)
    does not await it — that's what makes this "spawn a child", not "run inline".

    CONTRACT: the caller must have already awaited coordinator.register(agent_id).
    Registration cannot happen inside the task, because the task has not run by the time
    this returns, and a root that spawns and waits in one turn would then be told its
    children do not exist. Checked rather than assumed — the failure mode it replaces was
    a silently empty scan."""
    if agent_id not in coordinator.agents:
        raise RuntimeError(
            f"spawn_child_agent({agent_id!r}) before coordinator.register({agent_id!r}) — "
            "register first so the child is visible to wait_for_agents immediately"
        )
    return asyncio.create_task(
        _run_child(coordinator, agent_id, name, role, parent_id, run_coro_factory)
    )
