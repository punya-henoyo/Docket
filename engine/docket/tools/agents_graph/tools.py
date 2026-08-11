"""Inter-agent coordination tools, given only to the root agent: spawn a specialist,
wait for children, and inspect the current agent tree. `stop_agent`/
`send_message_to_agent` are deliberately NOT built yet — vulnshop's straight-line
spawn -> wait -> aggregate flow doesn't need mid-run redirection; add them if a real
run shows root needs to react to a stuck child.
# ponytail: no stop_agent/send_message_to_agent — add when the straight-line flow
# proves insufficient, not speculatively.
"""
from __future__ import annotations

import asyncio
import uuid
from collections.abc import Awaitable

from agents import RunContextWrapper, function_tool

from docket.core.execution import ScanContext, run_agent_loop, spawn_child_agent
from docket.interface.tui.backend.messages import get_emitter
from docket.agents.factory import SpecialistRole, build_agent
from docket.agents.prompts.specialist import build_task as build_specialist_task


@function_tool(strict_mode=False)
async def create_agent(
    ctx: RunContextWrapper[ScanContext],
    name: str,
    role: SpecialistRole,
    task: str,
    target_route: str,
) -> dict:
    """Spawn a specialist child agent scoped to ONE vulnerability class and ONE route.
    Check view_agent_graph first — don't spawn a duplicate for a route already covered
    by a running or completed agent."""
    parent = ctx.context
    coordinator = parent.coordinator
    if coordinator is None:
        return {"ok": False, "error": "no coordinator on this context — create_agent is root-only"}

    agent_id = uuid.uuid4().hex[:8]
    child_model = parent.model_override(role) if parent.model_override else None
    child_context = ScanContext(
        target_url=parent.target_url,
        run_dir=parent.run_dir,
        on_finding=parent.on_finding,
        agent_id=agent_id,
        role=role,
        coordinator=coordinator,
        config=parent.config,
        model_override=parent.model_override,
        # Children share the parent's sandbox. Without this they'd get sandbox=None and
        # their shell/browser tools would refuse to run. Sharing is safe: the shim is
        # single-threaded, so concurrent children's tool calls queue there rather than
        # racing — they still reason in parallel, only their sandbox calls serialize.
        sandbox=parent.sandbox,
    )
    child_agent = build_agent(role, parent.config, model=child_model, sandbox=parent.sandbox)
    child_task = build_specialist_task(role, target_route, task)

    def run_coro_factory() -> Awaitable[dict]:
        return run_agent_loop(child_agent, child_context, child_task, max_turns=12)

    get_emitter().agent_spawned(agent_id, name, role, parent.agent_id)
    spawn_child_agent(coordinator, agent_id, name, role, parent.agent_id, run_coro_factory)
    return {"agent_id": agent_id, "status": "spawned"}


@function_tool(strict_mode=False)
async def wait_for_agents(
    ctx: RunContextWrapper[ScanContext],
    agent_ids: list[str] | None = None,
    timeout_seconds: int = 120,
) -> dict:
    """Block until ALL of agent_ids (or all of your children, if omitted) have
    finished, or the timeout elapses. Returns one event per finished agent, including
    the findings each registered. Issue one wait, then react to what it returns —
    don't poll in a loop."""
    coordinator = ctx.context.coordinator
    if coordinator is None:
        return {"events": [], "timed_out": False, "error": "no coordinator on this context"}

    targets = agent_ids or coordinator.children_of(ctx.context.agent_id)
    targets = [aid for aid in targets if aid in coordinator.agents]
    if not targets:
        return {"events": [], "timed_out": False, "still_pending": []}

    # Wait for ALL of them, not the first to finish. A coordinator's actual need is
    # "everyone has reported, now aggregate" — returning on the first completion made
    # root miss slower siblings entirely, since an already-set wake Event resolves
    # instantly and a follow-up wait would return that same stale agent forever.
    # Only genuinely-pending agents get a waiter; the rest are already terminal.
    pending_ids = [aid for aid in targets if not coordinator.agents[aid].wake.is_set()]
    if pending_ids:
        waiters = [asyncio.create_task(coordinator.agents[aid].wake.wait()) for aid in pending_ids]
        _, unfinished = await asyncio.wait(
            waiters, timeout=timeout_seconds, return_when=asyncio.ALL_COMPLETED,
        )
        for task in unfinished:
            task.cancel()

    events = [
        {
            "agent_id": aid,
            "status": coordinator.statuses.get(aid),
            "summary": coordinator.results.get(aid, {}).get("summary"),
            "findings": coordinator.results.get(aid, {}).get("findings", []),
        }
        for aid in targets
        if coordinator.agents[aid].wake.is_set()
    ]
    still_pending = [aid for aid in targets if not coordinator.agents[aid].wake.is_set()]
    return {"events": events, "timed_out": bool(still_pending), "still_pending": still_pending}


@function_tool
async def view_agent_graph(ctx: RunContextWrapper[ScanContext]) -> dict:
    """Show the agent tree with parent/child relationships and current statuses."""
    coordinator = ctx.context.coordinator
    if coordinator is None:
        return {"agents": [], "counts": {}}
    return coordinator.view_graph()
