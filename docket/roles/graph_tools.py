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
from docket.roles.factory import SpecialistRole, build_agent
from docket.roles.prompts.specialist import build_task as build_specialist_task


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
    )
    child_agent = build_agent(role, parent.config, model=child_model)
    child_task = build_specialist_task(role, target_route, task)

    def run_coro_factory() -> Awaitable[dict]:
        return run_agent_loop(child_agent, child_context, child_task, max_turns=12)

    spawn_child_agent(coordinator, agent_id, name, role, parent.agent_id, run_coro_factory)
    return {"agent_id": agent_id, "status": "spawned"}


@function_tool(strict_mode=False)
async def wait_for_agents(
    ctx: RunContextWrapper[ScanContext],
    agent_ids: list[str] | None = None,
    timeout_seconds: int = 120,
) -> dict:
    """Block until at least one of agent_ids (or any of your children, if omitted)
    reaches a terminal status, or timeout elapses. Issue one wait, then react to what
    it returns — don't poll in a loop."""
    coordinator = ctx.context.coordinator
    if coordinator is None:
        return {"events": [], "timed_out": False, "error": "no coordinator on this context"}

    targets = agent_ids or coordinator.children_of(ctx.context.agent_id)
    targets = [aid for aid in targets if aid in coordinator.agents]
    if not targets:
        return {"events": [], "timed_out": False}

    # An agent that already reached a terminal status has its `wake` Event already
    # set — re-waiting on it returns instantly. If we created a waiter for it anyway,
    # asyncio.wait's FIRST_COMPLETED would always fire on that stale agent, and a
    # caller re-checking on a still-pending sibling would never actually block long
    # enough to see it finish. Only wait on genuinely-pending targets.
    already_done = [aid for aid in targets if coordinator.agents[aid].wake.is_set()]
    still_pending = [aid for aid in targets if aid not in already_done]

    newly_done: list[str] = []
    if still_pending:
        waiters = {aid: asyncio.create_task(coordinator.agents[aid].wake.wait()) for aid in still_pending}
        done, pending = await asyncio.wait(
            waiters.values(), timeout=timeout_seconds, return_when=asyncio.FIRST_COMPLETED,
        )
        for p in pending:
            p.cancel()
        newly_done = [aid for aid, w in waiters.items() if w in done]

    finished = already_done + newly_done
    events = [
        {
            "agent_id": aid,
            "status": coordinator.statuses.get(aid),
            "summary": coordinator.results.get(aid, {}).get("summary"),
            "findings": coordinator.results.get(aid, {}).get("findings", []),
        }
        for aid in finished
    ]
    return {"events": events, "timed_out": not finished}


@function_tool
async def view_agent_graph(ctx: RunContextWrapper[ScanContext]) -> dict:
    """Show the agent tree with parent/child relationships and current statuses."""
    coordinator = ctx.context.coordinator
    if coordinator is None:
        return {"agents": [], "counts": {}}
    return coordinator.view_graph()
