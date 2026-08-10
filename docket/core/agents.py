"""AgentCoordinator: tracks every spawned agent, its status, and its messages.

M4 scope: registration + asyncio.Lock only. Budgets and the crash-still-reports
guarantee land in M5 (the guarantee itself lives in execution.py's spawn wrapper —
this file just has to make mark_terminal() safe to call unconditionally from there).

Everything runs on ONE event loop; children are asyncio.Tasks (coroutines), not OS
threads — so asyncio.Lock is the correct primitive here, not threading.Lock. It
prevents two coroutines from interleaving a read-modify-write across an `await` point
(e.g. two create_agent calls racing on `len(self.agents) >= max_agents`); it is not
OS-thread-safe, and doesn't need to be, since nothing here crosses a thread boundary.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any, Literal

AgentStatus = Literal["pending", "running", "completed", "crashed", "failed", "stopped"]

_TERMINAL_STATUSES = {"completed", "crashed", "failed", "stopped"}


@dataclass(slots=True)
class AgentRuntime:
    task: asyncio.Task[Any] | None = None
    mailbox: list[dict[str, Any]] = field(default_factory=list)
    # Set once, on terminal status — lets wait_for_agents block on "any of these
    # finished" without polling. Never reset (an agent only terminates once).
    wake: asyncio.Event = field(default_factory=asyncio.Event)


class AgentCoordinator:
    def __init__(
        self,
        max_agents: int = 6,
        budget_usd: float = 2.0,
        per_agent_reserve_usd: float = 0.75,
    ) -> None:
        self._lock = asyncio.Lock()
        self.max_agents = max_agents
        self.agents: dict[str, AgentRuntime] = {}
        self.statuses: dict[str, AgentStatus] = {}
        self.names: dict[str, str] = {}
        self.roles: dict[str, str] = {}
        self.parent_of: dict[str, str | None] = {}
        self.results: dict[str, dict] = {}
        self.errors: dict[str, str] = {}
        # Budgets: one scan-wide ceiling, plus a per-child reserve so one runaway
        # specialist can't eat the whole scan. Root is deliberately NOT reserve-capped
        # (register() is children-only, so it never gets a reserve entry) — root is the
        # aggregator, and cutting it off early loses every child's reported findings.
        self.budget_usd = budget_usd
        self.per_agent_reserve_usd = per_agent_reserve_usd
        self.spent_usd = 0.0
        self.agent_spent: dict[str, float] = {}
        self.reserves: dict[str, float] = {}

    async def register(self, agent_id: str, *, name: str, role: str, parent_id: str | None) -> None:
        async with self._lock:
            if len(self.agents) >= self.max_agents:
                raise RuntimeError(f"max_agents={self.max_agents} reached, refusing to spawn {name!r}")
            self.agents[agent_id] = AgentRuntime()
            self.statuses[agent_id] = "pending"
            self.names[agent_id] = name
            self.roles[agent_id] = role
            self.parent_of[agent_id] = parent_id
            # Never let a child reserve exceed what's actually left in the scan budget.
            self.reserves[agent_id] = min(
                self.per_agent_reserve_usd, max(0.0, self.budget_usd - self.spent_usd)
            )

    async def attach_task(self, agent_id: str, task: asyncio.Task) -> None:
        async with self._lock:
            self.agents[agent_id].task = task

    async def mark_running(self, agent_id: str) -> None:
        async with self._lock:
            self.statuses[agent_id] = "running"

    async def mark_terminal(self, agent_id: str, status: AgentStatus, result: dict) -> None:
        """Safe to call unconditionally, even from a `finally:` on a crashed/cancelled
        task — that guarantee is what lets a parent's wait_for_agents ever unblock."""
        assert status in _TERMINAL_STATUSES, f"not a terminal status: {status!r}"
        async with self._lock:
            self.statuses[agent_id] = status
            self.results[agent_id] = result
        self.agents[agent_id].wake.set()

    async def record_spend(self, agent_id: str, usd: float) -> None:
        async with self._lock:
            self.spent_usd += usd
            self.agent_spent[agent_id] = self.agent_spent.get(agent_id, 0.0) + usd

    def over_budget(self, agent_id: str) -> str | None:
        """Returns a human-readable reason if `agent_id` must stop now, else None.

        Checked BEFORE each model turn (see BudgetHooks in core/execution.py) rather
        than after, so the cutoff never pays for the turn that breaches it. A hard
        cutoff, with no negotiated "wrap up" turn — at lab scale a well-behaved run
        against vulnshop should never come close, so the extra machinery would be
        speculative.
        # ponytail: hard cutoff, no graceful wrap-up turn — add one if real runs start
        # hitting the cap often enough that losing the final turn's context matters.
        """
        if self.spent_usd >= self.budget_usd:
            return f"scan budget exhausted (${self.spent_usd:.4f} of ${self.budget_usd:.2f})"
        reserve = self.reserves.get(agent_id)
        if reserve is not None:
            spent = self.agent_spent.get(agent_id, 0.0)
            if spent >= reserve:
                return f"agent reserve exhausted (${spent:.4f} of ${reserve:.2f})"
        return None

    async def deliver_message(self, target_agent_id: str, message: dict) -> None:
        async with self._lock:
            self.agents[target_agent_id].mailbox.append(message)
        self.agents[target_agent_id].wake.set()

    def children_of(self, parent_id: str) -> list[str]:
        # Computed on demand, not cached — with the ~6-agent ceiling this scales to,
        # a linear scan is cheaper than keeping a second structure in sync.
        return [aid for aid, p in self.parent_of.items() if p == parent_id]

    def view_graph(self) -> dict:
        counts: dict[str, int] = {}
        for status in self.statuses.values():
            counts[status] = counts.get(status, 0) + 1
        return {
            "agents": [
                {
                    "id": aid,
                    "name": self.names[aid],
                    "role": self.roles[aid],
                    "parent_id": self.parent_of[aid],
                    "status": self.statuses[aid],
                }
                for aid in self.agents
            ],
            "counts": counts,
        }


def demo() -> None:
    async def _run() -> None:
        coordinator = AgentCoordinator(max_agents=2)
        await coordinator.register("a1", name="child-1", role="sqli", parent_id="root")
        assert coordinator.statuses["a1"] == "pending"
        await coordinator.mark_running("a1")
        assert coordinator.statuses["a1"] == "running"
        await coordinator.mark_terminal("a1", "completed", {"summary": "ok", "success": True})
        assert coordinator.statuses["a1"] == "completed"
        assert coordinator.agents["a1"].wake.is_set()
        assert coordinator.children_of("root") == ["a1"]

        # max_agents enforced (2 slots: a1 already used one)
        await coordinator.register("a2", name="child-2", role="cmdi", parent_id="root")
        try:
            await coordinator.register("a3", name="child-3", role="xss", parent_id="root")
            raise AssertionError("should have refused: max_agents=2 already reached")
        except RuntimeError:
            pass

        graph = coordinator.view_graph()
        assert graph["counts"] == {"completed": 1, "pending": 1}

    async def _budgets() -> None:
        c = AgentCoordinator(max_agents=6, budget_usd=1.00, per_agent_reserve_usd=0.30)
        await c.register("k1", name="child", role="sqli", parent_id="root")
        assert c.over_budget("k1") is None

        # Per-child reserve trips before the scan-wide budget does.
        await c.record_spend("k1", 0.30)
        assert "reserve exhausted" in c.over_budget("k1")
        # ...and root, which has no reserve entry, is unaffected by it.
        assert c.over_budget("root") is None

        # Scan-wide budget catches everyone, root included.
        await c.record_spend("root", 0.75)
        assert c.spent_usd >= 1.00
        assert "scan budget exhausted" in c.over_budget("root")

        # A late child's reserve is clamped to what's actually left (nothing here).
        c2 = AgentCoordinator(budget_usd=0.50, per_agent_reserve_usd=0.40)
        await c2.record_spend("root", 0.45)
        await c2.register("k2", name="late", role="xss", parent_id="root")
        assert abs(c2.reserves["k2"] - 0.05) < 1e-9, c2.reserves["k2"]

    asyncio.run(_run())
    asyncio.run(_budgets())
    print("core.agents: ok")


if __name__ == "__main__":
    demo()
