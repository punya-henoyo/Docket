"""SDK-native LLM usage aggregation for scan reports. Mirrors docket/report/usage.py.

The coordinator tracks dollars because that's what enforces the budget; this tracks
TOKENS, per agent, because that's what explains the dollars in the report — "the sqli
agent spent 60% of the run" is only visible with a per-agent breakdown.

Aggregates the SDK's own Usage objects rather than counting tokens ourselves, so the
numbers are the provider's, not an estimate.
"""
from __future__ import annotations

import logging
from typing import Any

from agents.usage import Usage

logger = logging.getLogger(__name__)


class LLMUsageLedger:
    """Aggregate SDK Usage objects and attach best-effort cost estimates."""

    def __init__(self, *, cost_unavailable: bool = False) -> None:
        self._total = Usage()
        self._by_agent: dict[str, Usage] = {}
        self._metadata: dict[str, dict[str, str]] = {}
        self._total_cost = 0.0
        self._cost_by_agent: dict[str, float] = {}
        # When True, tokens are still tracked but cost stays $0 — the run is on a
        # model LiteLLM has no pricing for, and a fabricated number would be worse
        # than an explicit zero.
        self.cost_unavailable = cost_unavailable

    def record(
        self,
        agent_id: str,
        usage: Usage | None,
        *,
        cost_usd: float = 0.0,
        role: str | None = None,
        model: str | None = None,
    ) -> None:
        if usage is None:
            return
        self._total.add(usage)
        if agent_id not in self._by_agent:
            self._by_agent[agent_id] = Usage()
        self._by_agent[agent_id].add(usage)

        if not self.cost_unavailable and cost_usd:
            self._total_cost += cost_usd
            self._cost_by_agent[agent_id] = self._cost_by_agent.get(agent_id, 0.0) + cost_usd

        meta = self._metadata.setdefault(agent_id, {})
        if role:
            meta["role"] = role
        if model:
            meta["model"] = model

    @property
    def total_cost_usd(self) -> float:
        return round(self._total_cost, 6)

    def totals(self) -> dict[str, Any]:
        return {
            "requests": self._total.requests,
            "input_tokens": self._total.input_tokens,
            "output_tokens": self._total.output_tokens,
            "total_tokens": self._total.total_tokens,
            "cost_usd": self.total_cost_usd,
            "cost_available": not self.cost_unavailable,
        }

    def per_agent(self) -> list[dict[str, Any]]:
        rows = [
            {
                "agent_id": agent_id,
                "role": self._metadata.get(agent_id, {}).get("role"),
                "model": self._metadata.get(agent_id, {}).get("model"),
                "requests": usage.requests,
                "input_tokens": usage.input_tokens,
                "output_tokens": usage.output_tokens,
                "total_tokens": usage.total_tokens,
                "cost_usd": round(self._cost_by_agent.get(agent_id, 0.0), 6),
            }
            for agent_id, usage in self._by_agent.items()
        ]
        return sorted(rows, key=lambda r: r["total_tokens"], reverse=True)

    def to_dict(self) -> dict[str, Any]:
        return {"totals": self.totals(), "agents": self.per_agent()}


def demo() -> None:
    def usage(inp: int, out: int) -> Usage:
        return Usage(requests=1, input_tokens=inp, output_tokens=out, total_tokens=inp + out)

    ledger = LLMUsageLedger()
    ledger.record("root", usage(1000, 100), cost_usd=0.01, role="root", model="anthropic/claude-sonnet-5")
    ledger.record("a1", usage(5000, 900), cost_usd=0.05, role="sqli", model="anthropic/claude-sonnet-5")
    ledger.record("a1", usage(2000, 300), cost_usd=0.02, role="sqli")
    ledger.record("a2", None)  # a turn with no usage reported must be a safe no-op

    totals = ledger.totals()
    assert totals["requests"] == 3, totals
    assert totals["input_tokens"] == 8000 and totals["output_tokens"] == 1300, totals
    assert totals["cost_usd"] == 0.08, totals
    assert totals["cost_available"] is True

    rows = ledger.per_agent()
    assert [r["agent_id"] for r in rows] == ["a1", "root"], rows  # busiest first
    assert rows[0]["total_tokens"] == 8200 and rows[0]["cost_usd"] == 0.07, rows[0]
    assert rows[0]["role"] == "sqli" and rows[0]["model"] == "anthropic/claude-sonnet-5"

    # Unpriced model: tokens still counted, cost explicitly zero rather than invented.
    blind = LLMUsageLedger(cost_unavailable=True)
    blind.record("root", usage(100, 10), cost_usd=99.0)
    assert blind.totals()["input_tokens"] == 100
    assert blind.total_cost_usd == 0.0
    assert blind.totals()["cost_available"] is False
    assert "totals" in blind.to_dict() and "agents" in blind.to_dict()
    print("report.usage: ok")


if __name__ == "__main__":
    demo()
