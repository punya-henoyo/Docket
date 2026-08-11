"""M5 check: cost tracking and hard budget cutoff, exercised through the real
Runner/BudgetHooks pipeline with a ScriptedModel that reports real token usage.

Run: uv run python tests/test_budget.py  (uses the tests/fixtures/ target)
"""
from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from agents import Agent

from fixtures.target_app import ensure_target
from mock_model import ScriptedModel
from docket.config.settings import Config, run_dir
from docket.core.agents import AgentCoordinator
from docket.core.execution import ScanContext, run_agent_loop
from docket.core.hooks import estimate_cost
from docket.report.dedupe import FindingStore
from docket.report.state import get_global_report_state, reset_report_state
from docket.agents.factory import build_agent
from docket.tools.finish.tool import agent_finish

TARGET = ensure_target()
# A real, priced model string so litellm.cost_per_token returns non-zero — the test is
# about budget arithmetic, not about which model is configured.
PRICED_MODEL = "anthropic/claude-sonnet-4-5-20250929"


def _config(max_cost: float, per_child: float) -> Config:
    os.environ["DOCKET_LLM"] = PRICED_MODEL
    cfg = Config.from_env()
    cfg.max_cost_usd = max_cost
    cfg.max_child_cost_usd = per_child
    return cfg


def test_estimate_cost_prices_real_model_and_survives_unknown() -> None:
    priced = estimate_cost(PRICED_MODEL, _FakeUsage(1000, 500))
    assert priced > 0, priced
    # An unpriced model must degrade to 0.0 with a warning, not crash a scan.
    assert estimate_cost("totally-made-up-model-xyz", _FakeUsage(1000, 500)) == 0.0
    assert estimate_cost(PRICED_MODEL, None) == 0.0


class _FakeUsage:
    def __init__(self, input_tokens: int, output_tokens: int) -> None:
        self.input_tokens = input_tokens
        self.output_tokens = output_tokens


def test_spend_is_recorded_per_agent_and_scan_wide() -> None:
    """A normal (under-budget) run charges the coordinator for every turn it took."""
    reset_report_state()
    cfg = _config(max_cost=10.0, per_child=5.0)
    store = FindingStore()
    coordinator = AgentCoordinator(
        max_agents=cfg.max_agents, budget_usd=cfg.max_cost_usd,
        per_agent_reserve_usd=cfg.max_child_cost_usd,
    )
    context = ScanContext(
        target_url=TARGET, run_dir=run_dir("budget-test-spend"), on_finding=store.add,
        agent_id="solo", role="sqli", coordinator=coordinator, config=cfg,
    )
    script = [
        ("http_request", {"method": "GET", "url": f"{TARGET}/search", "params": {"q": "hello"}}),
        ("agent_finish", {"summary": "done", "findings": [], "success": True}),
    ]
    agent = build_agent("sqli", cfg, model=ScriptedModel(script, tokens_per_turn=(1000, 200)))

    output = asyncio.run(run_agent_loop(agent, context, "probe", max_turns=6))
    assert output["success"] is True, output
    # Two model turns were taken, so two turns must have been billed.
    assert coordinator.spent_usd > 0, coordinator.spent_usd
    assert coordinator.agent_spent["solo"] == coordinator.spent_usd

    # ...and the usage ledger recorded the same work in TOKENS, per agent — proving
    # the hook -> ledger path is live rather than scaffolding.
    ledger = get_global_report_state().usage
    totals = ledger.totals()
    assert totals["requests"] == 2, totals
    assert totals["input_tokens"] == 2000 and totals["output_tokens"] == 400, totals
    rows = ledger.per_agent()
    assert len(rows) == 1 and rows[0]["agent_id"] == "solo", rows
    assert rows[0]["role"] == "sqli" and rows[0]["total_tokens"] == 2400, rows[0]


def test_budget_cutoff_stops_the_loop_and_preserves_earlier_findings() -> None:
    """The cutoff is pre-turn, so it stops the agent mid-run — and a finding it already
    registered before the cutoff must survive (it's on disk and in the store already)."""
    # Priced at ~$0.006/turn for (1000, 200) tokens, so a $0.008 ceiling allows the
    # first turn or two and then bites — well before the script's finish call.
    cfg = _config(max_cost=0.008, per_child=0.008)
    store = FindingStore()
    coordinator = AgentCoordinator(
        max_agents=cfg.max_agents, budget_usd=cfg.max_cost_usd,
        per_agent_reserve_usd=cfg.max_child_cost_usd,
    )
    context = ScanContext(
        target_url=TARGET, run_dir=run_dir("budget-test-cutoff"), on_finding=store.add,
        agent_id="spendy", role="sqli", coordinator=coordinator, config=cfg,
    )
    script = [
        ("finding", {
            "rule_type": "sqli", "severity": "high",
            "title": "SQL injection in POST /login",
            "description": "registered before the budget cutoff",
            "location": {"url": f"{TARGET}/login", "method": "POST", "parameter": "username"},
            "poc": {
                "steps": ["POST /login with username=admin' -- "],
                "request": {"method": "POST", "url": f"{TARGET}/login", "body": {"username": "admin' -- "}},
                "response_excerpt": "200 Welcome",
            },
        }),
        # Many more turns the agent will never be allowed to reach.
        *[("http_request", {"method": "GET", "url": f"{TARGET}/search", "params": {"q": str(i)}}) for i in range(20)],
        ("agent_finish", {"summary": "should never be reached", "findings": [], "success": True}),
    ]
    agent = build_agent("sqli", cfg, model=ScriptedModel(script, tokens_per_turn=(1000, 200)))

    output = asyncio.run(run_agent_loop(agent, context, "probe", max_turns=40))

    # Stopped by budget, reported as a clean failure rather than an exception.
    assert output["success"] is False, output
    assert "BudgetExceeded" in output["summary"], output
    assert "exhausted" in output["summary"], output
    # It stopped early: nowhere near the 21+ scripted turns.
    assert coordinator.spent_usd < 0.05, coordinator.spent_usd
    # And the finding it registered before the cutoff survived.
    assert len(store) == 1, len(store)
    assert store.findings()[0].rule_id == "sql-injection"


def test_child_reserve_cutoff_reports_terminal_status_to_parent() -> None:
    """A child killed by its reserve still lands a terminal status via _run_child's
    finally: block — the M4 guarantee has to hold for budget stops too, or a parent
    waiting on it would hang."""
    from docket.core.execution import spawn_child_agent

    async def _run() -> AgentCoordinator:
        cfg = _config(max_cost=10.0, per_child=0.0)  # zero reserve: cut off before turn 1
        coordinator = AgentCoordinator(
            max_agents=cfg.max_agents, budget_usd=cfg.max_cost_usd,
            per_agent_reserve_usd=cfg.max_child_cost_usd,
        )
        child_ctx = ScanContext(
            target_url=TARGET, run_dir=run_dir("budget-test-child"), agent_id="c9",
            role="sqli", coordinator=coordinator, config=cfg,
        )
        child_agent = build_agent(
            "sqli", cfg,
            model=ScriptedModel([("agent_finish", {"summary": "x", "findings": [], "success": True})],
                                 tokens_per_turn=(1000, 200)),
        )
        task = spawn_child_agent(
            coordinator, "c9", "reserve-starved", "sqli", "root",
            lambda: run_agent_loop(child_agent, child_ctx, "probe", max_turns=5),
        )
        await task
        return coordinator

    coordinator = asyncio.run(_run())
    assert coordinator.statuses["c9"] == "failed", coordinator.statuses
    assert "BudgetExceeded" in coordinator.results["c9"]["summary"], coordinator.results["c9"]
    assert coordinator.agents["c9"].wake.is_set()  # a waiting parent would be released


if __name__ == "__main__":
    test_estimate_cost_prices_real_model_and_survives_unknown()
    test_spend_is_recorded_per_agent_and_scan_wide()
    test_budget_cutoff_stops_the_loop_and_preserves_earlier_findings()
    test_child_reserve_cutoff_reports_terminal_status_to_parent()
    print("test_budget: ok — spend recorded, hard cutoff enforced pre-turn, findings and child status survive it")
