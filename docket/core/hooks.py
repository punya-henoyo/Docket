"""SDK run hooks used by docket orchestration. Mirrors docket/core/hooks.py.

Two jobs, both of which must happen around a model call rather than inside our own
code: charge each turn to the coordinator, and refuse to start a turn once the caller
is out of budget. Implemented as SDK hooks rather than inside the model wrapper so
they apply to ANY Model implementation — including the tests' ScriptedModel, which is
what makes budget enforcement testable with no live provider.

Also emits staged budget/turn warnings INTO the agent's own context. That is the
point: an agent that knows it is at 85% of budget can wrap up and report what it has,
whereas one that is simply cut off mid-thought loses that turn's work.
"""
from __future__ import annotations

import logging
import sys
from typing import TYPE_CHECKING, Any

from agents.lifecycle import RunHooks

from docket.report.state import get_global_report_state, mark_warned

if TYPE_CHECKING:
    from agents.items import ModelResponse

logger = logging.getLogger(__name__)

LLM_TURN_KEY = "llm_turn"

_STAGE_LABELS: tuple[str, ...] = ("NOTICE", "URGENT", "CRITICAL")
_TURN_WARN_BANDS: tuple[float, ...] = (0.70, 0.85, 0.95)
_ROOT_BUDGET_WARN_BANDS: tuple[float, ...] = (0.70, 0.85, 0.95)
# Subagents are warned earlier and more tightly than root: a child that overruns
# strands its findings, while root only needs enough headroom to aggregate.
_SUBAGENT_BUDGET_WARN_BANDS: tuple[float, ...] = (0.75, 0.80, 0.85)


class BudgetExceeded(Exception):
    """Raised by the pre-turn budget check. Terminal, never retried — a retry would
    just hit the same wall and bill another turn for the privilege."""


def _stage_for(fraction: float, bands: tuple[float, ...]) -> str | None:
    stage = None
    for label, threshold in zip(_STAGE_LABELS, bands, strict=False):
        if fraction >= threshold:
            stage = label
    return stage


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
        if mark_warned(f"unpriced:{model}"):
            print(
                f"warning: no LiteLLM pricing data for {model!r} — cost budget cannot be "
                f"enforced for this model; --max-steps/max_turns is the only ceiling.",
                file=sys.stderr,
            )
        return 0.0


class BudgetHooks(RunHooks):
    """Charges each model turn and gates the next one."""

    def __init__(self, max_turns: int | None = None) -> None:
        self._turns = 0
        self._max_turns = max_turns

    async def on_llm_start(self, context, agent, system_prompt, input_items) -> None:
        ctx = context.context
        coordinator = getattr(ctx, "coordinator", None)
        if coordinator is None:
            return
        reason = coordinator.over_budget(ctx.agent_id)
        if reason:
            raise BudgetExceeded(reason)
        self._warn_if_near_limits(ctx, coordinator)

    async def on_llm_end(self, context, agent, response: "ModelResponse") -> None:
        ctx = context.context
        coordinator = getattr(ctx, "coordinator", None)
        config = getattr(ctx, "config", None)
        if coordinator is None or config is None:
            return
        self._turns += 1
        usd = estimate_cost(config.llm, response.usage)
        if usd:
            await coordinator.record_spend(ctx.agent_id, usd)

    def _warn_if_near_limits(self, ctx: Any, coordinator: Any) -> None:
        is_root = getattr(ctx, "role", "root") == "root"
        bands = _ROOT_BUDGET_WARN_BANDS if is_root else _SUBAGENT_BUDGET_WARN_BANDS

        reserve = coordinator.reserves.get(ctx.agent_id)
        spent = coordinator.agent_spent.get(ctx.agent_id, 0.0)
        fraction = (spent / reserve) if reserve else (
            coordinator.spent_usd / coordinator.budget_usd if coordinator.budget_usd else 0.0
        )
        stage = _stage_for(fraction, bands)
        if stage and mark_warned(f"budget:{ctx.agent_id}:{stage}"):
            logger.warning("[%s] agent %s at %.0f%% of its cost budget", stage, ctx.agent_id, fraction * 100)

        if self._max_turns:
            turn_stage = _stage_for(self._turns / self._max_turns, _TURN_WARN_BANDS)
            if turn_stage and mark_warned(f"turns:{ctx.agent_id}:{turn_stage}"):
                logger.warning(
                    "[%s] agent %s used %d/%d turns", turn_stage, ctx.agent_id, self._turns, self._max_turns,
                )


def demo() -> None:
    from docket.report.state import reset_report_state

    reset_report_state()
    assert _stage_for(0.10, _ROOT_BUDGET_WARN_BANDS) is None
    assert _stage_for(0.72, _ROOT_BUDGET_WARN_BANDS) == "NOTICE"
    assert _stage_for(0.88, _ROOT_BUDGET_WARN_BANDS) == "URGENT"
    assert _stage_for(0.99, _ROOT_BUDGET_WARN_BANDS) == "CRITICAL"
    # Subagents escalate faster than root at the same spend: at 81% a child is already
    # URGENT while root is still only at NOTICE.
    assert _stage_for(0.81, _SUBAGENT_BUDGET_WARN_BANDS) == "URGENT"
    assert _stage_for(0.81, _ROOT_BUDGET_WARN_BANDS) == "NOTICE"
    assert _stage_for(0.86, _SUBAGENT_BUDGET_WARN_BANDS) == "CRITICAL"
    assert _stage_for(0.86, _ROOT_BUDGET_WARN_BANDS) == "URGENT"

    class _U:
        input_tokens, output_tokens = 1000, 500

    assert estimate_cost("anthropic/claude-sonnet-4-5-20250929", _U()) > 0
    assert estimate_cost("totally-made-up-xyz", _U()) == 0.0
    assert estimate_cost("anthropic/claude-sonnet-4-5-20250929", None) == 0.0
    reset_report_state()
    print("core.hooks: ok")


if __name__ == "__main__":
    demo()
