"""SDK run hooks used by docket orchestration.

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
import os
import sys
from typing import TYPE_CHECKING, Any

from agents.lifecycle import RunHooks

from docket.interface.tui.backend.messages import get_emitter
from docket.report.state import get_global_report_state, mark_warned

if TYPE_CHECKING:
    from agents.items import ModelResponse

logger = logging.getLogger(__name__)

_STAGE_LABELS: tuple[str, ...] = ("HEADS-UP", "TIGHT", "LAST-CALL")
_TURN_WARN_BANDS: tuple[float, ...] = (0.65, 0.85, 0.95)
_ROOT_BUDGET_WARN_BANDS: tuple[float, ...] = (0.65, 0.85, 0.95)
# Subagents are warned earlier and more tightly than root: a child that overruns
# strands its findings, while root only needs enough headroom to aggregate.
_SUBAGENT_BUDGET_WARN_BANDS: tuple[float, ...] = (0.60, 0.78, 0.90)


class BudgetExceeded(Exception):
    """Raised by the pre-turn budget check. Terminal, never retried — a retry would
    just hit the same wall and bill another turn for the privilege."""


def _stage_for(fraction: float, bands: tuple[float, ...]) -> str | None:
    stage = None
    for label, threshold in zip(_STAGE_LABELS, bands, strict=False):
        if fraction >= threshold:
            stage = label
    return stage


def manual_rates() -> tuple[float, float] | None:
    """(input, output) USD per MILLION tokens from DOCKET_PRICE_INPUT_PER_1M /
    DOCKET_PRICE_OUTPUT_PER_1M, or None when unset.

    Per-million is how providers quote, so the number copied off a pricing page goes
    in as-is with no unit conversion to get wrong. Both must be set: pricing only one
    side would under-report every turn and hand back a budget that silently lets a run
    overspend, which is worse than the honest $0.
    """
    raw_in = os.environ.get("DOCKET_PRICE_INPUT_PER_1M", "").strip()
    raw_out = os.environ.get("DOCKET_PRICE_OUTPUT_PER_1M", "").strip()
    if not raw_in or not raw_out:
        return None
    try:
        return float(raw_in), float(raw_out)
    except ValueError:
        if mark_warned("bad-manual-price"):
            print(
                f"warning: DOCKET_PRICE_INPUT_PER_1M / _OUTPUT_PER_1M are not numbers "
                f"({raw_in!r}, {raw_out!r}) — ignoring them.",
                file=sys.stderr,
            )
        return None


def estimate_cost(model: str, usage: Any) -> float:
    """Dollar cost of one model turn.

    LiteLLM's pricing tables first, since those are the provider's real numbers. They
    miss any model LiteLLM does not know — notably a custom Azure AI Foundry
    DEPLOYMENT name, which is arbitrary text, so `openai/DeepSeek-V4-Pro` is unpriced
    however well-known the underlying model is.

    Without a price, budget enforcement silently becomes a no-op and max_turns is the
    only ceiling. DOCKET_PRICE_*_PER_1M closes that: set the two rates off your
    provider's pricing page and both the report and the pre-turn budget gate work
    again. Still 0.0 (and a one-time warning) when neither source knows the model —
    a fabricated number would be worse than an explicit zero.
    """
    if usage is None:
        return 0.0
    prompt_tokens = getattr(usage, "input_tokens", 0) or 0
    completion_tokens = getattr(usage, "output_tokens", 0) or 0
    try:
        import litellm

        prompt_cost, completion_cost = litellm.cost_per_token(
            model=model,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
        )
        return prompt_cost + completion_cost
    except Exception:
        rates = manual_rates()
        if rates is not None:
            per_in, per_out = rates
            if mark_warned(f"manual-priced:{model}"):
                print(
                    f"note: {model!r} is unpriced by LiteLLM; using DOCKET_PRICE_*_PER_1M "
                    f"(${per_in}/M in, ${per_out}/M out) so the budget stays enforceable.",
                    file=sys.stderr,
                )
            return (prompt_tokens * per_in + completion_tokens * per_out) / 1_000_000
        if mark_warned(f"unpriced:{model}"):
            print(
                f"warning: no LiteLLM pricing data for {model!r} and no "
                f"DOCKET_PRICE_INPUT_PER_1M / _OUTPUT_PER_1M set — cost budget cannot be "
                f"enforced; --max-steps/max_turns is the only ceiling.",
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
        # Token accounting is recorded even when cost is unavailable — an unpriced
        # model still tells you which agent did the work.
        get_global_report_state().usage.record(
            ctx.agent_id, response.usage, cost_usd=usd, role=ctx.role, model=config.llm,
        )
        if usd:
            await coordinator.record_spend(ctx.agent_id, usd)
        totals = get_global_report_state().usage.totals()
        get_emitter().usage(totals["cost_usd"], totals["total_tokens"])

    async def on_tool_start(self, context, agent, tool) -> None:
        # Emitting from RunHooks rather than wrapping each tool: one place covers all
        # 14 tools, and a tool added later is instrumented for free.
        ctx = context.context
        get_emitter().tool_call(
            getattr(ctx, "agent_id", "root"), getattr(ctx, "role", "root"),
            getattr(tool, "name", str(tool)), {},
        )

    async def on_tool_end(self, context, agent, tool, result) -> None:
        ctx = context.context
        name = getattr(tool, "name", str(tool))
        get_emitter().tool_result(
            getattr(ctx, "agent_id", "root"), getattr(ctx, "role", "root"), name, result,
        )

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
    assert _stage_for(0.72, _ROOT_BUDGET_WARN_BANDS) == "HEADS-UP"
    assert _stage_for(0.88, _ROOT_BUDGET_WARN_BANDS) == "TIGHT"
    assert _stage_for(0.99, _ROOT_BUDGET_WARN_BANDS) == "LAST-CALL"
    # Subagents escalate faster than root at the same spend: at 79% a child is already
    # TIGHT while root is still only at HEADS-UP.
    assert _stage_for(0.79, _SUBAGENT_BUDGET_WARN_BANDS) == "TIGHT"
    assert _stage_for(0.79, _ROOT_BUDGET_WARN_BANDS) == "HEADS-UP"
    assert _stage_for(0.91, _SUBAGENT_BUDGET_WARN_BANDS) == "LAST-CALL"
    assert _stage_for(0.91, _ROOT_BUDGET_WARN_BANDS) == "TIGHT"

    class _U:
        input_tokens, output_tokens = 1000, 500

    assert estimate_cost("anthropic/claude-sonnet-4-5-20250929", _U()) > 0
    assert estimate_cost("totally-made-up-xyz", _U()) == 0.0

    # Manual per-1M rates rescue an unpriced model (a custom Azure deployment name is
    # arbitrary text, so LiteLLM will never know it) — without which the budget gate
    # is a silent no-op.
    saved = {k: os.environ.pop(k, None)
             for k in ("DOCKET_PRICE_INPUT_PER_1M", "DOCKET_PRICE_OUTPUT_PER_1M")}
    try:
        assert manual_rates() is None
        os.environ["DOCKET_PRICE_INPUT_PER_1M"] = "0.28"
        assert manual_rates() is None, "one-sided pricing must be refused, not half-applied"
        os.environ["DOCKET_PRICE_OUTPUT_PER_1M"] = "0.42"
        assert manual_rates() == (0.28, 0.42)
        # 1000 in @ $0.28/M + 500 out @ $0.42/M = 0.00028 + 0.00021
        got = estimate_cost("totally-made-up-xyz", _U())
        assert abs(got - 0.00049) < 1e-9, got
        # A real LiteLLM price still wins over the manual override.
        assert estimate_cost("anthropic/claude-sonnet-4-5-20250929", _U()) != got

        os.environ["DOCKET_PRICE_INPUT_PER_1M"] = "not-a-number"
        assert manual_rates() is None  # garbage is ignored, never crashes a scan
    finally:
        for key, value in saved.items():
            if value is not None:
                os.environ[key] = value
            else:
                os.environ.pop(key, None)
    assert estimate_cost("anthropic/claude-sonnet-4-5-20250929", None) == 0.0
    reset_report_state()
    print("core.hooks: ok")


if __name__ == "__main__":
    demo()
