"""Model-aware token budgets, resolved from LiteLLM model metadata with a large
configurable fallback for models LiteLLM doesn't map. Mirrors docket/llm/context_budget.py.

Why this exists: the run loop needs to know "is this conversation about to overflow?"
BEFORE sending it, because a context-window error costs a full round trip and, for a
long agent run, tends to recur every turn afterwards. Asking LiteLLM for the model's
real window is cheaper and more accurate than a hardcoded guess.
"""
from __future__ import annotations

import logging
from functools import lru_cache

logger = logging.getLogger(__name__)

# LiteLLM keys its metadata without the routing prefix users type. Strip a leading
# provider segment on lookup so "openrouter/anthropic/claude-x" still resolves.
_STRIPPABLE_PREFIXES = (
    "openai/", "azure/", "anthropic/", "openrouter/", "litellm/", "ollama/",
    "vertex_ai/", "bedrock/", "together_ai/", "groq/", "mistral/", "deepseek/",
)

# Used when LiteLLM has no metadata for a model. Deliberately large: under-guessing
# would trigger constant needless compaction, which costs a summarisation call each
# time and throws away detail the agent may still need.
DEFAULT_MAX_INPUT_TOKENS = 200_000

# Fraction of the window we're willing to fill before compacting. The headroom covers
# the reply itself plus the tool schemas resent every turn.
USABLE_FRACTION = 0.75

# Rough chars-per-token for a pre-flight estimate. Only used to decide WHETHER to
# compact, never to bill anything — real token counts come back in the response usage.
CHARS_PER_TOKEN = 4


def _candidates(model: str) -> list[str]:
    seen, out = set(), []
    for candidate in (model, *(model[len(p):] for p in _STRIPPABLE_PREFIXES if model.startswith(p))):
        if candidate and candidate not in seen:
            seen.add(candidate)
            out.append(candidate)
    # "openrouter/anthropic/claude-x" -> also try the last segment pair
    if model.count("/") >= 2:
        tail = model.split("/", 1)[1]
        if tail not in seen:
            out.append(tail)
    return out


@lru_cache(maxsize=64)
def max_input_tokens(model: str) -> int:
    """The model's input window, or DEFAULT_MAX_INPUT_TOKENS if LiteLLM can't map it."""
    try:
        import litellm
    except ImportError:  # pragma: no cover
        return DEFAULT_MAX_INPUT_TOKENS

    for candidate in _candidates(model):
        try:
            info = litellm.get_model_info(candidate)
        except Exception:
            continue
        value = info.get("max_input_tokens") or info.get("max_tokens")
        if value:
            return int(value)
    logger.debug("no LiteLLM context metadata for %r; using fallback", model)
    return DEFAULT_MAX_INPUT_TOKENS


def usable_tokens(model: str, *, fraction: float = USABLE_FRACTION) -> int:
    return int(max_input_tokens(model) * fraction)


def estimate_tokens(items: object) -> int:
    """Cheap pre-flight size estimate for a conversation. Character-based on purpose:
    a real tokenizer would need the provider's exact encoding, cost real time every
    turn, and still only decide the same yes/no question."""
    return max(0, len(str(items)) // CHARS_PER_TOKEN)


def over_budget(model: str, items: object, *, fraction: float = USABLE_FRACTION) -> bool:
    return estimate_tokens(items) > usable_tokens(model, fraction=fraction)


def demo() -> None:
    claude = max_input_tokens("anthropic/claude-sonnet-4-5-20250929")
    assert claude == 200_000, claude
    # Prefix stripping: the bare form resolves to the same window.
    assert max_input_tokens("claude-sonnet-4-5-20250929") == claude
    assert max_input_tokens("openai/gpt-4o") == 128_000
    # Unknown models fall back rather than raising.
    assert max_input_tokens("totally-made-up-model-zzz") == DEFAULT_MAX_INPUT_TOKENS

    assert usable_tokens("openai/gpt-4o") == 96_000  # 128k * 0.75
    assert estimate_tokens("x" * 4000) == 1000
    assert not over_budget("openai/gpt-4o", "short conversation")
    assert over_budget("openai/gpt-4o", "x" * (4 * 96_000 + 8))
    print("llm.context_budget: ok")


if __name__ == "__main__":
    demo()
