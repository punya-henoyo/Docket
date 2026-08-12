"""Model-aware token budgets, resolved from LiteLLM model metadata with a large
configurable fallback for models LiteLLM doesn't map. Why this exists: the run loop needs to know "is this conversation about to overflow?"
BEFORE sending it, because a context-window error costs a full round trip and, for a
long agent run, tends to recur every turn afterwards. Asking LiteLLM for the model's
real window is cheaper and more accurate than a hardcoded guess.
"""
from __future__ import annotations

import logging
import os
from functools import lru_cache

from docket.report.state import mark_warned

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


@lru_cache(maxsize=1)
def _tokenizer() -> object | None:
    """The model's real tokenizer, when DOCKET_TOKENIZER_PATH points at a HuggingFace
    tokenizer.json. Cached: loading parses a multi-MB vocabulary.

    Uses the `tokenizers` package directly rather than `transformers` — same encoder,
    a fraction of the install, and nothing here needs a model runtime. Returns None
    (so callers fall back to CHARS_PER_TOKEN) if the var is unset, the file is
    missing, or the package is absent. A pre-flight estimate must never be the thing
    that breaks a scan.
    """
    path = os.environ.get("DOCKET_TOKENIZER_PATH", "").strip()
    if not path:
        return None
    try:
        from tokenizers import Tokenizer

        return Tokenizer.from_file(path)
    except Exception as exc:
        if mark_warned("tokenizer-load"):
            logger.warning("DOCKET_TOKENIZER_PATH=%r unusable (%s); using the "
                           "chars-per-token estimate instead", path, exc)
        return None


def estimate_tokens(items: object) -> int:
    """Pre-flight size estimate for a conversation.

    Real tokenizer when one is configured, characters otherwise. The fallback is
    genuinely poor on the content docket actually carries: measured against DeepSeek
    V4 Pro, chars/4 undercounts JSON tool results by ~38% and raw HTTP dumps by ~40%
    (it overcounts prose by ~10%). Undercounting is the dangerous direction — docket
    believes it is at 60% of the window while it is really at 100%, so compaction
    never fires until the provider rejects the request. That is the README's
    "compaction is reactive" gap, and pointing DOCKET_TOKENIZER_PATH at the model's
    tokenizer.json closes it: the same measurement puts the real encoder within ~2%
    across prose, code, JSON and HTTP.
    """
    text = str(items)
    tokenizer = _tokenizer()
    if tokenizer is not None:
        try:
            return len(tokenizer.encode(text).ids)
        except Exception:  # pragma: no cover — never fail a scan over an estimate
            pass
    return max(0, len(text) // CHARS_PER_TOKEN)


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

    saved = os.environ.pop("DOCKET_TOKENIZER_PATH", None)
    try:
        _tokenizer.cache_clear()
        assert _tokenizer() is None                       # unconfigured -> fallback
        assert estimate_tokens("x" * 4000) == 1000
        assert not over_budget("openai/gpt-4o", "short conversation")
        assert over_budget("openai/gpt-4o", "x" * (4 * 96_000 + 8))

        # A bad path degrades to the estimate rather than raising mid-scan.
        os.environ["DOCKET_TOKENIZER_PATH"] = "/nope/missing.json"
        _tokenizer.cache_clear()
        assert _tokenizer() is None
        assert estimate_tokens("x" * 4000) == 1000

        # The vendored tokenizer, when the optional package is installed. JSON is
        # where chars/4 is worst, so that is what this asserts on.
        from pathlib import Path

        bundled = Path(__file__).resolve().parent / "tokenizers" / "deepseek-v3.json"
        os.environ["DOCKET_TOKENIZER_PATH"] = str(bundled)
        _tokenizer.cache_clear()
        if _tokenizer() is not None:
            payload = '{"rule":"sqli","severity":"high","path":"app.py"}' * 20
            real, rough = estimate_tokens(payload), len(payload) // CHARS_PER_TOKEN
            assert real > rough * 1.25, (real, rough)  # measured gap was ~38%
    finally:
        _tokenizer.cache_clear()
        if saved is not None:
            os.environ["DOCKET_TOKENIZER_PATH"] = saved
        else:
            os.environ.pop("DOCKET_TOKENIZER_PATH", None)
    print("llm.context_budget: ok")


if __name__ == "__main__":
    demo()
