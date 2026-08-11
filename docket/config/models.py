"""Model capability detection. Mirrors docket/config/models.py.

LiteLLM lets any provider/model string through, but the SDK request we build has to
match what that model actually supports — asking a non-reasoning model for a reasoning
config, or a Chat-Completions-only route for Responses-style tool schemas, is a
request-time error rather than a graceful degradation. Everything here is a pure
string/lookup predicate so it stays testable without a network call.
"""
from __future__ import annotations

DEFAULT_MODEL_RETRY = 2

# LiteLLM addresses models as "<provider>/<model>"; a bare name means OpenAI.
_REASONING_HINTS = ("o1", "o3", "o4", "gpt-5", "claude-sonnet-4", "claude-opus-4",
                    "claude-sonnet-5", "claude-opus-5", "gemini-3", "grok-4")
_KNOWN_OPENAI_BARE = ("gpt-4", "gpt-4o", "gpt-4.1", "gpt-5", "o1", "o3", "o4")


def split_model(model: str) -> tuple[str, str]:
    """"anthropic/claude-sonnet-5" -> ("anthropic", "claude-sonnet-5")."""
    provider, _, name = model.partition("/")
    if not name:
        return "openai", provider  # bare name = OpenAI, per LiteLLM convention
    return provider.lower(), name


def provider_of(model: str) -> str:
    return split_model(model)[0]


def is_claude_model(model: str) -> bool:
    provider, name = split_model(model)
    return provider in {"anthropic", "bedrock", "vertex_ai"} and "claude" in name.lower()


def is_openrouter_model(model: str) -> bool:
    return provider_of(model) == "openrouter"


def is_bedrock_route(model: str) -> bool:
    return provider_of(model) == "bedrock"


def is_known_openai_bare_model(model: str) -> bool:
    provider, name = split_model(model)
    return provider == "openai" and any(name.startswith(p) for p in _KNOWN_OPENAI_BARE)


def model_supports_reasoning(model: str) -> bool:
    name = split_model(model)[1].lower()
    return any(hint in name for hint in _REASONING_HINTS)


def model_supports_prompt_caching(model: str) -> bool:
    """Anthropic-family models bill cached prompt prefixes far cheaper — worth turning
    on given every agent re-sends a long, identical system prompt each turn."""
    return is_claude_model(model)


def bedrock_route_supports_prompt_caching(model: str) -> bool:
    return is_bedrock_route(model) and is_claude_model(model)


def uses_chat_completions_tool_schema(model: str) -> bool:
    """Non-OpenAI routes go through LiteLLM's Chat-Completions shim, which wants the
    older function-calling schema rather than the Responses-API tool shape."""
    return provider_of(model) not in {"openai", "azure"}


def openrouter_attribution_headers(app_url: str = "https://github.com", title: str = "docket") -> dict[str, str]:
    """OpenRouter asks callers to identify themselves; it is not authentication."""
    return {"HTTP-Referer": app_url, "X-Title": title}


def request_timeout_extra_args(timeout_sec: float = 600.0) -> dict[str, float]:
    return {"timeout": timeout_sec}


def demo() -> None:
    assert split_model("anthropic/claude-sonnet-5") == ("anthropic", "claude-sonnet-5")
    assert split_model("gpt-5.4") == ("openai", "gpt-5.4")  # bare name -> openai
    assert is_claude_model("anthropic/claude-sonnet-5")
    assert is_claude_model("bedrock/anthropic.claude-sonnet-4-v1")
    assert not is_claude_model("openai/gpt-5.4")
    assert model_supports_reasoning("anthropic/claude-sonnet-5")
    assert model_supports_reasoning("openai/o3-mini")
    assert not model_supports_reasoning("openai/gpt-3.5-turbo")
    assert model_supports_prompt_caching("anthropic/claude-sonnet-5")
    assert not model_supports_prompt_caching("openai/gpt-5.4")
    assert uses_chat_completions_tool_schema("anthropic/claude-sonnet-5")
    assert not uses_chat_completions_tool_schema("openai/gpt-5.4")
    assert is_openrouter_model("openrouter/anthropic/claude-sonnet-5")
    assert is_bedrock_route("bedrock/x") and bedrock_route_supports_prompt_caching("bedrock/anthropic.claude-x")
    assert is_known_openai_bare_model("gpt-5.4") and not is_known_openai_bare_model("llama-3")
    assert "HTTP-Referer" in openrouter_attribution_headers()
    assert request_timeout_extra_args()["timeout"] == 600.0
    print("config.models: ok")


if __name__ == "__main__":
    demo()
