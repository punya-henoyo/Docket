"""Pure input builders for docket scan runs.

Everything here is a pure function of (config, model string) -> request settings, with
no I/O, so the model-capability branching is testable without touching a provider.
"""
from __future__ import annotations

from typing import Any

from agents.model_settings import ModelSettings

from docket.config.models import (
    is_openrouter_model,
    model_supports_prompt_caching,
    model_supports_reasoning,
    openrouter_attribution_headers,
    request_timeout_extra_args,
)

DEFAULT_MAX_TURNS = 20


def build_model_settings(
    model: str,
    *,
    temperature: float | None = None,
    max_tokens: int | None = None,
    reasoning_effort: str | None = "medium",
    parallel_tool_calls: bool = True,
    tool_choice: str | None = "required",
) -> ModelSettings:
    """Only set fields the model actually supports — asking a non-reasoning model for
    a reasoning config is a request error, not a graceful no-op.

    `tool_choice="required"` is load-bearing, not tuning. Agent.output_type is
    AgentFinalOutput, so the SDK ends a run the moment the model emits ANY message
    matching that schema — before the finish-tool gate in factory.py is consulted.
    The first live-model run hit this on turn one: root replied with a plain
    {"summary": "...I need to spawn three specialists...", "findings": [], "success":
    true} narrating its plan, and the scan "finished" having spawned nobody and
    tested nothing. Forcing a tool call every turn removes the bare-message exit, so
    finish_scan/agent_finish become the only way to stop. This is the README's
    "agents can stop without a finish tool" limit, closed.
    """
    settings: dict[str, Any] = {"parallel_tool_calls": parallel_tool_calls}
    if tool_choice is not None:
        settings["tool_choice"] = tool_choice
    if temperature is not None:
        settings["temperature"] = temperature
    if max_tokens is not None:
        settings["max_tokens"] = max_tokens
    if reasoning_effort and model_supports_reasoning(model):
        settings["reasoning"] = {"effort": reasoning_effort}
    if model_supports_prompt_caching(model):
        # Every agent re-sends a long, identical system prompt each turn; on
        # Anthropic-family routes that prefix bills far cheaper when cached.
        settings["prompt_cache_retention"] = "in_memory"
    return ModelSettings(**settings)


def build_extra_args(model: str, *, timeout_sec: float = 600.0) -> dict[str, Any]:
    """Provider-specific kwargs passed through LiteLLM."""
    extra: dict[str, Any] = dict(request_timeout_extra_args(timeout_sec))
    if is_openrouter_model(model):
        extra["extra_headers"] = openrouter_attribution_headers()
    return extra


def build_task_input(target_url: str, instruction: str | None, extra_lines: list[str] | None = None) -> str:
    lines = [f"Target: {target_url}"]
    lines.extend(extra_lines or [])
    if instruction:
        lines.append(f"Extra context from the operator: {instruction}")
    return "\n".join(lines)


def demo() -> None:
    claude = build_model_settings("anthropic/claude-sonnet-5", temperature=0.2, max_tokens=4096)
    assert claude.temperature == 0.2 and claude.max_tokens == 4096
    assert claude.reasoning is not None                # reasoning-capable
    assert claude.prompt_cache_retention == "in_memory"  # caching-capable

    # The bare-message exit must be closed by DEFAULT, on every model — a run that
    # can stop without calling a finish tool reports "success" having done nothing.
    assert claude.tool_choice == "required", claude.tool_choice
    assert build_model_settings("openai/DeepSeek-V4-Pro").tool_choice == "required"
    assert build_model_settings("x/y", tool_choice=None).tool_choice is None

    legacy = build_model_settings("openai/gpt-3.5-turbo")
    assert legacy.reasoning is None, "non-reasoning model must not get a reasoning config"
    assert legacy.prompt_cache_retention is None

    off = build_model_settings("anthropic/claude-sonnet-5", reasoning_effort=None)
    assert off.reasoning is None

    assert build_extra_args("anthropic/claude-sonnet-5")["timeout"] == 600.0
    assert "extra_headers" in build_extra_args("openrouter/anthropic/claude-sonnet-5")
    assert "extra_headers" not in build_extra_args("openai/gpt-5.4")

    task = build_task_input("http://x", "creds are a/b", ["- GET /search"])
    assert "Target: http://x" in task and "- GET /search" in task and "creds are a/b" in task
    assert "operator" not in build_task_input("http://x", None)
    print("core.inputs: ok")


if __name__ == "__main__":
    demo()
