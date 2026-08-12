"""Env/config for a docket run: LLM routing, budgets, and where run artifacts land.

Everything here is scan-wide and constant across a process run. Per-invocation values
(target URL, instruction) are CLI args / function params, not env vars — see
docket/core/runner.py.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from agents import set_tracing_disabled
from dotenv import load_dotenv

from docket.core.paths import run_path, runs_root

load_dotenv()

# docket runs via LiteLLM, not the OpenAI API — the SDK's default trace export target
# is OpenAI's platform, which is both irrelevant here and not what "nothing leaves
# your machine" (this project's own reporting philosophy) should allow by default.
set_tracing_disabled(True)

# Runs land under the CURRENT WORKING DIRECTORY, not next to the source. Deriving it from __file__ put artifacts inside the installed
# package once config.py became config/settings.py — a silent relocation that would
# also have shipped run data inside a wheel.
RUNS_DIR = runs_root()


@dataclass(slots=True)
class Config:
    llm: str
    llm_api_key: str | None
    max_cost_usd: float
    max_child_cost_usd: float
    max_agents: int
    # Self-hosted or proxied models (a company gateway, vLLM, Ollama, an
    # OpenAI-compatible reseller) are reachable only by overriding the provider's
    # default host. Without this, DOCKET_LLM can name any provider LiteLLM knows but
    # can never point at your own deployment of it.
    llm_base_url: str | None = None

    @classmethod
    def from_env(cls) -> "Config":
        llm = os.environ.get("DOCKET_LLM")
        if not llm:
            raise RuntimeError(
                "DOCKET_LLM is not set — e.g. export DOCKET_LLM=anthropic/claude-sonnet-5"
            )
        return cls(
            llm=llm,
            llm_api_key=os.environ.get("LLM_API_KEY"),
            llm_base_url=os.environ.get("DOCKET_LLM_BASE_URL") or None,
            max_cost_usd=float(os.environ.get("DOCKET_MAX_COST_USD", "2.00")),
            max_child_cost_usd=float(os.environ.get("DOCKET_MAX_CHILD_COST_USD", "0.75")),
            max_agents=int(os.environ.get("DOCKET_MAX_AGENTS", "6")),
        )


def run_dir(run_name: str) -> Path:
    """Directory a given run's artifacts (findings/, artifacts/, report.json, ...) live
    under. Layout itself is owned by docket/core/paths.py; this just creates it."""
    path = run_path(run_name)
    path.mkdir(parents=True, exist_ok=True)
    return path


def demo() -> None:
    os.environ["DOCKET_LLM"] = "anthropic/claude-sonnet-5"
    cfg = Config.from_env()
    assert cfg.llm == "anthropic/claude-sonnet-5"
    assert cfg.max_agents == 6
    d = run_dir("selftest")
    assert d.exists() and d.name == "selftest"
    d.rmdir()
    print("config: ok")


if __name__ == "__main__":
    demo()
