"""R5 check: SandboxAgent + the SDK-native sandbox session bound to our container.

OPT-IN since the first live run: these capabilities are hosted tools that only OpenAI's
Responses API accepts, so they are off unless DOCKET_SDK_SANDBOX_TOOLS=1. This test sets
that flag before importing the factory, and also pins the default the other way, because
the default is what every LiteLLM-routed provider depends on.

Agents are built as SandboxAgent with capabilities=[Filesystem, Shell] rather than a
plain Agent, which is why the tools/shell, apply_patch and view_image packages are
README-only: those tools come from the SDK.

Requires Docker. Run: uv run python tests/test_sdk_sandbox.py
"""
from __future__ import annotations

import asyncio
import io
import os
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from agents import Agent
from agents.sandbox import SandboxAgent

os.environ["DOCKET_SDK_SANDBOX_TOOLS"] = "1"  # before the factory reads it at import

from docket.agents.factory import build_agent
from docket.config.settings import Config, run_dir
from docket.runtime.sandbox import Sandbox
from docket.runtime.sdk_session import DocketSandboxSession


def _config() -> Config:
    os.environ.setdefault("DOCKET_LLM", "anthropic/claude-sonnet-4-5-20250929")
    return Config.from_env()


def test_default_is_a_plain_agent_even_with_a_sandbox() -> None:
    """The regression that killed the first live run. With the flag off, a sandboxed
    agent must NOT be a SandboxAgent: its hosted tools cannot be serialized to the Chat
    Completions API, so every non-Responses provider dies before turn one."""
    import docket.agents.factory as factory

    original = factory.SDK_SANDBOX_TOOLS
    factory.SDK_SANDBOX_TOOLS = False
    try:
        agent = factory.build_agent("sqli", _config(), sandbox=object())
        assert not isinstance(agent, SandboxAgent), type(agent)
        # ...and our own container-backed shell survives, which is what does the work.
        assert "shell" in {t.name for t in agent.tools}
    finally:
        factory.SDK_SANDBOX_TOOLS = original


def test_plain_agent_without_sandbox() -> None:
    """No container means no SDK-native shell/filesystem — those tools would have
    nowhere safe to run, so we must NOT hand the model capabilities it can't use."""
    agent = build_agent("sqli", _config())
    assert type(agent) is Agent, type(agent)
    assert not isinstance(agent, SandboxAgent)


def test_sandbox_agent_and_native_session() -> None:
    directory = run_dir("r5-sdk-session")
    try:
        with Sandbox(directory / "sandbox") as sb:
            agent = build_agent("sqli", _config(), sandbox=sb)
            assert isinstance(agent, SandboxAgent), type(agent)
            caps = {type(c).__name__ for c in agent.capabilities}
            assert caps == {"Filesystem", "Shell"}, caps

            session = DocketSandboxSession(sb)
            assert asyncio.run(session.running()) is True

            # argv exec (NOT via a shell) round-trips stdout/stderr/exit code.
            result = asyncio.run(session._exec_internal("sh", "-c", "echo out; echo err >&2; exit 3"))
            assert result.stdout.decode().strip() == "out", result.stdout
            assert b"err" in result.stderr, result.stderr
            assert result.exit_code == 3, result.exit_code

            # A missing binary is reported, not raised — the agent must see the error.
            missing = asyncio.run(session._exec_internal("definitely-not-a-real-binary"))
            assert missing.exit_code == 127, missing

            # Filesystem round-trip, including binary-safe content.
            payload = b"written via SDK session \x00\xff binary-safe"
            asyncio.run(session.write(Path("/work/run/hello.bin"), io.BytesIO(payload)))
            assert asyncio.run(session.read(Path("/work/run/hello.bin"))).read() == payload
            # It landed on the HOST too, through the bind mount.
            assert (directory / "sandbox" / "hello.bin").read_bytes() == payload

            try:
                asyncio.run(session.read(Path("/work/run/nope.txt")))
                raise AssertionError("reading a missing file should raise")
            except FileNotFoundError:
                pass

            # Workspace snapshot produces a real tar stream.
            snapshot = asyncio.run(session.persist_workspace()).read()
            assert len(snapshot) > 0, "expected a non-empty workspace tar"
    finally:
        shutil.rmtree(directory, ignore_errors=True)


if __name__ == "__main__":
    test_default_is_a_plain_agent_even_with_a_sandbox()
    test_plain_agent_without_sandbox()
    test_sandbox_agent_and_native_session()
    print("test_sdk_sandbox: ok — SandboxAgent + Filesystem/Shell capabilities driving the container")
