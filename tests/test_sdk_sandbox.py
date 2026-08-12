"""R5 check: SandboxAgent + the SDK-native sandbox session bound to our container.

These capabilities are HOSTED tools that only OpenAI's Responses API accepts, so
build_agent gates them behind supports_hosted_tools(model). That check is what every
LiteLLM-routed provider depends on, and it is pinned both ways below.

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

from docket.agents.factory import build_agent
from docket.config.settings import Config, run_dir
from docket.runtime.sandbox import Sandbox
from docket.runtime.sdk_session import DocketSandboxSession


def _config() -> Config:
    os.environ.setdefault("DOCKET_LLM", "anthropic/claude-sonnet-4-5-20250929")
    return Config.from_env()


def test_chatcompletions_model_gets_a_plain_agent_even_with_a_sandbox() -> None:
    """The regression that killed the first live run. A LiteLLM-routed model speaks Chat
    Completions, where hosted tools cannot be serialized at all — the SDK raises before
    turn one. So a sandboxed agent on such a model must NOT be a SandboxAgent, and our
    own container-backed shell must survive, because that is what does the work."""
    from docket.agents.factory import build_agent, supports_hosted_tools

    agent = build_agent("sqli", _config(), sandbox=object())
    assert not supports_hosted_tools(agent.model), "a LitellmModel must not claim hosted tools"
    assert not isinstance(agent, SandboxAgent), type(agent)
    assert "shell" in {t.name for t in agent.tools}


def test_plain_agent_without_sandbox() -> None:
    """No container means no SDK-native shell/filesystem — those tools would have
    nowhere safe to run, so we must NOT hand the model capabilities it can't use."""
    agent = build_agent("sqli", _config())
    assert type(agent) is Agent, type(agent)
    assert not isinstance(agent, SandboxAgent)


def test_native_session_drives_the_container() -> None:
    """The SDK-native session bound to our container.

    No SandboxAgent assertion here any more: build_agent only produces one for a model
    that supports hosted tools, which no LiteLLM-routed model does, and _config() is
    LiteLLM. The session itself is the part worth pinning — it is what binds the SDK's
    exec/read/write primitives to a real docket container, and it works regardless of
    which Agent class the factory chose.
    """
    directory = run_dir("r5-sdk-session")
    try:
        with Sandbox(directory / "sandbox") as sb:
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
    test_chatcompletions_model_gets_a_plain_agent_even_with_a_sandbox()
    test_plain_agent_without_sandbox()
    test_native_session_drives_the_container()
    print("test_sdk_sandbox: ok — hosted-tool gating + the native session driving the container")
