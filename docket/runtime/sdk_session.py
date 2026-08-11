"""Adapts docket's Docker sandbox to the SDK's BaseSandboxSession interface.

This is what lets SandboxAgent's NATIVE tools — shell and the filesystem/apply_patch
toolset — execute inside our container instead of wherever the SDK would otherwise put
them. It's the reason upstream Docket's tools/shell/, apply_patch/ and view_image/
directories contain only a README: those tools come from the SDK, and the sandbox
session is the seam that points them at a real container.

Only six methods are abstract, all of which our RPC shim already exposes (or now does):
_exec_internal, read, write, running, hydrate_workspace, persist_workspace. All six are
async on the base class, and every one of them ends up in a blocking HTTP call to the
shim — so each goes through asyncio.to_thread rather than stalling the event loop that
the other agents are running on.
"""
from __future__ import annotations

import asyncio
import base64
import io
import logging
import tarfile
from pathlib import Path
from typing import Any

from agents.sandbox.manifest import Manifest
from agents.sandbox.session.base_sandbox_session import BaseSandboxSession
from agents.sandbox.session.sandbox_session_state import SandboxSessionState
from agents.sandbox.snapshot import NoopSnapshot
from agents.sandbox.types import ExecResult

logger = logging.getLogger(__name__)

WORKSPACE = "/work"


class DocketSandboxSession(BaseSandboxSession):
    """Backs the SDK's sandbox capabilities with docket's container RPC shim."""

    def __init__(self, sandbox: Any) -> None:
        super().__init__()
        self._sandbox = sandbox
        # The SDK's session manager reads `state` directly (manifest root, snapshot,
        # workspace readiness). NoopSnapshot is the honest choice here: docket runs one
        # container per scan and never resumes one, so there is no snapshot to restore
        # — and a snapshot implementation that pretended otherwise would silently do
        # nothing. Manifest root is /work, matching the container's WORKSPACE.
        self.state = SandboxSessionState(
            type="docket",
            snapshot=NoopSnapshot(id=f"docket-{id(sandbox):x}"),
            manifest=Manifest(root=WORKSPACE),
        )

    # -- execution ---------------------------------------------------------------

    async def _exec_internal(self, *command: str | Path, timeout: float | None = None) -> ExecResult:
        # argv, not a shell string: the SDK hands us an argument vector, and pushing it
        # through `bash -lc` would re-introduce exactly the quoting bugs argv avoids.
        result = await asyncio.to_thread(
            self._sandbox.call, "exec_argv", argv=[str(c) for c in command],
            timeout_sec=timeout, rpc_timeout=(timeout or 60) + 30,
        )
        if "error" in result:
            return ExecResult(stdout=b"", stderr=str(result["error"]).encode(), exit_code=1)
        return ExecResult(
            stdout=base64.b64decode(result.get("stdout_b64", "")),
            stderr=base64.b64decode(result.get("stderr_b64", "")),
            exit_code=int(result.get("exit_code", 1)),
        )

    async def running(self) -> bool:
        return getattr(self._sandbox, "port", None) is not None

    # -- filesystem --------------------------------------------------------------

    async def read(self, path: Path, *, user: str | Any | None = None) -> io.IOBase:
        result = await asyncio.to_thread(self._sandbox.call, "read_file", path=str(path))
        if "error" in result:
            raise FileNotFoundError(f"{path}: {result['error']}")
        return io.BytesIO(base64.b64decode(result.get("b64", "")))

    async def write(self, path: Path, data: io.IOBase, *, user: str | Any | None = None) -> None:
        payload = data.read()
        if isinstance(payload, str):
            payload = payload.encode()
        result = await asyncio.to_thread(
            self._sandbox.call, "write_file", path=str(path),
            b64=base64.b64encode(payload).decode(),
        )
        if "error" in result:
            raise OSError(f"{path}: {result['error']}")

    # -- workspace snapshot ------------------------------------------------------

    async def persist_workspace(self) -> io.IOBase:
        """Tar the workspace out of the container. Used by the SDK for resume; docket
        runs one scan per container, so this exists to satisfy the interface and to
        make a run's workspace inspectable, not as a resume mechanism."""
        result = await asyncio.to_thread(
            self._sandbox.call, "exec_argv",
            argv=["tar", "-cf", "-", "-C", WORKSPACE, "."], rpc_timeout=120,
        )
        return io.BytesIO(base64.b64decode(result.get("stdout_b64", "")) if "error" not in result else b"")

    async def hydrate_workspace(self, data: io.IOBase) -> None:
        raw = data.read()
        if not raw:
            return
        # Unpack host-side into the bind-mounted run dir, which is the same filesystem
        # the container sees — no need to stream a tar back through the RPC.
        target = Path(self._sandbox.run_dir)
        try:
            with tarfile.open(fileobj=io.BytesIO(raw)) as tar:
                tar.extractall(target, filter="data")  # filter= guards path traversal
        except (tarfile.TarError, OSError) as exc:
            logger.warning("could not hydrate workspace: %s", exc)


def demo() -> None:
    """Structural check only — a live container round-trip is covered by
    tests/test_sdk_sandbox.py, which needs Docker."""
    abstract = getattr(BaseSandboxSession, "__abstractmethods__", frozenset())
    for name in abstract:
        assert not getattr(getattr(DocketSandboxSession, name), "__isabstractmethod__", False), name
    assert not getattr(DocketSandboxSession, "__abstractmethods__", frozenset()), (
        "DocketSandboxSession still has unimplemented abstract methods"
    )
    print("runtime.sdk_session: ok (all abstract methods implemented)")


if __name__ == "__main__":
    demo()
