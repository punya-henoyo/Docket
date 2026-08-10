"""M6 check: the Docker sandbox and its RPC shim, end to end.

Requires Docker running and vulnshop live on the host at 127.0.0.1:5000. Builds the
image on first run (~30s), then starts one container and drives real tools through it.

Run: uv run python tests/test_sandbox.py
"""
from __future__ import annotations

import asyncio
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from mock_model import ScriptedModel
from docket.config import Config, run_dir
from docket.core.execution import ScanContext, run_agent_loop
from docket.report.dedupe import FindingStore
from docket.roles.factory import build_agent
from docket.runtime.sandbox import HOST_ALIAS, Sandbox, rewrite_for_container

HOST_TARGET = "http://127.0.0.1:5000"


def test_rewrite_for_container() -> None:
    assert rewrite_for_container("http://127.0.0.1:5000/login") == f"http://{HOST_ALIAS}:5000/login"
    assert rewrite_for_container("http://localhost:5000") == f"http://{HOST_ALIAS}:5000"
    assert rewrite_for_container("http://127.0.0.1:5000") == f"http://{HOST_ALIAS}:5000"
    # A real remote host must be left alone.
    assert rewrite_for_container("http://example.com/x") == "http://example.com/x"


def test_sandbox_shell_http_and_sqlmap() -> None:
    target = rewrite_for_container(HOST_TARGET)
    directory = run_dir("m6-sandbox-test")
    with Sandbox(directory / "sandbox") as sb:
        # 1. shell works, and the pinned sqlmap is present.
        version = sb.call("shell", command="python3 /opt/sqlmap/sqlmap.py --version")
        assert version["exit_code"] == 0, version
        assert version["stdout"].strip().startswith("1.9"), version

        # 2. A failing command reports its exit code rather than blowing up the shim.
        assert sb.call("shell", command="exit 7")["exit_code"] == 7

        # 3. An exception inside a tool comes back as an error, shim still alive.
        broken = sb.call("shell", nonexistent_kwarg=1)
        assert "error" in broken, broken
        assert sb.call("shell", command="echo alive")["stdout"].strip() == "alive"

        # 4. http_request from INSIDE the container reaches the host's app, and the
        #    V1 auth bypass still works through the RPC hop.
        bypass = sb.call(
            "http_request", method="POST", url=f"{target}/login",
            data={"username": "admin' -- ", "password": "wrong"},
        )
        assert bypass["status_code"] == 200 and "Welcome" in bypass["body"], bypass

        # 5. Output bounding spools oversized output to the bind-mounted run dir and
        #    output_get pages it back.
        big = sb.call("shell", command="head -c 20000 /dev/zero | tr '\\0' 'A'")
        assert big["truncated"] is True and big["output_ref"], big
        page = sb.call("output_get", ref=big["output_ref"], offset=0, limit=50)
        assert page["text"] == "A" * 50, page
        # The artifact is on the HOST side already, via the bind mount — no copy-out.
        spooled = directory / "sandbox" / "artifacts" / "output" / f"{big['output_ref']}.txt"
        assert spooled.exists(), f"expected bind-mounted artifact at {spooled}"

        # 6. THE M6 GOAL: real external tooling confirms V1 from inside the container.
        #    See docket/roles/prompts/specialist.py for why these flags are required.
        sqlmap = sb.call(
            "shell",
            command=(
                "python3 /opt/sqlmap/sqlmap.py "
                f"-u {target}/login "
                '--data="username=admin&password=admin123" '
                "-p username --ignore-code=401 --string=Welcome --batch "
                "--flush-session --technique=B --level=1 --risk=1 --dbms=sqlite"
            ),
            timeout_sec=120,
        )
        out = sqlmap["stdout"]
        assert "is vulnerable" in out or "injectable" in out, out[-1500:]
        assert "boolean-based blind" in out, out[-1500:]
        assert "back-end DBMS: SQLite" in out, out[-1500:]

    # Container is gone after the context manager exits.
    assert sb.port is None
    shutil.rmtree(directory, ignore_errors=True)


def test_shell_tool_refuses_to_run_on_the_host() -> None:
    """The safety boundary: with no sandbox, `shell` must refuse outright rather than
    quietly executing an LLM-authored command on the operator's own machine."""
    import os

    os.environ.setdefault("DOCKET_LLM", "anthropic/claude-sonnet-4-5-20250929")
    cfg = Config.from_env()
    store = FindingStore()
    context = ScanContext(
        target_url=HOST_TARGET, run_dir=run_dir("m6-no-sandbox"), on_finding=store.add,
        agent_id="solo", role="sqli", config=cfg, sandbox=None,
    )
    marker = Path("/tmp/docket-should-never-exist")
    script = [
        ("shell", {"command": f"touch {marker}"}),
        ("agent_finish", {"summary": "tried shell without a sandbox", "findings": [], "success": True}),
    ]
    agent = build_agent("sqli", cfg, model=ScriptedModel(script))
    asyncio.run(run_agent_loop(agent, context, "probe", max_turns=6))
    assert not marker.exists(), "shell executed on the HOST — that must never happen"


if __name__ == "__main__":
    test_rewrite_for_container()
    test_shell_tool_refuses_to_run_on_the_host()
    test_sandbox_shell_http_and_sqlmap()
    print("test_sandbox: ok — shim RPC, container->host HTTP, output paging, and sqlmap-confirmed V1")
