"""Host side of the sandbox: build the image, run one container per scan, and drive
its RPC shim (docket/runtime/server.py) over HTTP.

Deliberate deviation from the original design, which specified the `docker` Python SDK
(docker>=7.1.0): this needs exactly five verbs — image inspect, build, run, port,
stop/rm — and the `docker` CLI is already installed. Shelling out keeps a dependency
out of pyproject.toml and makes every operation copy-pasteable when debugging.
# ponytail: docker via subprocess, not the SDK — revisit only if this starts needing
# streaming logs, exec sessions, or event subscriptions.
"""
from __future__ import annotations

import json
import subprocess
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DOCKERFILE = REPO_ROOT / "containers" / "Dockerfile"
DEFAULT_IMAGE = "docket-sandbox:latest"
SHIM_PORT = 8765

# The container reaches the target app on the host through this hostname. The
# --add-host flag below is a no-op on Docker Desktop (which provides it natively) but
# makes the same code work on Linux — cheaper than branching on platform.system().
#
# Verified on Docker Desktop for Mac: a target bound to the host's 127.0.0.1 IS
# reachable this way, because Docker Desktop proxies host.docker.internal to the host's
# loopback. On native Linux, --add-host=host-gateway resolves to a real bridge IP
# instead, so a 127.0.0.1-only target would NOT be reachable there and would have to be
# bound to 0.0.0.0. Worth knowing before assuming this is portable: it means no
# 0.0.0.0 rebind (and no LAN exposure of an intentionally-vulnerable app) is needed on
# a Mac dev box.
HOST_ALIAS = "host.docker.internal"

# Hostnames that mean "this machine" to the host process but would mean "this
# container" inside the sandbox, so they must be rewritten before an agent uses them.
_LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "0.0.0.0", "::1", "[::1]")


def rewrite_for_container(url: str) -> str:
    """Translate a host-side target URL into one the sandbox can actually reach.

    Without this, an agent inside the container that is handed
    "http://127.0.0.1:5000" dials its own loopback and finds nothing.
    """
    for host in _LOOPBACK_HOSTS:
        for prefix in (f"//{host}:", f"//{host}/"):
            if prefix in url:
                return url.replace(f"//{host}", f"//{HOST_ALIAS}", 1)
        if url.endswith(f"//{host}"):
            return url[: -len(host)] + HOST_ALIAS
    return url


class SandboxError(RuntimeError):
    pass


def _docker(*args: str, timeout: int = 600) -> str:
    proc = subprocess.run(
        ["docker", *args], capture_output=True, text=True, timeout=timeout,
    )
    if proc.returncode != 0:
        raise SandboxError(f"docker {' '.join(args)} failed:\n{proc.stderr.strip()}")
    return proc.stdout.strip()


def image_exists(image: str = DEFAULT_IMAGE) -> bool:
    try:
        _docker("image", "inspect", image, timeout=30)
        return True
    except SandboxError:
        return False


def build_image(image: str = DEFAULT_IMAGE, *, force: bool = False) -> bool:
    """Build the sandbox image if absent. Returns True if a build actually ran."""
    if not force and image_exists(image):
        return False
    if not DOCKERFILE.exists():
        raise SandboxError(f"missing {DOCKERFILE}")
    # Build context is the repo root so the Dockerfile can COPY the docket package in.
    _docker("build", "-f", str(DOCKERFILE), "-t", image, str(REPO_ROOT), timeout=1800)
    return True


class Sandbox:
    """One container per scan run. Fresh each time, so no cross-run state bleed
    (stale cookies, a browser tab left open, a previous run's proxy flows)."""

    def __init__(self, run_dir: Path, *, image: str = DEFAULT_IMAGE, name: str | None = None) -> None:
        self.run_dir = Path(run_dir).resolve()
        self.image = image
        self.name = name or f"docket-{uuid.uuid4().hex[:8]}"
        self.port: int | None = None

    # -- lifecycle ---------------------------------------------------------------

    def start(self, *, health_timeout: float = 30.0) -> "Sandbox":
        self.run_dir.mkdir(parents=True, exist_ok=True)
        build_image(self.image)
        _docker(
            "run", "-d",
            "--name", self.name,
            "--add-host", f"{HOST_ALIAS}:host-gateway",
            # Let Docker pick the host port (and bind it to loopback only) so two runs
            # can coexist instead of fighting over a hardcoded one.
            "-p", f"127.0.0.1::{SHIM_PORT}",
            "-v", f"{self.run_dir}:/work/run",
            "-e", "DOCKET_RUN_DIR=/work/run",
            self.image,
            timeout=120,
        )
        self.port = self._read_port()
        self._await_health(health_timeout)
        return self

    def _read_port(self) -> int:
        mapping = _docker("port", self.name, f"{SHIM_PORT}/tcp", timeout=30)
        # e.g. "127.0.0.1:55001" (possibly several lines, one per address family)
        for line in mapping.splitlines():
            if ":" in line:
                return int(line.rsplit(":", 1)[1])
        raise SandboxError(f"could not read published port from: {mapping!r}")

    def _await_health(self, timeout: float) -> None:
        deadline = time.monotonic() + timeout
        last: Exception | None = None
        while time.monotonic() < deadline:
            try:
                with urllib.request.urlopen(f"{self._base_url}/health", timeout=2) as resp:
                    if resp.status == 200:
                        return
            except Exception as exc:  # container still booting
                last = exc
                time.sleep(0.2)
        logs = ""
        try:
            logs = _docker("logs", "--tail", "20", self.name, timeout=30)
        except SandboxError:
            pass
        raise SandboxError(f"sandbox {self.name} never became healthy ({last!r})\nlogs:\n{logs}")

    def stop(self) -> None:
        # Ask the shim to close its own resources first (a live browser/proxy in later
        # milestones), then tear the container down regardless of whether that worked.
        try:
            self._post("/shutdown", {}, timeout=5)
        except Exception:
            pass
        for args in (("stop", "-t", "3", self.name), ("rm", "-f", self.name)):
            try:
                _docker(*args, timeout=60)
            except SandboxError:
                pass
        self.port = None

    def __enter__(self) -> "Sandbox":
        return self.start()

    def __exit__(self, *exc_info) -> None:
        self.stop()

    # -- RPC ---------------------------------------------------------------------

    @property
    def _base_url(self) -> str:
        if self.port is None:
            raise SandboxError("sandbox is not running — call start() first")
        return f"http://127.0.0.1:{self.port}"

    def _post(self, path: str, payload: dict, timeout: float) -> dict:
        request = urllib.request.Request(
            f"{self._base_url}{path}",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as resp:
                return json.loads(resp.read() or b"{}")
        except urllib.error.HTTPError as exc:
            return json.loads(exc.read() or b"{}")

    def call(self, tool: str, *, rpc_timeout: float | None = None, **args) -> dict:
        """Invoke a sandboxed tool. Returns the tool's own result dict, or
        {"error": ...} if the tool raised inside the container."""
        # Give the RPC a longer ceiling than the tool's own timeout so the tool's
        # timeout is what fires — an RPC that gives up first would leave the tool
        # running and report a misleading transport error.
        if rpc_timeout is None:
            tool_timeout = args.get("timeout_sec", 30)
            rpc_timeout = float(tool_timeout) + 30.0
        payload = self._post("/invoke", {"tool": tool, "args": args}, timeout=rpc_timeout)
        if not payload.get("ok"):
            return {"error": payload.get("error", "unknown sandbox error")}
        return payload["result"]

    def target_url(self, port: int, path: str = "") -> str:
        """Build a URL the CONTAINER can use to reach a service on the host."""
        return f"http://{HOST_ALIAS}:{port}{path}"
