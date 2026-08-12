"""Scan process management for the demo app.

Scans run as SUBPROCESSES, not in-process coroutines. `docket.core.runner.run_scan`
calls `asyncio.run()` internally, which raises if called from inside a running event
loop — which is exactly where a FastAPI handler lives. A subprocess sidesteps that,
and buys process isolation for free: a scan that segfaults inside Playwright cannot
take the demo server down with it, and killing a run is one signal rather than
cooperative cancellation threaded through the agent graph.

The scan writes everything to its run directory anyway (events.jsonl, report.json),
so the parent needs no IPC — it reads the same files the CLI and TUI read.
"""
from __future__ import annotations

import os
import signal
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

from dotenv import load_dotenv

from docket.core.paths import runs_root
from docket.interface.scan_setup import default_run_name, normalize_target, sanitize_run_name

_LOOPBACK = {"127.0.0.1", "localhost", "::1", "0.0.0.0", "host.docker.internal"}
_ALLOW_ANY_ENV = "DOCKET_APP_ALLOW_ANY_TARGET"


def allow_any_target() -> bool:
    """Read the override per call, never once at import.

    A browser button that fires real exploit payloads is a foot-gun on a stage, so the
    default is loopback-only and this is opt-out. But reading it at import meant a
    long-lived server could not be told about it without a restart, and it reported the
    stale value in /api/health too — so the UI insisted the guard was on after you had
    turned it off, with no way to tell which was true.
    """
    load_dotenv(override=True)
    return os.environ.get(_ALLOW_ANY_ENV) == "1"


class TargetRefused(ValueError):
    """Raised for a target the demo server will not point exploit tooling at."""


def check_target(target: str) -> str:
    """Normalise and gate a target. Returns the normalised URL or raises."""
    url = normalize_target(target)
    host = (urlparse(url).hostname or "").lower()
    if not allow_any_target() and host not in _LOOPBACK:
        raise TargetRefused(
            f"refusing to scan {host!r}: the demo server is limited to loopback targets. "
            "docket sends real exploit payloads. Set DOCKET_APP_ALLOW_ANY_TARGET=1 only "
            "for a host you own or are authorised to test."
        )
    return url


@dataclass(slots=True)
class ScanProcess:
    run_name: str
    target: str
    process: subprocess.Popen
    log: Path
    instruction: str | None = None

    @property
    def running(self) -> bool:
        return self.process.poll() is None

    @property
    def exit_code(self) -> int | None:
        return self.process.poll()

    def to_dict(self) -> dict:
        return {
            "run_name": self.run_name, "target": self.target,
            "instruction": self.instruction, "running": self.running,
            "exit_code": self.exit_code,
        }


@dataclass(slots=True)
class ScanManager:
    """Tracks the scans this server started. Not a scheduler: docket runs one scan per
    container and a demo runs one at a time, so concurrent starts are refused rather
    than queued."""

    active: dict[str, ScanProcess] = field(default_factory=dict)

    def current(self) -> ScanProcess | None:
        for scan in self.active.values():
            if scan.running:
                return scan
        return None

    def start(
        self, target: str, *, run_name: str | None = None, instruction: str | None = None,
        max_steps: int = 20, use_sandbox: bool = True, source: str | None = None,
    ) -> ScanProcess:
        if (busy := self.current()) is not None:
            raise RuntimeError(f"a scan is already running ({busy.run_name}); stop it first")

        url = check_target(target)
        name = sanitize_run_name(run_name) if run_name else default_run_name()
        directory = runs_root() / name
        directory.mkdir(parents=True, exist_ok=True)

        argv = [
            sys.executable, "-m", "docket.interface.main", "scan",
            "--target", url, "--run-name", name,
            "--max-steps", str(max_steps), "-n",
        ]
        if instruction:
            argv += ["--instruction", instruction]
        if source:
            # Without this the console's "Source tree" field was accepted and silently
            # dropped: no Semgrep ran, no candidates were correlated, and the UI gave no
            # hint that the value it collected went nowhere.
            argv += ["--source", source]
        if not use_sandbox:
            argv.append("--no-sandbox")

        # stdout/stderr go to a file rather than a pipe: nobody drains a pipe here, and
        # a full OS pipe buffer would deadlock the scan mid-run.
        log = directory / "scan.log"
        handle = log.open("w")
        process = subprocess.Popen(
            argv, stdout=handle, stderr=subprocess.STDOUT,
            # Own process group, so stopping a scan also kills the docker/sqlmap
            # children it spawned instead of orphaning them.
            start_new_session=True,
        )
        scan = ScanProcess(run_name=name, target=url, process=process, log=log,
                           instruction=instruction)
        self.active[name] = scan
        return scan

    def stop(self, run_name: str) -> bool:
        scan = self.active.get(run_name)
        if scan is None or not scan.running:
            return False
        # SIGINT, not SIGKILL: main.py catches KeyboardInterrupt and writes a report of
        # whatever was confirmed before the stop. A hard kill throws that away.
        os.killpg(os.getpgid(scan.process.pid), signal.SIGINT)
        try:
            scan.process.wait(timeout=20)
        except subprocess.TimeoutExpired:
            os.killpg(os.getpgid(scan.process.pid), signal.SIGKILL)
        return True

    def stop_all(self) -> None:
        for name in list(self.active):
            self.stop(name)


def demo() -> None:
    import tempfile

    assert check_target("127.0.0.1:8000") == "http://127.0.0.1:8000"
    assert check_target("localhost:8000/") == "http://localhost:8000"
    for bad in ("example.com", "http://10.0.0.5", "https://staging.internal"):
        try:
            check_target(bad)
            raise AssertionError(f"{bad} must be refused while loopback-only")
        except TargetRefused:
            pass
    # The guard must key on the HOST, not on a substring: this URL merely mentions
    # localhost in its path and is not loopback.
    try:
        check_target("http://evil.test/localhost")
        raise AssertionError("path-only 'localhost' must not pass the guard")
    except TargetRefused:
        pass

    # Every field the console's form collects must reach the argv. A field that is
    # accepted and dropped is worse than one that does not exist.
    import inspect

    params = set(inspect.signature(ScanManager.start).parameters)
    assert {"target", "run_name", "instruction", "max_steps", "source"} <= params, params

    mgr = ScanManager()
    assert mgr.current() is None
    assert mgr.stop("nope") is False

    # A tracked, already-exited process reports as not running.
    done = subprocess.Popen([sys.executable, "-c", "pass"])
    done.wait()
    mgr.active["x"] = ScanProcess("x", "http://127.0.0.1", done, Path(tempfile.gettempdir()) / "x")
    assert mgr.current() is None and mgr.active["x"].running is False
    assert mgr.stop("x") is False
    print("app.backend.scans: ok")


if __name__ == "__main__":
    demo()
