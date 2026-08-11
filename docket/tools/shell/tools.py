"""The `shell` tool: run a command and capture stdout/stderr/exit code.

Stdlib only, on purpose — this module runs INSIDE the sandbox container (imported by
docket/runtime/server.py), and keeping it dependency-free means the image needs no
Python packages installed for the shim itself.
"""
from __future__ import annotations

import os
import signal
import subprocess
import time
from pathlib import Path

from docket.tools.output_store import bound

MAX_TIMEOUT_SEC = 120


def run_shell(
    command: str,
    run_dir: Path,
    timeout_sec: int = 30,
    cwd: str | None = None,
) -> dict:
    timeout_sec = max(1, min(int(timeout_sec), MAX_TIMEOUT_SEC))
    start = time.monotonic()

    # start_new_session so a timeout can kill the whole process GROUP — sqlmap and
    # friends spawn children, and killing only the bash parent would leave them
    # running inside the sandbox for the rest of the scan.
    proc = subprocess.Popen(
        ["bash", "-lc", command],
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        errors="replace",
        start_new_session=True,
    )
    timed_out = False
    try:
        stdout, stderr = proc.communicate(timeout=timeout_sec)
        exit_code = proc.returncode
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            proc.kill()
        stdout, stderr = proc.communicate()
        exit_code = 124  # conventional shell exit code for "timed out"

    bounded_out = bound(stdout, run_dir)
    bounded_err = bound(stderr, run_dir)
    return {
        "exit_code": exit_code,
        "stdout": bounded_out["text"],
        "stderr": bounded_err["text"],
        "truncated": bounded_out["truncated"] or bounded_err["truncated"],
        "output_ref": bounded_out["ref"],
        "stderr_ref": bounded_err["ref"],
        "timed_out": timed_out,
        "duration_ms": int((time.monotonic() - start) * 1000),
    }


def demo() -> None:
    import shutil
    import tempfile

    tmp = Path(tempfile.mkdtemp())
    try:
        ok = run_shell("echo hello && echo oops >&2", tmp)
        assert ok["exit_code"] == 0, ok
        assert ok["stdout"].strip() == "hello", ok
        assert ok["stderr"].strip() == "oops", ok
        assert ok["timed_out"] is False

        bad = run_shell("exit 3", tmp)
        assert bad["exit_code"] == 3, bad

        # A timeout must kill the whole group, not just the bash parent, and must
        # report promptly rather than blocking for the child's full lifetime.
        slow = run_shell("sleep 30", tmp, timeout_sec=1)
        assert slow["timed_out"] is True, slow
        assert slow["exit_code"] == 124, slow
        assert slow["duration_ms"] < 10_000, slow

        big = run_shell("head -c 20000 /dev/zero | tr '\\0' 'A'", tmp)
        assert big["truncated"] is True and big["output_ref"], big
    finally:
        shutil.rmtree(tmp)
    print("shell: ok")


if __name__ == "__main__":
    demo()
