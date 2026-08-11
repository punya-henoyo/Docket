"""IN-CONTAINER entrypoint: a long-lived RPC shim the host drives over HTTP.

Why a persistent server rather than `docker exec` per tool call: `browser` (M8) and
`proxy` (M7) need long-lived in-container state — a live Playwright page, a running
mitmdump subprocess — that has to stay addressable across many calls. Reaching that
state from a fresh `docker exec` would mean building an IPC layer anyway; this IS that
layer, and it also skips ~50-150ms of process spawn per call.

Stdlib only (http.server + the stdlib-only tool modules), so the image needs no Python
packages installed just to serve tool calls.

Only SANDBOXED tools live here — ones whose effects belong inside the container.
Host-side tools (`finding`, which must reach the host process's FindingStore via its
on_finding callback) deliberately stay in the host process; see docket/agents/factory.py.
"""
from __future__ import annotations

import json
import os
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from docket.tools.agent_browser.tools import browser, browser_close
from docket.tools.http_request.tools import do_http_request
from docket.tools.output_store import get as output_get
from docket.tools.proxy.tools import (
    proxy_get,
    proxy_list,
    proxy_replay,
    proxy_start,
    proxy_stop,
)
from docket.tools.shell.tools import run_shell


def _read_file(path: str) -> dict:
    """Raw file read for the SDK sandbox session (base64 so binaries survive JSON)."""
    import base64

    data = Path(path).read_bytes()
    return {"ok": True, "b64": base64.b64encode(data).decode(), "size": len(data)}


def _write_file(path: str, b64: str) -> dict:
    import base64

    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = base64.b64decode(b64)
    target.write_bytes(payload)
    return {"ok": True, "size": len(payload)}


def _exec_argv(argv: list[str], timeout_sec: float | None = None) -> dict:
    """Exec an ARGV list (no shell). The SDK's sandbox session passes argv, and
    routing it through `bash -lc` would re-introduce shell quoting bugs."""
    import base64
    import subprocess

    try:
        proc = subprocess.run(
            [str(a) for a in argv], capture_output=True,
            timeout=timeout_sec if timeout_sec else None,
        )
        out, err, code = proc.stdout, proc.stderr, proc.returncode
    except subprocess.TimeoutExpired as exc:
        out, err, code = (exc.stdout or b""), (exc.stderr or b"") + b"\n[timed out]", 124
    except FileNotFoundError as exc:
        out, err, code = b"", str(exc).encode(), 127
    return {
        "stdout_b64": base64.b64encode(out).decode(),
        "stderr_b64": base64.b64encode(err).decode(),
        "exit_code": code,
    }

PORT = int(os.environ.get("DOCKET_SHIM_PORT", "8765"))
RUN_DIR = Path(os.environ.get("DOCKET_RUN_DIR", "/work/run"))

# Deliberately single-threaded (HTTPServer, not ThreadingHTTPServer). Playwright's sync
# API binds its objects to the thread that created them, and ThreadingHTTPServer hands
# each request to a NEW thread — so a Page created serving one call would be unusable
# from the next. Since a global lock was already serializing every tool call anyway,
# threading bought nothing and would only have broken the browser.
# ponytail: one sandbox serves one agent's calls in order — correct and cheap here; if
# agents ever need to share a container concurrently the fix is a sandbox per agent,
# not a threaded shim.

DISPATCH = {
    "shell": lambda **kw: run_shell(run_dir=RUN_DIR, **kw),
    "http_request": lambda **kw: do_http_request(run_dir=RUN_DIR, **kw),
    "output_get": lambda **kw: output_get(run_dir=RUN_DIR, **kw),
    "proxy_start": lambda **kw: proxy_start(run_dir=RUN_DIR, **kw),
    "proxy_stop": lambda **kw: proxy_stop(**kw),
    "proxy_list": lambda **kw: proxy_list(run_dir=RUN_DIR, **kw),
    "proxy_get": lambda **kw: proxy_get(run_dir=RUN_DIR, **kw),
    "proxy_replay": lambda **kw: proxy_replay(run_dir=RUN_DIR, **kw),
    "browser": lambda **kw: browser(run_dir=RUN_DIR, **kw),
    # Primitives backing the SDK-native sandbox session (docket/runtime/sdk_session.py).
    "read_file": lambda **kw: _read_file(**kw),
    "write_file": lambda **kw: _write_file(**kw),
    "exec_argv": lambda **kw: _exec_argv(**kw),
}


class Handler(BaseHTTPRequestHandler):
    # HTTP/1.0 so each response closes its connection. With a single-threaded server,
    # HTTP/1.1 keep-alive would let one idle client hold the only request-handling
    # thread and stall every other call.
    protocol_version = "HTTP/1.0"

    def _send(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 — stdlib naming
        if self.path == "/health":
            self._send(200, {"ok": True, "tools": sorted(DISPATCH)})
        else:
            self._send(404, {"ok": False, "error": f"no such path: {self.path}"})

    def do_POST(self) -> None:  # noqa: N802 — stdlib naming
        if self.path == "/shutdown":
            # Release long-lived in-container resources (mitmdump now; a Playwright
            # browser in M8) before the container is torn down.
            for release in (proxy_stop, browser_close):
                try:
                    release()
                except Exception:
                    pass
            self._send(200, {"ok": True})
            threading.Thread(target=self.server.shutdown, daemon=True).start()
            return
        if self.path != "/invoke":
            self._send(404, {"ok": False, "error": f"no such path: {self.path}"})
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
            request = json.loads(self.rfile.read(length) or b"{}")
            tool = request["tool"]
            args = request.get("args", {})
        except (ValueError, KeyError, json.JSONDecodeError) as exc:
            self._send(400, {"ok": False, "error": f"bad request: {exc!r}"})
            return

        handler = DISPATCH.get(tool)
        if handler is None:
            self._send(400, {"ok": False, "error": f"unknown tool: {tool!r}"})
            return

        try:
            result = handler(**args)
        except Exception as exc:
            # A failing tool must not take the shim down — the agent needs to see the
            # error as a tool result and carry on.
            self._send(200, {"ok": False, "error": f"{type(exc).__name__}: {exc}"})
            return
        self._send(200, {"ok": True, "result": result})

    def log_message(self, fmt: str, *args) -> None:
        # Default BaseHTTPRequestHandler logging spams stderr with a line per call;
        # `docker logs` is more useful without it.
        pass


def main() -> None:
    RUN_DIR.mkdir(parents=True, exist_ok=True)
    server = HTTPServer(("0.0.0.0", PORT), Handler)
    print(f"docket shim listening on 0.0.0.0:{PORT}, run_dir={RUN_DIR}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
