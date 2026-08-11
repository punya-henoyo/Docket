"""The `proxy` tool: an intercepting HTTP proxy the agent can inspect and replay from.

mitmdump (mitmproxy's headless mode) stands in for upstream Docket's Caido, which is
commercial, GUI-first, and needs an SDK client. One genuine simplification falls out of
this target: it speaks plain HTTP, so there is NO TLS to intercept and therefore no
CA-certificate bootstrap step at all — normally the fiddliest part of putting a MITM
proxy in front of a browser.

Honest scoping note: of the sandbox's tools this is the least load-bearing for vulnshop
specifically — shell + http_request + browser already prove all three vulns. It exists
because the locked-in scope is a full Docket-style clone, and because request
replay-with-modification is the one capability a pentester reaches for constantly on
real targets.

Runs INSIDE the container (imported by docket/runtime/server.py), so: stdlib only.
"""
from __future__ import annotations

import json
import socket
import subprocess
import time
from pathlib import Path

from docket.tools.http_request.tools import DEFAULT_PROXY_URL, do_http_request

# Derived from http_request's constant rather than repeated, so the port the proxy
# LISTENS on and the port replay/via_proxy DIALS can never drift apart.
PROXY_PORT = int(DEFAULT_PROXY_URL.rsplit(":", 1)[-1])
ADDON_MODULE_PATH = "/app/docket/runtime/proxy_addon.py"

# One mitmdump per container. The shim is a single process, so a module-level handle is
# the whole "lifecycle management" this needs.
_proc: subprocess.Popen | None = None


def _flows_path(run_dir: Path) -> Path:
    return run_dir / "artifacts" / "proxy_flows.jsonl"


def _port_open(port: int, host: str = "127.0.0.1") -> bool:
    with socket.socket() as sock:
        sock.settimeout(0.3)
        return sock.connect_ex((host, port)) == 0


def proxy_start(run_dir: Path, timeout_sec: float = 25.0) -> dict:
    """Start mitmdump if it isn't already running. Idempotent."""
    global _proc
    if _proc is not None and _proc.poll() is None:
        return {"ok": True, "proxy_url": f"http://127.0.0.1:{PROXY_PORT}", "already_running": True}

    _flows_path(run_dir).parent.mkdir(parents=True, exist_ok=True)
    _proc = subprocess.Popen(
        ["mitmdump", "-p", str(PROXY_PORT), "-s", ADDON_MODULE_PATH, "-q",
         "--set", "connection_strategy=lazy"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors="replace",
    )
    deadline = time.monotonic() + timeout_sec
    while time.monotonic() < deadline:
        if _proc.poll() is not None:
            return {"ok": False, "error": f"mitmdump exited early: {(_proc.stdout.read() or '')[:800]}"}
        if _port_open(PROXY_PORT):
            return {"ok": True, "proxy_url": f"http://127.0.0.1:{PROXY_PORT}", "already_running": False}
        time.sleep(0.2)
    return {"ok": False, "error": f"mitmdump did not open port {PROXY_PORT} within {timeout_sec}s"}


def proxy_stop() -> dict:
    global _proc
    if _proc is None or _proc.poll() is not None:
        _proc = None
        return {"ok": True, "was_running": False}
    _proc.terminate()
    try:
        _proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        _proc.kill()
    _proc = None
    return {"ok": True, "was_running": True}


def _read_flows(run_dir: Path) -> list[dict]:
    path = _flows_path(run_dir)
    if not path.exists():
        return []
    flows = []
    for line in path.read_text().splitlines():
        if line.strip():
            try:
                flows.append(json.loads(line))
            except json.JSONDecodeError:
                continue  # a partially-flushed final line; skip it
    return flows


def proxy_list(run_dir: Path, limit: int = 20, offset: int = 0, filter_url: str | None = None) -> dict:
    flows = _read_flows(run_dir)
    if filter_url:
        flows = [f for f in flows if filter_url in f.get("url", "")]
    window = flows[offset : offset + limit]
    return {
        "flows": [
            {"id": f["id"], "method": f["method"], "url": f["url"], "status": f["status"]}
            for f in window
        ],
        "total": len(flows),
        "offset": offset,
        "has_more": offset + limit < len(flows),
    }


def proxy_get(run_dir: Path, flow_id: str) -> dict:
    for flow in _read_flows(run_dir):
        if flow["id"] == flow_id:
            return flow
    return {"error": f"no such flow: {flow_id!r}"}


def proxy_replay(run_dir: Path, flow_id: str, modifications: dict | None = None) -> dict:
    """Re-send a captured request, optionally overriding method/url/headers/body.

    Deliberately fires the replay back THROUGH the proxy, so it is a genuinely new
    request/response cycle and lands in the flow log as a new entry automatically —
    no extra recording code, and the agent can diff original against replay.
    """
    original = proxy_get(run_dir, flow_id)
    if "error" in original:
        return original

    mods = modifications or {}
    method = mods.get("method", original["method"])
    url = mods.get("url", original["url"])
    headers = dict(original.get("req_headers") or {})
    headers.update(mods.get("headers") or {})
    # Hop-by-hop and length headers must not be replayed verbatim; urllib recomputes
    # them and a stale Content-Length would corrupt the request.
    for drop in ("Content-Length", "content-length", "Host", "host", "Connection", "connection"):
        headers.pop(drop, None)
    body = mods.get("body", original.get("req_body") or None)

    result = do_http_request(
        method, url, run_dir,
        headers=headers, data=body, via_proxy=True,
        timeout_sec=int(mods.get("timeout_sec", 15)),
    )
    return {"replayed_from": flow_id, "request": {"method": method, "url": url}, "response": result}
