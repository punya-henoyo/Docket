"""Direct HTTP client tool. Most of vulnshop's exploitation is plain HTTP — no need to
route everything through a browser. stdlib urllib is enough here; httpx shows up later
(M6/M7) once the RPC shim and proxy replay need its async/proxy ergonomics.
"""
from __future__ import annotations

import json as json_module
import time
import urllib.error
import urllib.parse
import urllib.request
from http.cookiejar import CookieJar
from pathlib import Path

from docket.tools.output_store import bound

DEFAULT_PROXY_URL = "http://127.0.0.1:8080"


def do_http_request(
    method: str,
    url: str,
    run_dir: Path,
    *,
    headers: dict | None = None,
    params: dict | None = None,
    data: str | dict | None = None,
    json: dict | None = None,
    cookies: dict | None = None,
    follow_redirects: bool = True,
    timeout_sec: int = 15,
    via_proxy: bool = False,
) -> dict:
    """Params/return shape match the tool contract in the delivery-layer design.
    `data` as a dict is form-urlencoded — matches Flask's `request.form.get(...)`
    exactly, which is what vulnshop's /login reads."""
    if params:
        url = f"{url}{'&' if '?' in url else '?'}{urllib.parse.urlencode(params)}"

    body_bytes: bytes | None = None
    req_headers = dict(headers or {})
    if json is not None:
        body_bytes = json_module.dumps(json).encode()
        req_headers.setdefault("Content-Type", "application/json")
    elif isinstance(data, dict):
        body_bytes = urllib.parse.urlencode(data).encode()
        req_headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
    elif isinstance(data, str):
        body_bytes = data.encode()

    if cookies:
        req_headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())

    request = urllib.request.Request(url, data=body_bytes, headers=req_headers, method=method.upper())

    opener_handlers = [urllib.request.HTTPCookieProcessor(CookieJar())]
    if not follow_redirects:
        opener_handlers.append(_NoRedirect())
    if via_proxy:
        opener_handlers.append(urllib.request.ProxyHandler({"http": DEFAULT_PROXY_URL, "https": DEFAULT_PROXY_URL}))
    opener = urllib.request.build_opener(*opener_handlers)

    start = time.monotonic()
    try:
        with opener.open(request, timeout=timeout_sec) as resp:
            status_code = resp.status
            resp_headers = dict(resp.headers)
            body = resp.read().decode(errors="replace")
    except urllib.error.HTTPError as exc:
        status_code = exc.code
        resp_headers = dict(exc.headers or {})
        body = exc.read().decode(errors="replace")
    elapsed_ms = int((time.monotonic() - start) * 1000)

    bounded = bound(body, run_dir)
    return {
        "status_code": status_code,
        "headers": resp_headers,
        "body": bounded["text"],
        "truncated": bounded["truncated"],
        "body_ref": bounded["ref"],
        "elapsed_ms": elapsed_ms,
        "flow_id": None,  # populated once the proxy tool (M7) is in the loop
    }


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def demo() -> None:
    """Self-contained: spins up a throwaway stdlib server rather than depending on an
    external target being up. Exercises the client itself — form encoding, query
    params, status codes, and elapsed timing."""
    import shutil
    import tempfile
    import threading
    import urllib.parse
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _reply(self, status: int, body: str) -> None:
            payload = body.encode()
            self.send_response(status)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_POST(self):  # noqa: N802
            length = int(self.headers.get("Content-Length", "0"))
            form = urllib.parse.parse_qs(self.rfile.read(length).decode())
            user = (form.get("user") or [""])[0]
            self._reply(200, f"hello {user}") if user else self._reply(401, "denied")

        def do_GET(self):  # noqa: N802
            parsed = urllib.parse.urlparse(self.path)
            params = urllib.parse.parse_qs(parsed.query)
            if parsed.path == "/slow":
                time.sleep(float((params.get("s") or ["0"])[0]))
                self._reply(200, "slept")
            elif parsed.path == "/big":
                self._reply(200, "A" * 20000)
            else:
                self._reply(200, "echo:" + (params.get("q") or [""])[0])

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    tmp = Path(tempfile.mkdtemp())
    try:
        # Form-encoded POST: what Flask's request.form reads.
        ok = do_http_request("POST", f"{base}/login", tmp, data={"user": "admin"})
        assert ok["status_code"] == 200 and ok["body"] == "hello admin", ok
        # A non-2xx is returned, not raised — the agent must see the status.
        denied = do_http_request("POST", f"{base}/login", tmp, data={"user": ""})
        assert denied["status_code"] == 401, denied
        # Query params.
        echoed = do_http_request("GET", f"{base}/echo", tmp, params={"q": "hi there"})
        assert echoed["body"] == "echo:hi there", echoed
        # Elapsed timing is real — this is the oracle blind command injection relies on.
        fast = do_http_request("GET", f"{base}/slow", tmp, params={"s": "0"})
        slow = do_http_request("GET", f"{base}/slow", tmp, params={"s": "1"})
        assert slow["elapsed_ms"] - fast["elapsed_ms"] > 700, (fast["elapsed_ms"], slow["elapsed_ms"])
        # Oversized bodies are bounded and spooled.
        big = do_http_request("GET", f"{base}/big", tmp)
        assert big["truncated"] is True and big["body_ref"], big
    finally:
        server.shutdown()
        shutil.rmtree(tmp, ignore_errors=True)
    print("http_request: ok")


if __name__ == "__main__":
    demo()
