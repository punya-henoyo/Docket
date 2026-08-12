"""⚠️  INTENTIONALLY VULNERABLE TEST FIXTURE — never run outside the test suite.

A ~3-route target carrying the same three textbook bugs docket's specialists are built
to find, so the test suite is self-contained instead of depending on an external app
being cloned, seeded, and running:

  V1  SQL injection      POST /login    (input f-string'd into the query)
  V2  Command injection  GET  /export   (input concatenated into os.system)
  V3  Reflected XSS      GET  /search   (input rendered into HTML unescaped)

Stdlib only (http.server + sqlite3) — deliberately no Flask, so this adds no
dependency to the project just to run tests.

Binds to 127.0.0.1 on an ephemeral port. Docker Desktop proxies host.docker.internal
to host loopback, so the sandbox container reaches it without exposing it to the LAN.
"""
from __future__ import annotations

import html
import os
import sqlite3
import tempfile
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

SEEDED_USER = ("admin", "admin123")


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    base_dir: Path  # set on the subclass created in start_target()

    def _reply(self, status: int, body: str) -> None:
        payload = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_POST(self) -> None:  # noqa: N802 — stdlib naming
        if self.path.split("?")[0] != "/login":
            self._reply(404, "not found")
            return
        length = int(self.headers.get("Content-Length", "0"))
        form = urllib.parse.parse_qs(self.rfile.read(length).decode(), keep_blank_values=True)
        username = (form.get("username") or [""])[0]
        password = (form.get("password") or [""])[0]

        # V1 — SQL INJECTION: user input formatted straight into the query string.
        query = f"SELECT id FROM users WHERE username = '{username}' AND password = '{password}'"
        try:
            with sqlite3.connect(self.base_dir / "shop.db") as db:
                row = db.execute(query).fetchone()
        except sqlite3.Error as exc:
            self._reply(500, f"database error: {exc}")
            return
        self._reply(200, "Welcome") if row else self._reply(401, "Invalid credentials")

    def do_GET(self) -> None:  # noqa: N802 — stdlib naming
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

        if parsed.path == "/export":
            filename = (params.get("file") or ["report.csv"])[0]
            # V2 — COMMAND INJECTION: user input concatenated into an OS command.
            # Blind: the command's stdout goes to this process, never the response.
            os.system(f"cat {self.base_dir / 'exports'}/" + filename)  # noqa: S605
            self._reply(200, "Export started")
        elif parsed.path == "/search":
            q = (params.get("q") or [""])[0]
            # V3 — REFLECTED XSS: untrusted input rendered into HTML without escaping.
            self._reply(200, "<h1>Results for " + q + "</h1>")
        elif parsed.path == "/":
            # A landing page that actually links to the app, because a real one does and
            # because discovery has to have something to crawl. Without the form and the
            # links, docket.discovery finds zero endpoints here and root is correctly told
            # the surface is unknown — honest, but it makes the whole discovery path
            # untestable against the only target we ship.
            self._reply(200,
                "<h1>target fixture</h1>"
                '<form method="post" action="/login">'
                '<input name="username"><input type="password" name="password">'
                '<button type="submit">Sign in</button></form>'
                '<form method="get" action="/search"><input name="q"></form>'
                '<a href="/export?file=report.csv">export</a>')
        else:
            self._reply(404, html.escape("not found"))

    def log_message(self, fmt: str, *args) -> None:
        pass  # keep test output readable


def start_target(port: int = 0) -> tuple[str, ThreadingHTTPServer, Path]:
    """Start the fixture on `port` (0 = ephemeral). Returns (base_url, server, base_dir)."""
    base_dir = Path(tempfile.mkdtemp(prefix="docket-target-"))
    (base_dir / "exports").mkdir()
    (base_dir / "exports" / "report.csv").write_text("id,total\n1,42\n")
    with sqlite3.connect(base_dir / "shop.db") as db:
        db.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
        db.execute("INSERT INTO users VALUES (1, ?, ?)", SEEDED_USER)

    handler = type("_BoundHandler", (_Handler,), {"base_dir": base_dir})
    server = ThreadingHTTPServer(("127.0.0.1", port), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return f"http://127.0.0.1:{server.server_address[1]}", server, base_dir


_shared: str | None = None


def ensure_target() -> str:
    """Start the fixture once per test process and return its base URL. Daemon thread
    plus a temp dir, so there is nothing to tear down explicitly."""
    global _shared
    if _shared is None:
        _shared, _, _ = start_target()
    return _shared


def demo() -> None:
    import json
    import urllib.request

    base = ensure_target()

    def post(path: str, data: dict) -> tuple[int, str]:
        req = urllib.request.Request(
            base + path, data=urllib.parse.urlencode(data).encode(), method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status, r.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode()

    def get(path: str) -> tuple[int, str]:
        with urllib.request.urlopen(base + path, timeout=10) as r:
            return r.status, r.read().decode()

    # Baseline behaviour is correct...
    assert post("/login", dict(zip(("username", "password"), SEEDED_USER)))[0] == 200
    assert post("/login", {"username": "admin", "password": "nope"})[0] == 401
    # ...and all three vulns are genuinely present.
    status, body = post("/login", {"username": "admin' -- ", "password": "nope"})
    assert status == 200 and "Welcome" in body, (status, body)          # V1
    import time
    t0 = time.monotonic(); get("/export?file=report.csv"); base_ms = time.monotonic() - t0
    t0 = time.monotonic(); get("/export?file=report.csv;%20sleep%202"); slow = time.monotonic() - t0
    assert slow - base_ms > 1.5, (base_ms, slow)                         # V2 (blind, timing)
    assert "<script>alert(1)</script>" in get("/search?q=%3Cscript%3Ealert(1)%3C/script%3E")[1]  # V3
    json.dumps({"ok": True})
    print("target_app fixture: ok — V1/V2/V3 all present")


if __name__ == "__main__":
    demo()
