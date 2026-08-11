"""Local HTTP server for the dashboard.

Binds to 127.0.0.1 only. Nothing leaves the machine: the page is served from this
package, the data comes from the run directory on disk, and there is no account, no
upload, and no outbound request anywhere in the page.
"""
from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from docket.interface.viewer.transcript import build_payload

DASHBOARD = Path(__file__).resolve().parent / "dashboard.html"


def make_handler(run_dir: Path) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _send(self, status: int, body: bytes, content_type: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802 — stdlib naming
            path = self.path.split("?", 1)[0]
            if path in ("/", "/index.html"):
                self._send(200, DASHBOARD.read_bytes(), "text/html; charset=utf-8")
            elif path == "/api/run":
                payload = json.dumps(build_payload(run_dir), default=str).encode()
                self._send(200, payload, "application/json")
            elif path == "/report.sarif":
                sarif = run_dir / "report.sarif"
                if sarif.exists():
                    self._send(200, sarif.read_bytes(), "application/json")
                else:
                    self._send(404, b'{"error":"no report.sarif"}', "application/json")
            elif path.startswith("/artifacts/"):
                # Screenshots and spooled tool output. Resolved and containment-checked:
                # this serves a directory the user chose, so a traversal here would
                # expose arbitrary files on their machine.
                target = (run_dir / path.lstrip("/")).resolve()
                if not str(target).startswith(str(run_dir.resolve())) or not target.is_file():
                    self._send(404, b"not found", "text/plain")
                    return
                kind = "image/png" if target.suffix == ".png" else "text/plain; charset=utf-8"
                self._send(200, target.read_bytes(), kind)
            else:
                self._send(404, b"not found", "text/plain")

        def log_message(self, fmt: str, *args) -> None:
            pass

    return Handler


def start_server(run_dir: Path, port: int = 0) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer(("127.0.0.1", port), make_handler(Path(run_dir)))
    return server


def demo() -> None:
    import shutil
    import tempfile
    import threading
    import urllib.request

    tmp = Path(tempfile.mkdtemp())
    try:
        (tmp / "report.json").write_text(json.dumps({
            "run_name": "r", "target": "http://x", "finding_count": 1,
            "severity_counts": {"high": 1}, "findings": [{"rule_id": "sql-injection"}]}))
        (tmp / "report.sarif").write_text('{"version":"2.1.0"}')
        (tmp / "artifacts").mkdir()
        (tmp / "artifacts" / "note.txt").write_text("hello artifact")

        server = start_server(tmp, port=0)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        base = f"http://127.0.0.1:{server.server_address[1]}"

        page = urllib.request.urlopen(base + "/", timeout=5).read().decode()
        assert "<title>docket" in page and "/api/run" in page
        # No outbound requests from the page: everything is inlined.
        assert "http://" not in page.split("<script>")[0].replace("http://x", "")

        data = json.loads(urllib.request.urlopen(base + "/api/run", timeout=5).read())
        assert data["target"] == "http://x" and data["finding_count"] == 1
        assert data["has_sarif"] is True

        sarif = urllib.request.urlopen(base + "/report.sarif", timeout=5).read().decode()
        assert "2.1.0" in sarif
        art = urllib.request.urlopen(base + "/artifacts/note.txt", timeout=5).read().decode()
        assert art == "hello artifact"

        # Traversal must not escape the run directory.
        for bad in ("/artifacts/../../../../etc/passwd", "/nope"):
            try:
                urllib.request.urlopen(base + bad, timeout=5)
                raise AssertionError(f"{bad} should 404")
            except urllib.error.HTTPError as exc:
                assert exc.code == 404, (bad, exc.code)
        server.shutdown()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print("viewer.server: ok")


if __name__ == "__main__":
    demo()
