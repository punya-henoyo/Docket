#!/usr/bin/env python3
"""Run the console end to end with GitHub stubbed out.

    .venv/bin/python scripts/demo_console.py        # -> http://127.0.0.1:8765

Everything downstream of GitHub is REAL: the same connect server, the same sandbox,
the same trivy/semgrep, the same Finding model and dedupe, the same report.json. Only
the GitHub API is replaced, by a local HTTP server that serves a fixed repo list and
hand-built tarballs. That means the radar, the findings table and the evidence panes
are showing genuine scanner output, not fixtures.

Deliberately a SCRIPT, not a `--demo` flag on `docket connect`: this pre-authenticates
the session and disables the OAuth handshake, and a flag that does that is one
mistyped command away from bypassing authentication on something real. Keeping it
outside the package means the shipped code has no demo path at all.

Needs Docker (the scanners run in the sandbox). No GitHub credentials, no API key, no
LLM: this exercises the static scanners, which never call a model.
"""
from __future__ import annotations

import io
import json
import sys
import tarfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "engine"))

import docket.interface.connect as connect  # noqa: E402

PORT = 8765

# Each repo is (files, language, private). The content is deliberately vulnerable so
# the scanners have something true to say — flask 0.12.2 and jinja2 2.10 carry real
# published CVEs, and the source below trips real semgrep rules.
REPOS: dict[str, dict] = {
    "acme/checkout-api": {
        "language": "Python",
        "private": True,
        "files": {
            "requirements.txt": "flask==0.12.2\njinja2==2.10\nrequests==2.19.1\npyyaml==5.1\n",
            "app.py": '''import os, sqlite3, yaml, subprocess

DB = sqlite3.connect("shop.db")

def login(username, password):
    # user input formatted straight into SQL
    query = f"SELECT id FROM users WHERE name = '{username}' AND pw = '{password}'"
    return DB.execute(query).fetchone()

def export_report(filename):
    # user input concatenated into an OS command
    os.system("cat /var/reports/" + filename)

def load_config(blob):
    # untrusted YAML deserialised with the unsafe loader
    return yaml.load(blob)

def run_hook(cmd):
    subprocess.Popen(cmd, shell=True)
''',
            "settings.py": '''SECRET_KEY = "hardcoded-not-a-real-key-demo-only"
DEBUG = True
ALLOWED_HOSTS = ["*"]
''',
        },
    },
    "acme/web-frontend": {
        "language": "JavaScript",
        "private": False,
        "files": {
            "package.json": json.dumps(
                {"name": "web-frontend", "version": "1.0.0",
                 "dependencies": {"lodash": "4.17.15", "minimist": "0.0.8"}},
                indent=2) + "\n",
            "server.js": '''const express = require("express");
const app = express();
app.get("/search", (req, res) => {
  // reflected without escaping
  res.send("<h1>Results for " + req.query.q + "</h1>");
});
''',
        },
    },
    "acme/infra": {
        "language": "Dockerfile",
        "private": True,
        "files": {
            "Dockerfile": "FROM python:3.9\nCOPY . /app\nRUN pip install -r requirements.txt\nCMD [\"python\", \"/app/main.py\"]\n",
            "requirements.txt": "django==2.2.0\n",
            ".github/workflows/ci.yml": '''name: ci
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - run: make test
''',
        },
    },
}


def tarball(full_name: str) -> bytes:
    """Shaped like GitHub's: every path under one `owner-repo-<sha>` directory."""
    root = full_name.replace("/", "-") + "-demo123"
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, text in REPOS[full_name]["files"].items():
            data = text.encode()
            info = tarfile.TarInfo(f"{root}/{name}")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


class FakeGitHub(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:  # noqa: N802 — stdlib naming
        path = self.path.split("?", 1)[0]
        if path.endswith("/tarball"):
            full_name = path[len("/repos/"):-len("/tarball")]
            if full_name not in REPOS:
                self.send_error(404)
                return
            return self._send(tarball(full_name), "application/gzip")
        if path == "/user":
            return self._json({"login": "acme-security"})
        if path == "/user/installations":
            return self._json({"installations": [{"id": 1}]})
        if path.startswith("/user/installations/"):
            return self._json({"repositories": [
                {"full_name": name, "private": meta["private"],
                 "language": meta["language"], "updated_at": "2026-08-12T06:00:00Z"}
                for name, meta in REPOS.items()
            ]})
        self._json({})

    def _send(self, body: bytes, content_type: str) -> None:
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, payload: object) -> None:
        self._send(json.dumps(payload).encode(), "application/json")

    def log_message(self, fmt: str, *args) -> None:
        pass


def main() -> int:
    fake = ThreadingHTTPServer(("127.0.0.1", 0), FakeGitHub)
    threading.Thread(target=fake.serve_forever, daemon=True).start()

    # Point the real connect module at the stub, and skip the OAuth round trip.
    connect.GITHUB_API = f"http://127.0.0.1:{fake.server_address[1]}"
    connect.SESSION.token = "demo-token"
    connect.SESSION.login = "acme-security"

    server = connect.start_server(PORT)
    print(f"  demo console : http://127.0.0.1:{PORT}")
    print(f"  signed in as : {connect.SESSION.login} (GitHub stubbed, no real auth)")
    print(f"  repositories : {', '.join(REPOS)}")
    print("  scanners     : trivy + semgrep, really running in the Docker sandbox")
    print("  stop         : Ctrl-C")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print()
    finally:
        server.shutdown()
        fake.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
