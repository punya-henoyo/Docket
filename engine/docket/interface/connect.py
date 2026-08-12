"""GitHub connect: authorize -> pick a repo -> fetch source read-only -> scan it.

This is the hosted-product surface, not the CLI. A customer opens the console, clicks
Connect GitHub, authorizes, and picks repositories; docket pulls each one read-only and
runs the deterministic scanners (trivy + semgrep) against it.

WHY A GITHUB APP AND NOT A CLASSIC OAUTH APP
--------------------------------------------
OAuth Apps have no read-only repository scope. `repo` grants full read AND WRITE to
private code; `public_repo` likewise for public. There is no `repo:read`. The only
GitHub mechanism that grants read-only source access is a GitHub App's
`contents: read` permission.

The customer-facing flow is identical either way: GitHub Apps support user
authorization over the same /login/oauth/authorize + /login/oauth/access_token
endpoints an OAuth App uses, so the code below works with either kind. Register a
GitHub App with `contents: read` + `metadata: read` to keep the access read-only.

WHAT THIS IS NOT
----------------
Single-tenant and in-memory: one operator, on their own machine, holding one token.
There is no user table, no encryption at rest, no tenant isolation. Do not point this
at real customers as-is.
# ponytail: in-memory single-tenant session, ceiling is "one operator on localhost".
# Multi-tenant needs a real session store, per-tenant token encryption, and a job queue
# (a scan takes minutes and needs Docker, so it cannot run inside a request handler).
"""
from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import tarfile
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from docket.utils.resource_paths import frontend_dir

GITHUB_AUTHORIZE = "https://github.com/login/oauth/authorize"
GITHUB_TOKEN = "https://github.com/login/oauth/access_token"
GITHUB_API = "https://api.github.com"

# "owner/repo" exactly. Anything else never reaches a URL or the filesystem: this value
# arrives from the browser and is interpolated into an api.github.com path, so a stray
# "../" or scheme here would be a path-traversal / SSRF primitive.
_FULL_NAME = re.compile(r"^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$")

# GitHub caps a tarball at a few hundred MB; refuse anything absurd rather than filling
# the disk of whoever runs this.
MAX_TARBALL_BYTES = 512 * 1024 * 1024


@dataclass
class Session:
    """One operator's connection. Module-level singleton — see the module docstring."""
    token: str | None = None
    login: str | None = None
    oauth_state: str | None = None
    scans: dict[str, dict[str, Any]] = field(default_factory=dict)
    lock: threading.Lock = field(default_factory=threading.Lock)


SESSION = Session()


def oauth_config() -> tuple[str, str, str] | None:
    """(client_id, client_secret, redirect_uri) or None when unconfigured."""
    client_id = os.environ.get("DOCKET_GITHUB_CLIENT_ID", "").strip()
    client_secret = os.environ.get("DOCKET_GITHUB_CLIENT_SECRET", "").strip()
    if not client_id or not client_secret:
        return None
    redirect = os.environ.get("DOCKET_GITHUB_REDIRECT_URI", "").strip()
    return client_id, client_secret, redirect


def _api(path: str, token: str, *, timeout: float = 20.0) -> Any:
    request = urllib.request.Request(
        f"{GITHUB_API}{path}",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "docket",
        },
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read() or b"null")


def exchange_code(code: str) -> tuple[str | None, str | None]:
    """Trade the callback's ?code for a user token. Returns (token, error)."""
    config = oauth_config()
    if config is None:
        return None, "DOCKET_GITHUB_CLIENT_ID / _SECRET are not set"
    client_id, client_secret, redirect = config
    form = {"client_id": client_id, "client_secret": client_secret, "code": code}
    if redirect:
        form["redirect_uri"] = redirect
    request = urllib.request.Request(
        GITHUB_TOKEN,
        data=urllib.parse.urlencode(form).encode(),
        headers={"Accept": "application/json", "User-Agent": "docket"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            payload = json.loads(response.read() or b"{}")
    except urllib.error.URLError as exc:
        return None, f"token exchange failed: {exc}"
    token = payload.get("access_token")
    if not token:
        # GitHub returns 200 with an error body on a bad/expired code.
        return None, payload.get("error_description") or payload.get("error") or "no access_token returned"
    return token, None


def list_repos(token: str) -> list[dict[str, Any]]:
    """Repos this authorization can see. A GitHub App user token returns only the
    repositories the customer selected at install time, which is the whole point."""
    try:
        installations = _api("/user/installations", token)
        repos: list[dict[str, Any]] = []
        for install in (installations or {}).get("installations", []):
            listing = _api(f"/user/installations/{install['id']}/repositories?per_page=100", token)
            repos.extend((listing or {}).get("repositories", []))
        if repos:
            return repos
    except urllib.error.HTTPError:
        # Classic OAuth App tokens have no /user/installations; fall through.
        pass
    return _api("/user/repos?per_page=100&sort=updated", token) or []


def fetch_source(full_name: str, token: str, dest: Path) -> Path:
    """Download `full_name`'s default-branch tarball and extract it under `dest`.

    Deliberately NOT `git clone`: a clone puts the token in the command line (visible
    to `ps`) or persists it in .git/config. The REST tarball carries the token in an
    Authorization header only, so it never touches the disk or the process table. It
    is also read-only by construction — there is no remote to push back to.
    """
    if not _FULL_NAME.match(full_name):
        raise ValueError(f"refusing suspicious repository name: {full_name!r}")

    request = urllib.request.Request(
        f"{GITHUB_API}/repos/{full_name}/tarball",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "User-Agent": "docket",
        },
    )
    dest.mkdir(parents=True, exist_ok=True)
    archive = dest / "source.tar.gz"
    with urllib.request.urlopen(request, timeout=120) as response:
        size = 0
        with archive.open("wb") as out:
            while chunk := response.read(1 << 16):
                size += len(chunk)
                if size > MAX_TARBALL_BYTES:
                    raise ValueError(f"tarball exceeds {MAX_TARBALL_BYTES} bytes; refusing")
                out.write(chunk)

    extracted = dest / "src"
    extracted.mkdir(exist_ok=True)
    with tarfile.open(archive, "r:gz") as tar:
        # filter="data" (3.12+) blocks absolute paths, "..", symlinks and device files.
        # This archive is third-party content, so extractall without it is exactly the
        # traversal bug semgrep flags in this very repo.
        tar.extractall(extracted, filter="data")
    archive.unlink(missing_ok=True)

    # GitHub wraps everything in one "owner-repo-<sha>" directory; hand back the real root.
    entries = [p for p in extracted.iterdir() if p.is_dir()]
    return entries[0] if len(entries) == 1 else extracted


def run_repo_scan(full_name: str, token: str, scan_id: str) -> None:
    """Fetch + scan, updating SESSION.scans[scan_id] as it goes. Never raises: the
    status dict is how the browser learns something failed.

    Findings are published as each scanner finishes rather than in one lump at the
    end, so the console's radar fills in during the run instead of staying empty and
    then jumping. Sequential scanners make that ordering exact.
    """
    from docket.report.dedupe import FindingStore

    def set_state(**fields: Any) -> None:
        with SESSION.lock:
            SESSION.scans[scan_id].update(fields)

    def stage(scanner: str, state: str) -> None:
        with SESSION.lock:
            SESSION.scans[scan_id]["stages"][scanner] = state

    store = FindingStore()

    def publish(finding: Any) -> None:
        store.add(finding)
        current = [f.model_dump(mode="json") for f in store.findings()]
        set_state(findings=current, finding_count=len(current))

    workdir = Path(tempfile.mkdtemp(prefix="docket-connect-"))
    started = time.time()
    run_name = f"connect-{scan_id}"
    try:
        set_state(status="fetching")
        stage("fetch", "running")
        source = fetch_source(full_name, token, workdir)
        stage("fetch", "done")

        set_state(status="scanning")
        from docket.core.runner import run_scan

        result = run_scan(
            target_url=None,
            whitebox_path=str(source),
            on_finding=publish,
            run_name=run_name,
            use_sandbox=True,
            store=store,
            static_only=True,
            on_stage=stage,
        )
        # Persist the same artifacts `docket scan` writes, so a console scan is
        # visible to `docket view`, to the run-history panel, and to anything reading
        # report.sarif — rather than existing only in this process's memory.
        from docket.core.paths import run_path
        from docket.report.writer import write_report

        write_report(
            store, run_path(run_name), run_name=run_name, target=f"github:{full_name}",
            summary=result.summary, cost_usd=result.cost_usd,
            agents_spawned=result.agents_spawned, success=result.success,
        )
        set_state(status="done", summary=result.summary,
                  elapsed_sec=round(time.time() - started, 1))
    except Exception as exc:
        stage("fetch", "error")
        set_state(status="error", error=f"{type(exc).__name__}: {exc}",
                  elapsed_sec=round(time.time() - started, 1))
    finally:
        # The customer's source never outlives the scan.
        shutil.rmtree(workdir, ignore_errors=True)


def new_scan_state(scan_id: str, full_name: str) -> dict[str, Any]:
    return {
        "id": scan_id,
        "repo": full_name,
        "status": "queued",
        # Radar rings, outermost last. "skipped" is a real outcome, not a failure:
        # nuclei needs a live URL and a source-only scan has none.
        "stages": {"fetch": "pending", "trivy": "pending",
                   "semgrep": "pending", "nuclei": "pending"},
        "findings": [],
        "finding_count": 0,
        "error": None,
    }


_MIME = {
    ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8", ".svg": "image/svg+xml",
    ".json": "application/json", ".woff2": "font/woff2", ".ico": "image/x-icon",
    ".png": "image/png", ".map": "application/json",
}

_NOT_BUILT = b"""<!doctype html><meta charset=utf-8>
<title>docket - not built</title>
<body style="background:#0b0b0b;color:#e8e6e1;font:15px/1.7 ui-monospace,monospace;padding:44px">
<h1 style="font-size:19px">Console not built</h1>
<p>The React app has not been compiled yet. From the repo root:</p>
<pre style="background:#1b1b1b;border:1px solid #333;border-radius:6px;padding:14px">cd frontend
npm install
npm run build</pre>
<p style="color:#8a8781">Then reload. For hot-reload development run <b>npm run dev</b> instead and use
the Vite URL it prints, which proxies /api and /auth back to this server.</p>"""


def frontend_dist() -> Path:
    return frontend_dir() / "dist"


def list_runs() -> list[dict[str, Any]]:
    """Past runs on disk, newest first. Read straight from the run directories the CLI
    already writes, so the console and `docket view` never disagree."""
    from docket.core.paths import runs_root

    root = runs_root()
    if not root.exists():
        return []
    runs: list[dict[str, Any]] = []
    for directory in root.iterdir():
        report = directory / "report.json"
        if not report.is_file():
            continue
        try:
            data = json.loads(report.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        runs.append({
            "run_name": data.get("run_name", directory.name),
            "target": data.get("target"),
            "generated_at": data.get("generated_at"),
            "finding_count": data.get("finding_count", 0),
            "severity_counts": data.get("severity_counts", {}),
            "cost_usd": data.get("cost_usd", 0.0),
            "mtime": report.stat().st_mtime,
        })
    runs.sort(key=lambda r: r["mtime"], reverse=True)
    return runs


def make_handler() -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _send(self, status: int, body: bytes, content_type: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _json(self, status: int, payload: Any) -> None:
            self._send(status, json.dumps(payload, default=str).encode(), "application/json")

        def _redirect(self, location: str) -> None:
            self.send_response(302)
            self.send_header("Location", location)
            self.send_header("Content-Length", "0")
            self.end_headers()

        # -- routes ----------------------------------------------------------------

        def do_GET(self) -> None:  # noqa: N802 — stdlib naming
            parsed = urllib.parse.urlparse(self.path)
            path, query = parsed.path, urllib.parse.parse_qs(parsed.query)

            if path.startswith("/assets/") or path in ("/favicon.ico", "/favicon.svg"):
                self._static(path)
            elif path == "/api/runs":
                self._json(200, {"runs": list_runs()})
            elif path == "/api/session":
                self._json(200, {
                    "connected": SESSION.token is not None,
                    "login": SESSION.login,
                    "configured": oauth_config() is not None,
                })
            elif path == "/auth/start":
                self._auth_start()
            elif path == "/auth/callback":
                self._auth_callback(query)
            elif path == "/api/repos":
                self._repos()
            elif path.startswith("/api/scan/"):
                scan_id = path.rsplit("/", 1)[-1]
                with SESSION.lock:
                    state = SESSION.scans.get(scan_id)
                self._json(200 if state else 404, state or {"error": "unknown scan"})
            elif path.startswith("/api/") or path.startswith("/auth/"):
                self._json(404, {"error": "no such endpoint"})
            else:
                # Everything else is a client-side route: serve the SPA shell and let
                # the router decide, so a deep link or a refresh does not 404.
                self._static("/index.html")

        def do_POST(self) -> None:  # noqa: N802 — stdlib naming
            if urllib.parse.urlparse(self.path).path != "/api/scan":
                self._send(404, b"not found", "text/plain")
                return
            if SESSION.token is None:
                self._json(401, {"error": "not connected to GitHub"})
                return
            length = int(self.headers.get("Content-Length", "0"))
            try:
                body = json.loads(self.rfile.read(length) or b"{}")
            except json.JSONDecodeError:
                self._json(400, {"error": "body must be JSON"})
                return
            full_name = str(body.get("repo", "")).strip()
            if not _FULL_NAME.match(full_name):
                self._json(400, {"error": "repo must look like owner/name"})
                return

            scan_id = secrets.token_hex(8)
            with SESSION.lock:
                SESSION.scans[scan_id] = new_scan_state(scan_id, full_name)
            threading.Thread(
                target=run_repo_scan, args=(full_name, SESSION.token, scan_id),
                name=f"docket-scan-{scan_id}", daemon=True,
            ).start()
            self._json(202, {"id": scan_id, "status": "queued"})

        # -- handlers --------------------------------------------------------------

        def _static(self, path: str) -> None:
            """Serve the Vite build. Resolved and containment-checked: this reads from
            a directory path derived from the URL, so a traversal here would hand out
            arbitrary files from the operator's machine."""
            dist = frontend_dist()
            index = dist / "index.html"
            if not index.is_file():
                self._send(200, _NOT_BUILT, "text/html; charset=utf-8")
                return
            target = (dist / path.lstrip("/")).resolve()
            if not str(target).startswith(str(dist.resolve())) or not target.is_file():
                if path == "/index.html":
                    self._send(200, _NOT_BUILT, "text/html; charset=utf-8")
                else:
                    self._send(404, b"not found", "text/plain")
                return
            self._send(200, target.read_bytes(),
                       _MIME.get(target.suffix, "application/octet-stream"))

        def _auth_start(self) -> None:
            config = oauth_config()
            if config is None:
                self._json(503, {
                    "error": "GitHub is not configured",
                    "detail": "Set DOCKET_GITHUB_CLIENT_ID and DOCKET_GITHUB_CLIENT_SECRET.",
                })
                return
            client_id, _, redirect = config
            # CSRF: an attacker who can make the browser hit /auth/callback with their
            # own code would otherwise bind THEIR GitHub account to this session.
            state = secrets.token_urlsafe(24)
            SESSION.oauth_state = state
            params = {"client_id": client_id, "state": state}
            if redirect:
                params["redirect_uri"] = redirect
            self._redirect(f"{GITHUB_AUTHORIZE}?{urllib.parse.urlencode(params)}")

        def _auth_callback(self, query: dict[str, list[str]]) -> None:
            expected, SESSION.oauth_state = SESSION.oauth_state, None
            state = (query.get("state") or [""])[0]
            if not expected or not secrets.compare_digest(state, expected):
                self._json(400, {"error": "state mismatch — restart the connection"})
                return
            code = (query.get("code") or [""])[0]
            if not code:
                self._json(400, {"error": "no code in callback"})
                return
            token, error = exchange_code(code)
            if error:
                self._json(502, {"error": error})
                return
            SESSION.token = token
            try:
                SESSION.login = (_api("/user", token) or {}).get("login")
            except urllib.error.URLError:
                SESSION.login = None
            self._redirect("/?connected=1")

        def _repos(self) -> None:
            if SESSION.token is None:
                self._json(401, {"error": "not connected to GitHub"})
                return
            try:
                repos = list_repos(SESSION.token)
            except urllib.error.HTTPError as exc:
                self._json(502, {"error": f"GitHub API {exc.code}"})
                return
            self._json(200, {"repos": [
                {
                    "full_name": r.get("full_name"),
                    "private": r.get("private"),
                    "language": r.get("language"),
                    "updated_at": r.get("updated_at"),
                }
                for r in repos
            ]})

        def log_message(self, fmt: str, *args) -> None:
            pass

    return Handler


def start_server(port: int = 8765) -> ThreadingHTTPServer:
    """Loopback only. The OAuth client secret lives in this process; binding it to a
    public interface would expose an unauthenticated scan trigger to the network."""
    return ThreadingHTTPServer(("127.0.0.1", port), make_handler())


def serve(port: int = 8765) -> int:
    from docket.interface.cli_args import EXIT_CLEAN

    server = start_server(port)
    actual = server.server_address[1]
    print(f"docket console: http://127.0.0.1:{actual}")
    if oauth_config() is None:
        print("warning: DOCKET_GITHUB_CLIENT_ID / DOCKET_GITHUB_CLIENT_SECRET are unset —")
        print("         the console loads but Connect GitHub will refuse. Register a GitHub App")
        print("         with 'Contents: read' + 'Metadata: read', callback")
        print(f"         http://127.0.0.1:{actual}/auth/callback, then export both values.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print()
    finally:
        server.shutdown()
    return EXIT_CLEAN


def demo() -> None:
    import threading as _threading

    # 1. Repo-name validation is the guard in front of every URL and path built below.
    for bad in ("../../etc/passwd", "owner/repo/../..", "https://evil.test/x",
                "owner", "", "owner/repo extra", "-flag/repo\nx"):
        assert not _FULL_NAME.match(bad), bad
    for good in ("punya-henoyo/Docket", "a/b", "org.name/repo_1.2-3"):
        assert _FULL_NAME.match(good), good

    state = new_scan_state("abc", "o/r")
    assert state["status"] == "queued" and state["finding_count"] == 0
    assert set(state["stages"]) == {"fetch", "trivy", "semgrep", "nuclei"}

    saved = {k: os.environ.pop(k, None)
             for k in ("DOCKET_GITHUB_CLIENT_ID", "DOCKET_GITHUB_CLIENT_SECRET")}
    try:
        assert oauth_config() is None
        token, error = exchange_code("irrelevant")
        assert token is None and "CLIENT_ID" in error, (token, error)

        os.environ["DOCKET_GITHUB_CLIENT_ID"] = "iv1.test"
        os.environ["DOCKET_GITHUB_CLIENT_SECRET"] = "shh"
        assert oauth_config()[:2] == ("iv1.test", "shh")

        server = start_server(port=0)
        base = f"http://127.0.0.1:{server.server_address[1]}"
        _threading.Thread(target=server.serve_forever, daemon=True).start()

        # "/" serves the built SPA, or a build-me page when dist/ is absent. Either
        # way it is HTML and mentions docket — never a 404.
        page = urllib.request.urlopen(base + "/", timeout=5).read().decode()
        assert "docket" in page.lower(), page[:200]
        # An unknown non-API path is a client-side route, not a 404.
        deep = urllib.request.urlopen(base + "/findings", timeout=5).read().decode()
        assert "docket" in deep.lower(), deep[:200]
        # ...but an unknown API path still 404s rather than returning HTML.
        try:
            urllib.request.urlopen(base + "/api/nonsense", timeout=5)
            raise AssertionError("unknown API path must 404")
        except urllib.error.HTTPError as exc:
            assert exc.code == 404, exc.code

        runs = json.loads(urllib.request.urlopen(base + "/api/runs", timeout=5).read())
        assert isinstance(runs.get("runs"), list), runs

        session = json.loads(urllib.request.urlopen(base + "/api/session", timeout=5).read())
        assert session == {"connected": False, "login": None, "configured": True}, session

        # 2. /auth/start redirects to GitHub and plants a CSRF state.
        opener = urllib.request.build_opener(_NoRedirect())
        try:
            opener.open(base + "/auth/start", timeout=5)
            raise AssertionError("expected a redirect")
        except urllib.error.HTTPError as exc:
            assert exc.code == 302, exc.code
            location = exc.headers["Location"]
        assert location.startswith(GITHUB_AUTHORIZE), location
        assert SESSION.oauth_state and SESSION.oauth_state in location

        # 3. A callback whose state does not match is refused (CSRF).
        for bad_state in ("", "not-the-state"):
            try:
                urllib.request.urlopen(f"{base}/auth/callback?code=x&state={bad_state}", timeout=5)
                raise AssertionError("bad state must be refused")
            except urllib.error.HTTPError as exc:
                assert exc.code == 400, exc.code
        assert SESSION.oauth_state is None, "state must be single-use"

        # 4. Scanning without a connection is refused rather than half-attempted.
        for path, method in (("/api/repos", "GET"), ("/api/scan", "POST")):
            request = urllib.request.Request(
                base + path, method=method,
                data=b'{"repo":"a/b"}' if method == "POST" else None,
            )
            try:
                urllib.request.urlopen(request, timeout=5)
                raise AssertionError(f"{path} must require a connection")
            except urllib.error.HTTPError as exc:
                assert exc.code == 401, (path, exc.code)

        # 5. With a token present, a malformed repo name never reaches the network.
        SESSION.token = "fake"
        try:
            urllib.request.urlopen(urllib.request.Request(
                base + "/api/scan", data=b'{"repo":"../../etc/passwd"}', method="POST"), timeout=5)
            raise AssertionError("bad repo name must be rejected")
        except urllib.error.HTTPError as exc:
            assert exc.code == 400, exc.code
        SESSION.token = None

        # 6. Polling an unknown scan id is a 404, not an empty "still running".
        try:
            urllib.request.urlopen(base + "/api/scan/nope", timeout=5)
            raise AssertionError("unknown scan id must 404")
        except urllib.error.HTTPError as exc:
            assert exc.code == 404, exc.code

        server.shutdown()
    finally:
        for key, value in saved.items():
            if value is not None:
                os.environ[key] = value
            else:
                os.environ.pop(key, None)
        SESSION.token = SESSION.login = SESSION.oauth_state = None
    print("interface.connect: ok")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # noqa: ANN002, ANN003
        return None


if __name__ == "__main__":
    demo()
