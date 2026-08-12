"""The docket console: one server, one frontend, both halves of the tool.

docket does two quite different things, and the console shows both rather than making
you pick a window:

  - a REPO SCAN: deterministic scanners (trivy, semgrep, nuclei) over source pulled
    read-only from GitHub. Four ordered stages, polls fine.
  - a LIVE RUN: agents choosing payloads against a target and proving what they find.
    Bursts and stalls unpredictably, so it streams over a WebSocket.

Routes are split by which of those they serve — `routers/github.py` and `routers/runs.py`
— rather than by HTTP verb, so a change to one half cannot quietly reach into the other.

Binds to loopback. Nothing here is hardened for exposure: it can start a process that
fires real exploit payloads, so it must never be reachable from anything but this machine.
"""
from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app.backend.routers import github, runs

FRONTEND_DIST = Path(__file__).resolve().parent.parent / "frontend" / "dist"


@asynccontextmanager
async def lifespan(_: FastAPI):
    yield
    # A scan outliving the server would keep a container up and keep writing to a run
    # directory nothing is watching.
    runs.manager.stop_all()


api = FastAPI(title="docket console", lifespan=lifespan)
api.include_router(runs.router)
api.include_router(github.router)

# Mounted LAST: a catch-all static mount at "/" would otherwise shadow every API route.
# html=True serves index.html for unknown paths, which is what the hash router needs.
if FRONTEND_DIST.is_dir():
    api.mount("/", StaticFiles(directory=FRONTEND_DIST, html=True), name="console")


def demo() -> None:
    from fastapi.testclient import TestClient

    with TestClient(api) as client:
        health = client.get("/api/health").json()
        assert "docker" in health and health["loopback_only"] in (True, False)
        assert isinstance(client.get("/api/runs").json()["runs"], list)

        # Both halves are mounted, and neither shadows the other. Read off the routers
        # rather than api.routes, which wraps included routers in an opaque object.
        paths = {r.path for r in (*runs.router.routes, *github.router.routes)}
        assert {"/api/health", "/api/runs", "/api/scans"} <= paths, paths
        assert {"/api/session", "/api/repos", "/api/scan"} <= paths, paths

        # The GitHub half degrades to a clear 401/503 rather than a 500 when nothing is
        # configured — this is the state a first-time user actually opens the console in.
        assert client.get("/api/session").json()["connected"] is False
        assert client.get("/api/repos").status_code == 401
        assert client.get("/auth/start", follow_redirects=False).status_code in (302, 503)

        # The loopback guard, tested through check_target with the override forced OFF
        # rather than by POSTing a real hostname. POSTing was the original test and it was
        # dangerous: on a machine where the operator has legitimately set
        # DOCKET_APP_ALLOW_ANY_TARGET=1, it does not 403 — it STARTS A SCAN against
        # whatever hostname the test named. A self-check must never be able to send
        # exploit traffic anywhere, whatever the local config says.
        import app.backend.scans as scans_mod

        original = scans_mod.allow_any_target
        scans_mod.allow_any_target = lambda: False
        try:
            for host in ("example.com", "http://10.0.0.5", "https://staging.internal"):
                try:
                    scans_mod.check_target(host)
                    raise AssertionError(f"{host} must be refused while loopback-only")
                except scans_mod.TargetRefused:
                    pass
            # Keys on the parsed HOST, not a substring: this merely mentions localhost.
            try:
                scans_mod.check_target("http://evil.test/localhost")
                raise AssertionError("path-only 'localhost' must not pass the guard")
            except scans_mod.TargetRefused:
                pass
            assert scans_mod.check_target("127.0.0.1:8000") == "http://127.0.0.1:8000"
        finally:
            scans_mod.allow_any_target = original
        assert runs.manager.current() is None, "no self-check may leave a scan running"

        # Run-name traversal must not escape the runs root.
        for bad in ("../../etc", "..%2f..%2fetc"):
            assert client.get(f"/api/runs/{bad}").status_code in (400, 404)
    print("app.backend.main: ok")


if __name__ == "__main__":
    demo()
