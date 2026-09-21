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

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app.backend.routers import compliance, github, runs, service

FRONTEND_DIST = Path(__file__).resolve().parent.parent / "frontend" / "dist"


log = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(_: FastAPI):
    # Reload the saved GitHub session BEFORE serving. Without this the OAuth token
    # lives only in connect.SESSION, so every restart of this console logs the operator
    # out: /api/session reports connected:false, the repo list comes back empty, and the
    # scan form has nothing to offer. connect.py already restores on its own startup;
    # this console never did, which is the twin-server divergence again.
    try:
        from docket.interface import connect

        if connect.restore_session():
            log.info("restored the saved GitHub session")
    except Exception as exc:  # noqa: BLE001 - a console that cannot restore must still boot
        log.warning("could not restore the saved session: %s", exc)
    yield
    # A scan outliving the server would keep a container up and keep writing to a run
    # directory nothing is watching.
    runs.manager.stop_all()


api = FastAPI(title="docket console", lifespan=lifespan)
api.include_router(runs.router)
api.include_router(github.router)
# The control plane: watched repos, policy, the PR-scan inbox, the poller. Included here,
# BEFORE the static mount below, for the reason stated there.
api.include_router(service.router)
# Control packs: list, read, upload a policy, delete an uploaded one. Same placement
# rule as the others — before the static mount.
api.include_router(compliance.router)

# Mounted LAST: a catch-all static mount at "/" would otherwise shadow every API route.
# html=True serves index.html for unknown paths, which is what the hash router needs.
if FRONTEND_DIST.is_dir():
    api.mount("/", StaticFiles(directory=FRONTEND_DIST, html=True), name="console")


def frontend_endpoints() -> set[str]:
    """Every /api path the console's client actually calls, read from its source.

    Derived rather than hand-listed, because a hand-listed copy is a THIRD place to
    forget — and forgetting is the entire failure mode this guards.
    """
    import re

    root = Path(__file__).resolve().parents[2] / "app" / "frontend" / "src" / "api"
    found: set[str] = set()
    for source in root.glob("*.ts"):
        for raw in re.findall(r'"(/api/[^"`]*)"|`(/api/[^`]*)`', source.read_text()):
            path = (raw[0] or raw[1]).split("?")[0]
            # Template holes become a single segment: `/api/scan/${id}` -> `/api/scan`.
            # A template hole can be glued to the previous segment by a dot
            # (`/api/download/${name}.${fmt}`), so strip the dot form first.
            path = re.sub(r"\.\$\{[^}]*\}", "", path)
            path = re.sub(r"/\$\{[^}]*\}", "", path).rstrip("/")
            if path:
                found.add(path)
    return found


def check_twin_server_parity() -> list[str]:
    """Endpoints the frontend calls that one of the two servers does not answer.

    THE RECURRING BUG. docket ships two servers for one console — this FastAPI app and
    the stdlib handler in interface/connect.py — and they have drifted six times:
    /auth/callback, /api/download, the AI-phase flags, /api/scan/cancel, the scan-detail
    payload, and finally /api/watch + /api/fixes + /api/scans/active, which existed only
    on the stdlib side while the frontend called all three unconditionally. Served by
    app/run.py, the Pull requests view was simply dead.

    Every one was found by a human noticing. This finds the next one.
    """
    import re

    # From the OpenAPI schema, not api.routes: this FastAPI version wraps included
    # routers in _IncludedRouter objects that carry no `.path`, so walking api.routes
    # finds four docs endpoints and nothing else — a check that would have reported every
    # single endpoint missing and been switched off within a day.
    fastapi_paths = {
        re.sub(r"/\{[^}]*\}", "", path).rstrip("/")
        for path in api.openapi().get("paths", {})
    }
    connect_source = (Path(__file__).resolve().parents[2] / "engine" / "docket" /
                      "interface" / "connect.py").read_text()

    problems: list[str] = []
    for endpoint in sorted(frontend_endpoints()):
        if endpoint not in fastapi_paths:
            problems.append(f"{endpoint}: called by the console, MISSING from FastAPI")
        # The stdlib server dispatches on string literals, so presence of the literal is
        # the signal available without running it.
        if f'"{endpoint}"' not in connect_source and f'"{endpoint}/' not in connect_source:
            problems.append(f"{endpoint}: called by the console, MISSING from connect.py")
    return problems


def demo_parity() -> None:
    """The check that would have caught all six divergences. Must be able to fail."""
    problems = check_twin_server_parity()
    assert not problems, "twin-server divergence:\n  " + "\n  ".join(problems)
    endpoints = frontend_endpoints()
    # Sanity: if the extraction silently returned nothing, the assertion above passes
    # vacuously and the guard is decorative.
    assert len(endpoints) >= 8, endpoints
    assert "/api/watch" in endpoints and "/api/session" in endpoints, endpoints
    # And it must actually fail on a missing route, or it proves nothing.
    import re as _re

    fastapi_paths = {_re.sub(r"/\{[^}]*\}", "", p).rstrip("/")
                     for p in api.openapi().get("paths", {})}
    assert "/api/watch" in fastapi_paths, "the parity check is looking in the wrong place"


def demo() -> None:
    # HERMETIC. The assertions below describe a console nobody has connected yet, but the
    # lifespan calls restore_session(), so on any machine with a saved GitHub token this
    # failed — `connected` came back True and the demo asserted False. It was a latent
    # flake for as long as this module was absent from `make check`; adding it turned that
    # into a build failure on the maintainer's own laptop. A self-check whose result
    # depends on the developer's saved credentials tests the developer, not the code.
    import os as _os

    _saved_session_flag = _os.environ.get("DOCKET_NO_SESSION_FILE")
    _os.environ["DOCKET_NO_SESSION_FILE"] = "1"
    try:
        _demo_body()
    finally:
        _os.environ.pop("DOCKET_NO_SESSION_FILE", None)
        if _saved_session_flag is not None:
            _os.environ["DOCKET_NO_SESSION_FILE"] = _saved_session_flag


def _demo_body() -> None:
    from fastapi.testclient import TestClient

    with TestClient(api) as client:
        health = client.get("/api/health").json()
        assert "docker" in health and health["loopback_only"] in (True, False)
        assert isinstance(client.get("/api/runs").json()["runs"], list)

        # Both halves are mounted, and neither shadows the other. Read off the routers
        # rather than api.routes, which wraps included routers in an opaque object.
        paths = {r.path for r in (*runs.router.routes, *github.router.routes,
                                  *service.router.routes)}
        assert {"/api/health", "/api/runs", "/api/scans"} <= paths, paths
        assert {"/api/session", "/api/repos", "/api/scan"} <= paths, paths
        assert {"/api/service/status", "/api/service/repos",
                "/api/service/scans"} <= paths, paths
        # The control plane degrades to a 503 naming the missing half rather than a 500,
        # which is the state every machine is in until the service store is built.
        assert client.get("/api/service/status").status_code in (200, 503)

        # The GitHub half degrades to a clear 401/503 rather than a 500 when nothing is
        # configured — this is the state a first-time user actually opens the console in.
        assert client.get("/api/session").json()["connected"] is False
        assert client.get("/api/repos").status_code == 401
        assert client.get("/auth/start", follow_redirects=False).status_code in (302, 503)

        # The OAuth callback. Tested in BOTH directions, because a route that 400s on
        # everything would pass a rejects-bad-state check while being completely broken —
        # and this route was missing entirely after the console consolidation, so GitHub
        # redirected back, the static mount served index.html, and the page looked fine
        # while never exchanging the code.
        from docket.interface import connect

        assert client.get("/auth/callback?code=x&state=wrong",
                          follow_redirects=False).status_code == 400
        connect.SESSION.oauth_state = "planted-state"
        passed = client.get("/auth/callback?code=c&state=planted-state",
                            follow_redirects=False)
        assert passed.status_code != 400, "a genuine state must reach the token exchange"
        # Single-use: the state was cleared on first use, so a replay must fail.
        assert client.get("/auth/callback?code=c&state=planted-state",
                          follow_redirects=False).status_code == 400
        connect.SESSION.oauth_state = None

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
    demo_parity()
    print("app.backend.main: ok")


if __name__ == "__main__":
    demo()
