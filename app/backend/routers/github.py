"""GitHub connect routes, backed by engine/docket/interface/connect.py.

The logic there is already separated from its HTTP layer — `list_repos`, `fetch_source`,
`run_repo_scan` and friends are plain functions — so this exposes them as FastAPI routes
instead of duplicating 600 lines. `docket connect` still serves the same endpoints from
its own stdlib server; this is the same behaviour reachable from the one console.
"""
from __future__ import annotations

import secrets
import threading
import urllib.parse
import uuid

from fastapi import APIRouter, HTTPException
from fastapi.responses import RedirectResponse
from pydantic import BaseModel

from docket.interface import connect

router = APIRouter()


class RepoScanRequest(BaseModel):
    repo: str


@router.get("/api/session")
def session() -> dict:
    configured = connect.oauth_config() is not None
    token = connect.SESSION.token
    return {
        "connected": bool(token),
        "login": connect.SESSION.login,
        "configured": configured,
    }


@router.get("/api/repos")
def repos() -> dict:
    token = connect.SESSION.token
    if not token:
        raise HTTPException(401, "not connected to GitHub — authorize first")
    try:
        return {"repos": connect.list_repos(token)}
    except Exception as exc:
        raise HTTPException(502, f"GitHub API call failed: {exc}") from exc


@router.get("/auth/start")
def auth_start() -> RedirectResponse:
    config = connect.oauth_config()
    if config is None:
        raise HTTPException(
            503,
            "GitHub App is not configured. Set the client id/secret — see "
            "engine/docket/interface/connect.py:oauth_config.",
        )
    client_id, _, redirect = config
    # CSRF, mirroring connect.py's own handler: an attacker who can make the browser hit
    # /auth/callback with their code would otherwise bind THEIR GitHub account to this
    # session. Single-use — the callback clears it.
    state = secrets.token_urlsafe(24)
    connect.SESSION.oauth_state = state
    params = {"client_id": client_id, "state": state}
    if redirect:
        params["redirect_uri"] = redirect
    return RedirectResponse(
        f"{connect.GITHUB_AUTHORIZE}?{urllib.parse.urlencode(params)}", status_code=302,
    )


@router.get("/api/scan/{scan_id}")
def scan_state(scan_id: str) -> dict:
    state = connect.SESSION.scans.get(scan_id)
    if state is None:
        raise HTTPException(404, f"no scan {scan_id!r}")
    return state


@router.post("/api/scan", status_code=201)
def start_repo_scan(request: RepoScanRequest) -> dict:
    token = connect.SESSION.token
    if not token:
        raise HTTPException(401, "not connected to GitHub — authorize first")
    if not connect._FULL_NAME.match(request.repo):
        # Validated before it reaches a URL or the filesystem, not after.
        raise HTTPException(400, f"invalid repository name: {request.repo!r}")
    scan_id = uuid.uuid4().hex[:12]
    connect.SESSION.scans[scan_id] = connect.new_scan_state(scan_id, request.repo)
    threading.Thread(
        target=connect.run_repo_scan, args=(request.repo, token, scan_id),
        name=f"repo-scan-{scan_id}", daemon=True,
    ).start()
    return {"id": scan_id, "status": "queued"}
