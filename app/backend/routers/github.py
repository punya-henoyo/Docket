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
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel

from docket.interface import connect

router = APIRouter()


class RepoScanRequest(BaseModel):
    repo: str
    # A branch, tag or commit SHA. None means the repository's default branch, which is
    # what GitHub serves when the tarball path omits a ref.
    ref: str | None = None


@router.get("/api/session")
def session() -> dict:
    configured = connect.oauth_config() is not None
    token = connect.SESSION.token
    return {
        "connected": bool(token),
        "login": connect.SESSION.login,
        "configured": configured,
        # Shown in the console so the granted scope is visible on screen rather than
        # buried in a config file nobody rereads.
        "scope": connect.oauth_scope(),
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
            "GitHub OAuth App is not configured. Set the client id/secret — see "
            "engine/docket/interface/connect.py:oauth_config.",
        )
    client_id, _, redirect = config
    # CSRF, mirroring connect.py's own handler: an attacker who can make the browser hit
    # /auth/callback with their code would otherwise bind THEIR GitHub account to this
    # session. Single-use — the callback clears it.
    state = secrets.token_urlsafe(24)
    connect.SESSION.oauth_state = state
    # The scope MUST reach the authorize URL. Without it GitHub issues a token that can
    # read nothing private, and the failure looks identical to "this user has no
    # repositories".
    params = {"client_id": client_id, "state": state, "scope": connect.oauth_scope()}
    if redirect:
        params["redirect_uri"] = redirect
    return RedirectResponse(
        f"{connect.GITHUB_AUTHORIZE}?{urllib.parse.urlencode(params)}", status_code=302,
    )


# response_model=None: FastAPI reads a return annotation as a response model, and a
# Response union is not a valid Pydantic field — it refuses to even start the app.
@router.get("/auth/callback", response_model=None)
def auth_callback(code: str = "", state: str = ""):
    """Mirrors connect.py's _auth_callback exactly. Ported because the consolidation moved
    /auth/start here and left the callback behind: GitHub redirected back, the static mount
    served index.html, the code was never exchanged, and the page looked fine while being
    unauthenticated. A half-connected console is worse than an error.
    """
    # Single-use, and cleared BEFORE any comparison so a replayed callback cannot re-use it.
    expected, connect.SESSION.oauth_state = connect.SESSION.oauth_state, None
    if not expected or not secrets.compare_digest(state, expected):
        # compare_digest, not ==, so the check is not timing-distinguishable. Without this
        # an attacker who can make the browser hit this URL with their own code binds THEIR
        # GitHub account to this session.
        return JSONResponse({"error": "state mismatch — restart the connection"}, 400)
    if not code:
        return JSONResponse({"error": "no code in callback"}, 400)

    token, error = connect.exchange_code(code)
    if error:
        return JSONResponse({"error": error}, 502)
    connect.SESSION.token = token
    try:
        connect.SESSION.login = (connect._api("/user", token) or {}).get("login")
    except Exception:
        connect.SESSION.login = None       # a name is cosmetic; the token is what matters
    # App.tsx watches for ?connected= and jumps to the repo picker.
    return RedirectResponse("/?connected=1", status_code=302)


@router.get("/api/scan/{scan_id}")
def scan_state(scan_id: str) -> dict:
    state = connect.SESSION.scans.get(scan_id)
    if state is None:
        raise HTTPException(404, f"no scan {scan_id!r}")
    return state


@router.get("/api/run/{run_name}")
def load_run(run_name: str) -> dict:
    """A finished run, rehydrated from disk into the ScanState shape.

    The console keeps its live scan in memory only, so without this a reload loses
    everything even though report.json has been sitting there the whole time.
    connect.load_run does the path-traversal check and returns (status, payload).
    """
    status, payload = connect.load_run(run_name)
    if status != 200:
        raise HTTPException(status, payload.get("error", "could not load run"))
    return payload


@router.post("/api/scan", status_code=201)
def start_repo_scan(request: RepoScanRequest) -> dict:
    token = connect.SESSION.token
    if not token:
        raise HTTPException(401, "not connected to GitHub — authorize first")
    if not connect._FULL_NAME.match(request.repo):
        # Validated before it reaches a URL or the filesystem, not after.
        raise HTTPException(400, f"invalid repository name: {request.repo!r}")
    ref = (request.ref or "").strip() or None
    # Slashes are legal in a ref and are not in owner/name, so this is a separate check
    # rather than a reuse of _FULL_NAME. Same reason it is done here: the ref is
    # interpolated into a GitHub API path.
    if ref is not None and not connect.valid_ref(ref):
        raise HTTPException(400, f"not a usable branch/tag/sha: {ref!r}")
    scan_id = uuid.uuid4().hex[:12]
    connect.SESSION.scans[scan_id] = connect.new_scan_state(scan_id, request.repo, ref)
    threading.Thread(
        target=connect.run_repo_scan, args=(request.repo, token, scan_id, ref),
        name=f"repo-scan-{scan_id}", daemon=True,
    ).start()
    return {"id": scan_id, "status": "queued"}
