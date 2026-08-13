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
from pydantic import BaseModel, Field

from docket.core.cancel import CancelToken
from docket.interface import connect

router = APIRouter()


class CancelRequest(BaseModel):
    # Optional: the Stop button sends {} and means "the live one".
    id: str | None = None


class RepoScanRequest(BaseModel):
    repo: str
    # A branch, tag or commit SHA. None means the repository's default branch, which is
    # what GitHub serves when the tarball path omits a ref.
    ref: str | None = None
    # The three AI-phase controls. They were MISSING here while the frontend already sent
    # them and connect.py's stdlib server already validated them, so pydantic dropped
    # them silently (extra fields are ignored by default) and run_repo_scan took its
    # defaults: triage_max=0, recon=False. Result: the console's "AI recon" and "AI
    # triage" toggles did nothing at all, with no error anywhere to say why. Third
    # instance of the same twin-server divergence as /auth/callback and /api/download.
    #
    # Each defaults OFF because each spends real money: one LLM agent per triaged
    # finding, one per repo for recon.
    triage_max: int = Field(default=0, ge=0)
    recon: bool = False
    # A ceiling in dollars, not a count — the only control that bounds what an AI phase
    # actually costs. triage_max caps how many findings are judged and says nothing about
    # the cost of each. gt=0 because 0 means "unset", not "spend nothing".
    budget_usd: float | None = Field(default=None, gt=0)


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
    """Mirrors connect.py's /api/scan/<id> handler, including the usage refresh it was
    missing here.

    Three bugs lived in the four lines this replaces:

    1. `_merge_live_usage` was never called, so cost_usd, input_tokens, output_tokens and
       every per-agent turn count stayed at their new_scan_state zeros for the whole run.
       That is the "live budget shows nothing" symptom. It has to happen on every READ
       rather than when something calls snapshot(), because during recon nothing calls
       snapshot() for minutes at a time — the runner's on_progress fires only after recon
       finishes. Joining at read time means a poll can never show a stale number.
    2. No SESSION.lock, while the scan thread mutates this dict from its own thread.
    3. The live dict was returned by reference, so FastAPI serialised a structure being
       mutated underneath it — a "dictionary changed size during iteration" waiting to
       happen. Copy inside the lock, like connect.py does.

    Fifth instance of the twin-server divergence, after /auth/callback, /api/download,
    the AI-phase flags and /api/scan/cancel.
    """
    with connect.SESSION.lock:
        state = connect.SESSION.scans.get(scan_id)
        if state is not None and state.get("status") in connect.LIVE_STATUSES:
            connect._merge_live_usage(state)
        payload = dict(state) if state is not None else None
    if payload is None:
        raise HTTPException(404, f"no scan {scan_id!r}")
    return payload


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
    if request.triage_max or request.recon:
        # Refuse early with the real reason rather than starting a scan that dies partway
        # through its first agent turn. Config.from_env() is what loads .env, so asking it
        # beats reading os.environ — the same mistake that made oauth_config report an
        # unconfigured GitHub App on a correctly-configured machine.
        try:
            from docket.config.settings import Config

            Config.from_env()
        except Exception as exc:
            raise HTTPException(400, f"AI agents need a model configured: {exc}") from exc

    scan_id = uuid.uuid4().hex[:12]
    # Echoed into the scan state so the console can show what was REQUESTED next to what
    # happened; TriagePanel reads scan.triage_max to say "judged 3 of 5" rather than just
    # "3", and a requested-but-zero count is how you tell "nothing to judge" from "the
    # phase never ran".
    # A real CancelToken, not None: passing None gave the scan nothing to check, so the
    # console's Stop button could not have worked even once the route below existed.
    cancel = CancelToken()
    with connect.SESSION.lock:
        connect.SESSION.scans[scan_id] = connect.new_scan_state(
            scan_id, request.repo, ref, request.triage_max, request.recon,
            request.budget_usd,
        )
        connect.SESSION.cancels[scan_id] = cancel
    threading.Thread(
        target=connect.run_repo_scan,
        args=(request.repo, token, scan_id, ref, request.triage_max, request.recon,
              cancel, request.budget_usd),
        name=f"repo-scan-{scan_id}", daemon=True,
    ).start()
    return {"id": scan_id, "status": "queued"}


@router.post("/api/scan/cancel", status_code=202)
def cancel_scan(request: CancelRequest) -> dict:
    """Ask the running scan to stop at its next checkpoint.

    Ported from connect.py:_cancel_scan, which was the only place it existed — so the
    frontend's Stop button (api/github.ts:19) POSTed to a path this server did not serve
    and the scan carried on. Fourth instance of the twin-server divergence, after
    /auth/callback, /api/download and the AI-phase flags above.

    202, not 200: the scan has NOT stopped when this returns, it has been asked to.
    Reporting a stop that has not happened is how a UI ends up showing "stopped" over a
    scanner still burning CPU.
    """
    scan_id = (request.id or "").strip()
    with connect.SESSION.lock:
        # No id means "whatever is running", which is what the Stop button sends: the
        # console only ever shows one live scan.
        if not scan_id:
            scan_id = next(
                (k for k, v in connect.SESSION.scans.items()
                 if v.get("status") in ("queued", "fetching", "scanning")),
                "",
            )
        cancel = connect.SESSION.cancels.get(scan_id)
        state = connect.SESSION.scans.get(scan_id)
    if cancel is None or state is None:
        raise HTTPException(404, "no scan is running")
    if state.get("status") in ("done", "error", "cancelled"):
        raise HTTPException(409, f"scan already {state['status']}")
    cancel.cancel("stopped by the operator")
    return {"id": scan_id, "status": "cancelling"}
