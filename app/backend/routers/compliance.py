"""Control packs: list, read, upload a policy, delete an uploaded one.

Thin on purpose. Every decision lives in docket.compliance.service as (status, body)
pairs, because interface/connect.py serves the same console from a stdlib
BaseHTTPRequestHandler and the two must not drift — a feature wired into only one of them
works on a coin flip depending on which server the operator started.

The upload takes a RAW BODY plus `?filename=`, not multipart. That keeps
`python-multipart` out of the dependency list for a form encoding docket has no other use
for, and it means connect.py — which reads a raw body already — needs no second parser.
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Body, HTTPException, Query
from fastapi.responses import JSONResponse

from docket.compliance.service import delete_pack, pack_detail, packs_index, upload_pack
from docket.config.settings import RUNS_DIR
from docket.compliance.ingest import MAX_BYTES

log = logging.getLogger("docket.console.compliance")
router = APIRouter(prefix="/api/compliance", tags=["compliance"])


def _respond(pair: tuple[int, dict]) -> JSONResponse:
    """One shape for both servers. A 4xx is a BODY, not an exception: connect.py has no
    exception handler to turn one into a response, so neither does this."""
    status, body = pair
    return JSONResponse(status_code=status, content=body)


def _config():
    """The model config, or None. None is an answer the service layer handles (503 with
    the fix named) — raising here would turn a missing env var into a 500."""
    from docket.config.settings import Config

    try:
        return Config.from_env()
    except RuntimeError:
        return None


@router.get("/packs")
def get_packs() -> JSONResponse:
    """Every pack a scan could be run against, with the number of controls a repository
    can actually answer — which a picker must show BEFORE the choice, not after."""
    return _respond(packs_index())


@router.get("/packs/{pack_id}")
def get_pack(pack_id: str) -> JSONResponse:
    """The controls themselves, for review before anything is audited against them."""
    return _respond(pack_detail(pack_id))


@router.post("/packs")
def post_pack(
    filename: str = Query(..., description="original filename; its extension picks the reader"),
    body: bytes = Body(..., media_type="application/octet-stream"),
) -> JSONResponse:
    """Upload a policy document. An agent compiles it into a reviewable control pack.

    Synchronous on purpose: this is one agent over one document with a low turn ceiling,
    and the customer is waiting on the result to review it. A job queue here would be
    state to manage for a wait measured in seconds.
    """
    if len(body) > MAX_BYTES:
        raise HTTPException(413, f"file too large; the limit is {MAX_BYTES // 1024 // 1024} MB")
    return _respond(upload_pack(body, filename, config=_config(), run_dir=RUNS_DIR))


@router.delete("/packs/{pack_id}")
def remove_pack(pack_id: str) -> JSONResponse:
    """Delete an uploaded pack. Built-in packs are not deletable and return 404."""
    return _respond(delete_pack(pack_id))


def demo() -> None:
    from fastapi.testclient import TestClient

    app = __import__("fastapi").FastAPI()
    app.include_router(router)
    client = TestClient(app)

    listed = client.get("/api/compliance/packs")
    assert listed.status_code == 200, listed.text
    packs = {p["id"]: p for p in listed.json()["packs"]}
    assert "owasp-api-2023" in packs, packs
    # The number a picker must show before the choice is made: how many of a regulatory
    # pack's controls a repository can actually answer.
    assert packs["sebi-cscrf"]["source_controls"] < packs["sebi-cscrf"]["total_controls"]

    one = client.get("/api/compliance/packs/twelve-factor")
    assert one.status_code == 200 and len(one.json()["pack"]["controls"]) == 12
    assert client.get("/api/compliance/packs/nope").status_code == 404

    # An unreadable upload is the user's to fix, and the body says how. Never a 500, and
    # never a cheerful empty pack.
    bad = client.post("/api/compliance/packs?filename=p.rtf", content=b"x")
    assert bad.status_code == 400 and "Supported" in bad.json()["error"], bad.text
    assert client.post("/api/compliance/packs?filename=p.md", content=b"").status_code in (400, 422)
    # A filename is required: without it there is no way to know the format.
    assert client.post("/api/compliance/packs", content=b"x").status_code == 422

    # A built-in pack is not deletable through this route.
    assert client.delete("/api/compliance/packs/twelve-factor").status_code == 404
    print("app.backend.routers.compliance: ok")


if __name__ == "__main__":
    demo()
