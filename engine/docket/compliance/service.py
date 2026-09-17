"""HTTP-shaped operations for control packs, as (status, body) pairs.

Written as plain functions rather than routes because docket has TWO servers that must
behave identically: the FastAPI app under app/backend/ and the stdlib
BaseHTTPRequestHandler in interface/connect.py that `docket connect` runs. The console is
served by whichever one is up, so a feature wired into only one of them is a feature that
works on a coin flip. Both call these; neither reimplements them.

Nothing here imports fastapi, and nothing here raises for an expected failure — a bad
upload is a 4xx body, not an exception, because connect.py has no exception handler to
turn one into a response.

Upload transport is a RAW BODY plus `?filename=`, not multipart. Multipart would need
`python-multipart` (a dependency, for a form encoding docket has no other use for) and a
second parser in connect.py, which reads a raw body already. See compliance/ingest.py.
"""
from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

from docket.compliance.ingest import MAX_BYTES, SUPPORTED, IngestError, extract_text
from docket.compliance.models import ControlPack
from docket.compliance.packs import (
    PACK_ID,
    PackError,
    list_packs,
    load_pack,
    save_uploaded,
    uploaded_root,
)

logger = logging.getLogger(__name__)

# A filename becomes a pack id and is echoed into every citation, so it is sanitised
# rather than trusted. Path separators and traversal are the reason, and `..` reduced to
# an empty slug is why a fallback id exists below.
_UNSAFE = re.compile(r"[^A-Za-z0-9._-]+")


def _pack_id_from(filename: str) -> str:
    stem = _UNSAFE.sub("-", Path(str(filename)).stem).strip("-.").lower()[:48]
    # A name that sanitises to nothing — "..", "///", "%%%" — must fall back, not produce
    # a dangling "policy-". PACK_ID happily matches that, so the emptiness is checked here
    # rather than being left to the pattern.
    if not stem:
        return "policy-uploaded"
    # Prefixed on purpose. A customer uploading "twelve-factor.md" must not produce a pack
    # id that collides with a shipped one — save_uploaded refuses the collision anyway, but
    # failing at the name is a clearer answer than failing at the write.
    candidate = f"policy-{stem}"
    return candidate if PACK_ID.match(candidate) else "policy-uploaded"


def packs_index(*, cwd: Path | None = None) -> tuple[int, dict[str, Any]]:
    """GET /api/compliance/packs — what a picker needs, and nothing more."""
    return 200, {"packs": list_packs(cwd=cwd)}


def pack_detail(pack_id: str, *, cwd: Path | None = None) -> tuple[int, dict[str, Any]]:
    """GET /api/compliance/packs/{id} — the controls, for review before use."""
    try:
        pack = load_pack(pack_id, cwd=cwd)
    except PackError as exc:
        return 404, {"error": str(exc)}
    return 200, {"pack": pack.model_dump(mode="json")}


def upload_pack(
    body: bytes,
    filename: str,
    *,
    config: Any,
    run_dir: Path,
    cwd: Path | None = None,
    model_override: Any = None,
) -> tuple[int, dict[str, Any]]:
    """POST /api/compliance/packs?filename=... — ingest, compile, save, return for review.

    Saved rather than held pending, because the alternative is server-side session state
    for a thing the customer will want to come back to. It is saved as `origin: uploaded`
    and cannot shadow a built-in pack, and the response carries every dropped clause so
    the customer can see what did not make it in before they audit anything against it.
    """
    if not body:
        return 400, {"error": "no file content was sent"}
    if len(body) > MAX_BYTES:
        return 413, {"error": f"file too large; the limit is {MAX_BYTES // 1024 // 1024} MB"}
    name = Path(str(filename or "")).name.strip()
    if not name:
        return 400, {"error": f"a filename is required so docket knows the format. "
                              f"Supported: {', '.join(SUPPORTED)}"}

    try:
        text, truncated = extract_text(body, name)
    except IngestError as exc:
        # The document could not be read. This is the user's to fix, and the message says
        # how — never a fabricated empty pack.
        return 400, {"error": str(exc)}

    if config is None or not getattr(config, "llm", ""):
        return 503, {"error": "compiling a policy needs a model. Set DOCKET_LLM and "
                              "LLM_API_KEY, then upload again."}

    from docket.core.compliance import compile_pack

    pack_id = _pack_id_from(name)
    try:
        pack, dropped, error = compile_pack(
            text, source_name=name, pack_id=pack_id, run_dir=run_dir, config=config,
            truncated=truncated, model_override=model_override)
    except Exception as exc:  # noqa: BLE001 — a route must not 500 on a bad document
        logger.exception("compiling %s failed", name)
        return 500, {"error": f"the policy could not be compiled ({type(exc).__name__})"}
    if pack is None:
        return 422, {"error": error, "dropped": dropped}

    try:
        path = save_uploaded(pack, cwd=cwd)
    except PackError as exc:
        return 409, {"error": str(exc)}

    source = pack.source_controls()
    return 201, {
        "pack": pack.model_dump(mode="json"),
        "path": str(path),
        # Reported, never hidden: these are the customer's own clauses that did not become
        # controls, and they must see them before relying on the pack.
        "dropped": dropped,
        "truncated": truncated,
        # The honest headline, computed here so the console cannot invent a different one.
        "summary": (
            f"{len(pack.controls)} control(s) extracted from {name}; "
            f"{len(source)} can be checked by reading source, "
            f"{len(pack.controls) - len(source)} cannot be answered from a repository. "
            f"{len(dropped)} clause(s) were dropped."
            + (" The document was truncated." if truncated else "")
        ),
    }


def delete_pack(pack_id: str, *, cwd: Path | None = None) -> tuple[int, dict[str, Any]]:
    """DELETE /api/compliance/packs/{id} — uploaded packs only."""
    key = str(pack_id).strip()
    if not PACK_ID.match(key):
        return 400, {"error": "not a pack id"}
    path = uploaded_root(cwd=cwd) / f"{key}.json"
    # Resolved and contained, because `key` reached us from a URL. PACK_ID already
    # excludes a separator; this is the belt that does not depend on the regex staying
    # right, and it is the check that matters if the pattern is ever widened.
    root = uploaded_root(cwd=cwd).resolve()
    if not path.exists() or root not in path.resolve().parents:
        return 404, {"error": f"no uploaded pack named {key!r}. Built-in packs cannot be "
                              f"deleted."}
    path.unlink()
    return 200, {"deleted": key}


def demo() -> None:
    import tempfile

    # --- id derivation: a filename is untrusted and never becomes a path --------------
    assert _pack_id_from("ACME InfoSec v2.pdf") == "policy-acme-infosec-v2", _pack_id_from(
        "ACME InfoSec v2.pdf")
    assert _pack_id_from("../../etc/passwd") == "policy-passwd", _pack_id_from("../../etc/passwd")
    assert _pack_id_from("..") == "policy-uploaded", _pack_id_from("..")
    assert _pack_id_from("") == "policy-uploaded"
    # A customer file named after a shipped pack must not produce the shipped pack's id.
    assert _pack_id_from("twelve-factor.md") != "twelve-factor"
    for name in ("a b/c.md", "x\\y.txt", "%2e%2e.md"):
        assert "/" not in _pack_id_from(name) and "\\" not in _pack_id_from(name), name

    # --- the index and detail routes --------------------------------------------------
    status, body = packs_index()
    assert status == 200 and {"owasp-api-2023", "sebi-cscrf"} <= {p["id"] for p in body["packs"]}
    status, body = pack_detail("owasp-api-2023")
    assert status == 200 and len(body["pack"]["controls"]) == 10
    status, body = pack_detail("nope")
    assert status == 404 and "owasp-api-2023" in body["error"], body

    # --- upload refusals, each before any model is reached ----------------------------
    with tempfile.TemporaryDirectory() as tmp:
        cwd = Path(tmp)
        for args, expect, needle in (
            ((b"", "p.md"), 400, "no file content"),
            ((b"x" * (MAX_BYTES + 1), "p.md"), 413, "too large"),
            ((b"x", ""), 400, "filename is required"),
            ((b"x", "p.rtf"), 400, "Supported"),
            ((b"   ", "p.md"), 400, "no text could be extracted"),
        ):
            status, body = upload_pack(*args, config=None, run_dir=cwd, cwd=cwd)
            assert (status, needle in body["error"]) == (expect, True), (args[1], status, body)

        # A readable document with no model configured must say so rather than half-work.
        status, body = upload_pack(b"3.2.1 Passwords shall be hashed.", "p.md",
                                   config=None, run_dir=cwd, cwd=cwd)
        assert status == 503 and "needs a model" in body["error"], body

        # --- delete: uploaded packs only ----------------------------------------------
        custom = ControlPack.model_validate({
            "id": "policy-acme", "title": "ACME", "authority": "customer",
            "origin": "uploaded",
            "controls": [{"id": "policy-acme:c1", "title": "t", "requirement": "r",
                          "citation": "p1"}],
        })
        save_uploaded(custom, cwd=cwd)
        assert "policy-acme" in {p["id"] for p in packs_index(cwd=cwd)[1]["packs"]}
        assert delete_pack("policy-acme", cwd=cwd) == (200, {"deleted": "policy-acme"})
        assert "policy-acme" not in {p["id"] for p in packs_index(cwd=cwd)[1]["packs"]}

        # A shipped pack is not deletable through this route, because it is not in the
        # uploaded directory at all.
        status, body = delete_pack("twelve-factor", cwd=cwd)
        assert status == 404 and "Built-in packs cannot be deleted" in body["error"], body
        # ...and a path cannot be walked out of it.
        for bad in ("../twelve-factor", "..%2f..%2fetc%2fpasswd", "/etc/passwd", ""):
            status, _ = delete_pack(bad, cwd=cwd)
            assert status in (400, 404), (bad, status)
        assert (uploaded_root(cwd=cwd) / "policy-acme.json").exists() is False

    print("compliance.service: ok")


if __name__ == "__main__":
    demo()
