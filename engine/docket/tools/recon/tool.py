"""`record_surface`: the only way a recon agent can end its turn.

What this exists to produce is the thing no pattern tool can: a map of the application
— where untrusted input enters, how the app decides who you are, and which of those
entry points nobody guarded. Semgrep answers "does this line look dangerous". This
answers "what is this application and where is it soft".

Same stance as `finding` and `triage_verdict`: every entry point must cite the file it
was read from. An invented route sends a DAST agent to attack something that does not
exist, and an invented "no auth check" is a false accusation about someone's codebase.
Both are worse than an incomplete map.
"""
from __future__ import annotations

from typing import Any

from agents import RunContextWrapper, function_tool

from docket.core.execution import ScanContext

MAX_ENTRY_POINTS = 200


def build_surface(
    entry_points: list[dict[str, Any]] | None,
    auth_model: str,
    candidates: list[dict[str, Any]] | None,
    notes: str,
) -> dict[str, Any]:
    """The gate, separate from the SDK wrapper so the rule is testable and readable."""
    entries = entry_points or []
    if not entries:
        return {
            "ok": False,
            "error": (
                "surface refused — no entry points recorded. If this repository truly "
                "exposes none (a library, a CLI, a config repo), say so in `notes` and "
                "pass a single entry with kind='none' explaining why. An empty map with "
                "no explanation is indistinguishable from not having looked."
            ),
        }
    if len(entries) > MAX_ENTRY_POINTS:
        entries = entries[:MAX_ENTRY_POINTS]

    uncited = [e for e in entries if not str(e.get("file", "")).strip()]
    if uncited:
        return {
            "ok": False,
            "error": (
                f"surface refused — {len(uncited)} entry point(s) cite no file. Every "
                "route must name the file it was read from. A route nobody can point at "
                "in source sends a scanner to attack something that may not exist."
            ),
        }
    return {
        "ok": True,
        "entry_points": entries,
        "auth_model": auth_model.strip(),
        "candidates": candidates or [],
        "notes": notes.strip(),
    }


@function_tool(strict_mode=False)  # open-ended dicts; strict schema cannot express them
async def record_surface(
    ctx: RunContextWrapper[ScanContext],
    entry_points: list[dict],
    auth_model: str,
    candidates: list[dict],
    notes: str,
) -> dict:
    """Record the application's attack surface, and finish.

    Args:
        entry_points: every place untrusted input enters. One object each:
            `method` (GET/POST/CLI/QUEUE/...), `path` ("/api/orders/<id>"),
            `handler` (function name), `file` ("app.py:29" — REQUIRED, must be a
            file you read), `params` (list of names the handler reads),
            `auth` ("session cookie" / "none found" / "@login_required").
            Use kind='none' for a repository that exposes no entry points at all.
        auth_model: how the app decides who you are and what you may do, in two or
            three sentences. Say "none found" if there is none — that is a finding.
        candidates: suspected issues NO scanner flagged, each with `title`, `file`,
            `why`. Missing ownership checks, unguarded admin routes, trust boundaries
            crossed without validation. This is the part a pattern tool cannot do.
        notes: what you could not determine and why. Gaps stated are useful; gaps
            hidden are not.
    """
    return build_surface(entry_points, auth_model, candidates, notes)


def demo() -> None:
    # An empty map must be refused: it is indistinguishable from not having looked.
    empty = build_surface([], "none", [], "")
    assert empty["ok"] is False and "no entry points" in empty["error"], empty

    # Uncited routes are the dangerous failure: they send a scanner at a route that
    # may not exist, or accuse a codebase of a check it actually has.
    uncited = build_surface(
        [{"method": "GET", "path": "/admin", "handler": "admin"}], "session", [], "")
    assert uncited["ok"] is False and "cite no file" in uncited["error"], uncited

    ok = build_surface(
        [{"method": "POST", "path": "/login", "handler": "login", "file": "app.py:29",
          "params": ["username", "password"], "auth": "none"}],
        "Session cookie set at /login; no role checks found.",
        [{"title": "no ownership check on /export", "file": "app.py:42",
          "why": "reads `file` param straight into a shell command"}],
        "Could not resolve how sessions are validated; middleware is not in this repo.",
    )
    assert ok["ok"] is True
    assert ok["entry_points"][0]["path"] == "/login"
    assert ok["candidates"][0]["file"] == "app.py:42"

    # A library with no HTTP surface is a legitimate answer, not a failure.
    lib = build_surface(
        [{"kind": "none", "file": "pyproject.toml", "path": "-", "method": "-"}],
        "n/a", [], "Packaged library; no server, no routes.")
    assert lib["ok"] is True, lib
    print("tools.recon: ok")


if __name__ == "__main__":
    demo()
