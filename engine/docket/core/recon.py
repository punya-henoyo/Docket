"""Run the recon agent over mounted source and return the attack surface.

One agent, not one per finding: recon builds a single map of the whole application,
where triage judges findings individually. That makes it far cheaper than triage — one
run regardless of whether the scanners produced 12 findings or 176.

The map feeds three things downstream, which is why it runs first:
  - entry points  -> route discovery for dynamic scanning, replacing the hardcoded
                     fixture list that docket's README calls its largest gap
  - candidates    -> suspected issues no scanner pattern encodes
  - auth model    -> context a fix generator needs to not break the app
"""
from __future__ import annotations

import asyncio
from pathlib import Path
from collections.abc import Callable
from typing import Any

from docket.agents.factory import build_agent
from docket.agents.prompts.recon import build_recon_task
from docket.config.settings import Config
from docket.core.cancel import NEVER, CancelToken, ScanCancelled
from docket.core.agents import AgentCoordinator
from docket.core.execution import ScanContext, run_agent_loop

# Measured, not guessed. A 60-line Flask app maps in 6 turns for $0.06. A 1254-file
# repository with NO web surface burned all 25 turns and $1.57 producing nothing,
# because the prompt gave it no way to conclude "there are no routes here". The prompt
# now decides repository type in the first two turns and exits early on non-web code,
# which is the actual fix; this ceiling is the backstop for when that judgement fails.
#
# Raised 15 -> 24 after a real codebase (docket's own engine) burned all 15 turns on
# 27 file reads and recorded NOTHING — the worst possible outcome, a full budget spent
# for no map. 15 was tuned on a 60-line app and did not survive contact with a real
# one. The prompt now also orders the agent to record the moment it sees a turn
# warning, because a ceiling alone only decides how much you lose.
DEFAULT_MAX_TURNS = 24

# Pull-request mode is a much smaller job and gets a much smaller ceiling. The
# discovery phase is gone — the changed files are handed over rather than grepped for
# — so the turns go straight into reading handlers and their siblings. Measured: a
# full map of a 26-file app used 22-40 reads across ~20 turns, and most of that was
# finding the routes rather than judging them.
#
# 5.3 minutes per pull request is too slow to gate a merge, and the turn count is what
# that time is made of.
PR_MAX_TURNS = 10
MAX_HINTS = 20


def hint_files(findings: list[dict[str, Any]]) -> list[str]:
    """Files the scanners already touched, as a starting point.

    A hint, never a boundary — the prompt says so explicitly. An agent that only looks
    where semgrep already looked cannot find what semgrep missed, which is the entire
    reason this agent exists.
    """
    seen: list[str] = []
    for finding in findings:
        location = finding.get("location") or {}
        path = location.get("source_file") or location.get("path") or ""
        path = str(path).split(":")[0]
        if path and path not in seen:
            seen.append(path)
        if len(seen) >= MAX_HINTS:
            break
    return seen


def run_recon(
    repo: str,
    *,
    run_dir: Path,
    config: Config,
    sandbox: Any,
    findings: list[dict[str, Any]] | None = None,
    max_turns: int = DEFAULT_MAX_TURNS,
    model_override: Any = None,
    cancel: CancelToken = NEVER,
    on_agent: Callable[[dict[str, Any]], None] | None = None,
    source_root: str | None = None,
    changed: list[str] | None = None,
) -> dict[str, Any] | None:
    """The attack surface, or None. Never raises: recon is enrichment, and a scan that
    already produced findings must not be lost because the mapper failed."""
    if sandbox is None:
        return None
    if cancel.cancelled:
        return None

    coordinator = AgentCoordinator(
        max_agents=1,
        budget_usd=config.max_cost_usd,
        per_agent_reserve_usd=config.max_child_cost_usd,
    )
    context = ScanContext(
        target_url="",  # recon reads the repository; it never touches a target
        run_dir=run_dir,
        agent_id="recon",
        role="recon",
        coordinator=coordinator,
        config=config,
        model_override=model_override,
        sandbox=sandbox,
        # Without this the host-side read_source/list_source/grep_source resolved
        # `source_root or ""` to the CWD and mapped docket's own repository.
        source_root=source_root,
    )
    if on_agent is not None:
        on_agent({"id": "recon", "role": "recon", "status": "running",
                  "label": repo, "detail": "mapping the attack surface"})
    agent = build_agent(
        "recon", config,
        model=model_override("recon") if model_override else None,
        sandbox=sandbox,
    )
    try:
        output = asyncio.run(run_agent_loop(
            agent, context,
            build_recon_task(repo, hint_files(findings or []), changed=changed),
            max_turns=max_turns,
        ))
    except ScanCancelled:
        raise  # a stop is not a failed map; it must reach run_repo_scan
    except Exception:
        if on_agent is not None:
            on_agent({"id": "recon", "role": "recon", "status": "error"})
        return None
    surface = _surface_from(output)
    if surface is not None and getattr(context, "salvaged", False):
        # The agent ran out of turns and was given one last turn to write down what it
        # had. What it recorded is real; what it never reached is unknown, and only
        # this flag distinguishes "the app has 20 routes" from "it found 20 before
        # running out".
        surface["partial"] = True
    if on_agent is not None:
        on_agent({"id": "recon", "role": "recon",
                  "status": "done" if surface else "error",
                  "outcome": (f"{len(surface['entry_points'])} entry points"
                              if surface else None)})
    return surface


def _surface_from(output: Any) -> dict[str, Any] | None:
    """Only a real record_surface call counts. An agent that stopped some other way has
    no map, and half a map presented as whole is how a scanner ends up attacking routes
    nobody confirmed exist."""
    if not isinstance(output, dict) or not output.get("entry_points"):
        return None
    return {
        "entry_points": output["entry_points"],
        "auth_model": output.get("auth_model", ""),
        "candidates": output.get("candidates", []),
        "notes": output.get("notes", ""),
    }


def demo() -> None:
    findings = [
        {"location": {"source_file": "app/views.py:42"}},
        {"location": {"source_file": "app/views.py:88"}},   # same file, once only
        {"location": {"path": "settings.py"}},
        {"location": {}},                                    # nothing to hint with
    ]
    assert hint_files(findings) == ["app/views.py", "settings.py"], hint_files(findings)
    assert hint_files([]) == []

    assert _surface_from(None) is None
    # No entry points means no map, however friendly the summary sounds.
    assert _surface_from({"summary": "stopped early"}) is None
    assert _surface_from({"entry_points": []}) is None

    got = _surface_from({
        "entry_points": [{"path": "/login", "file": "app.py:29"}],
        "auth_model": "session cookie",
        "candidates": [{"title": "no ownership check"}],
        "notes": "middleware not in this repo",
    })
    assert got["entry_points"][0]["path"] == "/login"
    assert got["candidates"][0]["title"] == "no ownership check"

    # No sandbox means no source; there is nothing honest to map.
    assert run_recon("x/y", run_dir=Path("/tmp"), config=None, sandbox=None) is None
    print("core.recon: ok")


if __name__ == "__main__":
    demo()
