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
DEFAULT_MAX_TURNS = 15
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
            build_recon_task(repo, hint_files(findings or [])),
            max_turns=max_turns,
        ))
    except ScanCancelled:
        raise  # a stop is not a failed map; it must reach run_repo_scan
    except Exception:
        if on_agent is not None:
            on_agent({"id": "recon", "role": "recon", "status": "error"})
        return None
    surface = _surface_from(output)
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
