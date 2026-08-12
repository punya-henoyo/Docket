"""Run the triage agent over static findings and attach its verdicts.

Scanners are cheap and noisy: one real repository produced 93 semgrep findings, another
176. Nobody reads 176. The expensive, human part is deciding which ones untrusted input
can actually reach, and that is what an agent can do here — it has the source, it just
cannot run the app.

Deliberately BOUNDED. One agent per finding, sequential, capped, with a hard budget:
triaging 176 findings at a few turns each is real money, and a feature that quietly
spends it is worse than one that says it did less. Anything past the cap is left
untouched and reported as skipped rather than silently dropped.
"""
from __future__ import annotations

import asyncio
from collections.abc import Callable
from pathlib import Path
from typing import Any

from docket.agents.factory import build_agent
from docket.agents.prompts.triage import build_triage_task
from docket.config.settings import Config
from docket.core.cancel import NEVER, CancelToken, ScanCancelled
from docket.core.agents import AgentCoordinator
from docket.core.execution import ScanContext, run_agent_loop
from docket.report.models import Severity

# Worst first: if the budget runs out, it should run out on the low-severity tail.
_ORDER = {s.value: i for i, s in enumerate(Severity)}

DEFAULT_MAX_FINDINGS = 15

# Loose on purpose. Cost is the real bound — per-agent (max_child_cost_usd) and
# scan-wide (max_cost_usd), both checked before every model turn — and turns are a
# poor proxy for it: a turn reading one small file and a turn pulling 400 lines cost
# wildly different amounts.
#
# It is not zero, for one reason: the cost gate is only armed when the model is
# PRICED. LiteLLM cannot price an Azure deployment name, so without
# DOCKET_PRICE_*_PER_1M every turn is charged $0.00 and the budget enforces nothing.
# That was this repo's actual state until recently. Unpriced plus no turn cap is a
# loop with no stop at all, so this stays as the backstop for a disarmed budget —
# not as the working limit.
#
# MEASURED, not guessed. Same repo, same 3 findings, only this constant changed:
#
#   8 turns  -> 2 of 3 judged, $0.16,  79k tokens
#   30 turns -> 2 of 3 judged, $0.80, 405k tokens
#
# Five times the money for an identical result. The agent that fails is not running
# out of room, it is failing to converge — one run burned 29/30 turns and still had no
# verdict. Raising this buys more wandering, not more answers, so it sits just above
# where a converging agent finishes (~7) and stops paying for one that will not.
#
# The non-convergence is a PROMPT problem: an agent that cannot settle it from source
# is supposed to return `uncertain`, and does not reach for that early enough. Fix it
# there, not here.
DEFAULT_MAX_TURNS = 12


def order_for_triage(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(findings, key=lambda f: _ORDER.get(str(f.get("severity")), 99))


def apply_verdicts(store: Any, verdicts: dict[str, dict[str, Any]]) -> int:
    """Attach verdicts to the Findings still held in the store, so they reach
    report.json and the console without a second source of truth."""
    from docket.report.models import Triage

    applied = 0
    for finding in store.findings():
        verdict = verdicts.get(finding.id)
        if verdict:
            finding.triage = Triage(**verdict)
            applied += 1
    return applied


def triage_findings(
    findings: list[dict[str, Any]],
    *,
    run_dir: Path,
    config: Config,
    sandbox: Any,
    max_findings: int = DEFAULT_MAX_FINDINGS,
    max_turns: int = DEFAULT_MAX_TURNS,
    on_verdict: Callable[[str, dict[str, Any]], None] | None = None,
    on_agent: Callable[[dict[str, Any]], None] | None = None,
    model_override: Callable[[str], Any] | None = None,
    cancel: CancelToken = NEVER,
) -> dict[str, dict[str, Any]]:
    """{finding_id: verdict} for the findings triaged. Never raises: a triage pass is
    an enrichment, and losing the whole scan because one agent failed would be a bad
    trade. A finding whose agent errors simply gets no verdict."""
    if sandbox is None or not findings:
        return {}

    coordinator = AgentCoordinator(
        max_agents=1,  # sequential: concurrent agents make the budget gate racy
        budget_usd=config.max_cost_usd,
        per_agent_reserve_usd=config.max_child_cost_usd,
    )
    verdicts: dict[str, dict[str, Any]] = {}

    for index, finding in enumerate(order_for_triage(findings)[:max_findings]):
        # Before each agent, because each one costs real money. A stop requested at
        # finding 12 of 50 must not pay for the other 38.
        if cancel.cancelled:
            break
        finding_id = str(finding.get("id") or index)
        agent_id = f"triage-{index}"
        # Announced BEFORE the agent runs, not after. A roster that only shows
        # finished agents is a receipt; the point of showing it live is that you can
        # see which finding is being read right now.
        location = (finding.get("location") or {})
        label = (location.get("source_file")
                 or f"{location.get('method','')} {location.get('path','')}".strip()
                 or finding.get("rule_id", "?"))
        if on_agent is not None:
            on_agent({"id": agent_id, "role": "triage", "status": "running",
                      "label": str(label).replace("/work/source/", ""),
                      "detail": str(finding.get("rule_id", "")).rsplit(".", 1)[-1]})
        context = ScanContext(
            target_url="",  # triage never touches the target; it reads the repository
            run_dir=run_dir,
            agent_id=agent_id,
            role="triage",
            coordinator=coordinator,
            config=config,
            model_override=model_override,
            sandbox=sandbox,
        )
        agent = build_agent(
            "triage", config,
            model=model_override("triage") if model_override else None,
            sandbox=sandbox,
        )
        try:
            output = asyncio.run(run_agent_loop(
                agent, context, build_triage_task(finding), max_turns=max_turns,
            ))
        except ScanCancelled:
            # Must escape the broad handler below. Caught there it would read as
            # "triage failed" and the loop would continue to the next finding, still
            # spending money on a scan the operator already stopped.
            break
        except Exception as exc:  # noqa: BLE001 — enrichment must not sink the scan
            output = {"summary": f"triage failed: {exc}", "success": False}

        verdict = _verdict_from(output)
        if verdict is not None:
            verdicts[finding_id] = verdict
            if on_verdict is not None:
                on_verdict(finding_id, verdict)
        if on_agent is not None:
            on_agent({"id": agent_id, "role": "triage",
                      "status": "done" if verdict else "error",
                      "outcome": (verdict or {}).get("verdict")})

    return verdicts


# Prefix on any verdict this module wrote rather than the agent. Without it a
# synthesised `uncertain` is indistinguishable from one the model reasoned its way to,
# and a reader would credit the agent with a judgement it never made.
UNJUDGED_PREFIX = "Not judged by the agent."


def _verdict_from(output: Any) -> dict[str, Any] | None:
    """The finish tool's dict reaches run_agent_loop via ScanContext.final_result, so a
    real verdict arrives shaped as it was written.

    When the agent stops WITHOUT calling triage_verdict — turn exhaustion, a budget
    cutoff, a crash — this records `uncertain` rather than nothing. Measured: an agent
    burned 11/12 turns investigating and returned silence, so the finding looked
    untouched next to ones nobody had tried. `uncertain` is already the honest verdict
    for "source did not settle it", and that is exactly what happened.

    It is NOT a fabricated judgement: the reasoning says plainly that the agent did not
    produce one, and carries the runner's own summary so the cause is traceable. The
    distinction the Finding model draws still holds — `triage: null` means nobody
    looked, `uncertain` means someone did and it did not resolve.
    """
    if not isinstance(output, dict):
        return None
    if output.get("verdict"):
        return {
            "verdict": output["verdict"],
            "reasoning": output.get("reasoning", ""),
            "evidence": output.get("evidence", ""),
        }
    summary = str(output.get("summary") or "stopped without a verdict").strip()
    return {
        "verdict": "uncertain",
        "reasoning": (
            f"{UNJUDGED_PREFIX} It stopped before reaching one, so reachability is "
            f"unresolved rather than ruled out."
        ),
        "evidence": f"agent outcome: {summary[:300]}",
    }


def demo() -> None:
    findings = [
        {"id": "a", "severity": "medium"},
        {"id": "b", "severity": "critical"},
        {"id": "c", "severity": "low"},
        {"id": "d", "severity": "high"},
    ]
    # Worst first, so a cap truncates the tail rather than the criticals.
    assert [f["id"] for f in order_for_triage(findings)] == ["b", "d", "a", "c"]

    assert _verdict_from(None) is None  # nothing ran; nothing to say
    got = _verdict_from({"verdict": "not_reachable", "reasoning": "r", "evidence": "e"})
    assert got == {"verdict": "not_reachable", "reasoning": "r", "evidence": "e"}, got

    # An agent that stops without a verdict is recorded as `uncertain`, not dropped —
    # silence made an investigated finding look identical to an untouched one.
    stopped = _verdict_from({"summary": "stopped: MaxTurnsExceeded: Max turns (12) exceeded"})
    assert stopped["verdict"] == "uncertain", stopped
    assert stopped["reasoning"].startswith(UNJUDGED_PREFIX), stopped
    assert "MaxTurnsExceeded" in stopped["evidence"], stopped
    # ...and it must never be mistakable for the agent's own reasoning.
    real = _verdict_from({"verdict": "uncertain", "reasoning": "checked callers", "evidence": "x.py:1"})
    assert not real["reasoning"].startswith(UNJUDGED_PREFIX), real

    # No sandbox means no source to read, so there is nothing honest to triage.
    assert triage_findings(findings, run_dir=Path("/tmp"), config=None, sandbox=None) == {}
    print("core.triage: ok")


if __name__ == "__main__":
    demo()
