"""Run control packs over mounted source and return one PackResult each.

Shaped like core/recon.py, and for the same economics: a pack of forty controls run as
forty agents costs forty times as much for work that shares almost all of its reading.
One agent judges a batch, so the repository is read once and the controls are answered
against that reading.

Two passes, because the cheap one is not always enough:

  batched     one agent per chunk of ~12 source-observable controls. ~$0.05-0.25/pack.
  escalation  one focused agent per control that came back `fail` or `unknown`, capped
              by `deep` and run worst-first, so a cap truncates the tail rather than the
              criticals. Sequential and max_agents=1 — concurrent agents make the budget
              gate racy (see core/triage.py).

Three things are written by CODE and never by a model, which is what keeps the numbers
honest:

  - a control whose `observability` is not SOURCE is never sent to an agent at all. Its
    result is NOT_OBSERVABLE, authored here. Most of RBI's and SEBI's frameworks are
    organisational, and asking a model a question with no code in it is asking it to
    invent one.
  - a source control no agent ever answered is UNKNOWN carrying core.triage's
    UNJUDGED_PREFIX, so a synthesised answer can never be mistaken for a real one. That
    is the difference between "we checked and could not tell" and "we ran out of money",
    and a coverage number that cannot tell them apart is worthless.
  - an escalation replaces the batched answer ONLY if it produced a real cited claim. A
    second look that also failed leaves the first answer standing rather than erasing it.

Never raises except ScanCancelled: compliance is enrichment, and a scan that already
produced findings must not be lost because a control pack failed.
"""
from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from docket.agents.factory import build_agent
from docket.agents.prompts.compliance import build_compliance_task
from docket.compliance.models import (
    Control,
    ControlPack,
    ControlResult,
    ControlStatus,
    Observability,
    PackResult,
)
from docket.config.settings import Config
from docket.core.agents import AgentCoordinator
from docket.core.cancel import NEVER, CancelToken, ScanCancelled
from docket.core.execution import ScanContext, run_agent_loop
from docket.core.recon import hint_files
from docket.core.triage import UNJUDGED_PREFIX
from docket.report.models import Severity
from docket.tools.compliance.tool import build_control_results

logger = logging.getLogger(__name__)

# Controls per batched agent. Twelve requirements plus their hints is a few thousand
# tokens of task, which leaves the context to the reading — the expensive part. Larger
# batches measurably shift the failure mode from "judged everything" to "answered the
# first five properly and guessed the rest", which is the one outcome worth paying to
# avoid.
CHUNK_SIZE = 12
# Turn ceiling for a batched chunk. Recon maps a whole application in 24; a chunk reads
# less breadth but must reach a verdict on each control, so it gets the same order.
DEFAULT_MAX_TURNS = 24
# A single control, re-read with a fresh budget. It already knows where to look.
ESCALATION_MAX_TURNS = 12
# Compiling a policy is one long read and one long write. It needs no exploration, so a
# low ceiling: an agent that has not recorded the pack by now is looping, not reading.
COMPILE_MAX_TURNS = 6

# Escalate failures before inconclusives: a `fail` is a claim about a customer's codebase
# and is the one most worth a second reading.
_STATUS_ORDER = {ControlStatus.FAIL: 0, ControlStatus.UNKNOWN: 1}


def chunk(controls: list[Control], size: int = CHUNK_SIZE) -> list[list[Control]]:
    return [controls[i:i + size] for i in range(0, len(controls), size)]


def order_for_escalation(
    results: list[ControlResult], controls: dict[str, Control]
) -> list[ControlResult]:
    """Worst first, so a `deep` cap truncates the tail rather than the criticals."""
    def key(result: ControlResult) -> tuple[int, int]:
        control = controls.get(result.control_id)
        severity = control.severity if control else Severity.INFO
        return (_STATUS_ORDER.get(result.status, 9), list(Severity).index(severity))

    return sorted(
        [r for r in results if r.status in _STATUS_ORDER], key=key
    )


def not_observable_results(pack: ControlPack) -> list[ControlResult]:
    """Written by code, before a token is spent. A model may never claim this status —
    see compliance.models.parse_status."""
    return [
        ControlResult(
            control_id=control.id,
            status=ControlStatus.NOT_OBSERVABLE,
            rationale=(
                f"This is a {control.observability.value} control: it is answered by an "
                "organisational or deployment artifact, not by anything in a repository. "
                "Docket did not assess it and does not count it as satisfied."
            ),
        )
        for control in pack.controls
        if control.observability is not Observability.SOURCE
    ]


def unjudged_result(control: Control, why: str) -> ControlResult:
    """A control nobody reached. NOT a verdict — the reasoning says so in the first
    sentence, and UNJUDGED_PREFIX is what every consumer downstream matches on."""
    return ControlResult(
        control_id=control.id,
        status=ControlStatus.UNKNOWN,
        rationale=(
            f"{UNJUDGED_PREFIX} No agent reached this control, so it is unassessed rather "
            f"than inconclusive. Cause: {why}"
        ),
        looked_at="nothing — the run ended first",
    )


def run_compliance(
    repo: str,
    packs: list[ControlPack],
    *,
    run_dir: Path,
    config: Config,
    sandbox: Any,
    source_root: str | None = None,
    findings: list[dict[str, Any]] | None = None,
    surface: dict[str, Any] | None = None,
    deep: int = 0,
    max_turns: int = DEFAULT_MAX_TURNS,
    model_override: Any = None,
    cancel: CancelToken = NEVER,
    on_agent: Callable[[dict[str, Any]], None] | None = None,
    on_progress: Callable[[], None] | None = None,
) -> list[PackResult]:
    """One PackResult per pack, always — including when nothing could be assessed.

    An empty list would read downstream as "compliance was not requested", which is a
    different statement from "we were asked and got nowhere". The second needs saying.
    """
    if not packs:
        return []

    # ONE coordinator for the whole stage. Per-pack coordinators would each be handed the
    # full budget, so three packs could spend three times the ceiling the operator set.
    coordinator = AgentCoordinator(
        max_agents=1,
        budget_usd=config.max_cost_usd,
        per_agent_reserve_usd=config.max_child_cost_usd,
    ) if config is not None else None

    hints = hint_files(findings or [])
    out: list[PackResult] = []
    counter = 0

    for pack in packs:
        source_controls = pack.source_controls()
        by_id = {c.id: c for c in pack.controls}
        results: dict[str, ControlResult] = {r.control_id: r for r in not_observable_results(pack)}
        judged = 0
        stopped: str | None = None

        if sandbox is None or not source_root:
            # No mounted source means no citation can be verified, so nothing is
            # assessable. Say that rather than returning an empty pack.
            stopped = "no source tree was mounted for this scan"

        for batch in chunk(source_controls) if stopped is None else []:
            if cancel.cancelled:
                stopped = "the scan was cancelled"
                break
            counter += 1
            agent_id = f"compliance-{counter}"
            label = f"{pack.id} ({len(batch)} controls)"
            _note(on_agent, agent_id, "running", label, f"auditing {pack.title}")
            produced = _judge(
                agent_id, repo, pack, batch, run_dir=run_dir, config=config,
                sandbox=sandbox, source_root=source_root, surface=surface, hints=hints,
                max_turns=max_turns, model_override=model_override,
                coordinator=coordinator,
            )
            if produced is None:
                # One chunk failing does not end the pack: the other chunks are separate
                # controls and their answers are still worth having.
                _note(on_agent, agent_id, "error", label)
                stopped = stopped or "an agent stopped before recording its answers"
                continue
            for result in produced:
                results[result.control_id] = result
                judged += 1
            _note(on_agent, agent_id, "done", label, outcome=f"{len(produced)} judged")
            if on_progress is not None:
                on_progress()

        # Fill the gaps BEFORE escalation, so `requested` and `unjudged` describe the
        # batched pass and a second look cannot paper over a budget that ran out.
        for control in source_controls:
            if control.id not in results:
                results[control.id] = unjudged_result(
                    control, stopped or "the agent did not return an answer for it")

        unjudged = sum(
            1 for c in source_controls
            if results[c.id].rationale.startswith(UNJUDGED_PREFIX)
        )

        # --- escalation ---------------------------------------------------------------
        if deep and stopped is None:
            queue = order_for_escalation(
                [results[c.id] for c in source_controls], by_id)[:deep]
            for prior in queue:
                if cancel.cancelled:
                    break
                control = by_id.get(prior.control_id)
                if control is None or prior.rationale.startswith(UNJUDGED_PREFIX):
                    # Nothing to re-check: nobody looked the first time. A fresh budget
                    # belongs on a control somebody actually struggled with.
                    continue
                counter += 1
                agent_id = f"compliance-{counter}"
                label = f"{control.id}"
                _note(on_agent, agent_id, "running", label, "second look")
                produced = _judge(
                    agent_id, repo, pack, [control], run_dir=run_dir, config=config,
                    sandbox=sandbox, source_root=source_root, surface=surface, hints=hints,
                    max_turns=ESCALATION_MAX_TURNS, model_override=model_override,
                    coordinator=coordinator, prior=prior.model_dump(mode="json"),
                )
                second = (produced or [None])[0]
                # Replace ONLY on a real cited claim. A second look that also came back
                # empty must not erase the first answer with a worse one.
                if second is not None and second.status in (
                    ControlStatus.PASS, ControlStatus.FAIL, ControlStatus.NOT_APPLICABLE
                ):
                    second.escalated = True
                    results[control.id] = second
                    _note(on_agent, agent_id, "done", label, outcome=second.status.value)
                else:
                    prior.escalated = True
                    _note(on_agent, agent_id, "done", label, outcome="unchanged")
                if on_progress is not None:
                    on_progress()

        ordered = [results[c.id] for c in pack.controls]
        out.append(PackResult(
            pack_id=pack.id, pack_title=pack.title, authority=pack.authority,
            version=pack.version, origin=pack.origin,
            total_controls=len(pack.controls), results=ordered,
            requested=len(source_controls), judged=judged, unjudged=unjudged,
        ))

    return out


def compile_pack(
    text: str,
    *,
    source_name: str,
    pack_id: str,
    run_dir: Path,
    config: Config,
    truncated: bool = False,
    max_turns: int = COMPILE_MAX_TURNS,
    model_override: Any = None,
) -> tuple[ControlPack | None, list[dict[str, str]], str]:
    """(pack, dropped, error). One agent, one document, no repository access.

    The pack is RETURNED, not saved. Whether it is persisted is the caller's decision,
    because a compiled pack should be reviewed by the customer before anything is audited
    against it — a pack nobody read is a pack nobody can defend to an auditor.
    """
    from docket.agents.prompts.compliance import build_compile_task
    from docket.tools.compliance.tool import build_pack

    if not text.strip():
        return None, [], "the document contained no text"

    coordinator = AgentCoordinator(
        max_agents=1, budget_usd=config.max_cost_usd,
        per_agent_reserve_usd=config.max_child_cost_usd,
    )
    context = ScanContext(
        target_url="", run_dir=run_dir, agent_id="compliance-compile",
        role="compliance_compile", coordinator=coordinator, config=config,
        model_override=model_override,
        # No sandbox and no source_root, deliberately: this role has no file tools, and
        # leaving them unset means even a future edit that hands it one finds no tree.
        sandbox=None, source_root=None,
        # `record_pack` reads the id and document name from here rather than from the
        # model, so a compiled pack cannot name itself after a built-in one.
        compliance_pack={"pack_id": pack_id, "source_name": source_name},
    )
    agent = build_agent(
        "compliance_compile", config,
        model=model_override("compliance_compile") if model_override else None,
    )
    try:
        output = asyncio.run(run_agent_loop(
            agent, context, build_compile_task(source_name, text, truncated=truncated),
            max_turns=max_turns,
        ))
    except ScanCancelled:
        raise
    except Exception as exc:  # noqa: BLE001
        logger.exception("compile agent failed on %s", source_name)
        return None, [], f"the policy could not be compiled ({type(exc).__name__}: {exc})"

    if not isinstance(output, dict) or output.get("ok") is not True:
        error = (output or {}).get("error") if isinstance(output, dict) else None
        return None, (output or {}).get("dropped", []) if isinstance(output, dict) else [], (
            error or "the agent stopped without recording any controls")
    # Re-validated through build_pack's own output shape: model_validate is what decides
    # whether this is a usable pack, and it is the same gate a shipped pack passes.
    try:
        pack = ControlPack.model_validate(output["pack"])
    except ValidationError as exc:
        return None, output.get("dropped", []), f"the compiled pack was not valid ({exc})"
    return pack, output.get("dropped", []), ""


def link_findings(
    pack_results: list[PackResult],
    packs: list[ControlPack],
    findings: list[Any],
) -> None:
    """Attach, in place, the findings that independently settle a control's weakness class.

    Deterministic and computed here, never supplied by the agent. Two directions, and the
    second is the interesting one:

      proven_findings   on a FAIL — a reproduced exploit of the same class exists. This is
                        the one case where a control failure is more than an LLM's opinion,
                        and it should be rendered that way.
      contradicted_by   on a PASS — the agent read the code and said it was fine while
                        another agent reproduced an exploit of exactly that class. That
                        count is the honest measure of how far to trust a pack run, and it
                        is free to compute.

    Matched by CWE and rule leaf, NEVER by file. A control is a property of the system; a
    finding is anchored to a line. Linking a "debug mode off" control to every finding in
    a 2,000-line app.py is a coincidence dressed as corroboration.

    Keyed by `dedupe_key`, not `Finding.id`: the id is a uuid4 marked internal-only, while
    dedupe_key is stable across runs and is already the SARIF partialFingerprint, so a link
    survives a rescan.
    """
    from docket.service.gate import rule_leaf  # the one spelling of a rule leaf

    by_id = {c.id: c for c in (control for pack in packs for control in pack.controls)}
    prepared = [
        (str(getattr(f, "cwe", "") or ""), rule_leaf(getattr(f, "rule_id", "")),
         getattr(f, "dedupe_key", ""))
        for f in findings
    ]
    for pack_result in pack_results:
        for result in pack_result.results:
            control = by_id.get(result.control_id)
            if control is None or result.status not in (ControlStatus.PASS, ControlStatus.FAIL):
                continue
            cwes = set(control.cwe)
            leaves = {rule_leaf(r) for r in control.rule_ids}
            matched = [key for cwe, leaf, key in prepared
                       if key and ((cwe and cwe in cwes) or (leaf and leaf in leaves))]
            if not matched:
                continue
            if result.status is ControlStatus.FAIL:
                result.proven_findings = matched
            else:
                result.contradicted_by = matched


def _judge(
    agent_id: str,
    repo: str,
    pack: ControlPack,
    controls: list[Control],
    *,
    run_dir: Path,
    config: Config,
    sandbox: Any,
    source_root: str | None,
    surface: dict[str, Any] | None,
    hints: list[str],
    max_turns: int,
    model_override: Any,
    coordinator: AgentCoordinator | None,
    prior: dict[str, Any] | None = None,
) -> list[ControlResult] | None:
    """One agent over one batch. None when it produced nothing usable."""
    context = ScanContext(
        target_url="",  # compliance reads the repository; it never touches a target
        run_dir=run_dir,
        agent_id=agent_id,
        role="compliance",
        coordinator=coordinator,
        config=config,
        model_override=model_override,
        sandbox=sandbox,
        source_root=source_root,
        # The tool checks every returned control_id against this. Without it an agent
        # answering a control from another pack would be recorded under a real-looking id.
        compliance_pack=pack,
    )
    agent = build_agent(
        "compliance", config,
        model=model_override("compliance") if model_override else None,
        sandbox=sandbox,
    )
    task = build_compliance_task(
        repo, controls, pack_title=pack.title, surface=surface, hints=hints, prior=prior)
    try:
        output = asyncio.run(run_agent_loop(agent, context, task, max_turns=max_turns))
    except ScanCancelled:
        raise  # a stop is not a failed audit; it must reach the runner
    except Exception:  # noqa: BLE001
        logger.exception("compliance agent %s failed on %s", agent_id, pack.id)
        return None
    return _results_from(output, pack=pack, source_root=source_root, judged_by=agent_id)


def _results_from(
    output: Any, *, pack: ControlPack, source_root: str | None, judged_by: str
) -> list[ControlResult] | None:
    """Only a real, accepted record_controls call counts.

    These rows are ALREADY gated — `build_control_results` is the finish tool, and the
    compliance role has no other finish tool to have called, so nothing else can be
    sitting in `final_result`. They are parsed back, not re-checked.

    Re-running the gate here was the obvious-looking thing and it is wrong: the second
    pass rebuilds each row from `control_id/status/rationale/citations/looked_at` and
    drops `downgraded_from`, so a claim the gate had REFUSED came out looking like an
    ordinary `unknown` the agent chose. That erases the audit trail for exactly the rows
    that most need one. Caught by tests/test_compliance.py; do not reinstate it.
    """
    if not isinstance(output, dict) or output.get("ok") is not True:
        return None  # a refusal is not an assessment
    rows = output.get("results")
    if not isinstance(rows, list) or not rows:
        return None
    parsed: list[ControlResult] = []
    for row in rows:
        try:
            parsed.append(ControlResult.model_validate(row))
        except ValidationError:
            # Unreachable through the tool, which builds these from the model itself.
            # Skipping beats raising: one malformed row must not lose the whole batch.
            logger.warning("compliance: discarding a malformed result row from %s", judged_by)
    return parsed or None


def _note(
    on_agent: Callable[[dict[str, Any]], None] | None,
    agent_id: str,
    status: str,
    label: str,
    detail: str | None = None,
    outcome: str | None = None,
) -> None:
    if on_agent is None:
        return
    event = {"id": agent_id, "role": "compliance", "status": status, "label": label}
    if detail:
        event["detail"] = detail
    if outcome:
        event["outcome"] = outcome
    on_agent(event)


def demo() -> None:
    from docket.compliance.packs import load_pack

    pack = load_pack("twelve-factor")
    by_id = {c.id: c for c in pack.controls}

    # --- chunking: every source control lands in exactly one batch --------------------
    batches = chunk(pack.source_controls(), 5)
    assert [len(b) for b in batches] == [5, 5, 1], [len(b) for b in batches]
    flat = [c.id for b in batches for c in b]
    assert flat == [c.id for c in pack.source_controls()], flat
    assert chunk([]) == []

    # --- not_observable is authored by CODE, for exactly the unanswerable controls -----
    unobservable = not_observable_results(pack)
    assert [r.control_id for r in unobservable] == ["twelve-factor:VIII"], unobservable
    assert unobservable[0].status is ControlStatus.NOT_OBSERVABLE
    # It must read as "not assessed", never as "satisfied" — that distinction is the
    # whole reason a regulatory pack can be shown to anyone.
    assert "does not count it as satisfied" in unobservable[0].rationale

    # --- an unjudged control is marked so it can never pass for a real verdict ---------
    gap = unjudged_result(by_id["twelve-factor:III"], "the budget ran out")
    assert gap.status is ControlStatus.UNKNOWN
    assert gap.rationale.startswith(UNJUDGED_PREFIX), gap.rationale
    assert "the budget ran out" in gap.rationale

    # --- escalation order: failures first, then by severity, criticals ahead of lows ---
    def result(control_id: str, status: ControlStatus) -> ControlResult:
        if status is ControlStatus.UNKNOWN:
            return ControlResult(control_id=control_id, status=status,
                                 rationale="could not settle", looked_at="grepped")
        return ControlResult(control_id=control_id, status=status, rationale="read it",
                             citations=[{"file": "settings.py", "line": 1}])

    queue = order_for_escalation([
        result("twelve-factor:I", ControlStatus.UNKNOWN),      # fail-less, low
        result("twelve-factor:XII", ControlStatus.FAIL),       # high
        result("twelve-factor:III", ControlStatus.FAIL),       # critical
        result("twelve-factor:II", ControlStatus.PASS),        # settled: not in the queue
        result("twelve-factor:XI", ControlStatus.UNKNOWN),     # medium
    ], by_id)
    assert [r.control_id for r in queue] == [
        "twelve-factor:III", "twelve-factor:XII", "twelve-factor:XI", "twelve-factor:I",
    ], [r.control_id for r in queue]
    # A settled control is never re-read: a second look costs the same as a first one and
    # has nothing to resolve.
    assert all(r.status is not ControlStatus.PASS for r in queue), queue

    # --- output gating: only a real record_controls call counts ------------------------
    for junk in (None, "done", {}, {"results": []}, {"summary": "finished"},
                 {"results": [{"control_id": "twelve-factor:III", "status": "pass",
                               "rationale": "fine"}]}):  # uncited claim: refused
        assert _results_from(junk, pack=pack, source_root=None, judged_by="x") is None, junk

    # --- no sandbox means no source; the pack still reports, saying nothing was assessed
    out = run_compliance("acme/api", [pack], run_dir=Path("/tmp"), config=None, sandbox=None)
    assert len(out) == 1, out
    only = out[0]
    assert only.assessed == 0 and only.judged == 0
    assert only.unjudged == len(pack.source_controls()), only.unjudged
    # Every control is accounted for: none silently missing from the report.
    assert len(only.results) == len(pack.controls) == only.total_controls
    assert only.counts["not_observable"] == 1, only.counts
    assert "no control could be assessed" in only.label, only.label
    assert "compliant" not in only.label.lower(), only.label
    # ...and the reason is stated, not implied by an empty list.
    unresolved = next(r for r in only.results if r.control_id == "twelve-factor:III")
    assert "no source tree was mounted" in unresolved.rationale, unresolved

    # Nothing requested is genuinely nothing, and must not fabricate a pack row.
    assert run_compliance("acme/api", [], run_dir=Path("/tmp"), config=None, sandbox=None) == []

    # --- cross-linking: by weakness class, never by file ------------------------------
    class _F:  # a Finding's shape, without paying for a valid PoC to build one
        def __init__(self, cwe, rule_id, key):
            self.cwe, self.rule_id, self.dedupe_key = cwe, rule_id, key

    secret = ControlResult(  # twelve-factor:III carries CWE-798 and rule hardcoded-secret
        control_id="twelve-factor:III", status=ControlStatus.FAIL,
        rationale="SECRET_KEY is a literal", citations=[{"file": "settings.py", "line": 2}])
    logs = ControlResult(  # twelve-factor:XI carries CWE-532
        control_id="twelve-factor:XI", status=ControlStatus.PASS,
        rationale="logs go to stdout", citations=[{"file": "log.py", "line": 3}])
    admin = ControlResult(  # CWE-489, with no matching finding
        control_id="twelve-factor:XII", status=ControlStatus.FAIL,
        rationale="a /debug route runs commands", citations=[{"file": "app.py", "line": 9}])
    rolled = PackResult(pack_id=pack.id, pack_title=pack.title, authority=pack.authority,
                        total_controls=len(pack.controls), results=[secret, logs, admin])
    link_findings([rolled], [pack], [
        _F("CWE-798", "semgrep/python.lang.security.hardcoded-secret", "aaa1"),
        _F(None, "semgrep/generic.secrets.generic-api-key", "bbb2"),   # by rule leaf
        _F("CWE-532", "semgrep/python.lang.information-disclosure", "ccc3"),
        _F("CWE-89", "sql-injection", "ddd4"),                          # matches nothing here
    ])
    # A FAIL corroborated by reproduced findings: the one case that is more than opinion.
    assert set(secret.proven_findings) == {"aaa1", "bbb2"}, secret.proven_findings
    assert secret.contradicted_by == []
    # A PASS sitting next to a proven exploit of that class is a contradiction, and the
    # count of those is how much to trust the whole run.
    assert logs.contradicted_by == ["ccc3"], logs.contradicted_by
    assert logs.proven_findings == []
    # No match means no link. A control must never be linked to a finding merely because
    # they share a file.
    assert admin.proven_findings == [] and admin.contradicted_by == []

    # --- compiling: refusals cost nothing and say what went wrong ---------------------
    empty_pack, dropped, error = compile_pack(
        "   ", source_name="p.md", pack_id="acme-policy", run_dir=Path("/tmp"), config=None)
    assert empty_pack is None and "no text" in error, (empty_pack, error)
    assert dropped == []

    print("core.compliance: ok")


if __name__ == "__main__":
    demo()
