"""Top-level docket scan runner.

The one seam between CLI, orchestration, sandbox, and reporting: docket.interface.main
calls run_scan() exactly once. Root spawns sqli/cmdi/xss specialists through
AgentCoordinator; findings reach the caller via the on_finding callback.
"""
from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from agents.models.interface import Model

from docket.agents.factory import build_agent
from docket.agents.prompts.root import build_root_task
from docket.config.settings import Config, run_dir
from docket.core.agents import AgentCoordinator
from docket.core.execution import ScanContext, run_agent_loop
from docket.core.inputs import DEFAULT_MAX_TURNS
from docket.discovery.discover import discover
from docket.static.correlate import correlate, summarise
from docket.static.engines import collect as collect_static
from docket.report.models import Finding
from docket.interface.tui.backend.messages import set_emitter
from docket.report.state import init_report_state, reset_report_state
from docket.runtime.sandbox import Sandbox, rewrite_for_container
from docket.tools.http_request.tools import do_http_request
from docket.tools.agents_graph.tools import create_agent, view_agent_graph, wait_for_agents
from docket.tools.scanners.nuclei import run_nuclei
from docket.tools.scanners.semgrep import run_semgrep
from docket.tools.scanners.trivy import run_trivy


def _run_scanner_prescans(
    sandbox: Sandbox, target_url: str | None, run_dir_: Path,
    on_finding: Callable[[Finding], None] | None,
    on_stage: Callable[[str, str], None] | None = None,
) -> None:
    """Deterministic scanner pass, BEFORE any agent turn runs. nuclei needs a real
    target (skipped when None — e.g. a --static-only, --source-only run with nothing
    live to hit); trivy/semgrep need real source, so they only run when the sandbox
    was started with one (see Sandbox.source_dir / --source in cli_args.py). Findings
    feed the same on_finding callback an agent-filed finding does — same dedupe, same
    live progress display, no separate "scanner report" to reconcile later.

    `on_stage(scanner, state)` reports per-scanner progress (state is "running",
    "done" or "skipped") so a UI can show which scanner is working rather than one
    opaque "scanning" spinner. Scanners run sequentially, so this is exact, not a
    guess.
    """
    def stage(scanner: str, state: str) -> None:
        if on_stage is not None:
            on_stage(scanner, state)

    def drain(scanner: str, findings: list[Finding]) -> None:
        for finding in findings:
            if on_finding is not None:
                on_finding(finding)
        stage(scanner, "done")

    if target_url is not None:
        stage("nuclei", "running")
        drain("nuclei", run_nuclei(sandbox, target_url, run_dir_))
    else:
        stage("nuclei", "skipped")

    if sandbox.source_dir is not None:
        stage("trivy", "running")
        drain("trivy", run_trivy(sandbox, run_dir_))
        stage("semgrep", "running")
        drain("semgrep", run_semgrep(sandbox, run_dir_))
    else:
        stage("trivy", "skipped")
        stage("semgrep", "skipped")


@dataclass(slots=True)
class ScanResult:
    success: bool
    summary: str
    finding_count: int
    cost_usd: float = 0.0
    agents_spawned: int = 1
    leads: list = field(default_factory=list)


def run_scan(
    target_url: str | None = None,
    *,
    instruction: str | None = None,
    whitebox_path: str | None = None,
    on_finding: Callable[[Finding], None] | None = None,
    config: Config | None = None,
    run_name: str = "scan",
    max_turns: int = DEFAULT_MAX_TURNS,
    model_override: Callable[[str], Model] | None = None,
    use_sandbox: bool = True,
    store: object | None = None,
    openapi_path: str | None = None,
    har_path: str | None = None,
    sarif_path: str | None = None,
    discovery: bool = True,
    static_only: bool = False,
    on_stage: Callable[[str, str], None] | None = None,
) -> ScanResult:
    """`model_override`, if given, is threaded through every agent (root and any
    child it spawns) instead of building a real LitellmModel — the hook tests use to
    script a whole multi-agent run without a live LLM_API_KEY.

    `use_sandbox=False` runs the HTTP tool in this process instead of a container. It
    exists so the test suite (and a machine without Docker) can exercise the agent
    layer, and it costs the `shell` tool, which always refuses to run un-sandboxed.

    `static_only=True` skips the agent entirely — only the deterministic scanner
    pre-scan runs (nuclei if target_url is given, trivy/semgrep if whitebox_path is
    given). No DOCKET_LLM/API key needed (see Config.static_only), and `target_url`
    becomes optional. For a CI gate that wants "check my dependencies/source" without
    spending LLM budget or needing a live app in the same job.
    """
    cfg = config or (Config.static_only() if static_only else Config.from_env())
    coordinator = AgentCoordinator(
        max_agents=cfg.max_agents,
        budget_usd=cfg.max_cost_usd,
        per_agent_reserve_usd=cfg.max_child_cost_usd,
    )
    directory = run_dir(run_name)
    # Publish live run state so SDK hooks (which Runner.run calls deep inside, with no
    # way to inject a reference) and any attached viewer/TUI can see it.
    if store is not None:
        init_report_state(
            run_name=run_name, target=target_url or "(static-only)", run_dir=directory,
            store=store, budget_usd=cfg.max_cost_usd,
        )

    emitter = set_emitter(directory)
    emitter.scan_started(target_url or "(static-only)", run_name)

    sandbox = (
        Sandbox(directory / "sandbox", source_dir=Path(whitebox_path) if whitebox_path else None)
        if use_sandbox else None
    )
    # Inside the container, "127.0.0.1" is the container itself — the agent has to be
    # handed a hostname that actually reaches the host's app. No target at all (a
    # --static-only, source-only run) means no rewrite to do.
    agent_target = (
        None if target_url is None
        else rewrite_for_container(target_url) if sandbox else target_url
    )

    if sandbox is not None:
        sandbox.start()
    try:
        if sandbox is not None:
            # Deterministic scanner pass BEFORE the first agent turn. Findings land through
            # the same on_finding path an agent-filed finding does. Inside the try so a
            # stray failure here still tears the container down via the finally below.
            # sandbox.run_dir (directory/"sandbox"), NOT `directory` — that is what is
            # bind-mounted to /work/run inside the container. Passing `directory` silently
            # starved every scanner reader.
            _run_scanner_prescans(sandbox, agent_target, sandbox.run_dir, on_finding, on_stage)

        # Discovery is deterministic and needs no model, so it runs for --static-only too:
        # surface.json is a useful artifact on its own, and correlation below needs it.
        surface = None
        if discovery and agent_target:
            # Discovery must reach the target the SAME way the agents will, or it maps a
            # host they cannot dial: inside the container 127.0.0.1 is the container, so
            # it has to go through the shim when there is one.
            def fetch(method: str, url: str, **kw) -> dict:
                if sandbox is not None:
                    return sandbox.call("http_request", method=method, url=url,
                                         timeout_sec=15, **kw)
                return do_http_request(method, url, directory, timeout_sec=15, **kw)

            surface = discover(
                agent_target, fetch=fetch, openapi_path=openapi_path, har_path=har_path,
                flows_path=(directory / "artifacts" / "proxy_flows.jsonl"),
            )
            surface.save(directory)
            emitter.log_discovery(len(surface), surface.requests_made, surface.sources_tried)

        # Static analysis AFTER discovery, because correlation needs the endpoint list:
        # a sink is only actionable once we know which request reaches it.
        leads = []
        if sarif_path or whitebox_path:
            static = collect_static(sarif_path=sarif_path, source_root=whitebox_path)
            static.save(directory)
            leads = correlate(static.findings, surface, whitebox_path)
            for note in static.notes:
                emitter.log_static(note)
            emitter.log_static(summarise(leads))

        if static_only:
            output = {
                "success": True,
                "summary": "static-only scan: scanner pre-scan only, no AI agents run",
                "findings": [],
            }
        else:
            if agent_target is None:
                raise ValueError("target_url is required unless static_only=True")
            context = ScanContext(
                target_url=agent_target,
                run_dir=directory,
                on_finding=on_finding,
                agent_id="root",
                role="root",
                coordinator=coordinator,
                config=cfg,
                model_override=model_override,
                sandbox=sandbox,
                # Children get a share of the operator's ceiling rather than a constant, so
                # --max-steps is the one knob that scales the whole run. Floor of 12 keeps
                # the previous default for anyone who does not pass the flag.
                child_max_turns=max(12, max_turns * 3 // 5),
            )
            root_model = model_override("root") if model_override else None
            agent = build_agent(
                "root", cfg,
                extra_tools=[create_agent, wait_for_agents, view_agent_graph],
                model=root_model, sandbox=sandbox,
            )
            task = build_root_task(agent_target, instruction, surface, leads)
            output = asyncio.run(run_agent_loop(agent, context, task, max_turns=max_turns))
    finally:
        if sandbox is not None:
            sandbox.stop()

    findings = output.get("findings", [])
    emitter.scan_finished(bool(output.get("success", True)), output.get("summary", ""))
    return ScanResult(
        success=bool(output.get("success", True)),
        summary=output.get("summary", ""),
        finding_count=len(findings),
        cost_usd=round(coordinator.spent_usd, 6),
        agents_spawned=0 if static_only else len(coordinator.agents) + 1,  # +1 for root
        leads=leads,
    )
