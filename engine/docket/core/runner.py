"""Top-level docket scan runner.

The one seam between CLI, orchestration, sandbox, and reporting: docket.interface.main
calls run_scan() exactly once. Root spawns sqli/cmdi/xss specialists through
AgentCoordinator; findings reach the caller via the on_finding callback.
"""
from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from agents.models.interface import Model

logger = logging.getLogger(__name__)

from docket.agents.factory import build_agent
from docket.agents.prompts.root import build_root_task
from dataclasses import replace

from docket.config.settings import Config, run_dir
from docket.core.agents import AgentCoordinator
from docket.core.execution import ScanContext, run_agent_loop
from docket.core.inputs import DEFAULT_MAX_TURNS
from docket.core.cancel import NEVER, CancelToken
from docket.core.recon import DEFAULT_MAX_TURNS as DEFAULT_RECON_TURNS
from docket.core.recon import PR_MAX_TURNS
from docket.discovery.discover import discover
from docket.report.dedupe import merge_static
from docket.static.correlate import correlate, summarise
from docket.static.engines import collect as collect_static
from docket.static.triage import triage_all
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
    cancel: CancelToken = NEVER,
    scope_paths: list[str] | None = None,
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

    def drain(scanner: str, produce) -> None:
        # Checked before the scanner starts, not during: semgrep is a subprocess and
        # the only safe place to stop is between runs.
        """Run one scanner. A scanner that could not run is marked `error`, never
        `done` — "0 findings" and "never analysed" must not look identical, which is
        exactly what a silently-failing semgrep did behind a green stage."""
        from docket.tools.scanners.semgrep import ScannerError

        cancel.check()
        try:
            # Merge before emitting, not after: semgrep returns the same line under
            # several framework namespaces, and every consumer downstream (the live
            # feed, the store, triage, the cost of triage) should see one finding
            # rather than three. Merging here means triage never pays to judge the
            # same line three times.
            findings = merge_static(produce())
        except ScannerError as exc:
            logger.warning("%s did not run: %s", scanner, exc)
            stage(scanner, "error")
            return
        for finding in findings:
            if on_finding is not None:
                on_finding(finding)
        stage(scanner, "done")

    if target_url is not None:
        stage("nuclei", "running")
        drain("nuclei", lambda: run_nuclei(sandbox, target_url, run_dir_))
    else:
        stage("nuclei", "skipped")

    if sandbox.source_dir is not None:
        stage("trivy", "running")
        drain("trivy", lambda: run_trivy(sandbox, run_dir_))
        stage("semgrep", "running")
        # Scoped to a pull request's changed files when given. Only semgrep takes a
        # scope: trivy reads dependency manifests, and a PR that changes none of them
        # still inherits every advisory from the ones it did not touch.
        drain("semgrep", lambda: run_semgrep(sandbox, run_dir_, paths=scope_paths))
    else:
        stage("trivy", "skipped")
        stage("semgrep", "skipped")


def _norm_path(raw: str) -> str:
    """One spelling for one file, so a scope entry and a scanner's path can be compared.
    Semgrep paths are rebased onto the source root (static/engines.py) and git prints
    repo-relative paths, so the two already agree apart from a "./" or leading "/"."""
    return raw.strip().removeprefix("./").lstrip("/")


def load_diff_scope(path: str | Path) -> set[str]:
    """Repo-relative paths from --changed-files, one per line, blank lines ignored.

    A missing or unreadable file RAISES, deliberately. strix's CI skill states the rule as
    "fail loudly rather than silently narrowing scope"; the inverse is just as wrong.
    Treating an unreadable scope file as "no scope given" would widen a PR check to the
    whole repository, or — worse in a gate — report a pass over findings nobody scoped.
    An EMPTY file is not an error: it means the PR changed nothing scannable, and the
    honest result for that is zero leads.
    """
    return {_norm_path(line) for line in Path(path).read_text().splitlines() if line.strip()}


def apply_diff_scope(static, scope: set[str]) -> int:
    """Keep only findings in files the PR touched; return how many were suppressed.

    POST-HOC on purpose, and not a path filter in semgrep's argv. The engines keep
    scanning the whole tree, so run-to-run counts stay comparable and the suppressed
    number is a real measurement rather than something invisible in a subprocess's
    arguments. It also has to be post-hoc to be safe: static/engines.py's collect()
    falls through to run_semgrep(source_root) over the ENTIRE tree whenever a supplied
    --sarif parses to zero findings, so this filter is the only thing between that
    fall-through and a full-repo result set.
    """
    kept = [f for f in static.findings if _norm_path(f.file) in scope]
    suppressed = len(static.findings) - len(kept)
    static.findings = kept
    static.notes.append(
        f"diff scope: {len(scope)} changed file(s), {len(kept)} candidate(s) kept, "
        f"{suppressed} suppressed as outside the diff"
    )
    return suppressed


@dataclass(slots=True)
class ScanResult:
    success: bool
    summary: str
    finding_count: int
    cost_usd: float = 0.0
    agents_spawned: int = 1
    leads: list = field(default_factory=list)
    triage: object | None = None
    # `success` alone cannot answer "did this run finish?", which is the only question a
    # CI gate actually needs. A budget-exhausted or cancelled run still returns
    # success=True with partial results, so a gate reading success sees green over a scan
    # that stopped halfway. strix's CI skill gates on run.json status == "completed" for
    # exactly this reason; docket had no equivalent field.
    status: str = "completed"          # completed | stopped | error
    stages: dict = field(default_factory=dict)
    # How many static candidates were dropped for living outside --changed-files. Carried
    # out of the run so the report can state it: "3 leads" over a filtered scan and "3
    # leads" over an unfiltered one are different claims, and a suppressed count is the
    # only thing that distinguishes them.
    suppressed_outside_diff: int = 0
    # service.fix.Patch per finding the fix agent attempted, refusals included. `.status`
    # comes from a scanner re-run over the patched copy, never from the agent, and
    # service/delivery.py ships only the verified ones.
    patches: list = field(default_factory=list)


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
    static_triage: bool = False,
    on_stage: Callable[[str, str], None] | None = None,
    triage_max: int = 0,
    fix_max: int = 0,
    on_progress: Callable[[], None] | None = None,
    recon: bool = False,
    on_surface: Callable[[dict], None] | None = None,
    cancel: CancelToken = NEVER,
    on_agent: Callable[[dict], None] | None = None,
    surface: dict | None = None,
    budget_usd: float | None = None,
    # Two scoping inputs, deliberately both. `scope_paths` narrows what semgrep is
    # asked to look at (cheaper, and it is what pr_service passes); `changed_files` is
    # the CLI's --changed-files path, read into a scope that filters what survives
    # collection. A CI job supplies one, the PR pipeline the other.
    changed_files: str | None = None,
    scope_paths: list[str] | None = None,
    # Which findings triage may spend the budget on. None means all of them, which is
    # right for a whole-repository scan.
    #
    # A pull request needs the opposite default. `triage_max` caps how many findings get
    # judged and each one costs a model run, so without this triage picks by severity
    # across EVERYTHING the scanners found — and on a file with a backlog, the pre-existing
    # findings outrank the ones the change introduced and consume the entire cap.
    #
    # Measured on kaizenmantra/vulnshop#23: triage judged two pre-existing SQL injections
    # at app.py:36-37, the diff then correctly discarded both as outside the change, and
    # the two findings actually in the diff at app.py:61-68 were never judged at all. The
    # check reported "none judged reachable" over findings nobody had judged.
    #
    # A PREDICATE, not a list of keys. The caller cannot name the findings in advance —
    # they do not exist until the scanners in this very call produce them. Passing a list
    # meant the caller had to run the whole scan once to learn the keys and again to act
    # on them, which is exactly the duplicated pass this replaced.
    triage_filter: Callable[[dict], bool] | None = None,
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
    # Scope is loaded FIRST, before a container starts or a single turn is paid for: a
    # typo'd --changed-files must fail the run, not fail it after the bill.
    scope = load_diff_scope(changed_files) if changed_files is not None else None

    # static_only means "no agents attacking a live target". Triage and recon ARE agents,
    # just pointed at source, so they still need a real model — Config.static_only() has an
    # empty llm and would build a LitellmModel(model="") that fails on every call.
    # static_triage counts too: it is a third agent path, and it was missing here. So does
    # fix_max — it is a fourth, and it is the one shape a PR check actually runs
    # (--static-only --no-sandbox --fix N), where Config.static_only()'s empty llm and
    # max_cost_usd=0.0 would refuse every fix agent before its first turn.
    wants_agents = bool(triage_max or recon or static_triage or fix_max)
    cfg = config or (
        Config.static_only()
        if static_only and not wants_agents
        else Config.from_env()
    )
    # VERIFIED fail-open, not a theory: Config.static_only() sets max_cost_usd=0.0
    # (config/settings.py) and AgentCoordinator.over_budget is `spent >= budget`
    # (core/agents.py), so 0.0 >= 0.0 is True and EVERY triage/recon agent is refused
    # before its first turn — the run then reports "0 judged" as though the findings were
    # examined and nothing came back. A zero budget must never silently mean "everything
    # fails unjudged". The ternary above is not enough on its own: interface/main.py hands
    # us a Config.static_only() explicitly for --static-only, and an explicit config wins.
    # max_child_cost_usd=0.0 is the same trap one level down (register() gives each child a
    # reserve of min(child_cap, remaining)), and max_agents=0 refuses the spawn outright,
    # so the whole config is swapped rather than patched field by field.
    if wants_agents and (not cfg.llm or cfg.max_cost_usd <= 0):
        cfg = Config.from_env()          # DOCKET_MAX_COST_USD, default $2.00
    # A per-scan ceiling from the operator overrides DOCKET_MAX_COST_USD. Replacing
    # the value on the config is what makes it real: the pre-turn gate in core/hooks
    # reads coordinator.budget_usd, which is built from this, so a budget set here
    # stops a run mid-flight rather than being a label on a dashboard.
    if budget_usd is not None and budget_usd > 0:
        cfg = replace(cfg, max_cost_usd=float(budget_usd),
                      max_child_cost_usd=min(cfg.max_child_cost_usd, float(budget_usd)))
    # Bound here so the name exists whether or not recon runs — root reads it much
    # later when building its task, and `if recon:` is otherwise the only binder.
    # Bound here so the name exists whether or not recon runs — root reads it much
    # later, and `if recon:` is otherwise the only binder.
    recon_surface: dict | None = None
    # Same reason: bound here so ScanResult can read it whether or not --fix ran.
    patches: list = []
    # Every stage transition already flowed to on_stage and was then dropped on the floor:
    # the state lived only in the console's in-memory SESSION, so report.json could not
    # distinguish "semgrep found nothing" from "semgrep never started". That is the
    # fail-open a PR gate cares about most, so record it here and persist it.
    stages: dict[str, str] = {}
    _caller_on_stage = on_stage

    def on_stage(scanner: str, state: str) -> None:      # noqa: F811 - deliberate wrap
        stages[scanner] = state
        if _caller_on_stage is not None:
            _caller_on_stage(scanner, state)
    coordinator = AgentCoordinator(
        max_agents=cfg.max_agents,
        budget_usd=cfg.max_cost_usd,
        per_agent_reserve_usd=cfg.max_child_cost_usd,
    )
    directory = run_dir(run_name)
    # A store with no sink is a scan that measures and then throws the result away, and
    # it fails SILENTLY: the scanners run, the coverage block fills in, and `findings[]`
    # is empty — which reads exactly like a clean repository.
    #
    # Measured on kaizenmantra/vulnshop#20. connect.py:_scan_for_pr passed `store=store`
    # and `on_finding=None`; semgrep found 17 hits inside the container INCLUDING the SQL
    # injection the pull request introduced (app.py:64 and app.py:66, `errors: []`,
    # `paths.scanned: ["/work/source/app.py"]` — all still on disk in
    # docket_runs/pr-kaizenmantra-vulnshop-262561b/sandbox/artifacts/scanners/semgrep.json)
    # and _run_scanner_prescans dropped every one of them at `if on_finding is not None`.
    # report.json said finding_count 0, diff_runs read `findings[]`, the verdict was "No
    # new findings", exit_code 0, and the autofix was then told there was nothing to fix.
    # The PR check reported a pass over a live SQL injection it had already found.
    #
    # The two other callers (interface/main.py:96, connect.py:962) both pass a sink that
    # is `store.add` with a display wrapper, so this default changes neither of them. It
    # exists so the next caller cannot make the same mistake: if you hand run_scan a
    # store, findings reach it unless you deliberately say otherwise.
    if store is not None and on_finding is None and hasattr(store, "add"):
        on_finding = store.add
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
            # Deterministic scanner pass BEFORE the first agent turn — see
            # _run_scanner_prescans. Findings land through the same on_finding path an
            # agent-filed finding does. Inside the try so a stray failure here still
            # tears the container down via the finally below.
            # sandbox.run_dir (directory/"sandbox"), NOT `directory` — that's what's
            # actually bind-mounted to /work/run inside the container (see Sandbox
            # construction above). Passing `directory` here silently starved every
            # scanner reader: the container wrote real output, the host looked one
            # level up and found nothing — confirmed by an end-to-end CLI run before
            # this fix, not assumed.
            _run_scanner_prescans(sandbox, agent_target, sandbox.run_dir, on_finding,
                              on_stage, cancel=cancel, scope_paths=scope_paths)

            # Recon BEFORE triage, deliberately. It maps the application once and
            # cheaply (~$0.06 regardless of finding count), and the candidates it
            # surfaces — an unguarded route, a guard that an env var disables — are
            # exactly the things worth triaging. Triage that only sees semgrep's output
            # can only ever judge what a pattern already matched.
            if recon:
                from docket.core.recon import run_recon


                if on_stage:
                    on_stage("recon", "running")
                recon_surface = run_recon(
                    str(whitebox_path or target_url or "repository"),
                    run_dir=directory, config=cfg, sandbox=sandbox,
                    findings=[f.model_dump(mode="json") for f in store.findings()]
                    if store is not None else [],
                    model_override=model_override, cancel=cancel,
                    on_agent=on_agent,
                    # In a pull-request scan this is the changed-file list, which
                    # switches recon from mapping the application to judging a diff —
                    # a smaller job, so a smaller ceiling.
                    changed=scope_paths,
                    max_turns=PR_MAX_TURNS if scope_paths else DEFAULT_RECON_TURNS,
                    source_root=str(whitebox_path) if whitebox_path else None,
                )
                if recon_surface:
                    # Into the SAME store the scanners feed, so candidates appear in
                    # the findings list, the report, the SARIF and the brief rather
                    # than only on a tab nobody opens. They carry discovered_by
                    # "recon" and status OPEN so nothing mistakes them for a match.
                    from docket.core.surface_findings import candidates_to_findings

                    # ONE sink, the same one the scanner prescan uses. This used to call
                    # store.add() here AND on_finding(), and every real caller's
                    # on_finding already ends in store.add (interface/main.py:96 wraps it,
                    # connect.py:962 `publish` calls it) — so every recon candidate was
                    # added twice. The second add takes FindingStore.add's "already seen"
                    # branch with `existing is candidate`, which appends the candidate's
                    # own PoC to its own corroborating_evidence: a lead that appears to
                    # corroborate itself. Routing through the single sink removes that and
                    # keeps a store-only caller working, because run_scan now defaults
                    # on_finding to store.add above.
                    for candidate in candidates_to_findings(recon_surface):
                        if on_finding is not None:
                            on_finding(candidate)
                if recon_surface and on_surface is not None:
                    on_surface(recon_surface)
                if on_stage:
                    # No surface means the agent never produced one. Reporting that as
                    # "done" would present a missing map as an empty application.
                    on_stage("recon", "done" if recon_surface else "error")
                if on_progress is not None:
                    on_progress()
            elif on_stage:
                on_stage("recon", "skipped")

            # Triage runs INSIDE this sandbox, after the scanners: the source is
            # already mounted at /work/source and tearing the container down just to
            # start another one would re-fetch nothing and cost seconds.
            if triage_max and store is not None and len(store):
                from docket.core.triage import apply_verdicts, triage_findings

                if on_stage:
                    on_stage("triage", "running")
                # Applied AS EACH VERDICT LANDS, not in one batch at the end. Batching
                # meant a 17-minute triage run reported "0 judged" for its entire
                # duration and then everything at once — the work was invisible for
                # exactly as long as it took.
                def _on_verdict(finding_id: str, verdict: dict) -> None:
                    apply_verdicts(store, {finding_id: verdict})
                    if on_progress is not None:
                        on_progress()

                candidates = [f.model_dump(mode="json") for f in store.findings()]
                if triage_filter is not None:
                    total = len(candidates)
                    try:
                        candidates = [f for f in candidates if triage_filter(f)]
                    except Exception:  # noqa: BLE001
                        # A broken filter must not silently mean "judge nothing", which
                        # would read downstream as "we looked and found nothing wrong".
                        logger.exception("triage_filter raised; judging all findings")
                        candidates = [f.model_dump(mode="json") for f in store.findings()]
                    logger.info("triage scope: %d of %d finding(s) are new here",
                                len(candidates), total)

                verdicts = triage_findings(
                    candidates,
                    run_dir=directory, config=cfg, sandbox=sandbox,
                    max_findings=triage_max, model_override=model_override,
                    source_root=str(whitebox_path) if whitebox_path else None,
                    cancel=cancel, on_agent=on_agent,
                    on_verdict=_on_verdict,
                )
                applied = len(verdicts)
                if on_stage:
                    # "done" with nothing applied is a lie the operator cannot debug;
                    # an error state at least points at the phase that failed.
                    on_stage("triage", "done" if applied else "error")
            elif on_stage:
                on_stage("triage", "skipped")

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
        triage_report = None
        suppressed_outside_diff = 0
        if sarif_path or whitebox_path:
            static = collect_static(sarif_path=sarif_path, source_root=whitebox_path)
            # Straight after collect_static, so everything downstream — correlation,
            # triage's bill, static.json, the leads in the report — sees the scoped set and
            # only the scoped set. An empty scope keeps NOTHING: "the PR changed nothing
            # scannable" is a real answer, and widening it back to the repo would be the
            # silent-scope-change this flag exists to prevent.
            if scope is not None:
                suppressed_outside_diff = apply_diff_scope(static, scope)
            static.save(directory)
            leads = correlate(static.findings, surface, whitebox_path)
            for note in static.notes:
                emitter.log_static(note)
            emitter.log_static(summarise(leads))

            # Agent triage: read the code around each candidate and rule on it. This is
            # the whole value over running Semgrep directly — a candidate with a verdict
            # and a quoted guard is actionable where a candidate alone is a queue item.
            # Needs the source, and a model. It used to also be gated on `not static_only`,
            # which made static_triage=True a silent no-op there — and combined with the
            # missing static_triage in the cfg ternary above, asking for it under
            # --static-only got you neither a model nor a triage pass, with no error. The
            # config swap above now guarantees a real model and a real budget whenever it
            # is requested, so the request is honoured instead of dropped.
            # Kept, deliberately OFF by default: core/triage.py above is the wired
            # triage. Two triage agents were built in parallel; running both would
            # double the model spend and produce two verdicts per finding with no
            # rule for which wins.
            # ponytail: pick a winner after a real run and delete the loser.
            if static_triage and whitebox_path and leads:
                triage_context = ScanContext(
                    target_url=agent_target or "", run_dir=directory,
                    on_finding=None, agent_id="triage", role="triage",
                    coordinator=coordinator, config=cfg,
                    model_override=model_override, sandbox=sandbox,
                    source_root=whitebox_path,
                )
                verdicts = asyncio.run(triage_all(leads, triage_context))
                triage_report = verdicts
                for note in verdicts.notes:
                    emitter.log_static(note)
                emitter.log_static(verdicts.summary())

        # AUTOFIX, after the static pass so it can see the candidates, and after triage so
        # it does not spend a turn patching something already ruled not reachable.
        #
        # Gated on `whitebox_path`, NOT on `sandbox` and NOT on `len(store)`. The shape a PR
        # check actually runs is `--static-only --no-sandbox --fix N`: there is no sandbox,
        # no Finding is ever constructed, and every scanner hit is a CANDIDATE. Either of
        # those gates would make --fix a silent no-op on exactly the invocation it exists
        # for — the same trap `static_triage` hit (interface/main.py:114). The agent needs
        # source and a model; it needs no container, because it runs no commands.
        if fix_max and whitebox_path:
            from docket.service.fix import fix_findings, report_for_fix

            if on_stage:
                on_stage("fix", "running")
            patches = fix_findings(
                report_for_fix(store, leads),
                source_root=whitebox_path, run_dir=directory, config=cfg,
                max_fixes=fix_max, model_override=model_override, cancel=cancel,
                on_agent=on_agent,
            )
            if on_stage:
                # "skipped", not "error", when nothing came back: an empty list means
                # nothing was fixable (no file:line anchor, or triage already cleared it),
                # and a fix agent that FAILS still produces a Patch record. Reporting that
                # as "error" would turn every such pull request red — service/gate.py reads
                # an errored stage as action_required.
                on_stage("fix", "done" if patches else "skipped")
            if on_progress is not None:
                on_progress()
        elif on_stage:
            on_stage("fix", "skipped")

        if static_only:
            # Was an unconditional success=True, so a static-only run could return 0 or 2
            # and never 1 — a run whose scanners all failed reported clean. `drain()`
            # already marks a scanner `error`; now that verdict reaches the caller.
            failed = sorted(k for k, v in stages.items() if v == "error")
            output = {
                "success": not failed,
                "summary": ("static-only scan: scanner pre-scan only, no AI agents run"
                            if not failed else
                            f"static-only scan: {', '.join(failed)} did not run"),
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
            # `surface` here is discovery's AttackSurface, probed over HTTP against a
            # live target. The recon AGENT's map (recon_surface below) is a different
            # thing built by reading source, and the two are complementary rather than
            # rivals: discovery knows what answers, recon knows what the code declares.
            task = build_root_task(agent_target, instruction, surface, leads)
            output = asyncio.run(run_agent_loop(agent, context, task, max_turns=max_turns))
    finally:
        if sandbox is not None:
            sandbox.stop()

    findings = output.get("findings", [])
    emitter.scan_finished(bool(output.get("success", True)), output.get("summary", ""))
    # "stopped" is NOT an error: partial results are still real, and the distinction is
    # the whole point — a caller may show them while a gate refuses to call them clean.
    if any(v == "error" for v in stages.values()):
        status = "error"
    # The `max_cost_usd > 0` guard is the same zero-budget trap one field over, and it was
    # firing: over_budget() is `spent >= budget`, so a --static-only run (budget 0.0, spent
    # 0.0, no agent even built) reported status="stopped" — every scanner-only PR check
    # looked like a scan that ran out of money halfway. Verified with a real CLI run before
    # this guard. A run that needed no budget did not stop early.
    elif cancel.cancelled or (cfg.max_cost_usd > 0
                               and coordinator.over_budget("root") is not None):
        status = "stopped"
    else:
        status = "completed"

    return ScanResult(
        success=bool(output.get("success", True)),
        summary=output.get("summary", ""),
        finding_count=len(findings),
        cost_usd=round(coordinator.spent_usd, 6),
        agents_spawned=0 if static_only else len(coordinator.agents) + 1,  # +1 for root
        leads=leads,
        triage=triage_report,
        status=status,
        stages=dict(stages),
        suppressed_outside_diff=suppressed_outside_diff,
        patches=patches,
    )
