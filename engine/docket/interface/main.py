"""Entrypoint: parse -> check environment -> run_scan -> write report -> exit code.

Exit codes follow the conventional CI gate contract:
0 = clean, 1 = error, 2 = findings present.
"""
from __future__ import annotations

import json
import sys

from docket.config.settings import Config
from docket.core.runner import run_scan
from docket.interface.cli_args import EXIT_CLEAN, EXIT_ERROR, EXIT_FINDINGS, build_parser
from docket.interface.environment import check_environment, format_report
from docket.interface.interactive import ProgressReporter, make_on_finding
from docket.interface.scan_setup import latest_run, list_runs, prepare_scan
from docket.report.dedupe import FindingStore
from docket.report.writer import build_report, format_summary, write_report


def exit_code(store: FindingStore, scan_ok: bool) -> int:
    if not scan_ok:
        return EXIT_ERROR
    return EXIT_FINDINGS if len(store) > 0 else EXIT_CLEAN


def _pack_ids(raw: str | None) -> list[str] | None:
    """`--compliance a,b` -> ["a", "b"]. None when the flag was not passed at all, which
    is a different thing from an empty list: run_scan gates the whole stage on it."""
    if not raw:
        return None
    return [part.strip() for part in str(raw).split(",") if part.strip()] or None


def cmd_doctor(args) -> int:
    report = check_environment(require_sandbox=False)
    print("docket environment check")
    print(f"  LLM      : {report.llm_model or '(unset)'}"
          f"{'  via ' + report.api_key_source if report.api_key_source else ''}")
    print(f"  Docker   : {'available' if report.docker_available else report.docker_error}")
    print(f"  Search   : {report.search_provider or 'not configured'}")
    text = format_report(report)
    if text:
        print()
        print(text)
    return EXIT_CLEAN if report.ok else EXIT_ERROR


def cmd_packs(args) -> int:
    """List the control packs. Without this the only way to learn a pack id is to get one
    wrong and read the error, which is a poor way to find out what a tool can do."""
    from docket.compliance.packs import list_packs

    rows = list_packs()
    if not rows:
        print("no control packs found", file=sys.stderr)
        return EXIT_ERROR
    width = max(len(str(r["id"])) for r in rows)
    print(f"{'PACK':<{width}}  CHECKABLE  TITLE")
    for row in rows:
        if not row.get("usable"):
            print(f"{row['id']:<{width}}  {'—':>9}  UNREADABLE: {row.get('error', '')}")
            continue
        # "14 of 43", never a percentage, and never just the pack size. The gap between
        # the two numbers IS the honest part: most of a regulatory framework is
        # organisational and no repository answers it.
        checkable = f"{row['source_controls']} of {row['total_controls']}"
        print(f"{row['id']:<{width}}  {checkable:>9}  {row['title']}"
              + (f"  [{row['authority']}]" if row.get("authority") else "")
              + ("  (uploaded)" if row.get("origin") == "uploaded" else ""))
    print()
    print("CHECKABLE is how many of a pack's controls can be answered by reading source.")
    print("The rest are organisational or deployment properties: docket reports them as")
    print("unassessed and never counts them as satisfied.")
    return EXIT_CLEAN


def cmd_scan(args) -> int:
    # --triage/--recon/--fix are agents pointed at source, so they need an LLM even under
    # --static-only. Checking that here means a CI job that asked for verdicts is told it
    # has no model up front, rather than producing an unjudged report that looks complete.
    # --fix belongs in this set for a second reason too: without it, `--static-only --fix`
    # gets Config.static_only() below, whose llm is "" — LitellmModel(model="") dies on its
    # first call — and whose max_cost_usd is 0.0, which `spent >= budget` turns into a
    # refusal of every agent before its first turn. The run would report no patches as
    # though it had tried and found nothing to do.
    # `--compliance` belongs here too, and it is the fifth path into the same trap. A
    # control pack is judged by an agent reading source, so without it
    # `--static-only --compliance python-baseline` skips the up-front LLM check, takes
    # Config.static_only() below (llm="", max_cost_usd=0.0), and then run_scan's own
    # repair calls Config.from_env() — which RAISES on an unconfigured machine, deep in a
    # scan, instead of refusing cleanly here with the reason. run_scan defends against
    # this as well; deciding it here keeps the two agreeing rather than relying on the
    # repair, which is what the comment below already says.
    wants_agents = bool(args.triage or args.recon or args.fix or args.compliance)
    env = check_environment(require_sandbox=not args.no_sandbox,
                            require_llm=not args.static_only or wants_agents)
    if not env.ok:
        print(format_report(env), file=sys.stderr)
        return EXIT_ERROR
    for warning in env.warnings:
        print(f"warning: {warning}", file=sys.stderr)
    if args.source and args.no_sandbox:
        print(
            "warning: --source has no effect with --no-sandbox — trivy/semgrep run "
            "inside the container only, and this run has none",
            file=sys.stderr,
        )

    try:
        setup = prepare_scan(
            args.target, run_name=args.run_name, instruction=args.instruction,
            out_dir=args.out_dir, use_sandbox=not args.no_sandbox,
            source_path=args.source, static_only=args.static_only,
        )
        # Config.static_only() carries llm="" AND max_cost_usd=0.0, and over_budget() is
        # `spent >= budget`, so handing it to a run that spawns triage/recon agents kills
        # every one of them before its first turn. run_scan() defends against this too;
        # deciding it here keeps the two agreeing rather than relying on the repair.
        config = (Config.static_only() if args.static_only and not wants_agents
                  else Config.from_env())
    except (ValueError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    if getattr(args, "tui", False):
        from docket.interface.tui.runtime import run_scan_with_tui

        return run_scan_with_tui(setup, config, max_turns=args.max_steps)

    store = FindingStore()
    # Filled by run_scan's on_surface callback below. A dict rather than a nonlocal so the
    # lambda can write to it without the closure gymnastics.
    surface: dict = {}
    reporter = None if args.non_interactive else ProgressReporter()
    kwargs = dict(run_name=setup.run_name, target=setup.target or "(static-only)")
    try:
        if reporter:
            reporter.start()
        result = run_scan(
            target_url=setup.target,
            instruction=setup.instruction,
            whitebox_path=setup.source_path,
            on_finding=make_on_finding(store.add, reporter),
            config=config,
            run_name=setup.run_name,
            use_sandbox=setup.use_sandbox,
            max_turns=args.max_steps,
            store=store,
            openapi_path=args.openapi,
            har_path=args.har,
            sarif_path=args.sarif,
            discovery=not args.no_discovery,
            static_only=setup.static_only,
            # Every one of these was already a run_scan parameter with no way for a CI job
            # to reach it: scanners were wired to the CLI, the AI triage that turns their
            # output into verdicts was not.
            changed_files=args.changed_files,
            triage_max=args.triage,
            # `triage_max` drives core/triage.py, which judges PROVEN findings, and
            # runner.py gates it on `len(store)`. Under --static-only there is no sandbox,
            # so no Finding is ever constructed and that store is empty — every scanner hit
            # is a CANDIDATE, judged by static/triage.py behind `static_triage`. So
            # `--triage N` on the one shape a CI job uses reached nothing at all. Setting
            # both means the flag judges whichever population the run actually produced,
            # which is what the operator asked for either way.
            static_triage=bool(args.triage),
            # No `static_fix` twin is needed, and that is deliberate rather than an
            # oversight: the trap above exists because core/triage.py judges PROVEN findings
            # and runner.py gates it on `len(store)`, which is empty under --static-only.
            # service/fix.py reads gate._all_rows instead, which normalises `findings[]` AND
            # `flagged_not_proven[]` into one list, so `--fix N` reaches whichever population
            # the run produced. runner.py gates it on the source tree, not on the store.
            fix_max=args.fix,
            budget_usd=args.budget,
            recon=args.recon,
            # The CLI DISCARDED this. run_scan produced a surface, used its candidates as
            # findings, and then threw the map away: report.json["surface"] came back {}
            # on every `docket scan --recon`, so `docket view` and the brief showed no
            # entry points and no auth model for a phase that had just been paid for.
            # connect.py has always captured it; main.py never did. Same CLI-vs-console
            # divergence as the twin-server one, one layer down.
            on_surface=lambda mapped: surface.update(mapped or {}),
            # Comma-separated on the command line, a list everywhere inside. Split here
            # rather than in run_scan so the engine takes one shape and the CLI's comma
            # convention stays a CLI concern.
            compliance=_pack_ids(args.compliance),
            compliance_deep=args.compliance_deep,
        )
    except KeyboardInterrupt:
        print("\ninterrupted — writing what was confirmed so far", file=sys.stderr)
        write_report(store, setup.run_dir, summary="interrupted by user", success=False, **kwargs)
        return EXIT_ERROR
    except Exception as exc:
        # Still persist whatever the agents confirmed before the failure — a crashed
        # scan that found a real bug should not throw that away.
        if len(store):
            write_report(store, setup.run_dir, summary=f"scan failed: {exc}", success=False, **kwargs)
        print(f"error: scan failed: {exc}", file=sys.stderr)
        return EXIT_ERROR
    finally:
        if reporter:
            reporter.stop()

    kwargs |= dict(summary=result.summary, cost_usd=result.cost_usd,
                   agents_spawned=result.agents_spawned, success=result.success,
                   leads=result.leads, triage=result.triage,
                   status=result.status, stages=result.stages,
                   # "4 leads" over a diff-scoped scan and "4 leads" over a whole-repo scan
                   # are different claims; the suppressed count is what separates them.
                   suppressed_outside_diff=result.suppressed_outside_diff,
                   # The CAP, not a demand. build_report clamps it to how many rows were
                   # actually judgeable, because `--triage 20` on a PR with 3 candidates is
                   # a request to judge 3, not a shortfall of 17.
                   triage_requested=args.triage,
                   # Refusals included. Each row carries the agent's claim next to the
                   # scanner's verdict, so a patch that did not verify is visible as that.
                   patches=result.patches,
                   # The attack surface recon mapped. Without this the entry points and
                   # auth model exist only in the agent's transcript.
                   surface=surface or None,
                   # One row per requested pack, always — including a pack where nothing
                   # could be assessed, which is a different statement from not asking.
                   compliance=result.compliance)
    paths = write_report(store, setup.run_dir, **kwargs)
    print(format_summary(build_report(store, **kwargs), paths=paths))
    return exit_code(store, result.success)


def cmd_view(args) -> int:
    if args.run_name:
        matches = [d for d in list_runs() if d.name == args.run_name]
        directory = matches[0] if matches else None
    else:
        directory = latest_run()

    if directory is None or not (directory / "report.json").exists():
        print(f"error: no report found for {args.run_name or 'any run'}", file=sys.stderr)
        return EXIT_ERROR

    if getattr(args, "web", False):
        from docket.interface.viewer.cli import serve_run

        return serve_run(directory, port=args.port, open_browser=not args.no_browser)

    if args.format == "sarif":
        print((directory / "report.sarif").read_text())
        return EXIT_CLEAN

    report = json.loads((directory / "report.json").read_text())
    print(json.dumps(report, indent=2) if args.format == "json"
          else format_summary(report, full=args.full))
    return EXIT_CLEAN


def cmd_connect(args) -> int:
    from docket.interface.connect import serve

    return serve(port=args.port)


def main() -> None:
    args = build_parser().parse_args()
    handlers = {"scan": cmd_scan, "view": cmd_view, "doctor": cmd_doctor,
                "connect": cmd_connect, "packs": cmd_packs}
    sys.exit(handlers[args.command](args))


if __name__ == "__main__":
    main()
