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


def cmd_scan(args) -> int:
    env = check_environment(require_sandbox=not args.no_sandbox)
    if not env.ok:
        print(format_report(env), file=sys.stderr)
        return EXIT_ERROR
    for warning in env.warnings:
        print(f"warning: {warning}", file=sys.stderr)

    try:
        setup = prepare_scan(
            args.target, run_name=args.run_name, instruction=args.instruction,
            out_dir=args.out_dir, use_sandbox=not args.no_sandbox,
        )
        config = Config.from_env()
    except (ValueError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    if getattr(args, "tui", False):
        from docket.interface.tui.runtime import run_scan_with_tui

        return run_scan_with_tui(setup, config, max_turns=args.max_steps)

    store = FindingStore()
    reporter = None if args.non_interactive else ProgressReporter()
    kwargs = dict(run_name=setup.run_name, target=setup.target)
    try:
        if reporter:
            reporter.start()
        result = run_scan(
            target_url=setup.target,
            instruction=setup.instruction,
            on_finding=make_on_finding(store.add, reporter),
            config=config,
            run_name=setup.run_name,
            use_sandbox=setup.use_sandbox,
            max_turns=args.max_steps,
            store=store,
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
                   agents_spawned=result.agents_spawned, success=result.success)
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


def main() -> None:
    args = build_parser().parse_args()
    handlers = {"scan": cmd_scan, "view": cmd_view, "doctor": cmd_doctor}
    sys.exit(handlers[args.command](args))


if __name__ == "__main__":
    main()
