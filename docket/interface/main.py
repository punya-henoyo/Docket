"""Entrypoint: parse -> run_scan() -> write report -> sys.exit(code).

Exit codes are Docket's contract, kept verbatim because it's the actual CI gate:
0 = clean, 1 = error, 2 = findings present.
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from docket.config import RUNS_DIR, Config, run_dir
from docket.interface.cli import build_parser
from docket.interface.scan import run_scan
from docket.report.dedupe import FindingStore
from docket.report.writer import build_report, format_summary, write_report


def exit_code(store: FindingStore, scan_ok: bool) -> int:
    if not scan_ok:
        return 1
    return 2 if len(store) > 0 else 0


def _default_run_name() -> str:
    return "run-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _latest_run() -> Path | None:
    if not RUNS_DIR.exists():
        return None
    runs = [d for d in RUNS_DIR.iterdir() if d.is_dir() and (d / "report.json").exists()]
    return max(runs, key=lambda d: (d / "report.json").stat().st_mtime, default=None)


def cmd_scan(args) -> int:
    store = FindingStore()
    try:
        config = Config.from_env()
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    run_name = args.run_name or _default_run_name()
    out_dir = Path(args.out_dir) / run_name if args.out_dir else run_dir(run_name)

    try:
        result = run_scan(
            target_url=args.target,
            instruction=args.instruction,
            on_finding=store.add,
            config=config,
            run_name=run_name,
            use_sandbox=not args.no_sandbox,
            **({"max_turns": args.max_steps} if args.max_steps else {}),
        )
    except Exception as exc:
        # Still persist whatever the agents managed to confirm before the failure —
        # a crashed scan that found a real bug should not throw that away.
        if len(store):
            write_report(
                store, out_dir, run_name=run_name, target=args.target,
                summary=f"scan failed: {exc}", success=False,
            )
        print(f"error: scan failed: {exc}", file=sys.stderr)
        return 1

    paths = write_report(
        store, out_dir,
        run_name=run_name, target=args.target, summary=result.summary,
        cost_usd=result.cost_usd, agents_spawned=result.agents_spawned,
        success=result.success,
    )
    report = build_report(
        store, run_name=run_name, target=args.target, summary=result.summary,
        cost_usd=result.cost_usd, agents_spawned=result.agents_spawned,
        success=result.success,
    )
    print(format_summary(report, paths=paths))
    return exit_code(store, result.success)


def cmd_view(args) -> int:
    directory = (RUNS_DIR / args.run_name) if args.run_name else _latest_run()
    if directory is None or not (directory / "report.json").exists():
        which = args.run_name or "any run"
        print(f"error: no report found for {which} under {RUNS_DIR}", file=sys.stderr)
        return 1

    if args.format == "sarif":
        print((directory / "report.sarif").read_text())
        return 0

    report = json.loads((directory / "report.json").read_text())
    if args.format == "json":
        print(json.dumps(report, indent=2))
    else:
        print(format_summary(report, full=args.full))
    return 0


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    if args.command == "scan":
        sys.exit(cmd_scan(args))
    elif args.command == "view":
        sys.exit(cmd_view(args))


if __name__ == "__main__":
    main()
