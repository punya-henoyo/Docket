"""Entrypoint: parse -> run_scan() -> dump -> sys.exit(code).

M1 prints a raw JSON dump of the (currently stubbed) findings. M9's writer.py takes
over persistence (report.json/report.sarif) and `view` starts reading real runs —
this file's shape doesn't change, only what it calls.
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone

from docket.config import Config, run_dir
from docket.interface.cli import build_parser
from docket.interface.scan import run_scan
from docket.report.dedupe import FindingStore


def exit_code(store: FindingStore, scan_ok: bool) -> int:
    if not scan_ok:
        return 1
    return 2 if len(store) > 0 else 0


def _default_run_name() -> str:
    return "run-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def cmd_scan(args) -> int:
    store = FindingStore()
    try:
        config = Config.from_env()
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    result = run_scan(
        target_url=args.target,
        instruction=args.instruction,
        on_finding=store.add,
        config=config,
    )

    run_name = args.run_name or _default_run_name()
    out_dir = run_dir(run_name)
    payload = {
        "run_name": run_name,
        "target": args.target,
        "success": result.success,
        "summary": result.summary,
        "findings": [f.model_dump(mode="json") for f in store.findings()],
    }
    print(json.dumps(payload, indent=2))
    print(f"\n({len(store)} finding(s) — artifacts dir: {out_dir})", file=sys.stderr)

    return exit_code(store, result.success)


def cmd_view(args) -> int:
    from docket.config import RUNS_DIR

    report_path = RUNS_DIR / (args.run_name or "") / "report.json"
    if not args.run_name or not report_path.exists():
        print(
            "no persisted report yet — `docket view` reads report.json, "
            "which lands in M9's writer.py. Use `docket scan` and read its stdout for now.",
            file=sys.stderr,
        )
        return 1
    print(report_path.read_text())
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
