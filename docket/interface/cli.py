"""argparse, not click/typer — two subcommands and a handful of flags don't earn a
dependency."""
from __future__ import annotations

import argparse

from docket import __version__


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="docket", description="Lab-scale autonomous pentesting agent.")
    parser.add_argument("--version", action="version", version=f"docket {__version__}")

    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Run a scan against a target.")
    scan.add_argument("--target", required=True, help="Base URL of the target, e.g. http://127.0.0.1:5000")
    scan.add_argument("--instruction", default=None, help="Freeform hints for the agent (e.g. seeded creds).")
    scan.add_argument("-n", "--non-interactive", action="store_true", help="Suppress progress streaming; print only the final summary.")
    scan.add_argument("--run-name", default=None, help="Name for this run's artifact directory (default: timestamp-based).")
    scan.add_argument("--max-steps", type=int, default=None, help="Cap on agent turns, for CI runs.")
    scan.add_argument(
        "--no-sandbox", action="store_true",
        help="Run HTTP tooling in this process instead of the Docker sandbox "
             "(no Docker needed; disables the shell tool, so no sqlmap).",
    )
    scan.add_argument("--out-dir", default=None, help="Override the default docket_runs/ output root.")

    view = sub.add_parser("view", help="Print a past run's findings.")
    view.add_argument("run_name", nargs="?", default=None, help="Run to show (default: most recent).")
    view.add_argument("--format", choices=["text", "json", "sarif"], default="text")
    view.add_argument("--full", action="store_true", help="Show full PoC evidence, not a truncated preview.")

    return parser
