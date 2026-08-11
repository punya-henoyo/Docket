"""Argument definitions, split out of cli.py.

Kept separate so the TUI and interactive mode can reuse the same flag definitions and
defaults rather than re-declaring them and drifting.
"""
from __future__ import annotations

import argparse

from docket import __version__
from docket.core.inputs import DEFAULT_MAX_TURNS

EXIT_CLEAN = 0
EXIT_ERROR = 1
EXIT_FINDINGS = 2


def add_scan_args(parser: argparse.ArgumentParser) -> argparse.ArgumentParser:
    parser.add_argument("--target", required=True,
                        help="Base URL of the target, e.g. http://127.0.0.1:5000")
    parser.add_argument("--instruction", default=None,
                        help="Freeform hints for the agents (e.g. seeded credentials).")
    parser.add_argument("-n", "--non-interactive", action="store_true",
                        help="Suppress progress output; print only the final summary.")
    parser.add_argument("--run-name", default=None,
                        help="Name for this run's artifact directory (default: timestamp).")
    parser.add_argument("--max-steps", type=int, default=DEFAULT_MAX_TURNS,
                        help=f"Cap on agent turns (default: {DEFAULT_MAX_TURNS}).")
    parser.add_argument("--out-dir", default=None,
                        help="Override the default docket_runs/ output root.")
    parser.add_argument("--no-sandbox", action="store_true",
                        help="Run HTTP tooling in-process instead of the Docker sandbox "
                             "(no Docker needed; disables the shell and browser tools).")
    parser.add_argument("--tui", action="store_true",
                        help="Watch the scan live in a terminal UI.")
    return parser


def add_view_args(parser: argparse.ArgumentParser) -> argparse.ArgumentParser:
    parser.add_argument("run_name", nargs="?", default=None,
                        help="Run to show (default: most recent).")
    parser.add_argument("--format", choices=["text", "json", "sarif"], default="text")
    parser.add_argument("--full", action="store_true",
                        help="Show full PoC evidence, not a truncated preview.")
    parser.add_argument("--web", action="store_true",
                        help="Open the run in a local web dashboard instead of printing.")
    parser.add_argument("--port", type=int, default=0,
                        help="Port for --web (default: an ephemeral one).")
    parser.add_argument("--no-browser", action="store_true",
                        help="With --web, don't open a browser automatically.")
    return parser


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="docket", description="Lab-scale autonomous pentesting agent.",
    )
    parser.add_argument("--version", action="version", version=f"docket {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    add_scan_args(sub.add_parser("scan", help="Run a scan against a target."))
    add_view_args(sub.add_parser("view", help="Show a past run's findings."))
    sub.add_parser("doctor", help="Check the environment (LLM key, Docker, search).")
    return parser


def demo() -> None:
    parser = build_parser()
    args = parser.parse_args(["scan", "--target", "127.0.0.1:5000", "-n"])
    assert args.command == "scan" and args.non_interactive is True
    assert args.max_steps == DEFAULT_MAX_TURNS and args.no_sandbox is False

    view = parser.parse_args(["view", "baseline", "--format", "sarif", "--full"])
    assert view.run_name == "baseline" and view.format == "sarif" and view.full is True
    assert parser.parse_args(["view"]).run_name is None  # defaults to most recent
    assert parser.parse_args(["doctor"]).command == "doctor"
    assert (EXIT_CLEAN, EXIT_ERROR, EXIT_FINDINGS) == (0, 1, 2)
    print("interface.cli_args: ok")


if __name__ == "__main__":
    demo()
