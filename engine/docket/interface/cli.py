"""Parser assembly. Definitions live in cli_args.py so the TUI and interactive mode
can reuse them; this module stays a thin re-export for callers that just want a parser.
"""
from __future__ import annotations

from docket.interface.cli_args import build_parser

__all__ = ["build_parser"]
