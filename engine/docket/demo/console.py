"""`python -m docket.demo.console`: the Code Security console on sample data, one command.

Seeds `./.docket-demo/` (or `--dir`), changes into it, and serves the console. Changing
directory is the whole mechanism: the console reads `./docket_runs`, `./docket_portfolio.json`
and `./docket_policy.json` from the working directory, so a demo that lives in its own
directory can never touch, or be confused with, real runs.

The data is labelled sample at every level (see demo/seed.py), and `GET /api/portfolio`
returns `"sample": true` so the console shows a persistent "Sample data" badge. Re-running
refreshes the dates; it replaces only directories whose report says `sample`.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path

from docket.demo.seed import seed

DEFAULT_DIR = ".docket-demo"
DEFAULT_PORT = 8765


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python -m docket.demo.console",
        description="Seed sample data and serve the Code Security console on it.")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT,
                        help=f"port to serve on (default {DEFAULT_PORT})")
    parser.add_argument("--selfcheck", action="store_true",
                        help="run the module self-check and exit (no server)")
    parser.add_argument("--dir", default=DEFAULT_DIR,
                        help=f"where to write the sample data (default ./{DEFAULT_DIR})")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.selfcheck:
        demo()
        return 0
    root = Path(args.dir).resolve()
    root.mkdir(parents=True, exist_ok=True)
    summary = seed(root)
    os.chdir(root)
    print(f"sample data: {summary['runs']} runs across {summary['applications']} applications in {root}")
    # Imported late: connect pulls in the whole interface layer, which --help does not need.
    from docket.interface.connect import serve

    return serve(args.port)


def demo() -> None:
    import tempfile

    args = parse_args([])
    assert (args.port, args.dir) == (DEFAULT_PORT, DEFAULT_DIR)
    args = parse_args(["--port", "9001", "--dir", "/x/y"])
    assert (args.port, args.dir) == (9001, "/x/y")
    with tempfile.TemporaryDirectory() as tmp:
        from docket.portfolio.api import portfolio_payload

        seed(Path(tmp), now=1_800_000_000.0)
        status, body = portfolio_payload(Path(tmp), now=1_800_000_000.0)
        assert status == 200 and body["sample"] is True
        assert body["counts"] == {"action": 2, "attention": 4, "clear": 5, "unknown": 1}, body["counts"]
    print("demo.console: ok")


# Unlike every other module, running this one SERVES (that is its job), so `make check`
# does not list it; `--selfcheck` runs demo() and tests/test_portfolio.py calls it.
if __name__ == "__main__":
    raise SystemExit(main())
