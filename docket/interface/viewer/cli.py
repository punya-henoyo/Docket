"""`docket view --web` entry point. Mirrors docket/interface/viewer/cli.py.

Serves the dashboard on loopback and (optionally) opens a browser. Works on a live run
as well as a finished one — the page polls while a scan is in progress and stops once
it sees the run finished.

No PDF export: upstream ships one via reportlab/pypdf, but the dashboard prints cleanly
from the browser, and two more dependencies to re-render a page the browser can already
print is not a trade worth making here.
"""
from __future__ import annotations

import threading
import webbrowser
from pathlib import Path

from docket.interface.cli_args import EXIT_CLEAN, EXIT_ERROR
from docket.interface.viewer.server import start_server


def serve_run(run_dir: Path, *, port: int = 0, open_browser: bool = True,
              block: bool = True) -> int:
    run_dir = Path(run_dir)
    if not run_dir.exists():
        print(f"error: no such run directory: {run_dir}")
        return EXIT_ERROR

    server = start_server(run_dir, port=port)
    url = f"http://127.0.0.1:{server.server_address[1]}"
    print(f"docket viewer: {url}   (run: {run_dir.name})")
    print("nothing leaves this machine — the page reads the run directory off disk")
    print("Ctrl-C to stop")

    if open_browser:
        threading.Timer(0.4, lambda: webbrowser.open(url)).start()
    if not block:
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return EXIT_CLEAN
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nviewer stopped")
    finally:
        server.shutdown()
    return EXIT_CLEAN


def demo() -> None:
    import json
    import shutil
    import tempfile
    import urllib.request

    tmp = Path(tempfile.mkdtemp())
    try:
        (tmp / "report.json").write_text(json.dumps(
            {"run_name": "r", "target": "http://x", "finding_count": 0, "findings": []}))
        assert serve_run(tmp / "missing", open_browser=False, block=False) == EXIT_ERROR
        assert serve_run(tmp, port=0, open_browser=False, block=False) == EXIT_CLEAN
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print("viewer.cli: ok")


if __name__ == "__main__":
    demo()
