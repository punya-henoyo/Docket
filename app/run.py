"""Launch the docket console:  uv run python -m app.run

Serves the built console and both API halves from one process on one port, which is
what you want in front of an audience. For frontend work run `npm run dev` in app/frontend
instead — it proxies /api and /ws back here.

Run it as a module, never as `python app/run.py`: the latter puts app/ on sys.path
instead of the repo root, so `import app.backend` fails. Same rule the tool itself
follows for `python -m docket.x.y`.
"""
from __future__ import annotations

import sys

import uvicorn

from app.backend.main import FRONTEND_DIST

# Not 5000 or 7000: macOS binds both to the AirPlay Receiver (ControlCenter) out of
# the box, so they look free right up until the bind fails.
PORT = 7717

if __name__ == "__main__":
    if not FRONTEND_DIST.is_dir():
        print("frontend not built. Run:\n  cd app/frontend && npm install && npm run build",
              file=sys.stderr)
        sys.exit(1)
    print(f"docket console → http://127.0.0.1:{PORT}")
    # Loopback only, always. This process can start a subprocess that fires real
    # exploit payloads; it must never be reachable off this machine.
    uvicorn.run("app.backend.main:api", host="127.0.0.1", port=PORT, log_level="warning")
