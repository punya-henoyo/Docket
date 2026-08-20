"""Launch the docket console:  uv run python -m app.run

ONE console, one server. This used to boot a SECOND HTTP server —
`uvicorn app.backend.main:api` — that served the same frontend as `docket connect` but
a DIFFERENT set of endpoints. The frontend's watcher and fix buttons POST to /api/watch
and /api/pr/fix, which only `docket connect` serves; against this backend they returned
405 and the buttons silently did nothing. Same UI, two backends, half-working depending
on which one you happened to start. Measured directly: POST /api/watch -> 405 here,
-> 200 under `docket connect`.

So this now delegates to `docket.interface.connect.serve`, the exact server the
`docket connect` CLI runs. Both entry points are the same console. The `app.backend`
package and the engine `docket.service.*` layer stay in the tree — the service modules
are what autofix validates through (interface/connect.attempt_autofix), and the backend
routers are kept for reference and their tests — but neither is a runtime server any
more. There is one console, and it is this one.

For frontend work run `npm run dev` in app/frontend instead; it proxies /api and /ws
back here.

Run as a module, never `python app/run.py`: the latter puts app/ on sys.path instead of
the repo root, so the docket package import resolves wrong.
"""
from __future__ import annotations

import os
import sys

# 8765 because that is the callback URL a GitHub App is registered with — see
# interface/connect.py's docstring (http://127.0.0.1:8765/auth/callback). Serving the
# console anywhere else means the OAuth redirect lands on a port nothing is listening on.
# Not 5000/7000: macOS binds both to the AirPlay Receiver, so they look free until bind.
PORT = int(os.environ.get("DOCKET_CONSOLE_PORT", "8765"))


def main() -> int:
    from docket.interface.connect import serve
    from docket.utils.resource_paths import frontend_dir

    if not frontend_dir().is_dir():
        print("frontend not built. Run:\n  cd app/frontend && npm install && npm run build",
              file=sys.stderr)
        return 1
    # The same server `docket connect` runs — watcher, fix button, live PR timeline,
    # scan, session restore. Loopback only, always: this process can start a subprocess
    # that fires real exploit payloads and must never be reachable off this machine.
    return serve(port=PORT)


if __name__ == "__main__":
    sys.exit(main())
