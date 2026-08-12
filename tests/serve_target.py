"""Run the intentionally-vulnerable test fixture as a standalone server.

The fixture is normally started in-process by the test suite on an ephemeral port.
This is the way to get it on a fixed port so `docket scan` can be pointed at it.

    uv run python tests/serve_target.py [port]     # default 8000

Port 5000 is deliberately not the default: macOS binds it to the AirPlay Receiver
(ControlCenter) out of the box, so it looks free until the bind fails.
"""
import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fixtures.target_app import SEEDED_USER, start_target

url, _server, base_dir = start_target(int(sys.argv[1]) if len(sys.argv) > 1 else 8000)
print(f"target : {url}")
print(f"login  : {SEEDED_USER[0]} / {SEEDED_USER[1]}")
print(f"data   : {base_dir}")
print("ctrl-c to stop")
threading.Event().wait()
