"""mitmproxy addon: append one JSON line per completed request/response pair.

Loaded by mitmdump inside the sandbox (see docket/tools/proxy/tools.py). Lives in the
docket package rather than containers/addons/ (where the original design put it) so the
Dockerfile's single `COPY engine/docket/` picks it up — one less COPY line, no path to
drift.

Hooking `response` rather than `request` means both halves of the exchange are already
populated, so one hook yields a complete record.
"""
from __future__ import annotations

import json
import os
import time
import uuid
from pathlib import Path

from docket.utils.secret_files import redact

RUN_DIR = Path(os.environ.get("DOCKET_RUN_DIR", "/work/run"))
FLOWS_PATH = RUN_DIR / "artifacts" / "proxy_flows.jsonl"
MAX_BODY_CHARS = 4000


def _text(message) -> str:
    try:
        return (message.get_text(strict=False) or "")[:MAX_BODY_CHARS]
    except Exception:
        return ""


def response(flow) -> None:  # mitmproxy calls this by name
    record = {
        "id": uuid.uuid4().hex[:12],
        "ts": time.time(),
        "method": flow.request.method,
        "url": flow.request.pretty_url,
        "req_headers": dict(flow.request.headers),
        "req_body": _text(flow.request),
        "status": flow.response.status_code,
        "resp_headers": dict(flow.response.headers),
        "resp_body": _text(flow.response),
    }
    FLOWS_PATH.parent.mkdir(parents=True, exist_ok=True)
    with FLOWS_PATH.open("a") as handle:
        # Redacted like report.json/report.sarif. This file is the worst offender by
        # volume: it records EVERY request/response pair the proxy sees, headers included,
        # so a single authenticated crawl writes the target's session cookie and bearer
        # token to disk hundreds of times. redact() is stdlib-only (`re`), which keeps this
        # module importable by mitmdump inside the container.
        handle.write(redact(json.dumps(record)) + "\n")
