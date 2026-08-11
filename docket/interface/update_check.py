"""Version reporting. py in shape, not behaviour.

docket is an internal tool with no package index behind it, and a security tool making
an unexpected outbound request on startup is exactly the behaviour you would not want
to explain in a review — so the network check is OFF unless DOCKET_UPDATE_URL is set.
"""
from __future__ import annotations

import json
import os
import urllib.request

from docket import __version__

TIMEOUT_SEC = 3


def current_version() -> str:
    return __version__


def check_for_update(url: str | None = None, timeout: float = TIMEOUT_SEC) -> dict:
    """Returns {'checked': False} unless an update endpoint is configured."""
    endpoint = url or os.environ.get("DOCKET_UPDATE_URL")
    if not endpoint:
        return {"checked": False, "current": current_version(), "reason": "no DOCKET_UPDATE_URL configured"}
    try:
        with urllib.request.urlopen(endpoint, timeout=timeout) as response:
            data = json.loads(response.read() or b"{}")
        latest = str(data.get("version", "")).strip()
    except Exception as exc:
        # Never let a version check break a scan.
        return {"checked": False, "current": current_version(), "reason": f"{type(exc).__name__}: {exc}"}
    return {
        "checked": True, "current": current_version(), "latest": latest or None,
        "update_available": bool(latest) and latest != current_version(),
    }


def demo() -> None:
    saved = os.environ.pop("DOCKET_UPDATE_URL", None)
    try:
        result = check_for_update()
        assert result["checked"] is False and result["current"] == current_version()
        assert "no DOCKET_UPDATE_URL" in result["reason"]
        # An unreachable endpoint degrades quietly rather than raising.
        broken = check_for_update("http://127.0.0.1:9/nope", timeout=0.4)
        assert broken["checked"] is False and "reason" in broken
    finally:
        if saved is not None:
            os.environ["DOCKET_UPDATE_URL"] = saved
    print("interface.update_check: ok")


if __name__ == "__main__":
    demo()
