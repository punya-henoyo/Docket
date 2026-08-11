"""Shared terminal-output helpers for the CLI. """
from __future__ import annotations

import os
import sys

_SEVERITY_COLORS = {
    "critical": "\033[95m", "high": "\033[91m", "medium": "\033[93m",
    "low": "\033[94m", "info": "\033[90m",
}
_RESET = "\033[0m"
_BOLD = "\033[1m"


def color_enabled(stream=None) -> bool:
    """Honour NO_COLOR and non-TTY output — colour codes in a piped report or a CI
    log are noise, not formatting."""
    if os.environ.get("NO_COLOR"):
        return False
    stream = stream or sys.stdout
    return hasattr(stream, "isatty") and stream.isatty()


def colorize(text: str, severity: str, *, enabled: bool | None = None) -> str:
    if enabled is None:
        enabled = color_enabled()
    if not enabled:
        return text
    return f"{_SEVERITY_COLORS.get(severity.lower(), '')}{text}{_RESET}"


def bold(text: str, *, enabled: bool | None = None) -> str:
    if enabled is None:
        enabled = color_enabled()
    return f"{_BOLD}{text}{_RESET}" if enabled else text


def truncate(text: str, limit: int = 120) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def human_duration(seconds: float) -> str:
    if seconds < 1:
        return f"{int(seconds * 1000)}ms"
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes, secs = divmod(int(seconds), 60)
    return f"{minutes}m{secs:02d}s"


def demo() -> None:
    assert colorize("x", "high", enabled=False) == "x"
    assert colorize("x", "high", enabled=True).startswith("\033[91m")
    assert colorize("x", "nonsense", enabled=True).endswith(_RESET)
    assert bold("x", enabled=False) == "x"
    assert truncate("a b   c") == "a b c"
    assert truncate("x" * 200).endswith("…") and len(truncate("x" * 200)) == 120
    assert human_duration(0.25) == "250ms"
    assert human_duration(3.14) == "3.1s"
    assert human_duration(125) == "2m05s"
    os.environ["NO_COLOR"] = "1"
    assert color_enabled() is False
    del os.environ["NO_COLOR"]
    print("interface.utils: ok")


if __name__ == "__main__":
    demo()
