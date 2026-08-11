"""Local logging setup. No analytics, no network — see README.md.

Off by default: a scan's user-facing output is the report and the progress stream, and
library-level debug logs interleaved with those would just be noise. Set
DOCKET_LOG_LEVEL=debug to turn it on when something misbehaves.
"""
from __future__ import annotations

import logging
import os
import sys

_LEVELS = {"critical": logging.CRITICAL, "error": logging.ERROR, "warning": logging.WARNING,
           "info": logging.INFO, "debug": logging.DEBUG}
DEFAULT_LEVEL = "warning"
_configured = False


def resolve_level(name: str | None = None) -> int:
    raw = (name or os.environ.get("DOCKET_LOG_LEVEL") or DEFAULT_LEVEL).strip().lower()
    return _LEVELS.get(raw, logging.WARNING)


def configure_logging(level: str | None = None, *, force: bool = False) -> int:
    """Attach one stderr handler to the `docket` logger. stderr, not stdout, so logs
    never contaminate a piped report."""
    global _configured
    resolved = resolve_level(level)
    logger = logging.getLogger("docket")
    if _configured and not force:
        logger.setLevel(resolved)
        return resolved
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))
    logger.addHandler(handler)
    logger.setLevel(resolved)
    logger.propagate = False  # don't double-print through the root logger
    _configured = True
    return resolved


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name if name.startswith("docket") else f"docket.{name}")


def demo() -> None:
    saved = os.environ.pop("DOCKET_LOG_LEVEL", None)
    try:
        assert resolve_level() == logging.WARNING           # quiet by default
        assert resolve_level("debug") == logging.DEBUG
        assert resolve_level("nonsense") == logging.WARNING  # unknown -> safe default
        os.environ["DOCKET_LOG_LEVEL"] = "info"
        assert resolve_level() == logging.INFO

        assert configure_logging("debug", force=True) == logging.DEBUG
        logger = logging.getLogger("docket")
        assert len(logger.handlers) == 1 and logger.propagate is False
        configure_logging("debug", force=True)
        assert len(logger.handlers) == 1, "reconfiguring must not stack handlers"
        assert get_logger("core.runner").name == "docket.core.runner"
        assert get_logger("docket.x").name == "docket.x"
    finally:
        if saved is not None:
            os.environ["DOCKET_LOG_LEVEL"] = saved
        else:
            os.environ.pop("DOCKET_LOG_LEVEL", None)
    print("telemetry.logging: ok")


if __name__ == "__main__":
    demo()
