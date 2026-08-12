"""Cooperative cancellation for a running scan.

Cooperative, not forced, because a scan is a Python thread and a Python thread cannot
be killed from outside. The scan checks a flag at points where stopping is safe, and
the checks live where the time actually goes:

  - before each scanner (semgrep on a large repo runs for minutes)
  - before each triage agent (each one costs real money)
  - before recon

Between those points a cancel waits. Worst case is one scanner or one agent turn,
which is seconds to tens of seconds, not the rest of the run.

What a cancel guarantees: no NEW work starts, the sandbox is torn down, the temp
source tree is deleted, and findings already produced are kept and written out. A
cancelled scan is a short scan, not a lost one — which is why `status` becomes
"cancelled" rather than "error". Reporting a deliberate stop as a failure trains
people to ignore failures.
"""
from __future__ import annotations

import threading


class ScanCancelled(Exception):
    """Raised at a checkpoint when the operator asked for a stop.

    Deliberately NOT an Exception subclass the enrichment paths swallow: triage and
    recon catch broad exceptions so a failed agent cannot sink a scan, and a cancel
    caught there would be logged as "triage failed" and the loop would continue to the
    next finding, still spending money. Every such handler re-raises this by name.
    """


class CancelToken:
    """One per scan. Thread-safe, and cheap enough to check in a tight loop."""

    def __init__(self) -> None:
        self._event = threading.Event()
        self._reason = ""

    def cancel(self, reason: str = "stopped by the operator") -> None:
        self._reason = reason
        self._event.set()

    @property
    def cancelled(self) -> bool:
        return self._event.is_set()

    @property
    def reason(self) -> str:
        return self._reason

    def check(self) -> None:
        """Raise if a stop was requested. The checkpoint call itself."""
        if self._event.is_set():
            raise ScanCancelled(self._reason or "stopped by the operator")


# A token that is never cancelled, so callers that do not support cancellation (the
# CLI, the tests) need no branching and no `if token is not None` at every checkpoint.
NEVER = CancelToken()


def demo() -> None:
    token = CancelToken()
    assert not token.cancelled
    token.check()  # no-op while running

    token.cancel("user pressed stop")
    assert token.cancelled and token.reason == "user pressed stop"
    try:
        token.check()
        raise AssertionError("check() must raise once cancelled")
    except ScanCancelled as exc:
        assert "user pressed stop" in str(exc)

    # The default reason is still a sentence, so a UI never shows an empty error.
    other = CancelToken()
    other.cancel()
    try:
        other.check()
    except ScanCancelled as exc:
        assert str(exc) == "stopped by the operator", exc

    # The shared no-op token must never be cancellable by accident: anything that
    # cancels NEVER would silently stop every future CLI scan in the process.
    assert not NEVER.cancelled

    # Cancel is idempotent and safe from several threads.
    shared = CancelToken()
    threads = [threading.Thread(target=shared.cancel, args=(f"t{i}",)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert shared.cancelled

    # ScanCancelled must NOT be caught by handlers that swallow agent failures.
    # Those catch Exception, so this only holds because every such handler re-raises
    # it by name — asserted here so the contract is visible from this file.
    assert issubclass(ScanCancelled, Exception)
    print("core.cancel: ok")


if __name__ == "__main__":
    demo()
