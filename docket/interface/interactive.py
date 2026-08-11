"""Interactive mode: stream a scan's progress and show findings as they land.
Mirrors docket/interface/interactive.py.

Deliberately NOT the TUI. This is the plain-stdout path for a normal `docket scan` —
it works over SSH, in a dumb terminal, and when piped to a file. The Textual TUI
(--tui) is the richer alternative, not a replacement for this.

The mechanism is the on_finding callback the runner already accepts, so live progress
costs no extra plumbing inside the agent loop.
"""
from __future__ import annotations

import sys
import threading
import time
from collections.abc import Callable

from docket.interface.utils import bold, color_enabled, colorize, human_duration, truncate
from docket.report.models import Finding
from docket.report.state import get_global_report_state


class ProgressReporter:
    """Prints findings as agents confirm them, plus a periodic heartbeat so a long
    quiet stretch doesn't look like a hang."""

    def __init__(self, *, stream=None, heartbeat_sec: float = 30.0, quiet: bool = False) -> None:
        self.stream = stream or sys.stderr  # stderr: stdout stays clean for the report
        self.quiet = quiet
        self.heartbeat_sec = heartbeat_sec
        self.started = time.monotonic()
        self.count = 0
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._color = color_enabled(self.stream)

    def on_finding(self, finding: Finding) -> None:
        self.count += 1
        if self.quiet:
            return
        severity = finding.severity.value
        tag = colorize(f"[{severity.upper()}]", severity, enabled=self._color)
        param = f" ({finding.location.parameter})" if finding.location.parameter else ""
        self._write(
            f"{tag} {bold(finding.rule_id, enabled=self._color)} "
            f"{finding.location.method} {finding.location.path}{param} "
            f"— by {finding.discovered_by}"
        )

    def _write(self, line: str) -> None:
        print(line, file=self.stream, flush=True)

    def _heartbeat_loop(self) -> None:
        while not self._stop.wait(self.heartbeat_sec):
            state = get_global_report_state()
            elapsed = human_duration(time.monotonic() - self.started)
            spend = f", ${state.spent_usd:.4f}" if state.spent_usd else ""
            self._write(f"  … {elapsed} elapsed, {self.count} finding(s) so far{spend}")

    def start(self) -> "ProgressReporter":
        if not self.quiet and self.heartbeat_sec > 0:
            self._thread = threading.Thread(target=self._heartbeat_loop, daemon=True)
            self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=1)

    def __enter__(self) -> "ProgressReporter":
        return self.start()

    def __exit__(self, *exc_info) -> None:
        self.stop()


def make_on_finding(
    store_add: Callable[[Finding], None], reporter: ProgressReporter | None,
) -> Callable[[Finding], None]:
    """Compose store.add with live reporting — the runner takes exactly one callback."""
    if reporter is None:
        return store_add

    def _combined(finding: Finding) -> None:
        store_add(finding)
        reporter.on_finding(finding)

    return _combined


def demo() -> None:
    import io

    from docket.report.dedupe import FindingStore
    from docket.report.models import Location, PoC, Severity

    finding = Finding(
        rule_id="sql-injection", title="SQLi", severity=Severity.HIGH,
        location=Location(method="POST", path="/login", parameter="username"),
        description="d", poc=PoC(request="r", response="p"), discovered_by="sqli",
    )

    buffer = io.StringIO()
    reporter = ProgressReporter(stream=buffer, heartbeat_sec=0)
    store = FindingStore()
    callback = make_on_finding(store.add, reporter)
    callback(finding)
    output = buffer.getvalue()
    assert "[HIGH]" in output and "sql-injection" in output and "by sqli" in output, output
    assert len(store) == 1 and reporter.count == 1

    # Quiet mode still counts and still stores, it just doesn't print.
    quiet_buf = io.StringIO()
    quiet = ProgressReporter(stream=quiet_buf, heartbeat_sec=0, quiet=True)
    make_on_finding(FindingStore().add, quiet)(finding)
    assert quiet_buf.getvalue() == "" and quiet.count == 1

    # No reporter -> the store callback is returned unchanged. (Compared against a
    # captured reference: `store.add is store.add` is False in Python, since attribute
    # access creates a fresh bound method each time.)
    plain_store = FindingStore()
    add = plain_store.add
    assert make_on_finding(add, None) is add
    assert truncate("x") == "x"
    print("interface.interactive: ok")


if __name__ == "__main__":
    demo()
