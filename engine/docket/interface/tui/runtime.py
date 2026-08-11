"""Runs a scan with the TUI attached.

The scan runs on a worker THREAD and the TUI owns the main thread, because Textual
needs the main thread for terminal I/O and the scan drives its own asyncio loop
(run_scan calls asyncio.run internally). They communicate only through the events file
— no shared objects, no locks — which is also why the same UI can replay a finished
run with nothing running at all.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass

from docket.config.settings import Config
from docket.core.runner import ScanResult, run_scan
from docket.interface.cli_args import EXIT_CLEAN, EXIT_ERROR, EXIT_FINDINGS
from docket.report.dedupe import FindingStore
from docket.report.writer import build_report, format_summary, write_report


@dataclass
class ScanThreadResult:
    result: ScanResult | None = None
    error: BaseException | None = None


def run_scan_in_thread(setup, config: Config, store: FindingStore, max_turns: int,
                        holder: ScanThreadResult) -> threading.Thread:
    def _target() -> None:
        try:
            holder.result = run_scan(
                target_url=setup.target,
                instruction=setup.instruction,
                on_finding=store.add,
                config=config,
                run_name=setup.run_name,
                use_sandbox=setup.use_sandbox,
                max_turns=max_turns,
                store=store,
            )
        except BaseException as exc:  # surfaced to the caller after the UI closes
            holder.error = exc

    thread = threading.Thread(target=_target, name="docket-scan", daemon=True)
    thread.start()
    return thread


def run_scan_with_tui(setup, config: Config, *, max_turns: int) -> int:
    from docket.interface.tui.live_view import DocketTUI

    store = FindingStore()
    holder = ScanThreadResult()
    thread = run_scan_in_thread(setup, config, store, max_turns, holder)

    DocketTUI(setup.run_dir, follow=True).run()

    # The UI is closable before the scan ends; wait so the report reflects the whole
    # run rather than whatever happened to be done when the user pressed q.
    if thread.is_alive():
        print("waiting for the scan to finish…")
        thread.join()

    if holder.error is not None:
        if len(store):
            write_report(store, setup.run_dir, run_name=setup.run_name, target=setup.target,
                         summary=f"scan failed: {holder.error}", success=False)
        print(f"error: scan failed: {holder.error}")
        return EXIT_ERROR

    result = holder.result
    kwargs = dict(run_name=setup.run_name, target=setup.target,
                  summary=result.summary if result else "",
                  cost_usd=result.cost_usd if result else 0.0,
                  agents_spawned=result.agents_spawned if result else 0,
                  success=bool(result and result.success))
    paths = write_report(store, setup.run_dir, **kwargs)
    print(format_summary(build_report(store, **kwargs), paths=paths))
    if not (result and result.success):
        return EXIT_ERROR
    return EXIT_FINDINGS if len(store) else EXIT_CLEAN


def demo() -> None:
    """Threading contract only — a live TUI needs a TTY."""
    import time

    holder = ScanThreadResult()

    class _Setup:
        target, instruction, run_name, use_sandbox = "http://x", None, "r", False

    # A scan that raises must land in holder.error rather than killing the process.
    # Patch THIS module's globals, not `import docket.interface.tui.runtime`: under
    # `python -m` this module is __main__, so importing by name would create a second
    # module object and patch a copy the worker thread never looks at.
    original = globals()["run_scan"]
    try:
        def _boom(**kwargs):
            raise RuntimeError("boom")

        globals()["run_scan"] = _boom
        thread = run_scan_in_thread(_Setup(), None, FindingStore(), 5, holder)
        thread.join(timeout=5)
        assert isinstance(holder.error, RuntimeError) and str(holder.error) == "boom"
        assert holder.result is None
    finally:
        globals()["run_scan"] = original
    assert (EXIT_CLEAN, EXIT_ERROR, EXIT_FINDINGS) == (0, 1, 2)
    time.sleep(0)
    print("tui.runtime: ok")


if __name__ == "__main__":
    demo()
