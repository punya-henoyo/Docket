"""Global report state. Mirrors docket/report/state.py.

A process-wide handle on the current run's findings and budget, so components that
the run loop can't hand a reference to — SDK hooks fire deep inside Runner.run, the
in-process tool wrappers, the TUI/viewer readers — can still see live scan state
without threading a parameter through every call site.

Deliberately a module-level singleton rather than a passed dependency: one process
runs exactly one scan (docket/interface/main.py), so there is nothing to isolate
between, and the SDK's hook signatures give us nowhere to inject it.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from docket.report.dedupe import FindingStore


@dataclass
class ReportState:
    run_name: str = ""
    target: str = ""
    run_dir: Path | None = None
    store: "FindingStore | None" = None
    budget_usd: float = 0.0
    spent_usd: float = 0.0
    # Warning bands already emitted, so a crossing is announced once, not every turn.
    warned_stages: set[str] = field(default_factory=set)

    @property
    def budget_fraction(self) -> float:
        if not self.budget_usd:
            return 0.0
        return self.spent_usd / self.budget_usd

    def finding_count(self) -> int:
        return len(self.store) if self.store is not None else 0


_lock = threading.Lock()
_state = ReportState()


def get_global_report_state() -> ReportState:
    return _state


def init_report_state(
    *, run_name: str, target: str, run_dir: Path, store: "FindingStore", budget_usd: float,
) -> ReportState:
    with _lock:
        _state.run_name = run_name
        _state.target = target
        _state.run_dir = run_dir
        _state.store = store
        _state.budget_usd = budget_usd
        _state.spent_usd = 0.0
        _state.warned_stages = set()
    return _state


def record_spend(usd: float) -> float:
    with _lock:
        _state.spent_usd += usd
        return _state.spent_usd


def mark_warned(stage: str) -> bool:
    """True the FIRST time `stage` is seen; False after. Keeps a crossed threshold
    from re-announcing itself on every subsequent turn."""
    with _lock:
        if stage in _state.warned_stages:
            return False
        _state.warned_stages.add(stage)
        return True


def reset_report_state() -> None:
    with _lock:
        _state.run_name = ""
        _state.target = ""
        _state.run_dir = None
        _state.store = None
        _state.budget_usd = 0.0
        _state.spent_usd = 0.0
        _state.warned_stages = set()


def demo() -> None:
    from docket.report.dedupe import FindingStore

    reset_report_state()
    store = FindingStore()
    state = init_report_state(
        run_name="r", target="http://x", run_dir=Path("/tmp"), store=store, budget_usd=2.0,
    )
    assert get_global_report_state() is state
    assert state.finding_count() == 0
    assert record_spend(0.5) == 0.5
    assert abs(state.budget_fraction - 0.25) < 1e-9
    assert mark_warned("NOTICE") is True
    assert mark_warned("NOTICE") is False  # announced once only
    reset_report_state()
    assert get_global_report_state().budget_usd == 0.0
    print("report.state: ok")


if __name__ == "__main__":
    demo()
