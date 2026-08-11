"""The live terminal UI.

Built in Textual so the whole front-end stays in one language and one process — no
separate UI toolchain and no protocol bridge. The backend split
(protocol/projection/messages) exists because it is what lets the web viewer render
the same run from the same events.

Reads <run>/events.jsonl incrementally, so it works equally as a live monitor during a
scan and as a replay of a finished one.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.reactive import reactive
from textual.widgets import DataTable, Footer, Header, RichLog, Static, Tree

from docket.interface.tui.backend.projection import ScanView, project
from docket.interface.tui.backend.protocol import read_events
from docket.interface.utils import truncate

REFRESH_SEC = 0.5

_STATUS_STYLE = {
    "running": "bold yellow", "pending": "dim",
    "completed": "bold green", "failed": "bold red",
    "crashed": "bold red", "stopped": "dim red",
}
_SEVERITY_STYLE = {
    "critical": "bold magenta", "high": "bold red", "medium": "yellow",
    "low": "cyan", "info": "dim",
}


class SummaryBar(Static):
    """Target, elapsed cost/tokens, and live counts."""

    def update_view(self, view: ScanView) -> None:
        counts = view.severity_counts()
        severities = "  ".join(
            f"[{_SEVERITY_STYLE.get(s, '')}]{n} {s}[/]" for s, n in counts.items()
        ) or "[dim]no findings yet[/]"
        state = "[bold green]finished[/]" if view.finished else "[bold yellow]running[/]"
        self.update(
            f"[bold]{view.target or '(target)'}[/]  {state}\n"
            f"{severities}\n"
            f"[dim]{len(view.agents)} agents · {view.tokens:,} tokens · "
            f"${view.cost_usd:.4f}[/]"
        )


class DocketTUI(App):
    """Live view of a scan: agent tree, findings table, and a transcript."""

    CSS = """
    Screen { layout: vertical; }
    #top { height: 9; }
    #summary { width: 40%; border: round $accent; padding: 0 1; }
    #agents { width: 60%; border: round $accent; }
    #middle { height: 1fr; }
    #findings { width: 50%; border: round $accent; }
    #transcript { width: 50%; border: round $accent; }
    """
    BINDINGS = [("q", "quit", "Quit"), ("r", "refresh", "Refresh")]

    view: reactive[ScanView] = reactive(ScanView, always_update=True)

    def __init__(self, run_dir: Path, follow: bool = True) -> None:
        super().__init__()
        self.run_dir = Path(run_dir)
        self.follow = follow
        self._offset = 0
        self._view = ScanView()
        self._seen_transcript = 0

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal(id="top"):
            yield SummaryBar(id="summary")
            yield Tree("agents", id="agents")
        with Horizontal(id="middle"):
            yield DataTable(id="findings")
            yield RichLog(id="transcript", wrap=True, markup=True, highlight=False)
        yield Footer()

    def on_mount(self) -> None:
        self.title = "docket"
        self.sub_title = self.run_dir.name
        table = self.query_one("#findings", DataTable)
        table.add_columns("sev", "rule", "route", "param")
        table.cursor_type = "row"
        self.refresh_events()
        if self.follow:
            self.set_interval(REFRESH_SEC, self.refresh_events)

    def action_refresh(self) -> None:
        self.refresh_events()

    def refresh_events(self) -> None:
        events, self._offset = read_events(self.run_dir, self._offset)
        if not events:
            return
        project(events, self._view)
        self._render()

    # -- rendering ---------------------------------------------------------------

    def _render(self) -> None:
        view = self._view
        self.query_one("#summary", SummaryBar).update_view(view)

        tree = self.query_one("#agents", Tree)
        tree.clear()
        nodes: dict[str, Any] = {}
        for depth, agent in view.tree():
            style = _STATUS_STYLE.get(agent.status, "")
            label = (
                f"[{style}]{agent.name or agent.agent_id}[/] "
                f"[dim]{agent.role} · {agent.status} · {agent.tool_calls} calls · "
                f"{agent.findings} findings[/]"
            )
            parent = nodes.get(agent.parent_id) if depth else tree.root
            node = (parent or tree.root).add(label, expand=True)
            nodes[agent.agent_id] = node
        tree.root.expand()

        table = self.query_one("#findings", DataTable)
        table.clear()
        for finding in view.findings:
            severity = finding.get("severity", "info")
            location = finding.get("location") or {}
            table.add_row(
                f"[{_SEVERITY_STYLE.get(severity, '')}]{severity}[/]",
                finding.get("rule_id", finding.get("rule_type", "?")),
                f"{location.get('method', '')} {location.get('path', '')}".strip() or "-",
                location.get("parameter", "") or "-",
            )

        # Append only what's new, so the transcript scrolls rather than redrawing.
        log = self.query_one("#transcript", RichLog)
        for entry in view.transcript[self._seen_transcript:]:
            arrow = "→" if entry["kind"] == "call" else "←"
            body = (truncate(str(entry.get("args", "")), 90) if entry["kind"] == "call"
                    else truncate(str(entry.get("output", "")), 90))
            log.write(f"[dim]{entry['agent_id']}[/] {arrow} [bold]{entry['tool']}[/] {body}")
        self._seen_transcript = len(view.transcript)


def run_tui(run_dir: Path, follow: bool = True) -> None:
    DocketTUI(run_dir, follow=follow).run()


def demo() -> None:
    """Headless check: the app constructs and projects events without a terminal.
    Driving the real UI needs a TTY, so rendering is covered by Textual itself."""
    import shutil
    import tempfile

    from docket.interface.tui.backend.protocol import Event, append_event

    tmp = Path(tempfile.mkdtemp())
    try:
        append_event(tmp, Event(type="scan_started", data={"target": "http://x", "run_name": "r"}))
        append_event(tmp, Event(type="agent_spawned", agent_id="a1", role="sqli",
                                 data={"name": "sqli-login", "parent_id": "root"}))
        append_event(tmp, Event(type="finding", agent_id="a1", role="sqli", data={
            "rule_id": "sql-injection", "severity": "high",
            "location": {"method": "POST", "path": "/login", "parameter": "username"},
        }))
        app = DocketTUI(tmp, follow=False)
        events, app._offset = read_events(tmp, 0)
        project(events, app._view)
        assert app._view.target == "http://x"
        assert len(app._view.findings) == 1
        assert {a.agent_id for a in app._view.agents.values()} == {"root", "a1"}
        assert app._view.severity_counts() == {"high": 1}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print("tui.live_view: ok")


if __name__ == "__main__":
    demo()
