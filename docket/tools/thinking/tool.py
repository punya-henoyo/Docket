"""The `thinking` tool: an explicit reasoning scratchpad.

Returns essentially nothing — that is the entire design. Its value is that calling it
forces the model to externalise a plan as a tool call, which (a) lands in the
transcript where the TUI/viewer and a human reviewer can see the reasoning behind a
payload choice, and (b) gives the model a place to deliberate that is not "emit a
final answer". It performs no action, touches no target, and cannot fail.
"""
from __future__ import annotations


def think(thought: str) -> dict:
    return {"ok": True, "recorded": len(thought)}


def demo() -> None:
    result = think("I'll try a quote-break payload before anything time-based.")
    assert result["ok"] is True and result["recorded"] > 0
    assert think("")["recorded"] == 0
    print("tools.thinking: ok")


if __name__ == "__main__":
    demo()
