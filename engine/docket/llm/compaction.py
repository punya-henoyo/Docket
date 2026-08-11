"""Provider-agnostic conversation compaction.

When an agent's history grows past the model's usable window, older turns are folded
into a single summary checkpoint while the most recent turns are kept verbatim.

The subtle part is not the summarising, it's the trimming: a `function_call` item and
its matching `function_call_output` MUST stay together. Cutting between them leaves an
orphan the provider rejects — so a naive "keep the last N items" slice can turn a
context-overflow error into a permanent 400 that never recovers. `split_preserving_pairs`
is the piece that prevents that.

Deliberately keeps a SECURITY-focused summary (targets probed, payloads tried, findings
confirmed) rather than a generic one: those are the facts an agent needs to avoid
re-running work it already did.
"""
from __future__ import annotations

import logging
from typing import Any

from docket.llm.context_budget import estimate_tokens, over_budget, usable_tokens

logger = logging.getLogger(__name__)

# Turns kept verbatim at the tail. Enough to preserve the agent's immediate train of
# thought (a probe, its result, the follow-up) without keeping the whole run.
KEEP_RECENT_ITEMS = 12

SUMMARY_MARKER = "[compacted-history]"


def _item_type(item: Any) -> str:
    return item.get("type", "") if isinstance(item, dict) else ""


def _call_id(item: Any) -> str | None:
    return item.get("call_id") if isinstance(item, dict) else None


def split_preserving_pairs(items: list[Any], keep_recent: int = KEEP_RECENT_ITEMS) -> tuple[list[Any], list[Any]]:
    """Split into (older, recent) without ever separating a function_call from its
    function_call_output. Moves the boundary EARLIER until the tail is self-contained."""
    if len(items) <= keep_recent:
        return [], list(items)

    boundary = len(items) - keep_recent
    # Any tool output in the tail whose call is older drags the boundary back.
    while boundary > 0:
        tail = items[boundary:]
        call_ids = {_call_id(i) for i in tail if _item_type(i) == "function_call"}
        orphans = [
            i for i in tail
            if _item_type(i) == "function_call_output" and _call_id(i) not in call_ids
        ]
        if not orphans:
            break
        boundary -= 1
    return items[:boundary], items[boundary:]


def summarize_items(items: list[Any]) -> str:
    """Structured, security-focused digest of the turns being dropped.

    Built by inspection rather than by asking the model: a summarisation call costs
    money and latency on every compaction, and for this purpose the mechanical facts
    (which tools ran, against what, with what result) are what matters.
    """
    tool_calls: list[str] = []
    findings: list[str] = []
    for item in items:
        kind = _item_type(item)
        if kind == "function_call":
            name = item.get("name", "?")
            args = str(item.get("arguments", ""))[:160]
            tool_calls.append(f"- {name}({args})")
            if name == "finding":
                findings.append(args)
        elif kind == "function_call_output" and "finding_id" in str(item.get("output", "")):
            findings.append(str(item.get("output"))[:160])

    lines = [
        f"{SUMMARY_MARKER} {len(items)} earlier item(s) were summarised to stay within "
        f"the model's context window.",
        "",
        f"Tool calls already made ({len(tool_calls)}) — do NOT repeat work already done:",
        *tool_calls[-40:],
    ]
    if findings:
        lines += ["", f"Findings already registered ({len(findings)}):", *findings[-10:]]
    return "\n".join(lines)


def compact(items: list[Any], model: str, *, keep_recent: int = KEEP_RECENT_ITEMS) -> tuple[list[Any], bool]:
    """Return (items, compacted). No-op when the history already fits."""
    if not over_budget(model, items):
        return items, False

    older, recent = split_preserving_pairs(items, keep_recent)
    if not older:
        # Everything is "recent" and it still doesn't fit — nothing safe to drop.
        logger.warning("history over budget but no separable older turns to compact")
        return items, False

    checkpoint = {"role": "user", "content": summarize_items(older)}
    compacted = [checkpoint, *recent]
    logger.info(
        "compacted %d items -> %d (est. %d -> %d tokens, budget %d)",
        len(items), len(compacted), estimate_tokens(items), estimate_tokens(compacted),
        usable_tokens(model),
    )
    return compacted, True


def demo() -> None:
    def call(cid: str, name: str = "http_request") -> dict:
        return {"type": "function_call", "call_id": cid, "name": name, "arguments": "{}"}

    def out(cid: str, payload: str = "{}") -> dict:
        return {"type": "function_call_output", "call_id": cid, "output": payload}

    # Pairing: a boundary that would orphan an output moves earlier.
    items = [{"role": "user", "content": "start"}, call("a"), out("a"), call("b"), out("b")]
    older, recent = split_preserving_pairs(items, keep_recent=2)
    assert all(_call_id(i) != "b" or _item_type(i) != "function_call_output"
               or any(_item_type(j) == "function_call" and _call_id(j) == "b" for j in recent)
               for i in recent), recent
    assert older + recent == items

    # A naive slice here would keep out("b") without call("b"); ours must not.
    tricky = [call("a"), out("a"), call("b"), out("b")]
    _, recent2 = split_preserving_pairs(tricky, keep_recent=1)
    ids = {_call_id(i) for i in recent2 if _item_type(i) == "function_call"}
    for i in recent2:
        if _item_type(i) == "function_call_output":
            assert _call_id(i) in ids, f"orphaned tool output in tail: {recent2}"

    # Short history is untouched.
    short = [{"role": "user", "content": "hi"}]
    assert compact(short, "openai/gpt-4o") == (short, False)

    # Oversized history compacts, keeps the tail, and records what was dropped.
    big = [{"role": "user", "content": "x" * 5000} for _ in range(200)]
    big += [call("z", "finding"), out("z", '{"finding_id": "abc123"}')]
    compacted, did = compact(big, "openai/gpt-4o")
    assert did is True
    assert len(compacted) < len(big)
    assert SUMMARY_MARKER in compacted[0]["content"]
    assert "finding" in compacted[0]["content"] or "finding" in str(compacted)
    assert compacted[-1] == big[-1], "most recent turn must survive verbatim"
    print("llm.compaction: ok")


if __name__ == "__main__":
    demo()
