"""Small, pure time helpers shared by the portfolio modules.

Kept separate so every module formats an instant the same way: the console compares
these strings and numbers across endpoints, and two spellings of "3 days" would show up
as two different facts.
"""
from __future__ import annotations

from datetime import datetime, timezone

DAY = 86400.0


def iso(epoch: float | None) -> str | None:
    """UTC ISO-8601 with a Z, or None. None in, None out: absent stays absent."""
    if epoch is None:
        return None
    return datetime.fromtimestamp(float(epoch), tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso(value: object) -> float | None:
    """Epoch seconds from an ISO-8601 string, or None when it is not one."""
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.timestamp()


def date(epoch: float | None) -> str | None:
    """UTC calendar date, "2026-10-19"; None in, None out."""
    if epoch is None:
        return None
    return datetime.fromtimestamp(float(epoch), tz=timezone.utc).strftime("%Y-%m-%d")


def short_date(epoch: float) -> str:
    """"5 Oct": day without a leading zero, then the month. Axis and tooltip wording."""
    d = datetime.fromtimestamp(float(epoch), tz=timezone.utc)
    return f"{d.day} {d:%b}"


def whole_days(seconds: float) -> int:
    """Floor to whole days, never negative (a clock a little ahead is not "-1 d")."""
    return max(0, int(seconds // DAY))


def ago(seconds: float) -> str:
    """"2 d" for a day or more, "5 h" for less, "now" under an hour."""
    if seconds >= DAY:
        return f"{int(seconds // DAY)} d"
    if seconds >= 3600:
        return f"{int(seconds // 3600)} h"
    return "now"


def demo() -> None:
    assert iso(None) is None
    assert iso(0) == "1970-01-01T00:00:00Z"
    assert parse_iso("1970-01-02T00:00:00Z") == DAY
    assert parse_iso("1970-01-02T00:00:00+00:00") == DAY
    assert parse_iso("not a date") is None and parse_iso(None) is None and parse_iso("") is None
    assert parse_iso("1970-01-02T00:00:00") == DAY  # naive reads as UTC, like report.json
    assert date(None) is None and date(DAY) == "1970-01-02" and short_date(DAY * 4) == "5 Jan"
    assert whole_days(-5) == 0 and whole_days(2.5 * DAY) == 2
    assert ago(2 * DAY + 1) == "2 d" and ago(7200) == "2 h" and ago(5) == "now"
    print("portfolio.timeutil: ok")


if __name__ == "__main__":
    demo()
