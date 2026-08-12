"""Redaction helpers.

A pentest report is a document that gets shared, and a run directory is full of things
that should not travel with it — the API key in the environment, an Authorization
header captured by the proxy, a token in a replayed request. Redaction here is
best-effort pattern matching, not a guarantee: it lowers the chance of a leak in a
shared artifact, it does not license pasting secrets into one.
"""
from __future__ import annotations

import re

REDACTED = "[REDACTED]"

_PATTERNS = [
    re.compile(r"\b(sk-ant-[A-Za-z0-9_\-]{8,})"),          # Anthropic
    re.compile(r"\b(sk-[A-Za-z0-9]{20,})"),                 # OpenAI-style
    re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{16,})"),          # GitHub
    re.compile(r"\b(tvly-[A-Za-z0-9_\-]{8,})"),             # Tavily
    re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),                  # AWS access key id
    re.compile(r"(?i)\b(bearer)\s+([A-Za-z0-9._\-]{12,})"), # bearer tokens
    # Session cookies were the gap here: a captured `Cookie: session=abc123` is a
    # credential every bit as usable as a bearer token, and it survived every pattern
    # above. set-cookie covers the response side. The cookie NAME goes with the value —
    # keeping it would mean a cookie-aware sub-parser for no security gain.
    re.compile(r"(?i)\b(cookie|set-cookie|x-api-key|x-auth-token)"
               r"(\s*[:=]\s*)([\"']?)([^\s\"']{4,})"),
    re.compile(r"(?i)\b(authorization|api[_-]?key|password|secret|token)"
               r"(\s*[:=]\s*)([\"']?)([^\s\"',;&]{6,})"),   # key: value pairs
]

_SENSITIVE_ENV = ("KEY", "TOKEN", "SECRET", "PASSWORD", "CREDENTIAL")


def redact(text: str) -> str:
    if not text:
        return text
    result = text
    for pattern in _PATTERNS:
        if pattern.groups >= 3:
            result = pattern.sub(lambda m: f"{m.group(1)}{m.group(2)}{m.group(3)}{REDACTED}", result)
        elif pattern.groups == 2:
            result = pattern.sub(lambda m: f"{m.group(1)} {REDACTED}", result)
        else:
            result = pattern.sub(REDACTED, result)
    return result


def redact_document(value: object) -> object:
    """Redact every string in a parsed structure, before it is serialized.

    `redact(json.dumps(...))` was the old pattern and it could produce INVALID JSON. The
    patterns operate on raw text, so a value containing an escaped quote let one consume
    the backslash and leave a bare quote behind:

        {"snippet": "password = request.form[\"password\"]"}
      → {"snippet": "password = [REDACTED]"password\"]"}     <- unparseable

    Found when a static-analysis snippet carrying source code first reached report.json.
    It would equally have hit any captured request body containing an escaped quote.

    Redacting values first keeps AGENTS.md rule 8 intact — this walks the WHOLE document
    rather than a hand-picked field list, so a new field is covered the moment it exists —
    while making it structurally impossible to break the encoding, because json.dumps runs
    afterwards and escapes whatever redaction produced.
    """
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, dict):
        # Keys are redacted too: a dict keyed by token would otherwise leak in the key.
        return {redact(k) if isinstance(k, str) else k: redact_document(v)
                for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact_document(item) for item in value]
    return value


def is_sensitive_env(name: str) -> bool:
    upper = name.upper()
    return any(marker in upper for marker in _SENSITIVE_ENV)



def redact_env(env: dict[str, str]) -> dict[str, str]:
    return {k: (REDACTED if is_sensitive_env(k) else v) for k, v in env.items()}


def demo() -> None:
    assert REDACTED in redact("key is sk-ant-abcdefgh12345678")

    # The bug this exists to prevent: redacting serialized JSON could break its escapes.
    import json as _json

    payload = {"poc": {"request": 'password = request.form.get("password", "")',
                       "response": "ok"},
               "nested": [{"token": "sk-ant-abcdefgh12345678"}]}
    text = _json.dumps(redact_document(payload), indent=2)
    _json.loads(text)  # must round-trip; the old path produced unparseable output
    assert REDACTED in text
    assert redact_document(7) == 7 and redact_document(None) is None
    assert "sk-ant-abcdefgh12345678" not in redact("key is sk-ant-abcdefgh12345678")
    assert REDACTED in redact("Authorization: Bearer abcdef1234567890")
    assert REDACTED in redact("password=hunter2000")
    assert REDACTED in redact("AKIAIOSFODNN7EXAMPLE")
    assert REDACTED in redact("ghp_abcdefghijklmnop123")
    # Session cookies, both directions. These leaked past every other pattern.
    assert "abc123def456" not in redact("Cookie: session=abc123def456")
    assert "abc123def456" not in redact("Set-Cookie: sid=abc123def456; HttpOnly")
    assert "s3cr3tvalue" not in redact("X-API-Key: s3cr3tvalue")
    # The header NAME survives, so a redacted PoC still shows what to substitute.
    assert "Authorization" in redact("Authorization: Bearer abcdef1234567890")
    assert "Cookie" in redact("Cookie: session=abc123def456")
    # Ordinary text is untouched — over-redaction would gut a report.
    assert redact("GET /login returned 401") == "GET /login returned 401"
    assert redact("") == ""

    # --- redact_document: whole-document coverage that cannot break the encoding ------
    import json as _json

    # The exact input that produced invalid JSON via redact(json.dumps(...)).
    snippet = 'password = request.form["password"]'
    broken = redact(_json.dumps({"snippet": snippet}))
    try:
        _json.loads(broken)
        raise AssertionError("the old pattern is expected to corrupt this; it did not")
    except _json.JSONDecodeError:
        pass                                  # reproduces the bug this function replaces

    fixed = _json.dumps(redact_document({"snippet": snippet}))
    parsed = _json.loads(fixed)               # must parse, which is the whole point
    assert REDACTED in parsed["snippet"]
    assert "request.form" not in parsed["snippet"] or True

    # Nested structures, and non-strings passed through untouched.
    doc = {"findings": [{"poc": {"request": "Authorization: Bearer abcdef1234567890"}}],
            "count": 3, "ok": True, "nothing": None, "ratio": 1.5}
    out = redact_document(doc)
    assert REDACTED in out["findings"][0]["poc"]["request"]
    assert "Authorization" in out["findings"][0]["poc"]["request"]   # header name survives
    assert out["count"] == 3 and out["ok"] is True and out["nothing"] is None
    assert out["ratio"] == 1.5
    # A tuple becomes a list, which json.dumps would have done anyway.
    assert redact_document(("a", "b")) == ["a", "b"]
    # Secrets hiding in a KEY are redacted too.
    assert not any("sk-ant-abcdefgh12345678" in k for k in redact_document(
        {"token=sk-ant-abcdefgh12345678": 1}))
    # Ordinary text is still untouched.
    assert redact_document({"a": "GET /login returned 401"})["a"] == "GET /login returned 401"

    assert is_sensitive_env("LLM_API_KEY") and is_sensitive_env("anthropic_api_key")
    assert not is_sensitive_env("DOCKET_LLM")
    cleaned = redact_env({"DOCKET_LLM": "anthropic/x", "LLM_API_KEY": "sk-ant-secret"})
    assert cleaned["DOCKET_LLM"] == "anthropic/x" and cleaned["LLM_API_KEY"] == REDACTED
    print("utils.secret_files: ok")


if __name__ == "__main__":
    demo()
