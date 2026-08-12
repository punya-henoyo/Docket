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


def is_sensitive_env(name: str) -> bool:
    upper = name.upper()
    return any(marker in upper for marker in _SENSITIVE_ENV)


def redact_tree(value):
    """Redact every string INSIDE a structure, leaving the structure intact.

    Use this instead of redact(json.dumps(...)). Redacting serialized JSON operates on
    text that contains escape sequences, and a pattern that spans one leaves the escape
    broken. Measured: 4 of 17 real reports were unparseable because

        password = request.form.get(\"password\", \"\")

    matched an assignment pattern and became

        password = [REDACTED]\"password\", ...

    where the surviving quote closed the JSON string early. A report a tool cannot read
    back is worse than one with a secret in it, because nothing downstream — the
    console, the download, `docket view` — can open it at all.

    Redacting values before serialization cannot produce invalid JSON: json.dumps
    re-escapes whatever it is given.
    """
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, dict):
        return {k: redact_tree(v) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_tree(v) for v in value]
    return value


def redact_env(env: dict[str, str]) -> dict[str, str]:
    return {k: (REDACTED if is_sensitive_env(k) else v) for k, v in env.items()}


def demo() -> None:
    assert REDACTED in redact("key is sk-ant-abcdefgh12345678")

    # The bug this exists to prevent: redacting serialized JSON could break its escapes.
    import json as _json

    payload = {"poc": {"request": 'password = request.form.get("password", "")',
                       "response": "ok"},
               "nested": [{"token": "sk-ant-abcdefgh12345678"}]}
    text = _json.dumps(redact_tree(payload), indent=2)
    _json.loads(text)  # must round-trip; the old path produced unparseable output
    assert REDACTED in text
    assert redact_tree(7) == 7 and redact_tree(None) is None
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

    assert is_sensitive_env("LLM_API_KEY") and is_sensitive_env("anthropic_api_key")
    assert not is_sensitive_env("DOCKET_LLM")
    cleaned = redact_env({"DOCKET_LLM": "anthropic/x", "LLM_API_KEY": "sk-ant-secret"})
    assert cleaned["DOCKET_LLM"] == "anthropic/x" and cleaned["LLM_API_KEY"] == REDACTED
    print("utils.secret_files: ok")


if __name__ == "__main__":
    demo()
