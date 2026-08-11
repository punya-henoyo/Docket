"""Redaction helpers. Mirrors docket/utils/secret_files.py.

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


def redact_env(env: dict[str, str]) -> dict[str, str]:
    return {k: (REDACTED if is_sensitive_env(k) else v) for k, v in env.items()}


def demo() -> None:
    assert REDACTED in redact("key is sk-ant-abcdefgh12345678")
    assert "sk-ant-abcdefgh12345678" not in redact("key is sk-ant-abcdefgh12345678")
    assert REDACTED in redact("Authorization: Bearer abcdef1234567890")
    assert REDACTED in redact("password=hunter2000")
    assert REDACTED in redact("AKIAIOSFODNN7EXAMPLE")
    assert REDACTED in redact("ghp_abcdefghijklmnop123")
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
