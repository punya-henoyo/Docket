"""The `web_search` tool: real-time intel lookup for the agent.

Upstream Docket backs this with Perplexity. Rather than hardcode one vendor, this is
provider-pluggable so whichever key you actually hold works:

    DOCKET_SEARCH_PROVIDER = tavily | brave | serper | perplexity | deepseek
    DOCKET_SEARCH_API_KEY  = <key>

All five are plain REST endpoints, so this stays on stdlib urllib — no SDK per vendor.
With no key configured the tool returns an explicit "not configured" error rather than
pretending: an agent told search is unavailable will work from what it can observe,
whereas one handed fabricated results will chase them.

Note deepseek/perplexity are chat-completion routes with live web access rather than
search APIs, so they return a synthesised answer plus whatever citations the model
provides; tavily/brave/serper return real ranked result lists.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

DEFAULT_MAX_RESULTS = 5
TIMEOUT_SEC = 20

_ENDPOINTS = {
    "tavily": "https://api.tavily.com/search",
    "brave": "https://api.search.brave.com/res/v1/web/search",
    "serper": "https://google.serper.dev/search",
    "perplexity": "https://api.perplexity.ai/chat/completions",
    "deepseek": "https://api.deepseek.com/chat/completions",
}


def _configured() -> tuple[str | None, str | None]:
    provider = (os.environ.get("DOCKET_SEARCH_PROVIDER") or "").strip().lower() or None
    key = (os.environ.get("DOCKET_SEARCH_API_KEY") or "").strip() or None
    return provider, key


def _post(url: str, payload: dict, headers: dict) -> dict:
    request = urllib.request.Request(
        url, data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", **headers}, method="POST",
    )
    with urllib.request.urlopen(request, timeout=TIMEOUT_SEC) as response:
        return json.loads(response.read() or b"{}")


def _get(url: str, headers: dict) -> dict:
    request = urllib.request.Request(url, headers=headers, method="GET")
    with urllib.request.urlopen(request, timeout=TIMEOUT_SEC) as response:
        return json.loads(response.read() or b"{}")


def _chat_route(provider: str, key: str, query: str) -> dict:
    """perplexity/deepseek: a chat model with live web access, not a search API."""
    model = "sonar" if provider == "perplexity" else "deepseek-chat"
    data = _post(
        _ENDPOINTS[provider],
        {
            "model": model,
            "messages": [
                {"role": "system", "content": "Answer concisely and cite sources as URLs."},
                {"role": "user", "content": query},
            ],
        },
        {"Authorization": f"Bearer {key}"},
    )
    choice = (data.get("choices") or [{}])[0]
    answer = (choice.get("message") or {}).get("content", "")
    citations = data.get("citations") or data.get("search_results") or []
    results = [
        {"title": c.get("title", "") if isinstance(c, dict) else "",
         "url": c if isinstance(c, str) else c.get("url", ""),
         "snippet": c.get("snippet", "") if isinstance(c, dict) else ""}
        for c in citations
    ]
    return {"ok": True, "provider": provider, "answer": answer, "results": results}


def web_search(query: str, max_results: int = DEFAULT_MAX_RESULTS) -> dict:
    provider, key = _configured()
    if not provider or not key:
        return {
            "ok": False,
            "error": (
                "web_search is not configured. Set DOCKET_SEARCH_PROVIDER "
                f"({'|'.join(_ENDPOINTS)}) and DOCKET_SEARCH_API_KEY to enable it. "
                "Work from what you can observe on the target instead."
            ),
            "results": [],
        }
    if provider not in _ENDPOINTS:
        return {"ok": False, "error": f"unknown search provider {provider!r}", "results": []}

    try:
        if provider in {"perplexity", "deepseek"}:
            return _chat_route(provider, key, query)

        if provider == "tavily":
            data = _post(_ENDPOINTS["tavily"],
                          {"query": query, "max_results": max_results},
                          {"Authorization": f"Bearer {key}"})
            raw = data.get("results", [])
            results = [{"title": r.get("title", ""), "url": r.get("url", ""),
                         "snippet": r.get("content", "")} for r in raw]
            answer = data.get("answer", "")
        elif provider == "brave":
            url = f"{_ENDPOINTS['brave']}?q={urllib.parse.quote(query)}&count={max_results}"
            data = _get(url, {"X-Subscription-Token": key, "Accept": "application/json"})
            raw = (data.get("web") or {}).get("results", [])
            results = [{"title": r.get("title", ""), "url": r.get("url", ""),
                         "snippet": r.get("description", "")} for r in raw]
            answer = ""
        else:  # serper
            data = _post(_ENDPOINTS["serper"], {"q": query, "num": max_results},
                          {"X-API-KEY": key})
            raw = data.get("organic", [])
            results = [{"title": r.get("title", ""), "url": r.get("link", ""),
                         "snippet": r.get("snippet", "")} for r in raw]
            answer = (data.get("answerBox") or {}).get("answer", "")
        return {"ok": True, "provider": provider, "answer": answer, "results": results[:max_results]}
    except urllib.error.HTTPError as exc:
        return {"ok": False, "error": f"{provider} returned HTTP {exc.code}", "results": []}
    except Exception as exc:
        return {"ok": False, "error": f"{provider} search failed: {type(exc).__name__}: {exc}", "results": []}


def demo() -> None:
    saved = {k: os.environ.pop(k, None) for k in ("DOCKET_SEARCH_PROVIDER", "DOCKET_SEARCH_API_KEY")}
    try:
        # Unconfigured: an explicit, actionable refusal — never fabricated results.
        result = web_search("CVE-2024-3094")
        assert result["ok"] is False and result["results"] == []
        assert "DOCKET_SEARCH_PROVIDER" in result["error"]
        assert "tavily" in result["error"] and "deepseek" in result["error"]

        os.environ["DOCKET_SEARCH_PROVIDER"] = "not-a-provider"
        os.environ["DOCKET_SEARCH_API_KEY"] = "x"
        bad = web_search("anything")
        assert bad["ok"] is False and "unknown search provider" in bad["error"]

        assert set(_ENDPOINTS) == {"tavily", "brave", "serper", "perplexity", "deepseek"}
    finally:
        for k, v in saved.items():
            if v is not None:
                os.environ[k] = v
            else:
                os.environ.pop(k, None)
    print("tools.web_search: ok (live query needs DOCKET_SEARCH_API_KEY)")


if __name__ == "__main__":
    demo()
