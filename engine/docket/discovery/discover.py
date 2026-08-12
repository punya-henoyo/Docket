"""The discovery ladder: work out a target's shape without asking a model to guess.

Deterministic code, not an agent task. The model exploits; it does not enumerate. That
split is not stylistic — an LLM crawling is slow, expensive, unreproducible between runs,
and produces prose nobody can diff. This produces a typed artifact instead.

Rungs, cheapest and most authoritative first, stopping at the first that yields:

  1. operator-supplied  --openapi / --graphql-schema / --har        0 requests
  2. well-known paths   /openapi.json, /graphql, robots, sitemap    ~10 requests
  3. recorded traffic    this run's proxy_flows.jsonl               0 requests
  4. bounded crawl       same-origin only, depth and request capped  N requests

The crawl is last and fenced on purpose. Guardrails live here rather than waiting on a
separate scope-control feature, because a discovery pass that can wander is the thing
that turns a lab tool into an incident:

  - same-origin is enforced in sources.parse_html, which drops off-origin links before
    they are ever queued, so this cannot follow one by mistake
  - MAX_REQUESTS is a hard ceiling across the whole pass, not per rung
  - MAX_DEPTH bounds how far from the entry point it walks
  - only text/html is parsed, so it will not stream a binary
"""
from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from urllib.parse import urlsplit

from docket.discovery.models import AttackSurface, Endpoint
from docket.discovery.sources import (
    WELL_KNOWN_HINTS,
    WELL_KNOWN_SPECS,
    parse_graphql_introspection,
    parse_html,
    parse_openapi,
    parse_recorded,
    parse_robots,
    parse_sitemap,
)

MAX_REQUESTS = 60
MAX_DEPTH = 2
MAX_CRAWL_PAGES = 25

# The smallest introspection query that names every root field. Sent as a POST body.
INTROSPECTION_QUERY = (
    "{__schema{queryType{name} mutationType{name} "
    "types{name fields{name args{name}}}}}"
)

# fetch(method, url, body=None, headers=None) -> dict with status_code / body / headers.
# Injected rather than imported so discovery runs identically on the host and through the
# sandbox shim, and so the tests exercise the ladder with no network at all.
Fetch = Callable[..., dict]


def _origin(target: str) -> str:
    parts = urlsplit(target)
    return f"{parts.scheme}://{parts.netloc}"


def _text(response: dict) -> str:
    return response.get("body") or "" if isinstance(response, dict) else ""


def _ok(response: dict) -> bool:
    return isinstance(response, dict) and 200 <= int(response.get("status_code") or 0) < 300


def _json(response: dict) -> dict | None:
    try:
        loaded = json.loads(_text(response))
    except (json.JSONDecodeError, TypeError):
        return None
    return loaded if isinstance(loaded, dict) else None


def discover(
    target: str,
    *,
    fetch: Fetch,
    openapi_path: str | None = None,
    har_path: str | None = None,
    flows_path: Path | None = None,
    max_requests: int = MAX_REQUESTS,
    max_depth: int = MAX_DEPTH,
    allow_crawl: bool = True,
) -> AttackSurface:
    """Build the attack surface. Never raises: a target that answers nothing yields an
    empty surface, and an empty surface is a fact the root agent must be told rather than
    a failure to paper over."""
    surface = AttackSurface(target=target)
    origin = _origin(target)
    base = target.rstrip("/")
    budget = {"left": max_requests}

    def get(url: str, method: str = "GET", **kw) -> dict:
        if budget["left"] <= 0:
            return {}
        budget["left"] -= 1
        surface.requests_made += 1
        try:
            return fetch(method, url, **kw) or {}
        except Exception:
            return {}                       # an unreachable path is a dead end, not a crash

    # --- rung 1: what the operator handed us ----------------------------------------
    if openapi_path:
        surface.sources_tried.append("openapi-file")
        document = _load_json_file(openapi_path)
        if document:
            _extend(surface, parse_openapi(document, source="openapi-file"))
        else:
            surface.notes.append(f"could not read an OpenAPI document from {openapi_path}")
    if har_path:
        surface.sources_tried.append("har-file")
        document = _load_json_file(har_path)
        entries = ((document or {}).get("log") or {}).get("entries") or []
        _extend(surface, parse_recorded(entries, origin, source="har-file"))
    if surface:
        return _done(surface, "operator-supplied spec/HAR")

    # --- rung 2: ask the app to describe itself -------------------------------------
    surface.sources_tried.append("well-known")
    for path in WELL_KNOWN_SPECS:
        document = _json(get(base + path))
        if document and document.get("paths"):
            _extend(surface, parse_openapi(document, source=f"well-known{path}"))
            break
    for path in ("/graphql", "/api/graphql", "/v1/graphql"):
        response = get(base + path, "POST",
                        data=json.dumps({"query": INTROSPECTION_QUERY}),
                        headers={"Content-Type": "application/json"})
        document = _json(response)
        if document and (document.get("data") or {}).get("__schema"):
            _extend(surface, parse_graphql_introspection(document, path=path))
            break
    for path in WELL_KNOWN_HINTS:
        response = get(base + path)
        if not _ok(response):
            continue
        body = _text(response)
        _extend(surface, parse_robots(body) if path.endswith(".txt") else parse_sitemap(body))
    if surface:
        return _done(surface, "the target's own published description")

    # --- rung 3: traffic already captured this run ----------------------------------
    if flows_path:
        surface.sources_tried.append("proxy-flows")
        entries = _load_jsonl(flows_path)
        _extend(surface, parse_recorded(entries, origin, source="proxy-flows"))
        if surface:
            return _done(surface, "captured proxy traffic")

    # --- rung 4: bounded crawl -------------------------------------------------------
    if not allow_crawl:
        surface.notes.append("crawl disabled; nothing cheaper answered")
        return _done(surface, "nothing")
    surface.sources_tried.append("crawl")
    queue: list[tuple[str, int]] = [(base + "/", 0)]
    seen: set[str] = set()
    pages = 0
    while queue and budget["left"] > 0 and pages < MAX_CRAWL_PAGES:
        url, depth = queue.pop(0)
        if url in seen or depth > max_depth:
            continue
        seen.add(url)
        response = get(url)
        if not _ok(response):
            continue
        content_type = _header(response, "content-type")
        if "html" not in content_type.lower():
            continue                        # do not parse a binary as markup
        pages += 1
        endpoints, follow = parse_html(_text(response), url, origin)
        _extend(surface, endpoints)
        for link in follow:
            if link not in seen:
                queue.append((link, depth + 1))
    if queue or pages >= MAX_CRAWL_PAGES:
        # Never let a cap look like completeness.
        surface.notes.append(
            f"crawl stopped early: {pages} pages, {surface.requests_made} requests, "
            f"{len(queue)} links unvisited (caps: {max_requests} requests, "
            f"depth {max_depth}, {MAX_CRAWL_PAGES} pages)"
        )
    return _done(surface, "a bounded crawl")


def _done(surface: AttackSurface, how: str) -> AttackSurface:
    surface.notes.append(f"surface derived from {how}")
    return surface


def _extend(surface: AttackSurface, endpoints: list[Endpoint]) -> None:
    for endpoint in endpoints:
        surface.add(endpoint)


def _header(response: dict, name: str) -> str:
    headers = response.get("headers") or {}
    if not isinstance(headers, dict):
        return ""
    for key, value in headers.items():
        if str(key).lower() == name:
            return str(value)
    return ""


def _load_json_file(path: str | Path) -> dict | None:
    try:
        loaded = json.loads(Path(path).read_text())
    except (OSError, json.JSONDecodeError):
        return None
    return loaded if isinstance(loaded, dict) else None


def _load_jsonl(path: str | Path) -> list[dict]:
    try:
        lines = Path(path).read_text().splitlines()
    except OSError:
        return []
    out = []
    for line in lines:
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            out.append(item)
    return out


def demo() -> None:
    import shutil
    import tempfile

    ORIGIN = "http://t.test"

    def responder(routes: dict, *, log: list | None = None) -> Fetch:
        """A fake target. `routes` maps path -> (status, body, content_type)."""
        def fetch(method: str, url: str, **kw) -> dict:
            path = urlsplit(url).path
            if log is not None:
                log.append(url)          # the FULL url: the host is what the fence guards
            status, body, ctype = routes.get(path, (404, "", "text/plain"))
            return {"status_code": status, "body": body, "headers": {"Content-Type": ctype}}
        return fetch

    # --- rung 1 short-circuits: a spec file means ZERO requests ----------------------
    tmp = Path(tempfile.mkdtemp())
    try:
        spec = tmp / "openapi.json"
        spec.write_text(json.dumps({"paths": {"/pets": {"get": {
            "parameters": [{"name": "limit", "in": "query"}]}}}}))
        log: list = []
        s = discover(ORIGIN, fetch=responder({}, log=log), openapi_path=str(spec))
        assert len(s) == 1 and s.endpoints[0].key == ("GET", "/pets")
        assert s.requests_made == 0 and log == [], "a supplied spec must not touch the network"

        # An unreadable spec is reported, not silently ignored, and falls through.
        s = discover(ORIGIN, fetch=responder({}), openapi_path=str(tmp / "missing.json"),
                      allow_crawl=False)
        assert any("could not read" in n for n in s.notes)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    # --- rung 2: the app describes itself, and the crawl never runs ------------------
    served = {"/openapi.json": (200, json.dumps({"paths": {"/login": {"post": {}}}}), "application/json")}
    log = []
    s = discover(ORIGIN, fetch=responder(served, log=log))
    assert [e.key for e in s.endpoints] == [("POST", "/login")]
    assert "crawl" not in s.sources_tried, "a spec was found; crawling anyway is waste"

    # robots.txt contributes even with no OpenAPI present
    s = discover(ORIGIN, fetch=responder({"/robots.txt": (200, "Disallow: /admin", "text/plain")}))
    assert ("GET", "/admin") in {e.key for e in s.endpoints}

    # --- rung 3: recorded flows, still zero new requests ----------------------------
    tmp = Path(tempfile.mkdtemp())
    try:
        flows = tmp / "proxy_flows.jsonl"
        flows.write_text(json.dumps({"request": {"method": "GET", "url": f"{ORIGIN}/x?a=1",
                                                  "headers": {}}}) + "\n{bad json\n")
        s = discover(ORIGIN, fetch=responder({}), flows_path=flows, allow_crawl=False)
        assert [e.key for e in s.endpoints] == [("GET", "/x")]
        assert s.endpoints[0].params[0].name == "a"
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    # --- rung 4: the crawl, and its fences ------------------------------------------
    site = {
        "/": (200, '<a href="/a">a</a><a href="http://evil.test/x">e</a>'
                    '<form method="post" action="/login"><input name="u"></form>', "text/html"),
        "/a": (200, '<a href="/b?q=1">b</a>', "text/html"),
        "/b": (200, "<html>leaf</html>", "text/html"),
    }
    log = []
    s = discover(ORIGIN, fetch=responder(site, log=log))
    keys = {e.key for e in s.endpoints}
    assert ("POST", "/login") in keys and ("GET", "/a") in keys and ("GET", "/b") in keys
    # The off-origin link is never REQUESTED. Asserted on the full url, because an
    # endpoint's .path for http://evil.test/x is just "/x" — checking .path for "evil"
    # is a test that cannot fail, which is how this guard first shipped untested.
    offsite = [u for u in log if urlsplit(u).hostname not in ("t.test",)]
    assert not offsite, offsite
    assert all(p.name == "u" for p in next(e for e in s.endpoints if e.key == ("POST", "/login")).params)

    # A request cap is a hard ceiling, and it must be REPORTED, never silent.
    log = []
    s = discover(ORIGIN, fetch=responder(site, log=log), max_requests=3)
    assert s.requests_made <= 3, s.requests_made
    assert len(log) <= 3
    assert any("stopped early" in n for n in s.notes), s.notes

    # Depth 0 visits the entry page only, so /b (two hops away) is never reached.
    s = discover(ORIGIN, fetch=responder(site), max_depth=0)
    assert ("GET", "/b") not in {e.key for e in s.endpoints}

    # A non-HTML body is not parsed as markup.
    s = discover(ORIGIN, fetch=responder({"/": (200, b"\x89PNG fake".decode("latin1"), "image/png")}))
    assert len(s) == 0

    # --- an empty surface is a fact, not an error -----------------------------------
    s = discover(ORIGIN, fetch=responder({}))
    assert len(s) == 0 and not s
    s = discover(ORIGIN, fetch=responder(site), allow_crawl=False)
    assert len(s) == 0 and any("crawl disabled" in n for n in s.notes)

    # A fetch that throws is a dead end, not a crash.
    def angry(method: str, url: str, **kw) -> dict:
        raise ConnectionError("refused")
    assert len(discover(ORIGIN, fetch=angry)) == 0

    # --- persistence round-trip ------------------------------------------------------
    tmp = Path(tempfile.mkdtemp())
    try:
        s = discover(ORIGIN, fetch=responder(site))
        s.save(tmp)
        back = AttackSurface.load(tmp)
        assert back is not None and len(back) == len(s)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print("discovery.discover: ok")


if __name__ == "__main__":
    demo()
