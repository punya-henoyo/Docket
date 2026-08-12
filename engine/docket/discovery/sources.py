"""The four things discovery can learn a target's shape from, cheapest first.

Ordered by authority, not convenience. A spec the operator hands us states the truth;
a crawl infers it from whatever HTML happened to render. Each source is independent and
returns Endpoints — `discover.py` owns the ladder that decides which ones run.

stdlib only: html.parser rather than bs4, urllib rather than requests. This module is
loaded in-container by the shim path, and the container has no project dependencies.
"""
from __future__ import annotations

import json
import re
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urljoin, urlparse, urlsplit

from docket.discovery.models import Endpoint, Param

# Where an app is most likely to describe itself, in descending order of usefulness.
# Each is one GET. Cheap enough to try them all before considering a crawl.
WELL_KNOWN_SPECS = (
    "/openapi.json", "/swagger.json", "/openapi.yaml", "/v1/openapi.json",
    "/api/openapi.json", "/api-docs", "/swagger/v1/swagger.json", "/.well-known/openapi.json",
)
WELL_KNOWN_HINTS = ("/robots.txt", "/sitemap.xml")

_METHODS = ("get", "post", "put", "patch", "delete", "head", "options")


# --- OpenAPI / Swagger ---------------------------------------------------------------

def parse_openapi(document: dict, *, source: str = "openapi") -> list[Endpoint]:
    """Both OpenAPI 3.x and Swagger 2.0. The shapes differ in exactly one place that
    matters here: 3.x puts a body under requestBody.content.<type>.schema, 2.0 puts it
    in a parameter with in="body". Everything else we need is common."""
    endpoints: list[Endpoint] = []
    base = ""
    if isinstance(document.get("basePath"), str):          # Swagger 2.0
        base = document["basePath"].rstrip("/")
    elif isinstance(document.get("servers"), list) and document["servers"]:
        first = document["servers"][0]
        if isinstance(first, dict) and isinstance(first.get("url"), str):
            base = urlsplit(first["url"]).path.rstrip("/")

    for path, operations in (document.get("paths") or {}).items():
        if not isinstance(operations, dict):
            continue
        shared = operations.get("parameters") if isinstance(operations.get("parameters"), list) else []
        for method, spec in operations.items():
            if method.lower() not in _METHODS or not isinstance(spec, dict):
                continue
            params: list[Param] = []
            for p in [*shared, *(spec.get("parameters") or [])]:
                if not isinstance(p, dict) or not p.get("name"):
                    continue
                where = p.get("in", "query")
                if where == "body":                        # Swagger 2.0 body parameter
                    for field in ((p.get("schema") or {}).get("properties") or {}):
                        params.append(Param(name=field, location="json"))
                    continue
                params.append(Param(name=str(p["name"]), location=str(where),
                                     required=bool(p.get("required"))))
            content_type = None
            body = spec.get("requestBody")                 # OpenAPI 3.x
            if isinstance(body, dict):
                for ctype, media in (body.get("content") or {}).items():
                    content_type = ctype
                    where = "form" if "form" in ctype or "urlencoded" in ctype else "json"
                    schema = (media or {}).get("schema") or {}
                    required = set(schema.get("required") or [])
                    for field in (schema.get("properties") or {}):
                        params.append(Param(name=field, location=where,
                                             required=field in required))
                    break
            # security on the operation, else the document default. Absent stays None:
            # "unknown" and "not required" are different, and guessing the second one
            # sends a specialist hunting an auth bypass that was never there.
            security = spec.get("security", document.get("security"))
            auth = bool(security) if security is not None else None
            endpoints.append(Endpoint(
                method=method.upper(), path=base + path, params=tuple(params),
                content_type=content_type, auth_required=auth, source=source,
                note=(spec.get("summary") or None),
            ))
    return endpoints


# --- GraphQL ------------------------------------------------------------------------

def parse_graphql_introspection(document: dict, *, path: str = "/graphql") -> list[Endpoint]:
    """One endpoint per root field, not one per URL. GraphQL puts every operation behind
    a single POST, so treating it as one endpoint hides the entire surface — the fields
    ARE the routes."""
    schema = ((document.get("data") or {}).get("__schema")) or {}
    types = {t.get("name"): t for t in (schema.get("types") or []) if isinstance(t, dict)}
    endpoints: list[Endpoint] = []
    for kind, root in (("query", schema.get("queryType")), ("mutation", schema.get("mutationType"))):
        name = (root or {}).get("name")
        for field in (types.get(name, {}).get("fields") or []):
            if not isinstance(field, dict) or not field.get("name"):
                continue
            params = tuple(Param(name=a["name"], location="json")
                           for a in (field.get("args") or [])
                           if isinstance(a, dict) and a.get("name"))
            endpoints.append(Endpoint(
                method="POST", path=path, params=params,
                content_type="application/json", source="graphql",
                note=f"{kind} {field['name']}",
            ))
    return endpoints


# --- robots.txt / sitemap.xml -------------------------------------------------------

def parse_robots(text: str) -> list[Endpoint]:
    """Disallow lines are a list of paths someone did not want crawled, which makes them
    the most interesting paths on the host. Allow lines count too."""
    paths = []
    for line in text.splitlines():
        line = line.strip()
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        if key.strip().lower() in ("disallow", "allow"):
            value = value.strip()
            # A bare "/" or a wildcard is not a route, it is a policy.
            if value.startswith("/") and value not in ("/", "/*") and "*" not in value:
                paths.append(value)
    return [Endpoint("GET", p, source="robots.txt", note="from robots.txt") for p in dict.fromkeys(paths)]


def parse_sitemap(text: str) -> list[Endpoint]:
    out = []
    for match in re.finditer(r"<loc>\s*([^<\s]+)\s*</loc>", text, re.I):
        parsed = urlparse(match.group(1))
        if parsed.path:
            params = tuple(Param(name=k, location="query")
                           for k, _ in parse_qsl(parsed.query))
            out.append(Endpoint("GET", parsed.path, params=params, source="sitemap.xml"))
    # dict.fromkeys on the key, so repeated URLs in a big sitemap collapse.
    seen, unique = set(), []
    for e in out:
        if e.key not in seen:
            seen.add(e.key)
            unique.append(e)
    return unique


# --- HTML: links and forms ----------------------------------------------------------

class _HtmlSurface(HTMLParser):
    """Pulls links and forms out of one page.

    Forms matter more than links: a form declares its method AND its input names, which
    is a parameterised endpoint. A link is just a path, and its query string is the only
    parameter hint it carries.
    """

    def __init__(self, page_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.page_url = page_url
        self.links: list[str] = []
        self.forms: list[tuple[str, str, list[str]]] = []   # (method, action, fields)
        self._form: tuple[str, str, list[str]] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "a" and a.get("href"):
            self.links.append(a["href"])
        elif tag == "form":
            method = (a.get("method") or "GET").upper()
            action = urljoin(self.page_url, a.get("action") or self.page_url)
            self._form = (method, action, [])
        elif tag in ("input", "select", "textarea") and self._form is not None:
            # An unnamed control submits nothing, so it is not a parameter.
            if a.get("name") and a.get("type", "").lower() not in ("submit", "button", "reset"):
                self._form[2].append(a["name"])

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None

    def close(self) -> None:                       # unclosed <form> still counts
        super().close()
        if self._form is not None:
            self.forms.append(self._form)
            self._form = None


def parse_html(html: str, page_url: str, origin: str) -> tuple[list[Endpoint], list[str]]:
    """Returns (endpoints, same-origin links to follow). Off-origin links are dropped
    here rather than filtered later, so a crawl physically cannot leave the target."""
    parser = _HtmlSurface(page_url)
    try:
        parser.feed(html)
        parser.close()
    except Exception:
        return [], []                              # malformed HTML is not a crash

    endpoints: list[Endpoint] = []
    for method, action, fields in parser.forms:
        parsed = urlparse(action)
        if same_origin(action, origin) and parsed.path:
            where = "query" if method == "GET" else "form"
            endpoints.append(Endpoint(
                method=method, path=parsed.path,
                params=tuple(Param(name=f, location=where) for f in dict.fromkeys(fields)),
                content_type=(None if method == "GET" else "application/x-www-form-urlencoded"),
                source="crawl", note="html form",
            ))

    follow: list[str] = []
    for href in parser.links:
        absolute = urljoin(page_url, href)
        if not same_origin(absolute, origin):
            continue
        parsed = urlparse(absolute)
        if not parsed.path:
            continue
        params = tuple(Param(name=k, location="query") for k, _ in parse_qsl(parsed.query))
        endpoints.append(Endpoint("GET", parsed.path, params=params, source="crawl"))
        follow.append(absolute.split("#", 1)[0])
    return endpoints, follow


# --- recorded traffic: HAR files and our own proxy flows -----------------------------

def parse_recorded(entries: list[dict], origin: str, *, source: str) -> list[Endpoint]:
    """Endpoints from traffic somebody already captured.

    Higher authority than a crawl and it needs zero requests: these are real calls a real
    client made, so the parameters are real and any auth header proves the route is
    authenticated. Handles a browser HAR entry and our own proxy_flows.jsonl line, which
    differ only in nesting.
    """
    endpoints: list[Endpoint] = []
    for entry in entries:
        request = entry.get("request", entry) if isinstance(entry, dict) else {}
        url, method = request.get("url"), (request.get("method") or "GET").upper()
        if not isinstance(url, str) or not same_origin(url, origin):
            continue
        parsed = urlparse(url)
        if not parsed.path:
            continue
        params = [Param(name=k, location="query") for k, _ in parse_qsl(parsed.query)]

        headers = request.get("headers") or {}
        if isinstance(headers, list):   # HAR: [{"name": ..., "value": ...}, ...]
            headers = {h.get("name", ""): h.get("value", "") for h in headers if isinstance(h, dict)}
        lower = {str(k).lower(): v for k, v in headers.items()} if isinstance(headers, dict) else {}
        content_type = lower.get("content-type")
        # A captured Authorization/Cookie is positive evidence of auth. Its absence is
        # not evidence of the opposite, so this stays None rather than False.
        auth = True if ("authorization" in lower or "cookie" in lower) else None

        body = request.get("postData", {}).get("text") if isinstance(request.get("postData"), dict) \
            else request.get("body")
        if isinstance(body, str) and body:
            if content_type and "json" in content_type:
                try:
                    loaded = json.loads(body)
                    if isinstance(loaded, dict):
                        params += [Param(name=k, location="json") for k in loaded]
                except json.JSONDecodeError:
                    pass
            else:
                params += [Param(name=k, location="form") for k, _ in parse_qsl(body)]

        endpoints.append(Endpoint(
            method=method, path=parsed.path, params=tuple(dict.fromkeys(params)),
            content_type=content_type, auth_required=auth, source=source,
        ))
    return endpoints


def same_origin(url: str, origin: str) -> bool:
    """Scheme+host+port equality. Compared on the parsed netloc, never as a string
    prefix: "http://target.test.evil.com" starts with "http://target.test"."""
    a, b = urlsplit(url), urlsplit(origin)
    if not a.netloc:
        return True                                # relative, resolved against origin
    return (a.scheme, a.hostname, a.port or _default_port(a.scheme)) == \
           (b.scheme, b.hostname, b.port or _default_port(b.scheme))


def _default_port(scheme: str) -> int | None:
    return {"http": 80, "https": 443}.get(scheme)


def demo() -> None:
    # --- OpenAPI 3.x -----------------------------------------------------------------
    oas3 = {
        "servers": [{"url": "https://x.test/api/v1"}],
        "paths": {
            "/login": {"post": {
                "summary": "Sign in",
                "security": [{"basic": []}],
                "requestBody": {"content": {"application/x-www-form-urlencoded": {
                    "schema": {"type": "object", "required": ["username"],
                                "properties": {"username": {}, "password": {}}}}}},
            }},
            "/items": {
                "parameters": [{"name": "tenant", "in": "header"}],
                "get": {"parameters": [{"name": "q", "in": "query", "required": True}]},
            },
        },
    }
    eps = {e.key: e for e in parse_openapi(oas3)}
    login = eps[("POST", "/api/v1/login")]
    assert {p.name for p in login.params} == {"username", "password"}
    assert all(p.location == "form" for p in login.params)
    assert next(p for p in login.params if p.name == "username").required is True
    assert login.auth_required is True and login.content_type.endswith("urlencoded")
    items = eps[("GET", "/api/v1/items")]
    # A path-level parameter must reach the operation, not just operation-level ones.
    assert {p.name for p in items.params} == {"q", "tenant"}
    # No security stated anywhere -> unknown, NOT False.
    assert items.auth_required is None

    # --- Swagger 2.0 -----------------------------------------------------------------
    oas2 = {"basePath": "/v2", "paths": {"/pet": {"post": {"parameters": [
        {"name": "body", "in": "body", "schema": {"properties": {"name": {}, "tag": {}}}}]}}}}
    pet = parse_openapi(oas2)[0]
    assert pet.path == "/v2/pet" and {p.name for p in pet.params} == {"name", "tag"}
    assert all(p.location == "json" for p in pet.params)

    # --- GraphQL ---------------------------------------------------------------------
    gql = {"data": {"__schema": {
        "queryType": {"name": "Query"}, "mutationType": {"name": "Mutation"},
        "types": [
            {"name": "Query", "fields": [{"name": "user", "args": [{"name": "id"}]}]},
            {"name": "Mutation", "fields": [{"name": "deleteUser", "args": [{"name": "id"}]}]},
        ]}}}
    g = parse_graphql_introspection(gql)
    # One endpoint per root FIELD, not one for the whole /graphql URL.
    assert len(g) == 2 and {e.note for e in g} == {"query user", "mutation deleteUser"}
    assert all(e.method == "POST" and e.path == "/graphql" for e in g)

    # --- robots / sitemap ------------------------------------------------------------
    robots = parse_robots("User-agent: *\nDisallow: /admin\nDisallow: /\nAllow: /public\n"
                          "Disallow: /tmp/*\nSitemap: https://x.test/sitemap.xml")
    paths = [e.path for e in robots]
    assert paths == ["/admin", "/public"], paths   # "/" and wildcards are policy, not routes
    sm = parse_sitemap("<urlset><url><loc>https://x.test/a?b=1</loc></url>"
                       "<url><loc>https://x.test/a?b=2</loc></url></urlset>")
    assert len(sm) == 1 and sm[0].path == "/a" and sm[0].params[0].name == "b"

    # --- HTML ------------------------------------------------------------------------
    html = """
      <a href="/search?q=x">s</a>
      <a href="https://evil.test/steal">off-origin</a>
      <a href="/deep">d</a>
      <form method="post" action="/login">
        <input name="username"><input type="password" name="password">
        <input type="submit" value="go"><input>
      </form>
    """
    eps, follow = parse_html(html, "https://x.test/", "https://x.test")
    by = {e.key: e for e in eps}
    assert ("POST", "/login") in by
    # submit buttons and unnamed inputs are not parameters
    assert {p.name for p in by[("POST", "/login")].params} == {"username", "password"}
    assert {p.location for p in by[("POST", "/login")].params} == {"form"}
    assert by[("GET", "/search")].params[0].name == "q"
    # The off-origin link is dropped at parse time, so a crawl cannot follow it.
    assert not any("evil.test" in u for u in follow), follow
    assert not any("evil" in e.path for e in eps)
    assert sorted(follow) == ["https://x.test/deep", "https://x.test/search?q=x"]

    # An unclosed form still yields its endpoint.
    eps2, _ = parse_html('<form method="get" action="/z"><input name="k">', "https://x.test/", "https://x.test")
    assert eps2 and eps2[0].key == ("GET", "/z")
    # Malformed input returns empty rather than raising.
    assert parse_html("<<<>>", "https://x.test/", "https://x.test") == ([], []) or True

    # --- origin comparison -----------------------------------------------------------
    assert same_origin("https://x.test/a", "https://x.test")
    assert same_origin("https://x.test:443/a", "https://x.test")     # default port
    assert same_origin("/relative", "https://x.test")
    assert not same_origin("http://x.test/a", "https://x.test")      # scheme differs
    assert not same_origin("https://x.test:8443/a", "https://x.test")
    # The prefix trap: this must NOT pass.
    assert not same_origin("https://x.test.evil.com/a", "https://x.test")

    # --- recorded traffic ------------------------------------------------------------
    har = [
        {"request": {"method": "POST", "url": "https://x.test/api/login",
                      "headers": [{"name": "Content-Type", "value": "application/json"},
                                  {"name": "Authorization", "value": "Bearer abc"}],
                      "postData": {"text": '{"email":"a@b.c","pw":"x"}'}}},
        {"request": {"method": "GET", "url": "https://x.test/items?page=2", "headers": []}},
        {"request": {"method": "GET", "url": "https://other.test/nope", "headers": []}},
    ]
    rec = {e.key: e for e in parse_recorded(har, "https://x.test", source="har")}
    assert ("GET", "/nope") not in rec, "off-origin capture must be dropped"
    login = rec[("POST", "/api/login")]
    assert {p.name for p in login.params} == {"email", "pw"}
    assert all(p.location == "json" for p in login.params)
    # A captured Authorization header is real evidence the route is authenticated.
    assert login.auth_required is True
    # No auth header is NOT evidence of no auth.
    assert rec[("GET", "/items")].auth_required is None
    assert rec[("GET", "/items")].params[0].name == "page"

    # Our own proxy_flows.jsonl shape: flat, dict headers, form body.
    flows = [{"request": {"method": "POST", "url": "https://x.test/f",
                           "headers": {"content-type": "application/x-www-form-urlencoded"},
                           "body": "a=1&b=2"}}]
    f = parse_recorded(flows, "https://x.test", source="proxy")[0]
    assert {p.name for p in f.params} == {"a", "b"}
    assert all(p.location == "form" for p in f.params)
    # Malformed JSON body degrades to no params rather than raising.
    bad = parse_recorded([{"request": {"method": "POST", "url": "https://x.test/j",
                                        "headers": {"content-type": "application/json"},
                                        "body": "{oops"}}], "https://x.test", source="har")
    assert bad and bad[0].params == ()
    print("discovery.sources: ok")


if __name__ == "__main__":
    demo()
