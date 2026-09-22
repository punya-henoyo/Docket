"""Specialist agent prompts. Shared rules (evidence-backed findings, finish-tool-only
stopping) mirror root.py's; the difference is scope — one route, one vuln class — and
`agent_finish` instead of `finish_scan`.
"""
from __future__ import annotations

SYSTEM_PROMPT = """You are a security researcher, one of several working the same
target web app. You are scoped to exactly ONE route and ONE class of vulnerability —
do not test anything outside that scope, and do not spawn further agents.

Rules:
- A finding must be backed by real evidence: an actual request you sent and the
  actual response/behavior you observed. Never register a vulnerability you haven't
  reproduced.
- Call `finding` once per distinct bug, with real repro details in `poc`.
- When you are done (found it, or exhausted reasonable leads on your route), call
  `agent_finish` exactly once with a summary and the finding IDs you registered.
  Nothing else ends your turn — call it even if you found nothing.
"""

_SQLMAP_HINT = """Try injection-style payloads (quote-breaking, boolean/comment tricks)
against the form field(s) on this route to find an auth bypass or data leak.

If you have a `shell` tool, sqlmap is installed at /opt/sqlmap/sqlmap.py and is the
strongest way to CONFIRM the bug rather than just assert it. Two things about this
target defeat sqlmap's defaults, so pass these or it will wrongly report "not
injectable":
  --ignore-code=401  A failed login answers 401, which sqlmap otherwise treats as an
                     auth wall and aborts the whole run.
  Use VALID credentials in --data (plus --string=Welcome). sqlmap's level-1 boolean
                     payloads append `AND ...` WITHOUT a comment, so the original
                     password check survives; with a wrong password both the true and
                     false variants answer 401, the true/false oracle disappears, and
                     detection fails. With valid credentials the baseline is a 200
                     "Welcome" and the oracle works.
A known-good invocation, verified against this target:
  python3 /opt/sqlmap/sqlmap.py -u <route-url> --data="username=<user>&password=<pass>"
    -p username --ignore-code=401 --string=Welcome --batch --flush-session
    --technique=B --level=1 --risk=1 --dbms=sqlite
Quote the payload/PoC line sqlmap prints ("Parameter: ... Type: ... Payload: ...") as
your evidence."""

_IDOR_HINT = """This route takes an object id from the caller. The question is not
whether it returns data — it is whether it checks that YOU own the object.

The proof needs TWO identities, and a finding without both is not a finding:
  1. Authenticate as identity A. Note an object id that genuinely belongs to A.
  2. Authenticate as identity B (register a second account if the app allows it; a
     second session/cookie/token is enough). If you cannot obtain a second identity,
     say so in `agent_finish` and register nothing — "the id looked guessable" is a
     suspicion, not a reproduction.
  3. Send B's session to this route asking for A's object id.
  4. If A's data comes back, you have it. Quote BOTH requests and BOTH responses: B's
     request with A's id, and the response containing A's data. The evidence is the
     pairing — one request alone proves nothing.

Unauthenticated access to an object that should require a session counts too, and is
simpler to show: request the object with NO credentials and quote what comes back.

Watch for the near-misses, which are not this bug: a 200 with an empty body, a 403 that
still leaks existence through timing, and an id that is a random UUID you only knew
because A's session showed it to you. Sequential or guessable ids make exploitation
practical and are worth stating, but the bug is the missing ownership check."""

_SSRF_HINT = """This route fetches a URL the caller influences. You are proving the
SERVER made a request it should not have — not that you could type a URL into a field.

You have no external collaborator, so prove it by DIFFERENCE. Send the same route two
URLs and show the responses differ in a way only a real outbound request explains:

  - Reflected content: if the fetched body comes back in the response, point it at
    something only the server can reach — its own loopback, an internal port, a
    metadata address — and quote the internal content you received. This is the
    strongest evidence available without a collaborator.
  - Differential error: a closed port on the server's own loopback answers
    "connection refused" almost instantly; a host that does not resolve answers a DNS
    error; a routable-but-silent address hangs. Three DIFFERENT errors from three URLs
    is the server dialling each one. Quote all three.
  - Timing: an unroutable RFC1918 address (10.255.255.1) hangs until the client
    timeout, while an invalid hostname fails immediately. A consistent, repeatable gap
    is a side channel and is real proof — the same technique the cmdi agent uses.

Try the bypasses only AFTER a plain URL is refused, and say which one worked:
redirect-based, alternate IP encodings, a hostname that resolves to a private address.

Do NOT register a finding because the parameter is named `url` and the code looks
reachable — that is the static scanner's job and it has already done it. Register one
when you can quote a response that only an outbound request from the server produces."""


_TECHNIQUE_HINTS: dict[str, str] = {
    "idor": _IDOR_HINT,
    "ssrf": _SSRF_HINT,
    "sqli": _SQLMAP_HINT,
    "cmdi": "Try shell metacharacters in the parameter. The response body may never "
    "change regardless of what the injected command does (blind) — a timing "
    "side-channel (e.g. append `; sleep 3` and compare latency to a baseline request) "
    "is a valid, real proof technique.",
    "xss": "Try reflecting an HTML/script payload through the parameter and check "
    "whether it comes back unescaped in the response body.\n"
    "Seeing your payload echoed in the HTML is only a hint, not proof. If you have a "
    "`browser` tool, PROVE execution: navigate to the route with an alert() payload "
    "(e.g. ?q=<script>alert(document.domain)</script>) and check the result's "
    "`dialog_message` field. A non-null dialog_message means a real DOM parsed and ran "
    "your script — that is the evidence to quote. Take a `screenshot` too, as a "
    "supporting artifact.",
}


def demo() -> None:
    """Every SpecialistRole must carry a technique hint, or it is a role with no method.

    The hint is the only thing that distinguishes one specialist from another: they share
    a system prompt, and the class-specific technique arrives here. A role added to the
    factory without one gets a task that says "find the bug" and nothing else.
    """
    from docket.agents.factory import SpecialistRole

    for role in SpecialistRole.__args__:
        assert role in _TECHNIQUE_HINTS, f"{role} is spawnable but has no technique hint"

    base = "http://target:5000"
    for role in SpecialistRole.__args__:
        task = build_task(role, "GET /x", "look at it", base)
        assert base in task and "absolute" in task, role
        assert "GET /x" in task and "agent_finish" in task, role

    # The two new ones, on the thing that makes each proof real rather than suggestive.
    idor = build_task("idor", "GET /invoice/<id>", "check ownership", base)
    assert "TWO identities" in idor, "an IDOR claim from one session proves nothing"
    assert "suspicion, not a reproduction" in idor, idor
    ssrf = build_task("ssrf", "GET /fetch", "check the url param", base)
    assert "DIFFERENCE" in ssrf, "with no collaborator, SSRF proof is differential"
    assert "that is the static scanner's job" in ssrf, ssrf

    # And the shared bar, which no hint may soften.
    assert "reproduced" in SYSTEM_PROMPT and "agent_finish" in SYSTEM_PROMPT
    print("agents.prompts.specialist: ok")


def build_task(role: str, target_route: str, task: str, target_url: str = "") -> str:
    """`target_url` is the ABSOLUTE base the child must dial, and omitting it was a real
    bug: given only a route like "POST /login", the first live run's specialists passed
    the bare path to http_request (urllib: "unknown url type: \'/login\'"), then guessed
    absolute URLs and hit `localhost` — which, inside the sandbox container, is the
    container itself. 19 connection failures and zero findings on a target that was up
    the whole time. Never let a child infer the host."""
    hint = _TECHNIQUE_HINTS.get(role, "")
    lines = []
    if target_url:
        lines.append(
            f"The target's base URL is {target_url} — use it verbatim. Every url you pass "
            f"to a tool must be absolute and start with it, e.g. {target_url}/some/path. "
            f"Never send a bare path, and never substitute localhost or 127.0.0.1: your "
            f"tools run inside a container where those mean the container itself."
        )
    lines += [
        f"You are scoped to exactly ONE route: {target_route}. Do not touch any other route.",
        f"Objective from the coordinating agent: {task}",
    ]
    if hint:
        lines.append(hint)
    lines.append(
        "Call `finding` only once you have a real, reproduced result, then call "
        "`agent_finish` with a summary and the finding IDs you registered."
    )
    return "\n".join(lines)


if __name__ == "__main__":
    demo()
