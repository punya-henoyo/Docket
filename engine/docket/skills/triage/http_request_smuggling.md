---
name: triage-http_request_smuggling
description: HTTP request smuggling testing covering CL.TE, TE.CL, H2.CL, H2.TE, and HTTP/2 desync techniques with practical detection and exploitation methodology
---

# http request smuggling — for triage over source

You are judging whether a reported finding is REACHABLE by
untrusted input, by reading source. You execute nothing.

The "Not a bug when" list below is the important half. Your job is as much ruling
things out as confirming them: a finding you can show is unreachable saves someone a
day, and a wrong `exploitable` verdict costs the same person a day. When the source
does not settle it, return `uncertain` — that is a real answer, not a failure.

## Not a bug when

- General network latency or server-side processing delays unrelated to smuggling
- Server consistently close connection after first request (no connection reuse, no socket sharing)
- HTTP/2 with full end-to-end HTTP/2 to back-end (no HTTP/1.1 downgrade, no desync surface)
- WAF or proxy that normalizes TE/CL headers before forwarding (removes the ambiguity)

## Impact if it IS real

- Authentication and authorization bypass by smuggling requests past front-end access controls
- Cross-user session hijacking by capturing requests containing session tokens
- Cache poisoning affecting all users of a cached resource
- Internal service access bypassing IP-based restrictions enforced at the front-end
- XSS delivery via response queue poisoning in shared connection contexts

---

Adapted from the strix project's `skills/vulnerabilities/http_request_smuggling.md` (Apache-2.0). Changes: sections
covering live-target testing, validation and bypass techniques were removed, because
docket's triage agent reads source and executes nothing; the remaining text is
unmodified. See NOTICE.
