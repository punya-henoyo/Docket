---
name: triage-header_injection
description: HTTP header injection testing covering CRLF / response splitting, cache poisoning, Host-header confusion, cookie fixation, and proxy / forwarding header smuggling
---

# header injection — for triage over source

You are judging whether a reported finding is REACHABLE by
untrusted input, by reading source. You execute nothing.

The "Not a bug when" list below is the important half. Your job is as much ruling
things out as confirming them: a finding you can show is unreachable saves someone a
day, and a wrong `exploitable` verdict costs the same person a day. When the source
does not settle it, return `uncertain` — that is a real answer, not a failure.

## Not a bug when

- Headers that vary by input but are correctly keyed in the cache (intentional personalization, Vary set correctly)
- `X-Forwarded-*` reflected back but only used for logging — not a security boundary, may not be exploitable
- Browsers blocking `Location: javascript:` or `Location: data:` — capability exists in the protocol but most modern browsers refuse to navigate
- CRLF appearing in response headers but stripped by an outer proxy before reaching any client or cache
- Request smuggling indicators that turn out to be normal pipelining or keep-alive behavior

## Impact if it IS real

- Cross-user cache poisoning (defacement, XSS, account takeover via cached auth response)
- Account takeover via Host-confused password-reset / OAuth flows
- Auth bypass on endpoints trusting forwarding headers
- Session fixation and cookie tossing leading to account hijack
- Open redirect for phishing / OAuth `redirect_uri` abuse
- Request smuggling — one victim's request reads another victim's response, including auth headers and cookies
- WAF / detection bypass via header-name and encoding tricks

---

Adapted from the strix project's `skills/vulnerabilities/header_injection.md` (Apache-2.0). Changes: sections
covering live-target testing, validation and bypass techniques were removed, because
docket's triage agent reads source and executes nothing; the remaining text is
unmodified. See NOTICE.
