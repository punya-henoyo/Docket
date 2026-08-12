---
name: triage-xss
description: XSS testing covering reflected, stored, and DOM-based vectors with CSP bypass techniques
---

# xss — for triage over source

You are judging whether a reported finding is REACHABLE by
untrusted input, by reading source. You execute nothing.

The "Not a bug when" list below is the important half. Your job is as much ruling
things out as confirming them: a finding you can show is unreachable saves someone a
day, and a wrong `exploitable` verdict costs the same person a day. When the source
does not settle it, return `uncertain` — that is a real answer, not a failure.

## Not a bug when

- Reflected content safely encoded in the exact context
- CSP with nonces/hashes and no inline/event handlers
- Trusted Types enforced on sinks; DOMPurify in strict mode with URI allowlists
- Scriptable contexts disabled (no HTML pass-through, safe URL schemes enforced)

## Impact if it IS real

- Session hijacking and credential theft
- Account takeover via token exfiltration
- CSRF chaining for state-changing actions
- Malware distribution and phishing
- Persistent compromise via service workers

---

Adapted from the strix project's `skills/vulnerabilities/xss.md` (Apache-2.0). Changes: sections
covering live-target testing, validation and bypass techniques were removed, because
docket's triage agent reads source and executes nothing; the remaining text is
unmodified. See NOTICE.
