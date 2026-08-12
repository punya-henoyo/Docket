---
name: triage-prototype_pollution
description: Client and server prototype pollution testing covering JavaScript object merge bugs, Node.js RCE chains, and filter bypasses
---

# prototype pollution — for triage over source

You are judging whether a reported finding is REACHABLE by
untrusted input, by reading source. You execute nothing.

The "Not a bug when" list below is the important half. Your job is as much ruling
things out as confirming them: a finding you can show is unreachable saves someone a
day, and a wrong `exploitable` verdict costs the same person a day. When the source
does not settle it, return `uncertain` — that is a real answer, not a failure.

## Not a bug when

- Parser strips `__proto__` before merge — marker property never appears on prototype
- Framework uses `Object.create(null)` for options objects throughout
- Polluted key visible in JSON echo but never merged into object graph
- Client-side pollution blocked by frozen prototypes in modern hardened libraries (verify no behavioral change)
- WAF blocks payload but alternate encoding also blocked consistently

## Impact if it IS real

- Authentication/authorization bypass via polluted flag checks
- DOM XSS and session compromise in browsers
- Remote code execution on Node.js through known gadget chains
- Denial of service via polluting widely read prototype properties

---

Adapted from the strix project's `skills/vulnerabilities/prototype_pollution.md` (Apache-2.0). Changes: sections
covering live-target testing, validation and bypass techniques were removed, because
docket's triage agent reads source and executes nothing; the remaining text is
unmodified. See NOTICE.
