---
name: triage-ssti
description: Server-side template injection across Jinja / Mako / Velocity / Freemarker / Thymeleaf / Twig / Handlebars / EJS / ERB with engine fingerprinting, sandbox escape, and RCE gadget chains
---

# ssti — for triage over source

You are judging whether a reported finding is REACHABLE by
untrusted input, by reading source. You execute nothing.

The "Not a bug when" list below is the important half. Your job is as much ruling
things out as confirming them: a finding you can show is unreachable saves someone a
day, and a wrong `exploitable` verdict costs the same person a day. When the source
does not settle it, return `uncertain` — that is a real answer, not a failure.

## Not a bug when

- Template syntax reflected literally (`{{7*7}}` rendered as `{{7*7}}`) — that's XSS-shaped, not SSTI
- Sandboxed environments where reflection succeeds but reachable objects expose nothing useful (Jinja `SandboxedEnvironment` with no `request` / `config` in context)
- Client-side template engines (Vue, Angular, Mustache running in the browser) — that's client-side template injection, different impact (XSS, not RCE)
- Markdown / static-site generators that template at build time only, with no user input reaching the build
- Engines where the output is HTML-escaped before display, masking evaluation as XSS-like reflection — verify with a non-HTML probe (`{{7*7}}` numeric)

## Impact if it IS real

- Remote code execution on the rendering host (the default outcome — almost every engine leaks a path to it)
- Server-side data exfiltration via gadget chains (filesystem, env vars, internal HTTP)
- Cloud credential theft via metadata service access from the compromised host
- Lateral movement into internal services reachable from the renderer
- Persistent backdoor via web shell or service-account key planting
- Build / supply-chain compromise when the templated content is a build artifact

---

Adapted from the strix project's `skills/vulnerabilities/ssti.md` (Apache-2.0). Changes: sections
covering live-target testing, validation and bypass techniques were removed, because
docket's triage agent reads source and executes nothing; the remaining text is
unmodified. See NOTICE.
