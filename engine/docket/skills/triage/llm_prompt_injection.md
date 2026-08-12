---
name: triage-llm_prompt_injection
description: Testing LLM-backed features for prompt injection, jailbreaks, system-prompt leakage, tool/agent abuse, and unsafe output handling
---

# llm prompt injection — for triage over source

You are judging whether a reported finding is REACHABLE by
untrusted input, by reading source. You execute nothing.

The "Not a bug when" list below is the important half. Your job is as much ruling
things out as confirming them: a finding you can show is unreachable saves someone a
day, and a wrong `exploitable` verdict costs the same person a day. When the source
does not settle it, return `uncertain` — that is a real answer, not a failure.

## Not a bug when

- The model *saying* it will do something without a privileged sink or tool to actually do it
- Refusals or hallucinated "system prompts" that don't match reality
- Output that is properly encoded/sanitized before reaching HTML/SQL/shell sinks
- Behavior not reproducible across runs (non-determinism, not a real bypass)
- Sandboxed tools with no access to sensitive data or actions

## Impact if it IS real

- Exfiltration of secrets, system prompts, and cross-tenant data
- Unauthorized privileged actions via tool/agent abuse (send/delete/modify)
- Stored XSS and downstream injection through unescaped model output
- Bypass of content policy and business rules; reputational and compliance harm

---

Adapted from the strix project's `skills/vulnerabilities/llm_prompt_injection.md` (Apache-2.0). Changes: sections
covering live-target testing, validation and bypass techniques were removed, because
docket's triage agent reads source and executes nothing; the remaining text is
unmodified. See NOTICE.
