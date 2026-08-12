---
name: triage-mass_assignment
description: Mass assignment testing for unauthorized field binding and privilege escalation via API parameters
---

# mass assignment — for triage over source

You are judging whether a reported finding is REACHABLE by
untrusted input, by reading source. You execute nothing.

The "Not a bug when" list below is the important half. Your job is as much ruling
things out as confirming them: a finding you can show is unreachable saves someone a
day, and a wrong `exploitable` verdict costs the same person a day. When the source
does not settle it, return `uncertain` — that is a real answer, not a failure.

## Not a bug when

- Server recomputes derived fields (plan/price/role) ignoring client input
- Fields marked read-only and enforced consistently across encodings
- Only UI-side changes with no persisted effect

## Impact if it IS real

- Privilege escalation and admin feature access
- Cross-tenant or cross-account resource takeover
- Financial/billing manipulation and quota abuse
- Policy/approval bypass by toggling verification or status flags

---

Adapted from the strix project's `skills/vulnerabilities/mass_assignment.md` (Apache-2.0). Changes: sections
covering live-target testing, validation and bypass techniques were removed, because
docket's triage agent reads source and executes nothing; the remaining text is
unmodified. See NOTICE.
