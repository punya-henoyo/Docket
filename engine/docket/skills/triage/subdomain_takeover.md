---
name: triage-subdomain_takeover
description: Subdomain takeover testing for dangling DNS records and unclaimed cloud resources
---

# subdomain takeover — for triage over source

You are judging whether a reported finding is REACHABLE by
untrusted input, by reading source. You execute nothing.

The "Not a bug when" list below is the important half. Your job is as much ruling
things out as confirming them: a finding you can show is unreachable saves someone a
day, and a wrong `exploitable` verdict costs the same person a day. When the source
does not settle it, return `uncertain` — that is a real answer, not a failure.

## Not a bug when

- "Unknown domain" pages that are not claimable due to enforced TXT/ownership checks
- Provider-branded default pages for valid, owned resources (not a takeover)
- Soft 404s from your own infrastructure or catch-all vhosts

## Impact if it IS real

- Content injection under trusted subdomain: phishing, malware delivery, brand damage
- Cookie and CORS pivot: if parent site sets Domain-scoped cookies or allows subdomain origins
- OAuth/SSO abuse via whitelisted redirect URIs
- Email delivery manipulation for subdomain

---

Adapted from the strix project's `skills/vulnerabilities/subdomain_takeover.md` (Apache-2.0). Changes: sections
covering live-target testing, validation and bypass techniques were removed, because
docket's triage agent reads source and executes nothing; the remaining text is
unmodified. See NOTICE.
