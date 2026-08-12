---
name: triage-open_redirect
description: Open redirect testing for phishing pivots, OAuth token theft, and allowlist bypass
---

# open redirect — for triage over source

You are judging whether a reported finding is REACHABLE by
untrusted input, by reading source. You execute nothing.

The "Not a bug when" list below is the important half. Your job is as much ruling
things out as confirming them: a finding you can show is unreachable saves someone a
day, and a wrong `exploitable` verdict costs the same person a day. When the source
does not settle it, return `uncertain` — that is a real answer, not a failure.

## Not a bug when

- Redirects constrained to relative same-origin paths with robust normalization
- Exact pre-registered OAuth redirect_uri with strict verifier
- Validators using a single canonical parser and comparing post-IDNA host and scheme
- User prompts that show the exact final destination before navigating

## Impact if it IS real

- Credential and token theft via phishing and OAuth/OIDC interception
- Internal data exposure when server fetchers follow redirects
- Policy bypass where allowlists are enforced only on the first hop
- Cross-application trust erosion and brand abuse

---

Adapted from the strix project's `skills/vulnerabilities/open_redirect.md` (Apache-2.0). Changes: sections
covering live-target testing, validation and bypass techniques were removed, because
docket's triage agent reads source and executes nothing; the remaining text is
unmodified. See NOTICE.
