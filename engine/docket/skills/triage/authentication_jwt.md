---
name: triage-authentication_jwt
description: JWT and OIDC security testing covering token forgery, algorithm confusion, and claim manipulation
---

# authentication jwt — for triage over source

You are judging whether a reported finding is REACHABLE by
untrusted input, by reading source. You execute nothing.

The "Not a bug when" list below is the important half. Your job is as much ruling
things out as confirming them: a finding you can show is unreachable saves someone a
day, and a wrong `exploitable` verdict costs the same person a day. When the source
does not settle it, return `uncertain` — that is a real answer, not a failure.

## Not a bug when

- Token rejected due to strict audience/issuer enforcement
- Key pinning with JWKS whitelist and TLS validation
- Short-lived tokens with rotation and revocation on logout
- ID token not accepted by APIs that require access tokens

## Impact if it IS real

- Account takeover and durable session persistence
- Privilege escalation via claim manipulation or cross-service acceptance
- Cross-tenant or cross-application data access
- Token minting by attacker-controlled keys or endpoints

---

Adapted from the strix project's `skills/vulnerabilities/authentication_jwt.md` (Apache-2.0). Changes: sections
covering live-target testing, validation and bypass techniques were removed, because
docket's triage agent reads source and executes nothing; the remaining text is
unmodified. See NOTICE.
