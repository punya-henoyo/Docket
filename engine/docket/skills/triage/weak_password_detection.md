---
name: triage-weak_password_detection
description: Weak password detection, credential stuffing, and brute-force testing using common passwords, system-generated credentials, and HTTP fuzzing / NSE brute-force tooling
---

# weak password detection — for triage over source

You are judging whether a reported finding is REACHABLE by
untrusted input, by reading source. You execute nothing.

The "Not a bug when" list below is the important half. Your job is as much ruling
things out as confirming them: a finding you can show is unreachable saves someone a
day, and a wrong `exploitable` verdict costs the same person a day. When the source
does not settle it, return `uncertain` — that is a real answer, not a failure.

## Not a bug when

- Honey accounts or honeypot responses designed to mislead attackers
- Temporary lockouts that resolve quickly (distinguish from permanent bans)
- Different error messages that don't actually indicate valid username enumeration
- CAPTCHA or WAF blocking that appears as a failed login
- Rate limiting that returns 429 instead of 401 (adjust timing)

## Impact if it IS real

- Complete account takeover for affected users
- Administrative access leading to full system compromise
- Lateral movement via reused credentials across services
- Data exfiltration, privilege escalation, and persistence
- Reputational damage and compliance violations (GDPR, PCI-DSS)

---

Adapted from the strix project's `skills/vulnerabilities/weak_password_detection.md` (Apache-2.0). Changes: sections
covering live-target testing, validation and bypass techniques were removed, because
docket's triage agent reads source and executes nothing; the remaining text is
unmodified. See NOTICE.
