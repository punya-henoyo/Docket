---
name: recon-weak_password_detection
description: Weak password detection, credential stuffing, and brute-force testing using common passwords, system-generated credentials, and HTTP fuzzing / NSE brute-force tooling
---

# weak password detection — for reconnaissance over source

You are READING SOURCE, not sending requests. Nothing below is a
step to perform against a running application; it is a description of where this class
of bug lives and what it looks like in code.

Use it to decide **where to read** and **what to compare**. The highest-value finding
in this class is usually an ABSENCE — a check that every sibling handler performs and
this one does not. You cannot grep for a line that was never written, so find it by
reading neighbours and noticing the disagreement.

Record what you find with `record_surface` as a candidate, citing file and line. A
candidate is a suspicion with evidence, never a proven vulnerability.

## Where this lives

- Login portals (web, API, mobile, SSH, FTP, Telnet, RDP)
- Admin panels, dashboards, and management interfaces
- Default or hardcoded credentials in applications and devices
- Self-registration flows with weak password policies
- Password reset flows that generate predictable tokens or passwords
- API key and token authentication with weak secrets

## Shapes this takes in code

### Weak Password Policies

- No minimum length or complexity requirements
- Allowing common passwords: `password`, `123456`, `qwerty`, `admin`, `letmein`
- Not checking against breached password databases (Have I Been Pwned)
- Case-insensitive password storage
- No password history enforcement
- Excessively short maximum length (indicates plaintext or weak hashing)

### Default and Hardcoded Credentials

- Vendor defaults: `admin/admin`, `admin/password`, `root/root`, `guest/guest`
- Application frameworks: `django/admin`, `tomcat/tomcat`, `weblogic/weblogic`
- IoT devices, routers, cameras: manufacturer-specific defaults
- Database defaults: `postgres/postgres`, `sa/sa`, `root/(empty)`
- Cloud defaults: AWS instance metadata, Azure default service principals
- Hardcoded in source code, configuration files, or documentation

### Credential Stuffing

- Users reuse passwords across services
- Breached credential lists (COMB, Collection #1-5, etc.) enable mass account takeover
- No multi-factor authentication allows direct access with valid credentials
- Missing breach detection or forced password rotation after known leaks

### Predictable System-Generated Passwords

- Sequential or pattern-based: `Password1`, `Welcome2025!`, `CompanyName123`
- Time-based generation: passwords derived from registration timestamp
- Weak randomness: predictable PRNG seeds in password generators
- Reset tokens that double as temporary passwords with short expiration

### Brute-Force Vulnerabilities

- No rate limiting on login attempts
- Absent or ineffective account lockout (client-side only, easily bypassed)
- IP-based blocking without session/user correlation (rotate IPs via proxy)
- CAPTCHA bypassable or only triggered after excessive attempts
- Parallel login attempts not tracked (race conditions on attempt counters)
- Verbose error messages revealing valid usernames

---

Adapted from the strix project's `skills/vulnerabilities/weak_password_detection.md` (Apache-2.0). Changes: sections
covering live-target testing, validation and bypass techniques were removed, because
docket's recon agent reads source and executes nothing; the remaining text is
unmodified. See NOTICE.
