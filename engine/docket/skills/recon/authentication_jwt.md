---
name: recon-authentication_jwt
description: JWT and OIDC security testing covering token forgery, algorithm confusion, and claim manipulation
---

# authentication jwt — for reconnaissance over source

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

- Web/mobile/API authentication using JWT (JWS/JWE) and OIDC/OAuth2
- Access vs ID tokens, refresh tokens, device/PKCE/Backchannel flows
- First-party and microservices verification, gateways, and JWKS distribution

## Shapes this takes in code

### Signature Verification

- RS256→HS256 confusion: change alg to HS256 and use the RSA public key as HMAC secret if algorithm is not pinned
- "none" algorithm acceptance: set `"alg":"none"` and drop the signature if libraries accept it
- ECDSA malleability/misuse: weak verification settings accepting non-canonical signatures

### Header Manipulation

- **kid injection**: path traversal `../../../../keys/prod.key`, SQL/command/template injection in key lookup, or pointing to world-readable files
- **jku/x5u abuse**: host attacker-controlled JWKS/X509 chain; if not pinned/whitelisted, server fetches and trusts attacker keys
- **jwk header injection**: embed attacker JWK in header; some libraries prefer inline JWK over server-configured keys
- **SSRF via remote key fetch**: exploit JWKS URL fetching to reach internal hosts

### Key and Cache Issues

- JWKS caching TTL and key rollover: accept obsolete keys; race rotation windows; missing kid pinning → accept any matching kty/alg
- Mixed environments: same secrets across dev/stage/prod; key reuse across tenants or services
- Fallbacks: verification succeeds when kid not found by trying all keys or no keys (implementation bugs)

### Claims Validation Gaps

- iss/aud/azp not enforced: cross-service token reuse; accept tokens from any issuer or wrong audience
- scope/roles fully trusted from token: server does not re-derive authorization; privilege inflation via claim edits when signature checks are weak
- exp/nbf/iat not enforced or large clock skew tolerance; accept long-expired or not-yet-valid tokens
- typ/cty not enforced: accept ID token where access token required (token confusion)

### Token Confusion and OIDC

- Access vs ID token swap: use ID token against APIs when they only verify signature but not audience/typ
- OIDC mix-up: redirect_uri and client mix-ups causing tokens for Client A to be redeemed at Client B
- PKCE downgrades: missing S256 requirement; accept plain or absent code_verifier
- State/nonce weaknesses: predictable or missing → CSRF/logical interception of login
- Device/Backchannel flows: codes and tokens accepted by unintended clients or services

### Refresh and Session

- Refresh token rotation not enforced: reuse old refresh token indefinitely; no reuse detection
- Long-lived JWTs with no revocation: persistent access post-logout
- Session fixation: bind new tokens to attacker-controlled session identifiers or cookies

### Transport and Storage

- Token in localStorage/sessionStorage: susceptible to XSS exfiltration; cookie vs header trade-offs with SameSite/CSRF
- Insecure CORS: wildcard origins with credentialed requests expose tokens and protected responses
- TLS and cookie flags: missing Secure/HttpOnly; lack of mTLS or DPoP/"cnf" binding permits replay from another device

## Special Contexts

### Mobile

- Deep-link/redirect handling bugs leak codes/tokens; insecure WebView bridges exposing tokens
- Token storage in plaintext files/SQLite/Keychain/SharedPrefs; backup/adb accessible

### SSO Federation

- Misconfigured trust between multiple IdPs/SPs, mixed metadata, or stale keys lead to acceptance of foreign tokens

---

Adapted from the strix project's `skills/vulnerabilities/authentication_jwt.md` (Apache-2.0). Changes: sections
covering live-target testing, validation and bypass techniques were removed, because
docket's recon agent reads source and executes nothing; the remaining text is
unmodified. See NOTICE.
