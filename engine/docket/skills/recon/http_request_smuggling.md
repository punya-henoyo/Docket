---
name: recon-http_request_smuggling
description: HTTP request smuggling testing covering CL.TE, TE.CL, H2.CL, H2.TE, and HTTP/2 desync techniques with practical detection and exploitation methodology
---

# http request smuggling — for reconnaissance over source

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

**Infrastructure Topologies**
- CDN or load balancer in front of origin server (Cloudflare, Nginx, HAProxy, AWS ALB)
- Reverse proxy chains (Nginx → Gunicorn, HAProxy → Node.js, Varnish → Apache)
- API gateways forwarding to microservices
- HTTP/2 front-end to HTTP/1.1 back-end translation (H2.CL / H2.TE)
- Tunneling servers or WAFs that terminate and re-forward requests

**HTTP Versions in Play**
- HTTP/1.1: CL.TE and TE.CL classic smuggling
- HTTP/2: H2.CL (downgrade injects Content-Length) and H2.TE (injects Transfer-Encoding)
- HTTP/3: emerging QUIC-based desync (less common, research-stage)

**Parser Differentials**
- Treatment of duplicate `Content-Length` headers
- Handling of `Transfer-Encoding: chunked` when `Content-Length` is also present
- Chunk size obfuscation via whitespace, tab, case, or invalid extensions

## Shapes this takes in code

### Front-End Security Control Bypass

A front-end proxy enforces authentication or IP restriction by checking request headers and blocking or allowing based on rules. If a smuggled prefix bypasses the front-end (because it's buried in a prior request's body from the front-end's view), the back-end processes it without the security check.

**PoC structure (CL.TE):**
```http
POST /not-restricted HTTP/1.1
Host: target.com
Content-Length: 100
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: target.com
X-Forwarded-Host: target.com
Content-Length: 10

x=1
```
The `GET /admin` is seen by the back-end as a new, legitimate request originating from the trusted proxy IP.

### Cross-User Request Capture

Poison the back-end socket with a partial request prefix that captures the next victim user's request (including their cookies, tokens, request body) into the response of a controlled endpoint (search, comment submission).

**PoC structure (CL.TE capture):**
```http
POST /search HTTP/1.1
Host: target.com
Content-Length: 120
Transfer-Encoding: chunked

0

POST /search HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 100

q=
```
`Content-Length: 100` in the smuggled prefix is longer than the actual smuggled body, so the back-end waits for 100 bytes — which it sources from the *next* user's request. The `/search` endpoint reflects the query, capturing headers and body of the subsequent request.

### Response Queue Poisoning

On pipelined connections, cause a misaligned response to be delivered to the wrong user (HTTP/1.1 response queue poisoning). Used to deliver attacker-controlled content or steal another user's response.

### Request Reflection / Cache Poisoning Chain

Smuggle a prefix that hits a cacheable endpoint with an injected `Host` header. If the cache stores the response keyed only on URL, the poisoned response is served to all users requesting that URL.

### WebSocket Handshake Hijacking

If the proxy performs WebSocket upgrade, a smuggled `Upgrade` request can hijack an existing WebSocket connection from a subsequent user.

## Where to look first

- Front-end security controls (authentication bypass via desync)
- Endpoints shared by many users (high-traffic APIs, chat, feeds)
- Request capture endpoints (search, logging, analytics)
- Session-sensitive endpoints (auth callbacks, account settings)
- Internal admin interfaces proxied through the same connection pool

---

Adapted from the strix project's `skills/vulnerabilities/http_request_smuggling.md` (Apache-2.0). Changes: sections
covering live-target testing, validation and bypass techniques were removed, because
docket's recon agent reads source and executes nothing; the remaining text is
unmodified. See NOTICE.
