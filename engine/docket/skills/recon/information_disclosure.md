---
name: recon-information_disclosure
description: Information disclosure testing covering error messages, debug endpoints, metadata leakage, and source exposure
---

# information disclosure — for reconnaissance over source

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

- Errors and exception pages: stack traces, file paths, SQL, framework versions
- Debug/dev tooling reachable in prod: debuggers, profilers, feature flags
- DVCS/build artifacts and temp/backup files: .git, .svn, .hg, .bak, .swp, archives
- Configuration and secrets: .env, phpinfo, appsettings.json, Docker/K8s manifests
- API schemas and introspection: OpenAPI/Swagger, GraphQL introspection, gRPC reflection
- Client bundles and source maps: webpack/Vite maps, embedded env, `__NEXT_DATA__`, static JSON
- Headers and response metadata: Server/X-Powered-By, tracing, ETag, Accept-Ranges, Server-Timing
- Storage/export surfaces: public buckets, signed URLs, export/download endpoints
- Observability/admin: /metrics, /actuator, /health, tracing UIs (Jaeger, Zipkin), Kibana, Admin UIs
- Directory listings and indexing: autoindex, sitemap/robots revealing hidden routes

## Shapes this takes in code

### Differential Oracles

- Compare owner vs non-owner vs anonymous for the same resource
- Track: status, length, ETag, Last-Modified, Cache-Control
- HEAD vs GET: header-only differences can confirm existence
- Conditional requests: 304 vs 200 behaviors leak existence/state

### CDN and Cache Keys

- Identity-agnostic caches: CDN/proxy keys missing Authorization/tenant headers
- Vary misconfiguration: user-agent/language vary without auth vary leaks content
- 206 partial content + stale caches leak object fragments

### Cross-Channel Mirroring

- Inconsistent hardening between REST, GraphQL, WebSocket, and gRPC
- SSR vs CSR: server-rendered pages omit fields while JSON API includes them

---

Adapted from the strix project's `skills/vulnerabilities/information_disclosure.md` (Apache-2.0). Changes: sections
covering live-target testing, validation and bypass techniques were removed, because
docket's recon agent reads source and executes nothing; the remaining text is
unmodified. See NOTICE.
