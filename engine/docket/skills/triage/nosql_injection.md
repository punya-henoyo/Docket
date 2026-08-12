---
name: triage-nosql_injection
description: NoSQL injection testing covering MongoDB operator injection, authentication bypass, blind extraction, GraphQL variable injection, and Redis/DynamoDB/Elasticsearch/Neo4j-specific attack surfaces
---

# nosql injection — for triage over source

You are judging whether a reported finding is REACHABLE by
untrusted input, by reading source. You execute nothing.

The "Not a bug when" list below is the important half. Your job is as much ruling
things out as confirming them: a finding you can show is unreachable saves someone a
day, and a wrong `exploitable` verdict costs the same person a day. When the source
does not settle it, return `uncertain` — that is a real answer, not a failure.

## Not a bug when

- Framework-level query builder that casts input to string before constructing the query (Mongoose `strict` mode on)
- Input sanitization stripping operator keys before they reach the driver
- Endpoints that accept JSON but cast the `password` field to string — operator object becomes `[object Object]`
- Response differences caused by validation errors, not actual operator execution

## Impact if it IS real

- Authentication bypass granting access to arbitrary or all accounts
- Full extraction of sensitive fields (tokens, hashed passwords, PII) via blind regex enumeration
- Privilege escalation by querying admin/superuser records directly
- Data exfiltration at scale via widened `$ne`/`$regex`/`$gt` filters
- Server-side JavaScript execution via `$where` on unpatched MongoDB instances

---

Adapted from the strix project's `skills/vulnerabilities/nosql_injection.md` (Apache-2.0). Changes: sections
covering live-target testing, validation and bypass techniques were removed, because
docket's triage agent reads source and executes nothing; the remaining text is
unmodified. See NOTICE.
