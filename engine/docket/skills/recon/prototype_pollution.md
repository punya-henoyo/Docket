---
name: recon-prototype_pollution
description: Client and server prototype pollution testing covering JavaScript object merge bugs, Node.js RCE chains, and filter bypasses
---

# prototype pollution — for reconnaissance over source

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

**Languages & Runtimes**
- JavaScript/TypeScript (browser and Node.js)
- JSON parsers that preserve `__proto__`, `constructor`, `prototype` keys
- Server-side template engines and config merge utilities

**Input Vectors**
- JSON request bodies, query strings, multipart form fields
- URL-encoded nested objects (`__proto__[key]=value`)
- WebSocket messages, GraphQL variables, file import formats (JSON, YAML)

**Vulnerable Patterns**
- Deep merge/extend: `lodash.merge`, `jQuery.extend`, custom `Object.assign` loops
- Query parsers: `qs`, `body-parser` with nested object support
- Client-side routing, state hydration, analytics SDK config merges

## Shapes this takes in code

### Client-Side Prototype Pollution

**Gadget Effects**
- Bypass auth checks reading `user.isAdmin` when polluted on prototype
- DOM XSS via polluted properties consumed by `innerHTML`, `document.write`, script loaders
- Cookie/session manipulation if app reads config from polluted defaults

**Payload Shapes**
```json
{"__proto__": {"isAdmin": true}}
{"constructor": {"prototype": {"isAdmin": true}}}
{"__proto__.polluted": "yes"}
```

**URL-encoded (qs-style)**
```
?__proto__[isAdmin]=true
?constructor[prototype][isAdmin]=true
```

### Server-Side Prototype Pollution (Node.js)

**Common Sinks**
- `lodash.merge`, `lodash.defaultsDeep`, `deep-extend`, `merge-options`
- Express/query parsers accepting nested objects
- YAML `load()` (not `safeLoad`) with prototype keys
- JSON.parse → merge into existing object without null prototype

**RCE Gadget Chains (Node.js)**
Pollute properties consumed by child_process, template engines, or require paths:
```json
{"__proto__": {"shell": "/proc/self/exe", "argv0": "node", "NODE_OPTIONS": "--require /tmp/evil.js"}}
{"__proto__": {"outputFunctionName": "x;process.mainModule.require('child_process').execSync('id')//"}}
```

Gadget availability depends on package versions — enumerate `node_modules` in white-box scans.

### Filter Bypasses

**Key Sanitization Bypasses**
- Unicode normalization: `__proto__` variants, fullwidth underscores
- Nested forms: `constructor.prototype` instead of `__proto__`
- Array pollution: `__proto__[0]`, `[].__proto__`
- JSON `$` or `.` keys in some parsers (MongoDB-style operators overlap — see nosql_injection skill)

**Freeze/Seal Gaps**
- Pollution before `Object.freeze` on instance but not prototype
- Pollution affecting newly created objects after merge

---

Adapted from the strix project's `skills/vulnerabilities/prototype_pollution.md` (Apache-2.0). Changes: sections
covering live-target testing, validation and bypass techniques were removed, because
docket's recon agent reads source and executes nothing; the remaining text is
unmodified. See NOTICE.
