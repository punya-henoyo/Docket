---
name: recon-mass_assignment
description: Mass assignment testing for unauthorized field binding and privilege escalation via API parameters
---

# mass assignment — for reconnaissance over source

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

- REST/JSON, GraphQL inputs, form-encoded and multipart bodies
- Model binding in controllers/resolvers; ORM create/update helpers
- Writable nested relations, sparse/patch updates, bulk endpoints

## Shapes this takes in code

### Privilege Escalation

- Set role/isAdmin/permissions during signup/profile update
- Toggle admin/staff flags where exposed

### Ownership Takeover

- Change ownerId/accountId/tenantId to seize resources
- Move objects across users/tenants

### Feature Gate Bypass

- Enable premium/beta/feature flags via flags/features fields
- Raise limits/seatCount/quotas

### Billing and Entitlements

- Modify plan/price/prorate/trialEnd or creditBalance
- Bypass server recomputation

### Nested and Relation Writes

- Writable nested serializers or ORM relations allow creating or linking related objects beyond caller's scope

---

Adapted from the strix project's `skills/vulnerabilities/mass_assignment.md` (Apache-2.0). Changes: sections
covering live-target testing, validation and bypass techniques were removed, because
docket's recon agent reads source and executes nothing; the remaining text is
unmodified. See NOTICE.
