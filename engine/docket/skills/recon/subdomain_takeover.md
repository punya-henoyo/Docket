---
name: recon-subdomain_takeover
description: Subdomain takeover testing for dangling DNS records and unclaimed cloud resources
---

# subdomain takeover — for reconnaissance over source

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

- Dangling CNAME/A/ALIAS to third-party services (hosting, storage, serverless, CDN)
- Orphaned NS delegations (child zones with abandoned/expired nameservers)
- Decommissioned SaaS integrations (support, docs, marketing, forms) referenced via CNAME
- CDN "alternate domain" mappings (CloudFront/Fastly/Azure CDN) lacking ownership verification
- Storage and static hosting endpoints (S3/Blob/GCS buckets, GitHub/GitLab Pages)

## Shapes this takes in code

### Claim Third-Party Resource

- Create the resource with the exact required name:
  - Storage/hosting: S3 bucket "sub.example.com" (website endpoint)
  - Pages hosting: create repo/site and add the custom domain
  - Serverless/app hosting: create app/site matching the target hostname

### CDN Alternate Domains

- Add the victim subdomain as an alternate domain on your CDN distribution if the provider does not enforce domain ownership checks
- Upload a TLS cert or use managed cert issuance

### NS Delegation Takeover

- If a child zone is delegated to nameservers under an expired domain, register that domain and host authoritative NS
- Publish records to control all hosts under the delegated subzone

### Mail Surface

- If MX points to a decommissioned provider, takeover could enable email receipt for that subdomain

## Special Contexts

### Storage and Static

- S3/GCS/Azure Blob static sites: bucket naming constraints dictate whether a bucket can match hostname
- Website vs API endpoints differ in claimability and fingerprints

### Serverless and Hosting

- GitHub/GitLab Pages, Netlify, Vercel, Azure Static Web Apps: domain binding flows vary
- Most require TXT now, but historical projects may not

### CDN and Edge

- CloudFront/Fastly/Azure CDN/Akamai: alternate domain verification differs
- Some products historically allowed alt-domain claims without proof

### DNS Delegations

- Child-zone NS delegations outrank parent records
- Control of delegated NS yields full control of all hosts below that label

---

Adapted from the strix project's `skills/vulnerabilities/subdomain_takeover.md` (Apache-2.0). Changes: sections
covering live-target testing, validation and bypass techniques were removed, because
docket's recon agent reads source and executes nothing; the remaining text is
unmodified. See NOTICE.
