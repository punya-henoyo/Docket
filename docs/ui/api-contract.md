# Code Security console: API and file contract

The console (app/frontend) reads these endpoints from the stdlib server in
`engine/docket/interface/connect.py`. New routes are implemented in
`engine/docket/portfolio/` and wired into the handler with one line each. All JSON, all GET, all
loopback. Shapes mirror `docs/ui/mockup/sample.js`, which is what the approved mockup renders.

Nothing here may invent data. A field with no source is `null` or absent and the UI says so.

## Inputs on disk (cwd is the working directory; runs live in `./docket_runs/`)

| File | Who writes it | Shape |
|---|---|---|
| `docket_runs/<run>/report.json` | the scan | existing, plus `stage_timings` and `run_timing` (below) |
| `docket_runs/<run>/events.jsonl` | the scan | existing: `{type, ts, agent_id, role, data}` |
| `docket_portfolio.json` | the user (or the demo seeder) | `{ "organization": str, "cadence_days": 7, "applications": [{ "repo": "owner/name", "label": str, "tier": "Tier 1", "owner": str, "lang": str, "policy": "<policy id>" }] }` |
| `docket_policy.json` | the user (or the demo seeder) | `{ "policies": [Policy] }` (below). Absent: the built-in default policy applies to every application. |

A run belongs to an application by `report.provenance.repo`, else the `owner/name` in `target`
(`github:owner/name@ref`), else `target` itself. An application with no run is "unknown" (never scanned).

### New in report.json

```json
"stage_timings": { "trivy": {"started": 1760000000.1, "ended": 1760000056.4}, "semgrep": {...}, "nuclei": {...},
                   "recon": {...}, "compliance": {...}, "triage": {...}, "fix": {...}, "apisec": {...} },
"run_timing":   { "started": 1760000000.0, "ended": 1760000760.0 }
```
Epoch seconds, floats. Only stages that began have an entry. A stage with state `skipped` has none.
`apisec` is a reserved key for the Henoyo API Security engine, which reports through the same shape when wired in;
Docket does not run it yet, so for real runs it is absent (rendered "Not run" only when the policy requires it).

## Scanner catalog (code, `portfolio/catalog.py`)

| id | label | tool | origin | phase | stage key |
|---|---|---|---|---|---|
| trivy | Dependencies and secrets | Trivy | third_party | pre | trivy |
| semgrep | Static analysis | Semgrep | third_party | pre | semgrep |
| nuclei | Web templates | Nuclei | third_party | pre | nuclei |
| apisec | API Security engine | | henoyo | pre | apisec |
| recon | Attack-surface recon | | henoyo | agents | recon |
| triage | Triage | | henoyo | agents | triage |
| compliance | Compliance reader | | henoyo | agents | compliance |
| swarm | Exploit swarm | | henoyo | agents | (agents in report.json `agents[]` with role root/specialist; times from events.jsonl) |
| fix | Fix proposals | | henoyo | agents | fix |

## Health level (one function, `portfolio/health.py`, unit-tested)

For an application, from its latest report plus history:

- `unknown`: no report.
- `action`: any open **proven** finding (see proof below), OR a deterministic-floor secret in source, OR the latest scan's gate would fail.
- `attention`: not action, and any of: a required scanner missing or stale (older than cadence), a reachable critical CVE, triage UNCERTAIN > 0 on a high or critical, partial coverage, no scan inside the cadence.
- `clear`: otherwise.
- `reason`: one plain sentence naming the worst cause. Never a percentage. Never the word "compliant".

### Proof (per finding)

- `reproduced`: a Finding discovered by an agent (not trivy/semgrep/nuclei), or status `validated`, or with corroborating_evidence. It has a PoC.
- `deterministic`: a rule-floor finding (secret in source; the list in `service/gate.py`) that needs no exploit.
- `candidate`: a scanner finding or `flagged_not_proven` entry, triage CONFIRMED/UNCERTAIN or untriaged. `reach` = Reachable (correlated to an endpoint) / Uncertain / null.
- `not_reachable`: triage FALSE_POSITIVE or `not_reachable`.

## Endpoints

### GET /api/portfolio
```json
{ "generated_at": "iso", "window_days": 28, "cadence_days": 7, "organization": "str",
  "counts": {"action": 2, "attention": 4, "clear": 5, "unknown": 1},
  "applications": [ { "id": "ibank/card-payments", "label": "Card Payments API", "repo": "ibank/card-payments", "tier": "Tier 1",
      "owner": "str", "lang": "str", "level": "action|attention|clear|unknown", "reason": "str", "age_days": 3,
      "last_scan_at": "iso|null", "events": [ {"id": "<run name>", "at": "iso", "coverage": "full|partial|failed",
                                             "proven": 0, "candidates": 0, "kind": "scan|pr", "label": "str|null"} ] } ],
  "scanner_coverage": [ {"id":"trivy","label":"Dependencies and secrets","tool":"Trivy","origin":"third_party","required":true,"current":5,"of":6} ],
  "trend": { "periods": [{"key":"w0","label":"3 w ago"}], "series": [{"key":"critical","label":"Critical","values":[0,1]}] },
  "severity_age": { "old_critical": 3, "old_age": "14 days", "rows": ["critical","high","medium","low"],
                    "columns": ["0-30","31-90","91-180","181+"], "cells": [{"row":"critical","col":"0-30","value":3}] } }
```
`events[].coverage`: `full` = every scanner the policy requires ran and none errored; `partial` = a required one did not run; `failed` = a stage errored or the run did not finish.
`scanner_coverage` has one entry per required step of the default (first matching) policy: how many applications under it ran that scanner inside the cadence window.
It replaces any "findings by tool" chart: counting scanner candidates beside proven findings would present leads as findings (AGENTS.md rule 10).

### GET /api/application/<url-encoded id>
```json
{ "application": { ...as above... },
  "health": { "level": "action", "verdict": "str", "reasons": ["str"],
     "annunciators": [ {"key":"proven","label":"Proven exploits","state":"ok|warn|bad|off","value":"2","hint":"str","advisory":false} ],
     "analytes": [ {"key":"proven","label":"Proven exploitable","hint":"str","value":2,"display":"2","scaleMax":6,
                    "bands":[{"from":0,"to":0.4,"tone":"ok"},{"from":0.4,"to":6,"tone":"bad"}],"ref":"0",
                    "flag":"ok|warn|bad|unknown","flagWord":"Out of range","trend":[0,0,1],"previous":"1"} ] },
  "banner": [ {"id":"b1","level":"danger|warning|info|success","word":"Exploit proven","message":"str","reason":"str","actionLabel":"str|null","href":"str|null"} ],
  "lifecycle": { "current": "onboarded|scanned|proven|fix_proposed|fix_merged|verified", "since": "iso", "owner": "str" },
  "pipeline": { "run": "<run name>|null", "lanes": [Lane], "groups": [Group], "policy": "str|null" },
  "findings": [Finding], "scans": [ {"id":"run","at":"iso","kind":"scan|pr","coverage":"full|partial|failed","proven":0,"candidates":0} ],
  "fixes": [ {"title":"str","fixes":"str","status":"str","url":"str|null","opened_at":"iso"} ],
  "compliance": [ {"pack_id":"rbi-csf","title":"str","met":6,"not_met":5,"unknown":3,"not_observable":26} ] }
```
An annunciator's `state` must equal the `flag` of the analyte it summarises (one fact, one colour); the compliance annunciator has `advisory: true`, never `bad`, and no analyte.
Analyte set (fixed order, each with a policy-derived reference): proven exploitable (ref 0), reachable not proven (ref 3 or fewer),
secrets in source (0), critical dependency CVEs (0), oldest open critical in days (ref 7 or fewer), required scanners that ran (n of n),
triage could not decide (2 or fewer). Annunciators: proven, secrets, critical CVEs, required scanners, last scan, compliance (worst pack), fix PRs.
`trend` is the last 8 scans' values. If fewer than 2 scans, omit it. If no scan, `analytes: []`.

### GET /api/pipeline/<run name>
```json
{ "run": "name", "application": "id", "started_at": "iso", "ended_at": "iso|null", "elapsed": 760.0, "commit": "a91f3c2|null",
  "cost_usd": 1.84, "agents": 6, "tokens": {"input": 41200, "output": 9800}, "policy": "str|null",
  "lanes": [Lane], "groups": [Group] }
```
- `Lane` = `{ id, label, tool?, origin: "henoyo|third_party", group: "pre|agents", state: "done|running|queued|error|skipped|not_run", icon, start?, end?, required?, requiredBy?: [str], candidates?, proven?, summary?, cost?, parentId? }` (start/end are seconds from `run_timing.started`; a `not_run` lane carries the slot after the previous lane).
- `Group` = `{ key: "pre", label: "Before the agents", sub: "Deterministic scanners, run in policy order" }`, `{ key: "agents", label: "Docket agents", sub: "Henoyo exploit validation: recon, triage, compliance, exploit, fix" }`.
- Lanes come from: catalog order = policy step order; times from `stage_timings`; swarm and its specialists from `events.jsonl` (`agent_spawned`/`agent_finished` ts, role, label) and `agents[]`; `required`/`requiredBy` from the policy; `not_run` for a required lane with no timing.

### GET /api/findings
All open findings across the latest run of each application:
`Finding = { id, run, application, sev: critical|high|medium|low|info, title, sub, proof, reach, by: {origin, name}, age_days, status, rule_id, cwe, location, poc: {request, response, notes}|null, triage: {verdict, reasoning, evidence}|null, fix: {summary, diff}|null, evidence_ref: str|null }`.

### GET /api/policy
```json
{ "policies": [ { "id": "tier1-payments", "name": "Tier 1 payments baseline", "applies": "Applications tagged Tier 1", "applies_count": 6,
    "version": 3, "approved": "str|null", "cadence_days": 7,
    "steps": [ { "n": 1, "id": "trivy", "label": "str", "tool": "Trivy|null", "origin": "third_party", "phase": "Before the agents", "required": true,
                 "cadence": "At least every 7 days, and on every pull request", "on_fail": "str",
                 "why": [ {"kind": "security|regulatory", "text": "str", "authority": "RBI|null", "obligation_ref": "rbi-csf:secrets|null", "clause": "str|null", "source_url": "str|null"} ] } ],
    "regulatory": [ {"authority": "RBI", "text": "str", "obligation_ref": "str", "clause": "str|null", "source_url": "str|null"} ],
    "security": [ {"text": "str", "detail": "str"} ],
    "gate": [ {"effect": "blocks|flags|advises", "text": "str"} ] } ],
  "coverage": { "policy": "tier1-payments", "window_days": 7, "scanners": [ {"id":"trivy","label":"str","tool":"Trivy","origin":"third_party","icon":"package"} ],
                "rows": [ {"id":"repo","label":"str","tier":"Tier 1","cells": {"trivy": {"state":"ok|stale|missing|na","ago":"2 d"}},
                           "consequence": {"effect":"blocks|flags|advises|null","text":"Flagged: API Security engine is 9 days stale"}} ] } }
```
**One definition of "required scanner" everywhere.** A policy's `steps` are the whole sequence that runs, in order, and each carries
`required: true|false`. The *required scanners* are the steps with `required: true`. The same set drives the pipeline's "N of M required scanners ran",
the health card's "Required scanners that ran" measure, the coverage matrix columns and the `coverage: full|partial` of a scan. Optional steps
(Nuclei when a staging URL exists, recon, the compliance reader, fix proposals) appear in the sequence and the pipeline but never count as missing.
The compliance reader is always optional: compliance is advisory and never gates (AGENTS.md rule 15).

**What blocks (gate wording, must match `service/gate.py`):** `blocks` = a reproduced exploit, a hardcoded secret or other deterministic-floor rule,
a triage verdict CONFIRMED. `flags` = a required scanner that did not run inside its window. `advises` = compliance results. A critical dependency CVE is
never listed as blocking: it goes to triage; reachable and unproven it is an `attention` reason. Never write a rule that contradicts these three lists.

Default policy (no `docket_policy.json`): steps trivy, semgrep, then the agents (swarm), cadence 7, gate blocks on reproduced exploit, secret in source, reachable critical CVE.

### Compliance citations (existing `/api/compliance/packs[/<id>]`, extended)
Each control gains `citation_parts: {authority, instrument, section, clause|null, source_url|null}`. The pack's `authority` and `source_url` are used;
`instrument` and `section` are split from the existing `citation` string at " — " or ": " (e.g. `RBI Cyber Security Framework, Annex 1 — Secure configuration` -> instrument `RBI Cyber Security Framework, Annex 1`, section `Secure configuration`).
`clause` is `null` unless the pack data supplies one. **Never invent a clause number.** Packs may add optional `clause` and `obligation_ref` per control.
Control results keep their existing shape. No score, no percent, never "compliant".

## Demo mode
`python -m docket.demo.console` seeds `./.docket-demo/` (runs, portfolio, policy; deterministic, dates relative to now, clearly labelled
`sample: true` in report.json), changes into it, and serves the console on 8765 (or `--port`). The console shows a persistent
"Sample data" badge when `GET /api/portfolio` returns `"sample": true`.
