# Policy builder and posture map: design and contract (v2)

Founder brief (2026-10-19), condensed:

1. A **policy** says "for this kind of application, run these checks, in this order, from any
   vendor, then apply these regulatory guidelines". Policies are chosen by category (banking vs
   non-banking), exposure (customer-facing vs internal), stack and tier. A person must be able to
   SEE a policy, BUILD one visually, and watch a RUN of it as evidence ("click this, this happens";
   later it happens by itself).
2. Customers use market-leading scanners whatever the vendor. Docket's own scanner is one step.
3. An **aggregate view**: how many assessments ran, what came out, which applications are worst and
   best, a **two-by-two** (magic-quadrant style) of where every application sits on source-code
   security, and how that is **evolving** (more robust or less). Glanceable in 15 seconds; click a
   dot to go to the application and its assessments.

This builds on `docs/ui/api-contract.md` (v1). Everything not changed here is as in v1.

## 1. Honesty rules (they decide the design)

* **One required-scanner definition** stays (policy steps with `required: true`).
* **Position is not a grade.** The two-by-two plots two *named, explainable* measures. No composite
  score, no percentage, no rank number is shown on a dot. Compliance results are NOT an axis input
  (AGENTS.md rules 13 and 14). The word "compliant" never appears.
* **Quiet is not safe.** An application with few findings and little assessment must not look good.
  That is the whole reason there are two axes.
* **Unassessed applications are not plotted.** No evidence means no coordinates. They sit in a
  "Not assessed" tray beside the chart (never at standing 100).
* **Availability is stated.** Every tool in the palette carries one of `runs` (Docket runs it today),
  `imports` (Docket ingests its SARIF results and records that the slot ran, see 3a) or `planned`.
  `planned` tools are visible and disabled, never selectable, never saved.
* **A policy judges; it does not configure the run.** Docket runs a fixed pipeline (scanners, then
  agents). The policy decides what must have run, how recently, and what a gap means. The builder
  says so, shows steps in the order Docket really runs them, and has no reordering. Steps with
  no effect on the run are never presented as if the policy started them.
* **Starting is stated, not configured.** The flow's first node shows how assessments start:
  "Run now" (works), "Pull request" (works where the repository is watched), "Every N days"
  (`cadence_days` is what Docket JUDGES staleness against; Docket does not start scans by itself yet,
  tagged Planned). There is no `triggers` field in a policy.
* **A preview is a plan, not a result.** "Preview a run" shows what each step will do and what it
  will produce. It never shows invented outcomes. Results come only from a real run's evidence.
* **Gate wording is fixed** (blocks = reproduced exploit / deterministic-floor secret / triage
  CONFIRMED; flags = required scanner missing; advises = compliance). A policy cannot change it; the
  builder shows it read-only.
* The compliance step is always optional/advisory (v1 rule).
* Clause numbers are never invented (v1 rule).

## 2. Application profile (new fields on every application)

`category`: `Banking` | `Non-banking`. `exposure`: `Customer-facing` | `Partner-facing` | `Internal`.
`stack`: `Web` | `API` | `Mobile` | `Batch`. Existing `tier` (`Tier 1..3`) stays. All come from
`docket_portfolio.json`; missing means `null` and the application matches only policies that do not
constrain that field.

## 3. Policy (extends v1 `Policy`)

```jsonc
{
  "id": "banking-customer",
  "name": "Banking, customer-facing",
  "applies": "Customer-facing banking applications",       // sentence, derived if absent
  "applies_when": { "category": ["Banking"], "exposure": ["Customer-facing"], "stack": [], "tier": [] },
  "cadence_days": 7,
  "steps": [ { "id":"semgrep", "tool":"codeql", "required":true, "cadence_days":null,
               "on_fail":null, "why":[ ... v1 ... ] } ],    // `tool` = chosen vendor; absent = slot default
  "guidelines": ["rbi-csf","sebi-cscrf","owasp-api-2023"],  // compliance pack ids, advisory only
  "regulatory": [ ... v1, now generated from guidelines + step why ... ],
  "security": [ ... v1 ... ],
  "version": 3, "approved": "...", "default": false, "status": "saved"
}
```

* **Assignment** (server, one function, used everywhere): an application's explicit `policy` id wins
  and is reported as `via: "pinned"` with `overrides: <id the profile would have matched>` when
  that differs. Otherwise every policy whose `applies_when` matches is a candidate (a non-empty
  field must contain the application's value; an empty field is unconstrained; v1 `applies_tier`
  is read as `applies_when.tier`). The most specific candidate wins (most non-empty fields). Then a
  policy marked `default`, then the built-in default. Each application carries
  `assignment: {policy, via: "pinned"|"matched"|"default", incomplete: [fields], overrides}`.
  **Fail closed on gaps**: an application whose profile lacks a field that some policy constrains
  is `incomplete`; it still gets the best policy, but the health card says "Profile incomplete:
  category is missing, so the default policy applies" as an attention reason. **Ties** (two
  candidates equally specific for the same application) are refused on save (400, naming both).
* **Floor** (a warning, never a block): a policy whose `applies_when` matches customer-facing
  applications must require `trivy`, `semgrep` and `triage`; one that matches Banking
  customer-facing must also require `swarm`. A thinner policy saves, but the builder, the
  preview (`warnings`) and the Policies library show "Thinner than the baseline for ...".
  This stops a policy author from raising every dot by requiring less.
* **Unchanged by this spec**: the compliance step is always optional.
* **Slots and tools**. A step `id` names a *slot* (v1 catalog ids). `tool` picks the vendor filling
  it. A slot's default tool is the catalog tool. `tool` must be one of the slot's alternatives whose
  availability is `runs` or `imports`; anything else is refused with a warning.

### Catalog (`GET /api/catalog`)

```jsonc
{ "slots": [ { "id":"semgrep","label":"Static analysis","capability":"sast","phase":"pre","icon":"file-code",
    "origin":"third_party","what":"Reads source for injection and unsafe patterns.",
    "produces":"Static candidates (never findings until proven)","command":"semgrep --config=p/default --sarif",
    "tools":[ {"id":"semgrep","name":"Semgrep","origin":"third_party","availability":"runs","default":true},
              {"id":"codeql","name":"CodeQL","origin":"third_party","availability":"imports"},
              {"id":"sonarqube","name":"SonarQube","origin":"third_party","availability":"imports"},
              {"id":"checkmarx","name":"Checkmarx","origin":"third_party","availability":"imports"},
              {"id":"snyk-code","name":"Snyk Code","origin":"third_party","availability":"imports"},
              {"id":"veracode","name":"Veracode","origin":"third_party","availability":"imports"},
              {"id":"sarif","name":"Any SARIF 2.1.0 tool","origin":"third_party","availability":"imports"} ] },
    ... trivy (Dependencies and secrets: Trivy runs; Grype, Snyk Open Source, Gitleaks, Dependency-Check planned),
        nuclei (Web templates: Nuclei runs; OWASP ZAP planned), apisec (Henoyo API Security engine: planned),
        recon, triage, compliance, swarm, fix (Henoyo agents: runs) ],
  "starts": [ {"kind":"manual","label":"Run now","availability":"works"},
              {"kind":"pull_request","label":"Pull request","availability":"works","note":"where the repository is watched"},
              {"kind":"schedule","label":"Every N days","availability":"planned","note":"the cadence is judged, not started"},
              {"kind":"release","label":"Release tag","availability":"planned"} ],
  "profile": { "category":[...], "exposure":[...], "stack":[...], "tier":[...] },   // option lists, from data
  "guidelines": [ {"id":"rbi-csf","authority":"RBI","title":"...","controls":N,"observable":N,"source_url":"..."} ] }
```

`imports` is honest only for the **static analysis** slot (Docket has `ingest_sarif_file`) and
only once 3a is done; one SARIF file per scan. Every other alternative is `planned`.

### 3a. Making an imported tool count (engine change, small)

Today the SARIF path records no stage, so an imported result can never count as "ran", and a clean
(empty) SARIF falls through to running Semgrep, and an unknown driver name ("CodeQL") would be
credited to Docket's own agents. Fix: when `--sarif` is used, record the static-analysis stage as
ran with `tool` = the SARIF `driver.name`, `tool_version`, the run's `endTimeUtc` when present
(`sarif_at`) and the source revision when present; an empty SARIF is a clean result and never
falls through; `classify_source` credits any unrecognised SARIF driver to `third_party` with its own
name. Freshness of an imported step is the SARIF's own time when present, so a stale file
re-imported today does not look fresh. If this cannot be done cleanly, `imports` stays `planned`.

### Policy writes (the console is local and single-user; same trust as the existing PUT /api/service/repos)

* `PUT /api/policy/<id>` body = one policy as above. Validated by `parse_policy`; refused with
  `{errors:[...]}` and status 400 on any warning that would drop it, and on a tie. It PATCHES THE RAW
  JSON entry by id (never round-trips through `load_policies`, which silently drops invalid
  policies and would delete them), so other policies and unknown keys are preserved. Writes
  `docket_policy.json` atomically (temp file + rename) and bumps `version`.
  Never writes outside the working directory. `DELETE /api/policy/<id>` removes it (404 if absent).
* `POST /api/policy/preview` body = a draft policy. Returns, with NO side effects:
  `{matches:[{id,label,tier,category,exposure}], would_meet:N, would_breach:N,
    changes:[{id,label,before:"meets"|"breaches"|"none",after:"meets"|"breaches",why}],
    plan:[ {id, n, label, tool, origin, availability, required, command, what, produces} ]}`.
  `changes` compares the application's current policy outcome with the draft's, using the same
  coverage logic as the matrix. This is the "who is affected if I save" panel.

## 4. Posture (additions to `GET /api/portfolio`)

```jsonc
"posture": {
  "as_of": "...", "history_days": 28, "snapshots": ["2026-09-21","2026-09-28","2026-10-05","2026-10-12","2026-10-19"],
  "points": [ { "id":"card-payments","label":"Card Payments API","tier":"Tier 1","category":"Banking",
      "exposure":"Customer-facing","policy":"banking-customer","level":"action",
      "assurance": 38, "standing": 12, "cell":"bl", "days_in_cell": 9,
      "assignment":{"policy":"banking-customer","via":"matched","incomplete":[],"overrides":null},
      "assurance_note":"3 of 5 required scanners current","standing_note":"2 reproduced exploits open",
      "trail":[ {"at":"2026-09-21","assurance":40,"standing":80}, ..., ],   // oldest first; null entry when not yet assessed
      "moved":{"assurance":"down","standing":"down"} | "new" } ],
  "by_snapshot": [ {"at":"2026-09-21","tl":2,"tr":3,"bl":1,"br":0,"unassessed":6} ],
  "unassessed": [ {"id","label","tier","category","exposure","reason":"Never scanned"} ],
  "quadrants": [ {"key":"tl","title":"Quiet, not fully assessed","note":"Little found, but little was looked for."}, ... 4 ],
  "leaders": { "worst":[{id,label,tier,level,reason,moved}] (3), "best":[...] (3) },
  "assessments": { "days":28, "total":N, "scan":N, "pr":N,
      "outcomes":{"proven":N,"candidates":N,"clean":N,"incomplete":N},
      "weekly":[ {"label":"21 Sep","proven":N,"candidates":N,"clean":N,"incomplete":N} ] },
  "categories": [ {"key":"Banking · Customer-facing","apps":5,"meet_policy":3,"levels":{"action":2,"attention":1,"clear":2,"unknown":0}} ]
}
```

**Definitions (server computes, UI never derives).** The quadrant a dot sits in is decided by
RULE, using the same facts the health card uses; the number only places it inside its cell.

* **Right half (x)** iff every policy-required step has finished inside its window (exactly the
  matrix's "meets the policy"). Left half otherwise. Freshness counts only FULL scans: a pull-request
  check does not refresh a required step. `assurance` 0..100 places it: left half 4..46 by the
  fraction of required steps current (a step inside twice its window counts half); right half
  54..96 by recency (the fresher, the further right). `assurance_note` says "N of M required
  scanners current" and the tooltip adds the policy's depth ("policy requires 5 steps").
* **Upper half (y)** iff nothing proven or confirmed is open. Ordinal bands, lowest first:
  1 a reproduced exploit or a deterministic-floor secret open (y 4..30, more of them lower);
  2 a triage-CONFIRMED item not reproduced, or a reachable critical dependency CVE (y 30..48);
  3 UNCERTAIN high or critical item(s) a person must judge (y 52..64, upper half, never counted
  as clean or as confirmed: AGENTS.md rule 12); 4 candidates only (y 66..84, a little lower as
  they grow); 5 nothing open (y 88..96). `standing_note` states the band in words.
  Candidates never lower a dot below the midline.
* **Proven items persist.** Today an open reproduced finding vanishes when a later static-only scan
  does not list it, which would make an app look better for running less. Rule: proven counts come
  from the **latest run in which the exploit lane ran**; a later run that skipped it does not clear
  them. Carry them forward and say so ("as of the 12 Oct exploit run"). The health card and the
  map read the same function.
* **Replay.** Positions at each snapshot date are computed by replaying runs up to that date
  against TODAY'S policy and profile (policies have no history yet). The screen says
  "Past positions use today's policy." Needs `last_ran(asof)` in the model.
* **Movement** is worded per axis, never summed: `moved: {assurance: "up"|"down"|"steady",
  standing: "up"|"down"|"steady"}` compared with the snapshot at least 14 days earlier, with a
  band-change or a half-change counting as a move, else steady; no earlier point is `new`. The UI
  words it: "Standing worse, assurance steady since 5 Oct".
* **Time in cell**: `days_in_cell` = days the dot has been in its current quadrant, replayed daily,
  capped at 28 ("28+"). It appears on the dot tooltip and in "Look here first" for `bl`.
* The four quadrants split at 50/50. Names, **top-right best**:
  `tr` "Assessed and sound" (Fully assessed, nothing proven open),
  `tl` "Quiet, not fully assessed" (Little found, but little was looked for. Do not trust the quiet),
  `br` "Exposed, fully assessed" (The risk is real and well evidenced. Fix it),
  `bl` "Exposed, not fully assessed" (Proven problems and gaps in coverage. Look here first).
* `points[].cell`: `tl|tr|bl|br` (server decided). `posture.by_snapshot`: per snapshot date the
  number of applications in each cell plus `unassessed`, drawn as small multiples so "are we
  getting better" reads without scrubbing.
* `assessments.outcomes`: per assessment (a scan or a pull-request check) in the window, the worst
  that applies: `proven` (>=1 reproduced or deterministic), else `incomplete` (coverage partial or
  failed), else `candidates` (any), else `clean`. Weekly buckets end on the snapshot dates.
* `categories`: applications grouped by `category · exposure`; `meet_policy` uses the matrix logic.
* `leaders.worst`: level order (action, attention; unassessed excluded), then cell (`bl` before
  `br` before `tl`), then standing ascending. `leaders.best`: ONLY applications in `tr`, ordered by
  standing then assurance descending. If fewer than three, fewer are shown; never padded.
* Dots that share a coordinate are clustered by the UI with a count badge (quiet applications
  stack); the cluster opens a list.

## 5. Screens

### 5.1 Home, "Posture" (the 15-second read)

Order, top to bottom:

1. Headline sentence (v1) and a six-number strip: applications, assessments in 28 days, proven
   exploits open, applications meeting policy "N of M", not assessed, and the oldest critical.
2. **Posture map** (`<docket-quadrant>`, about two thirds wide) with, at right, "Look here first"
   (3 worst) and "Steadiest" (3 best), each row with level lamp, tier, one-line reason and a
   movement word ("Worse than 2 weeks ago"). The "Not assessed" tray sits under the map.
3. Policy adherence by category (bars per `categories`), and **Assessments, by week** (stacked bars
   by outcome, with the totals).
4. The scan continuum (v1), then the severity-by-age grid (v1).

The old donut and "Needs you" list are removed: the map and the two short lists carry the same
information in less space. The grouped "Needs you" list remains reachable from Applications.

### 5.2 Posture map (`<docket-quadrant>`)

Plot area with a centre cross at 50/50, tinted corners (only `bl` carries a warning tint; the rest
are neutral paper, so the chart does not shout), corner titles with their note. X axis "Assurance:
how much of the policy has been run, and how recently". Y axis "Standing: how few proven problems".
Dot = level colour (with the level word in the tooltip and legend), **size = tier** (Tier 1
largest), label on hover and focus for all, always-on label for dots in `bl`/`br`. Controls:
"Show movement" toggle draws each dot's trail (thin line with the earlier positions as small
rings and an arrow into the current one); a time scrubber over the five snapshots re-plots the
whole portfolio at that date (labelled "Past positions use today's policy"); beneath the map,
small multiples (`by_snapshot`) show the count per quadrant at each date; filter chips
by category, exposure and policy dim everything that does not match. Clicking a dot emits
`docket:open-app`. Keyboard: dots are buttons in reading order, arrows nudge focus.
No numbers on the plot. The tooltip says: name, tier, policy, `assurance_note`, `standing_note`,
movement word.

### 5.3 Policies (replaces "Policy")

* **Library** (left): one card per policy: name, "applies when" chips, application count, a
  miniature of its flow (one dot per step, filled when required), and how many of its applications
  meet it. "New policy" and "Start from a template" (the three seeded ones plus a blank).
* **Policy flow** (`<docket-policy-flow>`), the hero of the selected policy, left to right:
  **Starts** (Run now, Pull request, Every N days: with their availability words, not editable) → **Before the agents**
  (scanner stations, each: capability, chosen tool with origin chip and availability chip,
  Required or Optional, cadence) → **Docket agents** (recon, triage, exploit, fix) → **Guidelines**
  (one chip per selected pack with its authority) → **Gate** (Blocks / Flags / Advises, fixed) →
  **Outcome** (pull-request check, report, fix pull request). Arrows say what flows ("candidates go
  to triage"; "reproduced exploit blocks"). Two modes: `design` (stations are buttons that open the
  inspector) and `run` (stations show the real state, count and duration of the last run and open
  the lane drawer, which shows tool, tool version, commit and the SARIF's own time where recorded).
* **Builder** (right of the flow in design mode): *Applies when* (profile chips with a live "matches
  N applications" line), *Cadence* (the window staleness is judged against), *Steps* (add from a palette grouped by capability and
  vendor with availability chips, remove, move earlier or later, toggle Required, pick the tool,
  set cadence; steps always sit in the order Docket runs them), *Guidelines* (pack cards), the read-only gate, and a **"If you save"** panel from
  `POST /api/policy/preview`: matched applications, would meet, would breach, and per-application
  change. Plus the floor warning and any tie error. A banner under the title says: "Docket runs a fixed
  pipeline. This policy decides what must have run, how recently, and what a gap means." Actions:
  Save and apply (PUT), Discard, Delete.
* **Run it** (below the flow): choose an application (default: the most recent match). **Preview a
  run** shows the plan: per station the command, what it reads, what it produces, who wrote the
  detection. **Last run** switches the same flow to `run` mode with the real evidence per station.
  "Run now" uses the existing scan launcher; when no repository is connected it says so and shows
  the CLI command instead. Never a fake progress bar.
* Below: policy against reality (v1 matrix) for the selected policy (`GET /api/policy?policy=<id>`).

### 5.4 Application page

Adds a "Position" strip under the health card: the dot on a miniature two-by-two with its trail,
the policy it falls under (link), and "moved" word. The flow in `run` mode replaces the old
pipeline heading only where it fits; the Gantt stays.

## 6. Out of scope here (say so on the design page)

Starting scans on a schedule or on release, API pulls from vendors (only SARIF import exists),
the API Security engine as a real stage, per-organisation approvals and audit trail, clause
mapping, Core pack integration.
