<div align="center">

# docket

**Autonomous pentesting agents that report a vulnerability only once they have reproduced it.**

A docket is a register where nothing is entered without evidence. That is the whole design.

</div>

> [!WARNING]
> Only point docket at systems you own or have written authorisation to test. It sends real
> exploit payloads, runs real tooling, and will change state on the target.

---

## Contents

- [Why docket](#why-docket)
- [The guarantee](#the-guarantee)
- [How a scan runs](#how-a-scan-runs)
- [Proof, per vulnerability class](#proof-per-vulnerability-class)
  - [Verified live](#verified-live)
- [Agent capabilities](#agent-capabilities)
- [Skills](#skills)
- [The sandbox](#the-sandbox)
- [Cost control](#cost-control)
- [Install](#install)
- [Usage](#usage)
- [Output](#output)
- [Watching a scan](#watching-a-scan)
- [Configuration](#configuration)
- [Handling of sensitive data](#handling-of-sensitive-data)
- [Architecture](#architecture)
- [Troubleshooting](#troubleshooting)
- [Current limits](#current-limits)
- [Roadmap](#roadmap)
- [Development](#development)

## Why docket

Most scanners tell you what *might* be wrong. Pattern matchers flag a line of code;
crawlers flag a reflected string. Both hand you a queue of maybes, and somebody spends
their afternoon deciding which ones are real. The triage costs more than the scan.

docket only files a finding it has already exploited, and attaches the request it sent and
the response it got back. There is no "likely" severity and no confidence score to
interpret. A finding is a reproduction or it does not exist.

## The guarantee

Enforced by the type system, not by convention.

`PoC.request` and `PoC.response` are validated non-empty at construction, so a `Finding`
carrying no evidence cannot be instantiated. The layer in front of that validator refuses to
manufacture content: a `null` from the model becomes `""` and is rejected, rather than
becoming the string `"None"` and slipping through.

When an agent tries to file a claim instead of a proof, the tool refuses and says why:

```
finding refused — no reproduced evidence in: response_excerpt.
Send the literal request you issued and the literal output you observed.
A description of what you believe happens is not evidence. Go run the
exploit, capture the real request/response, then call this again.
```

Refusing is only half of it. The agent has to know *why*, or it cannot correct course.

## How a scan runs

A root agent is handed the target's route list, then delegates one vulnerability class and
one route to each specialist. Specialists work in parallel, each with a deliberately narrow
tool set, and each has to prove its own finding before it can report.

Root does not discover routes itself. Today that list is hardcoded to the test fixture, which
is the largest open gap in this tool — see [Current limits](#current-limits) and
[Roadmap](#roadmap).

```
root ──┬── sqli   → POST /login    shell + sqlmap        → confirmed injection + DBMS
       ├── cmdi   → GET  /export   timing side-channel   → measured latency delta
       └── xss    → GET  /search   real Chromium         → captured alert() dialog
```

Root aggregates only what its children proved. It cannot invent a finding on their behalf,
because `finding` is not one of its tools.

Structural guarantees in the agent graph:

- **A child is registered before its task is spawned**, so a root that spawns and waits in
  the same turn sees its children rather than being told nothing is running
- **A refused spawn reaches the model.** Hitting the agent cap returns
  `{"status": "refused", "error": ...}`, so root can re-plan instead of believing a route
  is covered
- **A dead child still reports.** A `finally:` block guarantees a terminal status, so a
  waiting parent cannot hang on a task that crashed
- **Root gets 20 turns by default** (`--max-steps`); each specialist gets 12

## Proof, per vulnerability class

| Class | What counts as proof |
|---|---|
| **SQL injection** | `sqlmap` confirms the injection and fingerprints the DBMS. Not a payload that "looked reflected" |
| **Blind command injection** | A timing side-channel. Stdout never reaches the response, so an injected `sleep` plus a measured latency delta is the only honest oracle |
| **Reflected XSS** | Real Chromium raises `alert()` and the dialog is captured. Proves the script *executed*, rather than that your payload appeared in the HTML |

### Verified live

Not a claim about the harness this time. One run, four agents, a real model reasoning
unaided, against the bundled fixture through a real container:

```
success: True   findings: 3   agents: 4   cost: $0.108

cmdi:  ?file=test.csv; sleep 5              -> "Response time: ~5016ms"
sqli:  username=admin' --&password=[REDACTED] -> "Welcome"
xss:   browser dialog_message='host.docker.internal'
```

Every payload was the model's own choice. The sqli specialist did not reach for sqlmap at
all: it found `admin' --` comments out the password check, and proved the bypass with a
request and a `Welcome`. The `[REDACTED]` is redaction firing at the write boundary.

A second run on `DeepSeek-V4-Pro` through an OpenAI-compatible gateway found the same three
classes, at 6x the tokens. Reproduce either against `tests/serve_target.py`. Read
"Current limits" first: model choice changes cost by an order of magnitude, and one of these
runs proved its XSS more weakly than the other.

Findings carry a `Severity` (`critical`/`high`/`medium`/`low`/`info`), a CWE tag where the
class has one, and a stable dedupe key: `sha256(rule_id|method|path|parameter)` truncated to
16 hex chars. The same key becomes the SARIF `partialFingerprints` value, so a finding keeps
its identity across runs and GitHub can track it as one issue rather than a new one each
scan. When two specialists corroborate the same bug, the report collapses them and keeps the
higher severity.

## Agent capabilities

Every specialist gets `http_request`, `finding`, `thinking`, `notes`, `todo`, `web_search`,
`load_skill`, `list_skills` and `agent_finish`. On top of that:

| Tool | Who has it | What it does |
|---|---|---|
| `shell` | `sqli` only | Arbitrary commands in the container. sqlmap pinned to 1.9.9 and pre-installed |
| `browser` | `xss` only | A persistent Playwright/Chromium page, with dialog capture and screenshots |
| `create_agent`, `wait_for_agents`, `view_agent_graph` | `root` only | Delegation and aggregation |
| `respond` | `root` only | Send a message to the operator mid-run |
| `finish_scan` | `root` only | The only way root can end a scan |
| `http_request` | all | Direct HTTP with full control over method, headers, body |
| `thinking` | all | An explicit reasoning scratchpad, kept out of the findings record |
| `notes`, `todo` | all | Durable shared scratchpad and per-agent task list |
| `web_search` | all | Live intel lookup. Refuses explicitly when unconfigured rather than inventing results |
| `load_skill`, `list_skills` | all | Pull a playbook into context on demand |

Large tool output is truncated head-and-tail, not head-only, because tools like sqlmap put
the verdict at the *end* of noisy output. The full text is spooled to
`artifacts/output/<ref>.txt`.

Thirteen tool packages are implemented. Two more (`apply_patch`, `view_image`) are
documentation stubs for capabilities the SDK provides directly, plus a shared `output_store`
module.

## Skills

Playbooks live in markdown, not in prompts, so target-specific tradecraft can be added
without touching code. An agent calls `list_skills`, then `load_skill` on what looks
relevant.

| Skill | Covers |
|---|---|
| `coordination/root_agent` | How to decompose a target and delegate |
| `custom/blind_injection` | Timing oracles when output never returns |
| `custom/api_spec_testing` | Driving an endpoint from its spec |
| `coordination/source_aware_whitebox` | Reading source alongside probing |

Adding one is a file drop in `engine/docket/skills/<category>/`. No code change.

## The sandbox

One container per run, built from `containers/Dockerfile`.

Deliberately **not** a Kali base. Kali's value is breadth across an unknown estate; the cost
is a multi-GB pull and a much larger patch surface. What is installed is what proves
something: sqlmap pinned to a release tag for deterministic results, mitmproxy as a
scriptable proxy, and Playwright with Chromium so an XSS finding is an execution proof
rather than an inference.

Agent tool calls reach the container over a long-lived in-container RPC shim rather than
`docker exec` per call, which is what lets a live `Page` handle persist between turns. The
shim is single-threaded on purpose: Playwright's sync API binds objects to their creating
thread.

**`shell` and `browser` refuse outright when there is no sandbox.** There is no host
fallback, by design: an LLM-authored command belongs in the container or nowhere. The only
subprocesses docket starts on your machine are `docker` invocations. `--no-sandbox` runs
without Docker and drops both tools rather than quietly relocating them.

The SDK's own `Filesystem`/`Shell` capabilities are **off by default** (`DOCKET_SDK_SANDBOX_TOOLS=1`
to enable). They are *hosted* tools, which only OpenAI's Responses API accepts; over the Chat
Completions API that LiteLLM uses for everything else, a run dies before its first turn with
`Hosted tools are not supported with the ChatCompletions API`. docket's own container-backed
`shell` and `browser` are unaffected and do the actual work; only `apply_patch` and
`view_image` go away, and no vulnerability class uses them.

## Cost control

Budgets are checked *before* each model turn, so a run stops rather than discovering the
overage afterwards. Three ceilings: scan-wide, per-specialist, and a concurrent agent cap.
Warnings escalate as an agent approaches its limit instead of arriving only at the cutoff.

Every run writes a token and cost ledger into `report.json`, broken down per agent and per
model. Context is compacted when a provider rejects an oversized request, preserving
tool-call and tool-result pairing so the conversation stays valid. Sessions persist to
`.state/sessions.db`, so a run's conversation is inspectable after the fact.

## Install

Requires Python 3.12+, [uv](https://docs.astral.sh/uv/), and Docker.

```bash
uv sync
cp .env.example .env      # set DOCKET_LLM and your key
make image                # build the sandbox container
docket doctor             # verify key, Docker and search
```

`docket doctor` exits non-zero when something is missing, so it works in a setup script.

## Usage

```bash
# scan, with live progress
docket scan --target http://127.0.0.1:5000

# watch it work in a terminal UI
docket scan --target http://127.0.0.1:5000 --tui

# hand the agents context they could not discover alone
docket scan --target https://staging.internal \
  --instruction "Seeded login is admin/admin123. Skip /billing, it is third-party."

# CI mode: no progress output, named run, exit code as the gate
docket scan --target https://staging.internal -n --run-name nightly

# raise the turn ceiling for a larger target
docket scan --target https://staging.internal --max-steps 40

# no Docker available — costs you shell and browser
docket scan --target http://127.0.0.1:5000 --no-sandbox
```

Review a past run:

```bash
docket view                       # most recent run
docket view nightly --full        # every finding with its PoC
docket view nightly --web         # local dashboard
docket view nightly --format sarif
```

**Exit codes:** `0` clean, `1` error, `2` findings present. So `docket scan` works directly
as a pipeline gate — a run that proves a vulnerability fails the build.

## Output

Every run writes to `docket_runs/<name>/`:

| Artifact | What it is |
|---|---|
| `report.json` | Findings with full PoC evidence, plus the cost and token ledger |
| `report.sarif` | SARIF 2.1.0 for GitHub code scanning. Stable fingerprints, CWE tags |
| `findings/*.json` | One file per finding |
| `events.jsonl` | The event stream. Feeds the TUI and dashboard, live or replayed |
| `artifacts/output/` | Full untruncated tool output, addressable by ref |
| `artifacts/screenshots/` | Browser captures |
| `artifacts/proxy_flows.jsonl` | Captured request/response pairs |
| `.state/sessions.db` | Per-agent conversation history |

## Watching a scan

Both front-ends read the same `events.jsonl`, so either works live or as a replay of a
finished run.

**Terminal UI** (`--tui`) — agent tree with live status, findings table by severity, a
running tool-call transcript, and elapsed cost and tokens.

**Web dashboard** (`docket view <run> --web`) — a single self-contained file, responsive,
light and dark. No CDN scripts, fonts, or remote assets; its only request is to the loopback
server serving it. No account, no upload, nothing hosted by us.

## Configuration

| Variable | Purpose |
|---|---|
| `DOCKET_LLM` | Any LiteLLM `provider/model`, e.g. `anthropic/claude-sonnet-5` |
| `LLM_API_KEY` | Or a provider-specific variable |
| `DOCKET_LLM_BASE_URL` | Point at a self-hosted or proxied deployment. For an OpenAI-compatible gateway, use `openai/<gateway-model-name>` as `DOCKET_LLM` |
| `DOCKET_STRUCTURED_OUTPUT` | `1` to send a response schema with the tool list. Off by default: it stops some models calling tools at all |
| `DOCKET_SDK_SANDBOX_TOOLS` | `1` to add the SDK's hosted `Filesystem`/`Shell` tools. Off by default: they only work on OpenAI's Responses API |
| `DOCKET_MAX_COST_USD` | Scan-wide budget ceiling. Default `2.00` |
| `DOCKET_MAX_CHILD_COST_USD` | Per-specialist ceiling. Default `0.75` |
| `DOCKET_MAX_AGENTS` | Concurrent agent cap. Default `6` |
| `DOCKET_SEARCH_PROVIDER` | Optional live search: `tavily`, `brave`, `serper`, `perplexity`, `deepseek` |
| `DOCKET_SEARCH_API_KEY` | Key for the above |

`.env` is loaded automatically. Provider-agnostic by design: docket routes through LiteLLM,
so any supported model works without a code change. Per-run values (target, instruction, run
name) are flags rather than environment variables, because they change every run.

## Handling of sensitive data

- **No telemetry.** No analytics, no update ping, no crash reporting in any code path.
  Outbound traffic goes to the scan target, your LLM provider, and your search provider if
  you configure one. Nothing else. The SDK's trace export is disabled at import, and
  litellm's import-time price fetch is switched to its bundled map — that one took an audit
  to find, since it fires before any docket code runs
- **Shared artifacts are redacted.** `report.json`, `report.sarif` and captured proxy flows
  pass through redaction at the write boundary, on the whole serialized document, so a new
  field is covered by default. Bearer tokens, session cookies, API keys and known key
  formats are matched. The header *name* survives and only the value is replaced, so
  `Authorization: [REDACTED]` still shows what to substitute and the PoC stays reproducible.
  Best-effort pattern matching, not a guarantee
- **Your keys never enter the container.** The sandbox receives exactly one environment
  variable, its run directory. An agent running `env` finds nothing of yours
- **Everything stays local.** No account, no upload, no dashboard we host

## Architecture

`engine/` is only a source root; the importable package is `docket`, so imports read
`from docket.core...` regardless of what the wrapper is called.

| Path | Role |
|---|---|
| `engine/docket/core/` | `AgentCoordinator`, run loop, budget hooks, sessions, runner |
| `engine/docket/agents/` | Agent factory and prompts |
| `engine/docket/tools/` | One package per tool |
| `engine/docket/runtime/` | Docker sandbox, in-container RPC shim, SDK sandbox session |
| `engine/docket/llm/` | Context budget and conversation compaction |
| `engine/docket/report/` | Finding model, dedupe, SARIF, writer, usage ledger |
| `engine/docket/interface/` | CLI, Textual TUI, local web viewer |
| `engine/docket/skills/` | Markdown playbooks |
| `app/` | Optional demo web app (FastAPI + React). Not part of the tool, not in the wheel |

Built on the OpenAI Agents SDK with LiteLLM for provider routing, pydantic for the finding
model — the trust boundary where model free-text becomes a structured report — and stdlib
everywhere else. SARIF is hand-rolled: roughly fifteen fields, not worth a dependency.

## Troubleshooting

**`DOCKET_LLM is not set`** — copy `.env.example` to `.env` and fill in a model plus key.
`docket doctor` tells you exactly what is missing.

**`shell`/`browser` refuse with a sandbox error** — the container is not running. Run
`make image`, check `docker info`, and drop `--no-sandbox` if you passed it.

**Scan exits 0 with no findings on a target you know is vulnerable** — check the run's
`events.jsonl` or `--tui` transcript. Most often the agents could not authenticate; pass
credentials through `--instruction`.

**`docket view` cannot find a run** — do not use `--out-dir`; it currently splits a run's
files across two directories (see Current limits).

**Costs hit the ceiling early** — raise `DOCKET_MAX_COST_USD`, or lower `DOCKET_MAX_AGENTS`
so fewer specialists run at once.

## Current limits

Findings from an audit of this codebase, listed because a security tool that hides its own
gaps is worse than one that has none.

- **Routes are hardcoded to the test fixture.** `build_root_task()` writes the same three
  routes into every run's root task regardless of `--target`, and no crawl, spec-parsing or
  discovery capability exists anywhere in the tool. Aimed at anything but the fixture, root
  starts from three route hints that probably do not exist there, with no way to find the
  real ones. Pass them through `--instruction` until discovery lands. This is the blocker
  for real use, ahead of everything else on this list
- **Scope is not enforced, only requested.** The one guard point that would cover docket's
  own HTTP calls does not cover sqlmap, `curl` or Chromium, all of which open their own
  sockets from inside the container. An allowlist has to live at the container's network
  edge to mean anything
- **Three vulnerability classes.** Specialists exist for SQL injection, command injection
  and reflected XSS. Anything else goes untested
- **Model cost varies enormously for the same result.** Two live runs, same fixture, all
  three classes found by both: `gpt-4.1` took 19 model requests and 46k tokens; DeepSeek-V4-Pro
  took 70 requests and 297k tokens, and spawned 7 specialists for 3 routes. Both correct,
  6x apart. Nothing caps agent count per route beyond `DOCKET_MAX_AGENTS`
- **The evidence gate proves the output is real, not that it proves the claim.** It rejects an
  empty or invented `request`/`response`, which is what stops fabrication. It cannot judge
  whether what came back supports the verdict. Seen live: an XSS specialist filed
  reflection-only evidence — the payload echoed in the HTML — where the prompt asks for a
  captured `dialog_message` from a real DOM. A true finding, proved weakly. Read the PoC,
  do not just count findings
- **A response schema and tools together defeat some models**, which is why `output_type` is
  off unless `DOCKET_STRUCTURED_OUTPUT=1`. With a schema present, `DeepSeek-V4-Pro`,
  `DeepSeek-V3.2`, `Kimi-K2.5` and `Llama-3.3-70B` each answered the schema and called no
  tool at all; each calls tools normally without one. docket reads the finish tool's dict out
  of the run items instead, so the schema is not needed. Turn it on only for a model that
  needs it, and check a new model against the fixture first either way
- **A run can still end without the finish tool, it just cannot lie about it now.** The SDK
  ends a run on any plain assistant message matching `output_type`, and it checks that
  *before* the tool-use gate. Observed live: a model emitted a schema-shaped message on turn
  one with zero tool calls, inventing finding IDs and a verdict for routes it never
  requested. docket now discards that, re-prompts, and refuses on the third attempt rather
  than printing it. But the escape itself is the SDK's, and it is still there
- **Budget enforcement is inert for models LiteLLM cannot price.** Cost is computed from
  LiteLLM's price map, so a self-hosted or gateway model it does not recognise is charged
  \$0.00 per turn and the ceilings never fire. Seen live: 8,562 tokens billed as nothing.
  Token counts stay correct; only the money does not
- **Compaction is reactive and can decline.** It runs only after the provider rejects an
  oversized request, then second-guesses that with a token estimate, and gives up if the
  estimate disagrees
- **Budgets can overshoot.** The gate is pre-turn but the charge is post-turn, so concurrent
  agents can each slip one turn past the cap. Separately, see the pricing gap above
- **No scope controls or rate limiting.** Out-of-scope routes are avoided only by asking in
  `--instruction`
- **`--out-dir` splits a run across two directories**, so `docket view` cannot find it.
  Screenshots land one directory below where the dashboard looks
- **The intercepting proxy is built but unreachable** from any agent, and per-request model
  settings are not applied, so prompt caching and request timeouts are inert

## Roadmap

In rough priority order:

Deliberately in this order. Discovery is the bigger gap, but a tool that finds its own
routes before it can be told where not to go is how a lab experiment becomes an incident, so
the lane markings go in first.

1. **Scope and rate controls** — allow and deny lists, per-host request budgets, enforced at
   the container's network edge rather than in Python. Make the already-built proxy mandatory
   egress and deny by default there, so sqlmap, `curl` and Chromium are covered by the same
   guard as docket's own requests. A rule enforced anywhere above the socket is bypassed by
   the first tool that opens its own
2. **Target discovery** — replace the hardcoded route list with a typed, persisted attack
   surface (`method`, `path`, params and their location, content type, auth), written to the
   run directory so it is reviewable before spend, diffable between runs, and testable
   without a model. Deterministic code, not an agent task: the model exploits, it does not
   enumerate. Cheapest authoritative source first, stopping at the first that yields
   endpoints — an OpenAPI/GraphQL/HAR file passed in, then well-known paths
   (`/openapi.json`, `/graphql` introspection, `robots.txt`, `sitemap.xml`), then flows
   captured through the proxy, and only then a bounded same-origin crawl with `html.parser`,
   depth 2 and a hard request cap. When the surface comes back empty root must be *told* it
   is empty, rather than handed fiction as fact
3. **Expose the proxy** — capture, modify and replay is already built and tested, just not
   registered as a tool. It is also rung 3 of discovery and the route to authenticated
   scanning, so it pays for itself three times
4. **Authenticated scanning** — a real login flow and session reuse, instead of pasting
   credentials into `--instruction`
5. **A scheduled live-model eval** — one live run now passes by hand, which is what shook out
   the hosted-tools incompatibility, the fabricated-summary escape and a missing base URL.
   Make it a timed job against the fixture asserting all three classes still land, recording
   cost and turns. Off the per-push path, since it costs money and is nondeterministic.
   Nothing automated currently fails when a prompt edit makes the agents worse
6. **More classes** — IDOR/BOLA, SSRF, path traversal, auth bypass, SSTI, open redirect.
   Adding one is a role literal, a prompt and a tool grant. Worth little until a scan can
   find the routes to point them at
7. **Source-aware scanning** — the plumbing accepts a source path but nothing mounts or
   reads it
8. **A packaged CI action** — SARIF and exit codes already exist, so this is thin

## Development

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the dev loop and for adding tools, skills and
vulnerability classes, and [`AGENTS.md`](AGENTS.md) for the invariants you must not break.

[`app/`](app/README.md) is an optional browser front end for demoing a scan: start one, watch
agents prove things live, page through past runs. It installs separately
(`uv sync --extra app`) and the tool does not depend on it.

## License

Apache 2.0.
