<div align="center">

# docket

**Autonomous pentesting agents that report a vulnerability only once they have reproduced it.**

A docket is a register where nothing is entered without evidence. That is the whole design.

</div>

> [!WARNING]
> Only point docket at systems you own or have written authorisation to test. It sends
> real exploit payloads, runs real tooling, and will change state on the target.

---

## Why docket

Most scanners tell you what *might* be wrong. Pattern matchers flag a line of code;
crawlers flag a reflected string. Both hand you a queue of maybes, and somebody spends
their afternoon deciding which ones are real.

docket only files a finding it has already exploited, and attaches the request it sent and
the response it got back. There is no "likely" severity and no confidence score to
interpret. A finding is a reproduction or it does not exist.

That is enforced by the type system, not by convention. `PoC.request` and `PoC.response`
are validated non-empty at construction, and the layer in front of them refuses to
manufacture content — a `null` from the model becomes `""` and is rejected. When an agent
tries to file a claim instead of a proof, the tool refuses and tells it to go and reproduce
the bug first.

## How a scan runs

A root agent maps the target, then delegates one vulnerability class and one route to each
specialist. Specialists work in parallel, each with a deliberately narrow tool set, and
each has to prove its own finding.

```
root ──┬── sqli   → POST /login    shell + sqlmap        → confirmed injection + DBMS
       ├── cmdi   → GET  /export   timing side-channel   → measured latency delta
       └── xss    → GET  /search   real Chromium         → captured alert() dialog
```

Every agent action happens inside a Docker container, never on your machine. `shell` and
`browser` refuse outright when there is no sandbox rather than falling back to the host.

## Proof, per vulnerability class

| Class | What counts as proof |
|---|---|
| **SQL injection** | `sqlmap` confirms the injection and fingerprints the DBMS. Not a payload that "looked reflected" |
| **Blind command injection** | A timing side-channel. Stdout never reaches the response, so an injected `sleep` plus a measured latency delta is the only honest oracle |
| **Reflected XSS** | Real Chromium raises `alert()` and the dialog is captured. Proves the script *executed*, rather than that your payload appeared in the HTML |

## Agent capabilities

Each specialist gets `http_request`, `finding`, `thinking`, `notes`, `todo`, `web_search`,
`load_skill` and `agent_finish`. On top of that:

- **`shell`** (sqli only) — arbitrary commands in the container. sqlmap is pinned and
  pre-installed
- **`browser`** (xss only) — Playwright and Chromium, with dialog capture and screenshots
- **`create_agent` / `wait_for_agents` / `view_agent_graph`** (root only) — delegation and
  aggregation
- **Skills** — markdown playbooks agents load on demand, so target-specific tradecraft
  lives in text rather than in prompts. Ships with root coordination, blind-injection
  technique, API-spec testing and source-aware review
- **Notes and todos** — a shared scratchpad, so one specialist's discovery is visible to
  its siblings instead of being rediscovered

Budgets are enforced per agent and scan-wide, checked before each turn, so a run cannot
quietly cost more than you allowed.

## Install

Requires Python 3.12+, [uv](https://docs.astral.sh/uv/), and Docker.

```bash
uv sync
cp .env.example .env      # set DOCKET_LLM and your key
make image                # build the sandbox container
docket doctor             # verify key, Docker and search
```

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

# no Docker available — costs you shell and browser
docket scan --target http://127.0.0.1:5000 --no-sandbox
```

Review a past run:

```bash
docket view nightly              # summary
docket view nightly --full       # every finding with its PoC
docket view nightly --web        # local dashboard
```

**Exit codes:** `0` clean, `1` error, `2` findings present. So `docket scan` works directly
as a pipeline gate.

## Output

Every run writes to `docket_runs/<name>/`:

| Artifact | What it is |
|---|---|
| `report.json` | Findings with full PoC evidence, cost and token ledger |
| `report.sarif` | SARIF 2.1.0, ready for GitHub code scanning. Stable fingerprints, CWE tags |
| `findings/*.json` | One file per finding |
| `events.jsonl` | The event stream. Feeds the TUI and the dashboard, live or replayed |
| `artifacts/` | Screenshots, spooled tool output, captured proxy flows |

The terminal UI and the web dashboard read the same event stream, so you can watch a run in
progress or replay a finished one. The dashboard is a single self-contained file with no CDN
scripts, fonts or remote assets — its only request is to the loopback server serving it.

## Configuration

| Variable | Purpose |
|---|---|
| `DOCKET_LLM` | Any LiteLLM `provider/model`, e.g. `anthropic/claude-sonnet-5` |
| `LLM_API_KEY` | Or a provider-specific variable |
| `DOCKET_MAX_COST_USD` | Scan-wide budget ceiling. Default `2.00` |
| `DOCKET_MAX_CHILD_COST_USD` | Per-specialist ceiling. Default `0.75` |
| `DOCKET_MAX_AGENTS` | Concurrent agent cap. Default `6` |
| `DOCKET_SEARCH_PROVIDER` | Optional live search: `tavily`, `brave`, `serper`, `perplexity`, `deepseek` |
| `DOCKET_SEARCH_API_KEY` | Key for the above |

`.env` is loaded automatically. Provider-agnostic by design: docket routes through LiteLLM,
so any supported model works without a code change.

## Handling of sensitive data

- **No telemetry.** No analytics, no update ping, no crash reporting in any code path.
  Outbound traffic goes to the scan target, your LLM provider, and your search provider if
  you configure one. Nothing else. The SDK's trace export is disabled at import, and
  litellm's import-time price fetch is switched to its bundled map
- **Shared artifacts are redacted.** `report.json`, `report.sarif` and captured proxy flows
  pass through redaction at the write boundary. The header name survives and only the value
  is replaced, so `Authorization: [REDACTED]` still shows what to substitute and the PoC
  stays reproducible. Best-effort pattern matching, not a guarantee
- **Your keys never enter the container.** The sandbox receives one environment variable,
  its run directory. An agent running `env` finds nothing of yours
- **Everything stays local.** No account, no upload, no dashboard we host

## Current limits

Findings from an audit of this codebase, listed because a security tool that hides its own
gaps is worse than one that has none.

- **Three vulnerability classes.** Specialists exist for SQL injection, command injection
  and reflected XSS. Anything else goes untested
- **Blast radius is wider than the per-role tool lists suggest.** With the sandbox on,
  every role is a `SandboxAgent` with filesystem and shell capabilities, so all roles have
  an in-container shell even though only `sqli` is handed the `shell` tool. Still contained,
  but not least-privilege
- **Agents can stop without a finish tool.** The structured-output path lets the SDK end a
  run on a plain message matching the schema, before the finish-tool gate is consulted
- **Compaction is reactive and can decline.** It runs only after the provider rejects an
  oversized request, then second-guesses that with a token estimate, and gives up if the
  estimate disagrees
- **No scope controls or rate limiting.** Out-of-scope routes are avoided only by asking
  in `--instruction`
- **`--out-dir` splits a run across two directories**, so `docket view` cannot find it.
  Screenshots land one directory below where the dashboard looks
- **The intercepting proxy is built but unreachable** from any agent, and per-request model
  settings are not applied

## Roadmap

In rough priority order:

1. **More classes** — IDOR/BOLA, SSRF, path traversal, auth bypass, SSTI, open redirect.
   Adding one is a role literal, a prompt and a tool grant
2. **Authenticated scanning** — a real login flow and session reuse, instead of pasting
   credentials into `--instruction`
3. **Scope and rate controls** — allow and deny lists, request budgets. Table stakes for
   pointing this at anything shared
4. **Expose the proxy** — capture, modify and replay is already built and tested, just not
   registered as a tool
5. **Source-aware scanning** — the plumbing accepts a source path but nothing mounts or
   reads it
6. **A packaged CI action** — SARIF and exit codes are already there, so this is thin

## Development

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for adding tools, skills and vulnerability
classes, and [`AGENTS.md`](AGENTS.md) for the invariants you must not break.

## License

Apache 2.0.
