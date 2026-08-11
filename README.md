# docket

> ⚠️ **Only point this at systems you own or are authorised to test.**

`docket` is an autonomous pentesting tool: LLM agents that exploit a target *dynamically*
and file a finding only once they have reproduced it with a working proof-of-concept.

The name is the point. A docket is a register where nothing is entered without evidence.

Built for internal use: no accounts, no upload, no outbound calls beyond the target and
the providers you configure.

## What it actually proves

A finding **cannot exist** without evidence. `PoC.request` and `PoC.response` are
validated non-empty at construction, and the coercion in front of that validator refuses
to manufacture content — a `null` from the model becomes `""` and is rejected, not the
string `"None"`. `register_finding` returns an explicit refusal naming the missing field,
so the agent is told to go and reproduce the bug rather than hitting an opaque error.

| Vuln class | How it's proven |
|---|---|
| SQL injection | **sqlmap** confirms the injection and fingerprints the DBMS |
| Command injection (blind) | **Timing side-channel** — stdout never reaches the response, so an injected `sleep` and a measured latency delta is the oracle |
| Reflected XSS | **Real Chromium** raises `alert()`; the captured dialog proves the script *executed*, not merely echoed |

## Quickstart

```bash
uv sync
cp .env.example .env          # add DOCKET_LLM + your key
make image                    # build the sandbox container
docket doctor                 # check LLM key, Docker, search

docket scan --target http://127.0.0.1:5000            # live progress
docket scan --target ... --tui                        # live TUI
docket scan --target ... -n --run-name baseline       # CI mode
docket view baseline --full                           # terminal report
docket view baseline --web                            # local dashboard
```

Exit codes: `0` clean, `1` error, `2` findings present — so it works as a CI gate.

`--no-sandbox` runs without Docker; it costs you `shell` (sqlmap) and `browser` (the XSS
execution proof).

## Architecture

`engine/` is only a source root; the importable package is `docket`, so imports read
`from docket.core...` no matter what the wrapper is called.

| Path | Role |
|---|---|
| `engine/docket/core/` | `AgentCoordinator`, run loop, budget hooks, sessions, runner |
| `engine/docket/agents/` | agent factory (`SandboxAgent` + Filesystem/Shell capabilities) + prompts |
| `engine/docket/tools/` | 15 tool packages, plus the shared `output_store` module |
| `engine/docket/runtime/` | Docker sandbox, in-container RPC shim, SDK sandbox session |
| `engine/docket/llm/` | context budget + conversation compaction |
| `engine/docket/report/` | finding model, dedupe, SARIF 2.1.0, writer, usage ledger |
| `engine/docket/interface/` | CLI, Textual TUI, local web viewer |
| `engine/docket/skills/` | markdown playbooks agents load on demand |

Design points worth knowing:

- **Root delegates; specialists prove.** One root agent spawns per-vuln specialists
  (`sqli`/`cmdi`/`xss`), each scoped to one route. The *custom* tool sets are narrow: only
  `sqli` gets `shell`, only `xss` gets `browser`. See the caveat under Known limits — with
  the sandbox on, the SDK's own capabilities widen this.
- **`shell` and `browser` refuse to run without the sandbox.** No host fallback: an
  LLM-authored command belongs in the container or nowhere. The only subprocesses docket
  starts on your machine are `docker` invocations.
- **A child is registered before its task is spawned.** Registration is `create_agent`'s
  job, not the child task's, so a root that spawns and waits in one turn sees its children,
  and a `max_agents` refusal reaches the model instead of vanishing.
- **A dead child still reports.** A `finally:` block guarantees a terminal status, so a
  waiting parent can't hang on a task that crashed.
- **Budgets are enforced pre-turn**, though the charge lands post-turn, so concurrent
  agents can overshoot by up to one turn each.
- **Shared artifacts are redacted.** `report.json`, `report.sarif` and
  `artifacts/proxy_flows.jsonl` pass through `redact()` at the write boundary. The header
  *name* survives and only the value is replaced (`Authorization: [REDACTED]`), so a PoC
  stays reproducible once you substitute your own credential. Best-effort pattern matching,
  not a guarantee.
- **One event stream** (`events.jsonl`) feeds both the TUI and the web viewer, live or
  replayed.

## Configuration

`DOCKET_LLM` (any LiteLLM `provider/model`), `LLM_API_KEY` (or a provider-specific var),
`DOCKET_MAX_COST_USD`, `DOCKET_MAX_CHILD_COST_USD`, `DOCKET_MAX_AGENTS`. Optional real web
search via `DOCKET_SEARCH_PROVIDER` (`tavily|brave|serper|perplexity|deepseek`) +
`DOCKET_SEARCH_API_KEY`. A `.env` is loaded automatically. See `.env.example`.

### What leaves the machine

Nothing docket collects. There is no telemetry, no analytics, no update ping in any code
path — see `engine/docket/telemetry/README.md`. Outbound traffic is limited to the scan
target, the LLM provider in `DOCKET_LLM`, and the search provider if you configure one.

One non-obvious detail, since it took an audit to find: importing `litellm` fetches a model
price map from `raw.githubusercontent.com` at import time, before any docket code runs.
`engine/docket/__init__.py` sets `LITELLM_LOCAL_MODEL_COST_MAP=true` to suppress it and use
the bundled map instead. The cost is that a model newer than the pinned litellm has no
price entry, which surfaces as a one-time "unpriced model" warning rather than a silent
`$0.00`. Export `LITELLM_LOCAL_MODEL_COST_MAP=false` if you would rather have current
prices than the offline guarantee.

## Development

```bash
make check      # 43 module self-checks — no Docker, no API key
make test       # 12 test scripts (needs Docker)
```

Every module carries a runnable `demo()`. Tests are plain-assert scripts, no pytest. Run
modules as `python -m docket.x.y`, never `python engine/docket/x/y.py`. The test target is
`tests/fixtures/target_app.py` — self-contained, intentionally vulnerable, loopback only.
See `AGENTS.md` and `CONTRIBUTING.md`.

CI runs `make check` plus the non-Docker tests on every push, and builds the sandbox image
and asserts the shim registers all 12 tools whenever the image or package changes. The
container-backed tests are local-only for an environment reason documented in
`.github/README.md`. There is no lint job yet, also explained there.

## Verification status

The tool is exercised end-to-end: a 4-agent run against the fixture target produces 3
findings with evidence extracted from real tool output — sqlmap's own verdict line, a
measured latency delta, and a real DOM dialog — plus valid SARIF.

**Not yet verified with a live model.** The agent tests drive a `ScriptedModel` through the
*real* SDK pipeline: every tool call genuinely executes, but the "which tool next" decision
is scripted. That proves the harness end to end; it does not prove a real model reasons its
way there. Add `DOCKET_LLM` + `LLM_API_KEY` to `.env` and run a scan to close that gap.

## Known limits

Findings from a three-agent audit of this codebase. Listed because a security tool that
hides its own gaps is worse than one that has none.

**Blast radius is wider than the per-role tool lists suggest.** With the sandbox on, every
role is built as a `SandboxAgent` with `Filesystem` + `Shell` capabilities, which add the
SDK's `exec_command`, `apply_patch` and `view_image`. So `root`, `cmdi` and `xss` each have
an in-container shell even though only `sqli` is given the custom `shell` tool. Everything
still executes inside the container — this is a least-privilege gap, not a host-safety one.

**Agents can stop without a finish tool.** `tool_use_behavior` is correct, but a non-`str`
`output_type` lets the SDK end a run on any plain assistant message matching that schema,
before the tool-use gate is consulted. When it happens the result is mangled: the structured
output is stringified into `summary` and the agent records as failed.

**Compaction is reactive and can decline.** It runs only after the provider rejects the
request, then second-guesses that with a 4-chars-per-token estimate that ignores the system
prompt and tool schemas. If the estimate disagrees, the agent dies instead of trimming.

**Not wired up.** The intercepting proxy is unreachable from any agent (no `proxy` tool is
registered, though the image still installs mitmproxy). `core/inputs.py`'s model settings
are never applied, so prompt caching, reasoning effort and the request timeout are inert.
`telemetry/logging.py` has no callers, so `DOCKET_LOG_LEVEL` does nothing.

**Smaller sharp edges.** `--out-dir` splits a run's files across two directories, so
`docket view` cannot find the run. Screenshots land under `<run>/sandbox/artifacts/` while
the web viewer looks in `<run>/artifacts/`, so they 404. `register_finding` discards
`screenshot_path` and `dialog_message`. Dedupe merge upgrades severity but keeps the weaker
PoC. `dedupe_key` collides if a path or parameter contains a literal `|`. The viewer's
containment check is a string-prefix compare, so a sibling directory sharing the run's name
prefix is readable over loopback.
