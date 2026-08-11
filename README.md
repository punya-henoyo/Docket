# docket

> ⚠️ **Only point this at systems you own or are authorised to test.**

`docket` is an autonomous pentesting tool: LLM agents that exploit a target *dynamically*
and report a finding only once they've reproduced it with a working proof-of-concept.

Built for internal use: no accounts, no upload, no telemetry. Everything stays on the
machine that runs it.

## What it actually proves

A finding **cannot exist** without evidence — `PoC.request` and `PoC.response` are
validated non-empty at construction, so "validated" is enforced by the type system, not
by convention.

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
docket doctor                  # check LLM key, Docker, search

docket scan --target http://127.0.0.1:5000            # live progress
docket scan --target ... --tui                        # live TUI
docket scan --target ... -n --run-name baseline       # CI mode
docket view baseline --full                           # terminal report
docket view baseline --web                            # local dashboard
```

Exit codes: `0` clean, `1` error, `2` findings present — so it works as a CI gate.

`--no-sandbox` runs without Docker; it costs you `shell` (sqlmap) and `browser` (the
XSS execution proof).

## Architecture

`engine/` is only a source root; the importable package is `docket`, so imports read
`from docket.core...` no matter what the wrapper is called.

| Path | Role |
|---|---|
| `engine/docket/core/` | `AgentCoordinator`, run loop, budget hooks, sessions, runner |
| `engine/docket/agents/` | agent factory (`SandboxAgent` + Filesystem/Shell capabilities) + prompts |
| `engine/docket/tools/` | 14 tool packages |
| `engine/docket/runtime/` | Docker sandbox, in-container RPC shim, SDK sandbox session |
| `engine/docket/llm/` | context budget + conversation compaction |
| `engine/docket/report/` | finding model, dedupe, SARIF 2.1.0, writer, usage ledger |
| `engine/docket/interface/` | CLI, Textual TUI, local web viewer |
| `engine/docket/skills/` | markdown playbooks agents load on demand |

Design points worth knowing:

- **Root delegates; specialists prove.** One root agent spawns per-vuln specialists
  (`sqli`/`cmdi`/`xss`), each scoped to one route with a deliberately narrow tool set —
  only `sqli` gets a shell, only `xss` gets a browser.
- **`shell` and `browser` refuse to run without the sandbox.** No host fallback: an
  LLM-authored command belongs in the container or nowhere.
- **A dead child still reports.** A `finally:` block guarantees a terminal status, so a
  waiting parent can't hang on a task that crashed.
- **Agents stop only via a finish tool**, enforced structurally by `tool_use_behavior`.
- **Budgets are enforced pre-turn**, so a cutoff never pays for the turn that breaches it.
- **One event stream** (`events.jsonl`) feeds both the TUI and the web viewer, live or
  replayed.

## Configuration

`DOCKET_LLM` (any LiteLLM `provider/model`), `LLM_API_KEY` (or a provider-specific var),
`DOCKET_MAX_COST_USD`, `DOCKET_MAX_CHILD_COST_USD`, `DOCKET_MAX_AGENTS`. Optional real web
search via `DOCKET_SEARCH_PROVIDER` (`tavily|brave|serper|perplexity|deepseek`) +
`DOCKET_SEARCH_API_KEY`. A `.env` is loaded automatically. See `.env.example`.

**No telemetry.** Nothing is collected or transmitted — see `engine/docket/telemetry/README.md`.

## Development

```bash
make check      # 43 module self-checks — no Docker, no API key
make test       # 12 test scripts (needs Docker)
```

Every module carries a runnable `demo()`. Tests are plain-assert scripts, no pytest.
The test target is `tests/fixtures/target_app.py` — self-contained, intentionally
vulnerable, loopback only. See `AGENTS.md` and `CONTRIBUTING.md`.

## Verification status

The tool is exercised end-to-end: a 4-agent run against the fixture target produces
3 findings with evidence extracted from real tool output — sqlmap's own verdict line, a
measured latency delta, and a real DOM dialog — plus valid SARIF.

**Not yet verified with a live model.** The agent tests drive a `ScriptedModel` through
the *real* SDK pipeline: every tool call genuinely executes, but the "which tool next"
decision is scripted. That proves the harness end to end; it does not prove a real model
reasons its way there. Add `DOCKET_LLM` + `LLM_API_KEY` to `.env` and run a scan to close
that gap.
