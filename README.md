# docket

> ⚠️ **Lab tool. Targets a known-vulnerable app on purpose. Do not point it at anything you don't own.**

`docket` is a lab-scale clone of [Docket](https://github.com/internal/docket)'s core idea:
autonomous LLM agents that pentest a target *dynamically* — running real exploit
attempts through real tools, and only reporting a finding once they've reproduced it
with a proof-of-concept.

It's built to run against [`vulnshop`](../vulnshop), a ~60-line intentionally vulnerable
Flask app with three planted bugs.

## What it actually proves

A finding can't exist in this codebase without real evidence — `PoC.request` and
`PoC.response` are validated non-empty at construction (`docket/report/models.py`), so
"validated" is enforced by the type, not by convention. Per vuln:

| Vuln | Route | How it's proven |
|---|---|---|
| SQL injection | `POST /login` | **sqlmap** confirms boolean-based blind injection and fingerprints the DBMS |
| Command injection | `GET /export` | **Timing side-channel** — this one is *blind* (`os.system` stdout never reaches the response), so an injected `sleep 3` and a measured latency delta is the oracle |
| Reflected XSS | `GET /search` | **Real Chromium DOM** raises an `alert()`; the captured `dialog_message` proves the script *executed*, not merely echoed |

## Architecture

- **Orchestration** (`docket/core/`, `docket/roles/`) — a root agent that delegates to
  three per-vuln specialists, coordinated by `AgentCoordinator`, on
  [`openai-agents`](https://github.com/openai/openai-agents-python) with the LiteLLM
  extra so any provider/model works. Stopping is only possible via a dedicated finish
  tool (a `tool_use_behavior` gate), and a child that crashes or is cancelled still
  reports a terminal status via a `finally:` block — so a waiting parent can't hang.
- **Sandbox** (`docket/runtime/`, `docket/tools/`) — one Docker container per run, driven
  by a small in-container RPC shim, exposing shell (sqlmap), HTTP, a mitmproxy-based
  intercepting proxy, and Playwright/Chromium. `shell` and `browser` **refuse to run
  without the sandbox** rather than falling back to the host.
- **Reporting** (`docket/report/`) — deduped findings out to `report.json` +
  `report.sarif` (SARIF 2.1.0, local artifact).

Per-role tools are deliberately narrow: only `sqli` gets a shell, only `xss` gets a
browser, `cmdi` gets neither.

## Run

```bash
uv sync

# vulnshop must be up, with its DB/exports seeded (see its CLAUDE.md)
# then, from this directory:
export DOCKET_LLM=anthropic/claude-sonnet-5    # any LiteLLM provider/model string
export LLM_API_KEY=...                        # or the provider's own env var
uv run docket scan --target http://127.0.0.1:5000 -n --run-name baseline
uv run docket view baseline --full
```

Exit codes (Docket's contract, kept as-is because it's the CI gate): `0` clean, `1`
error, `2` findings present.

`--no-sandbox` runs the HTTP tooling in-process for a machine without Docker; it costs
you `shell` (so no sqlmap) and `browser` (so no execution proof).

Config: `DOCKET_LLM`, `LLM_API_KEY`, plus `DOCKET_MAX_COST_USD` /
`DOCKET_MAX_CHILD_COST_USD` / `DOCKET_MAX_AGENTS`. A `.env` file is picked up
automatically.

## Tests

Plain-assert scripts, no pytest. Each module also has a runnable `demo()` self-check.

```bash
uv run python tests/test_report.py          # finding model + dedupe + exit codes
uv run python tests/test_tools.py           # V1/V2 exploitable, host-side
uv run python tests/test_coordinator.py     # echo/crash/cancel all reach terminal status
uv run python tests/test_budget.py          # cost tracking + pre-turn hard cutoff
uv run python tests/test_agent_loop_mock.py # SDK harness (Runner / finish-tool gate)
uv run python tests/test_multiagent_mock.py # root spawns 3 specialists concurrently
uv run python tests/test_sandbox.py         # container RPC + sqlmap confirms V1   (Docker)
uv run python tests/test_proxy.py           # capture + replay-with-modification  (Docker)
uv run python tests/test_browser.py         # XSS execution proof + control case  (Docker)
uv run python tests/test_full_run.py        # 4 agents, 3 findings, SARIF         (Docker)
```

**On verification honesty:** there is no LLM API key in the environment this was built
in, so the agent tests drive a `ScriptedModel` (`tests/mock_model.py`) that plays a
fixed tool-call sequence through the *real* SDK pipeline — every tool call genuinely
executes (live HTTP, real sqlmap, real Chromium, real finding registration); only the
"which tool next" decision is scripted. That proves the harness end to end. It does
**not** prove a real model reasons its way to those calls unprompted — that needs a key
and a live run.
