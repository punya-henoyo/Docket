# docket

> ⚠️ **Lab tool. Targets a known-vulnerable app on purpose. Do not point at anything you don't own.**

`docket` is a lab-scale clone of [Docket](https://github.com/internal/docket)'s core idea:
autonomous LLM agents that pentest a target *dynamically* — running real exploit
attempts through real tools and only reporting a finding once they've reproduced it
with a proof-of-concept, not by pattern-matching source code.

It's built to run against [`vulnshop`](../vulnshop), a ~60-line intentionally
vulnerable Flask app with 3 planted bugs (SQLi, command injection, reflected XSS).

## Architecture

- **Orchestration** (`docket/core/`, `docket/agents/`) — a root agent plus per-vuln-class
  specialist agents, coordinated via `AgentCoordinator`, using
  [`openai-agents`](https://github.com/openai/openai-agents-python) with the
  [LiteLLM](https://docs.litellm.ai/) extra so any provider/model works.
- **Sandbox + tools** (`docket/runtime/`, `docket/tools/`) — a Docker container exposing
  shell, HTTP, browser (Playwright), and proxy (mitmproxy) tools to the agents.
- **Reporting** (`docket/report/`) — a validated `Finding` model (a finding can't exist
  without real PoC evidence), deduped, exported as `report.json` + `report.sarif`.

See `/Users/punya07/.claude/plans/snug-greeting-dolphin.md` for the full design and
build-order rationale.

## Run

```bash
uv sync
export DOCKET_LLM=anthropic/claude-sonnet-5
export LLM_API_KEY=...
uv run docket scan --target http://127.0.0.1:5000 -n --run-name baseline
uv run docket view baseline
```

Exit codes: `0` clean, `1` error, `2` findings present.
