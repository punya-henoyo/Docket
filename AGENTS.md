# Working on docket

Orientation for anyone (human or agent) editing this repo.

## What this is
An autonomous pentesting tool: LLM agents that exploit a target dynamically and report
a finding only once they have reproduced it with a working proof-of-concept.

## Layout
| Path | Role |
|---|---|
| `docket/core/` | coordinator, run loop, hooks, sessions, paths, runner |
| `docket/agents/` | agent factory + prompts (root / specialist) |
| `docket/tools/` | one package per tool (14) |
| `docket/runtime/` | Docker sandbox, in-container RPC shim, SDK sandbox session |
| `docket/llm/` | context budget + conversation compaction |
| `docket/report/` | finding model, dedupe, SARIF, writer, usage |
| `docket/interface/` | CLI, TUI (Textual), local web viewer |
| `docket/skills/` | markdown playbooks agents load on demand |

## Rules that are load-bearing
1. **A finding requires evidence.** `PoC.request`/`PoC.response` are validated
   non-empty at construction. Do not add a path that creates a `Finding` without real
   reproduced output — that guarantee is the product.
2. **`shell` and `browser` never run on the host.** With no sandbox they refuse. Do not
   add a host fallback.
3. **Tool modules imported by the shim must stay stdlib-only.** `tools/shell`,
   `tools/http_request`, `tools/output_store`, `tools/proxy` run inside the container,
   where nothing is installed.
4. **Agents stop only via a finish tool.** Enforced by `tool_use_behavior`, not prompts.
5. **A dead child still reports.** The `finally:` block in `_run_child` is what stops a
   waiting parent from hanging. Don't make it conditional.
6. **No telemetry.** See `docket/telemetry/README.md`.

## Conventions
- Every module has a runnable `demo()` self-check. Run them all with `make check`
  (43 of them, no Docker or API key needed). Add one for anything non-trivial.
- Run modules as `python -m docket.x.y`, never `python docket/x/y.py` — the latter puts
  the package dir on `sys.path` and shadows the third-party `agents` SDK.
- Tests are plain-assert scripts, no pytest. `make test` needs Docker.
- The test target is `tests/fixtures/target_app.py`: self-contained, intentionally
  vulnerable, loopback only.

## Before you commit
```bash
make check      # 43 module self-checks, fast
make test       # 12 test scripts (Docker)
```
