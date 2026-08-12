# Working on docket

Orientation for anyone (human or agent) editing this repo.

## What this is
An autonomous pentesting tool: LLM agents that exploit a target dynamically and report
a finding only once they have reproduced it with a working proof-of-concept.

## Layout
`engine/` is a source root, nothing more — it is never imported and holds no code of its
own. The importable package is `docket`, so imports are always `from docket.core...`
regardless of the wrapper. `containers/`, `tests/`, and packaging live at the repo root.

| Path | Role |
|---|---|
| `engine/docket/core/` | coordinator, run loop, hooks, sessions, paths, runner |
| `engine/docket/agents/` | agent factory + prompts (root / specialist) |
| `engine/docket/tools/` | 15 tool packages (several expose more than one tool) + `output_store` |
| `engine/docket/runtime/` | Docker sandbox, in-container RPC shim, SDK sandbox session |
| `engine/docket/llm/` | context budget + conversation compaction |
| `engine/docket/report/` | finding model, dedupe, SARIF, writer, usage |
| `engine/docket/interface/` | CLI, TUI (Textual), local web viewer |
| `engine/docket/skills/` | markdown playbooks agents load on demand |

## Rules that are load-bearing
1. **A finding requires evidence.** `PoC.request`/`PoC.response` are validated non-empty
   at construction. The validator is necessary but not sufficient: it only ever sees the
   output of the coercion in `tools/reporting/tool.py`, and `str()` will happily invent
   something non-blank from nothing (`str(None)` is `"None"`; rendering an empty request
   dict is `"GET "`). Both used to pass. Coerce through `_evidence()`, which returns `""`
   for absent or structurally empty input, and keep the explicit refusal that tells the
   agent which field is missing. Do not add a path that creates a `Finding` without real
   reproduced output — that guarantee is the product.
2. **`shell` and `browser` never run on the host.** With no sandbox they refuse. Do not
   add a host fallback. The only host subprocesses are `docker` invocations.
3. **Tool modules imported by the shim must stay stdlib-only.** They run inside the
   container, where no project dependency is installed. The `shim-stdlib-only` pre-commit
   hook enumerates the guarded files — if you add an import to anything the shim or
   mitmdump loads, add the file to that list too.
4. **Agents should stop via a finish tool** — `tool_use_behavior` enforces it for the
   tool path, but it is **not** the only exit. A non-`str` `output_type` lets the SDK end a
   run on any plain assistant message matching that schema, checked before the tool-use
   gate. This is not theoretical: on the first live run a model took that exit on turn one
   with zero tool calls and invented findings. `run_agent_loop` now discards such output,
   re-prompts with `_NO_TOOL_CORRECTION`, and refuses on the third attempt. **Keep that
   path** — without it a fabricated summary reaches the report, which defeats rule 1.
5. **A dead child still reports.** Two halves. `coordinator.register()` is the *caller's*
   job in `create_agent`, before `spawn_child_agent` — that makes the child visible to a
   same-turn `wait_for_agents` and puts a `max_agents` refusal somewhere the model can see
   it. Everything after registration lives inside `_run_child`'s `try`, whose `finally:`
   guarantees a terminal status. Don't move registration back into the task and don't make
   the `finally:` conditional.
6. **No telemetry, and no incidental outbound calls.** Nothing docket collects. Note
   `engine/docket/__init__.py` sets `LITELLM_LOCAL_MODEL_COST_MAP=true`, because importing
   litellm otherwise fetches a price map from GitHub before any of our code runs. Keep that
   line, and keep `__init__.py` stdlib-only. See `engine/docket/telemetry/README.md`.
7. **The SDK's sandbox capabilities stay opt-in.** `Filesystem`/`Shell` from
   `agents.sandbox.capabilities` are *hosted* tools: only OpenAI's Responses API accepts
   them, and over Chat Completions (every LiteLLM-routed provider, every OpenAI-compatible
   gateway) the run dies before turn one. `DOCKET_SDK_SANDBOX_TOOLS=1` re-enables them.
   Don't flip the default: our own container-backed `shell`/`browser` already do the work,
   and no scripted test can catch this because a scripted model never serializes tools.
8. **Shared artifacts are redacted at the write boundary.** `report/writer.py`,
   `report/sarif.py` and `runtime/proxy_addon.py` pass serialized output through
   `redact()`. Redact whole documents, not hand-picked fields, so a new field is covered by
   default. `redact()` must stay stdlib-only — `proxy_addon` imports it in-container.

## Conventions
- Every module has a runnable `demo()` self-check. Run them all with `make check`
  (43 of them, no Docker or API key needed). Add one for anything non-trivial.
- Run modules as `python -m docket.x.y`, never `python engine/docket/x/y.py` — the latter puts
  the package dir on `sys.path` and shadows the third-party `agents` SDK.
- Tests are plain-assert scripts, no pytest. `make test` needs Docker.
- The test target is `tests/fixtures/target_app.py`: self-contained, intentionally
  vulnerable, loopback only.

## Before you commit
```bash
make check      # 43 module self-checks, fast
make test       # 12 test scripts (Docker)
```
