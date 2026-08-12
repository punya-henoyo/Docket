# Contributing

## Setup
```bash
uv sync
cp .env.example .env      # then add your model + key
make image                # build the sandbox container (~1 min first time)
make check                # 57 self-checks, no Docker or key needed
```

## The loop
```bash
make check                # every module's demo(), fast, no Docker or key
make test-fast            # 7 test scripts that need no container
make test                 # all 12, builds the image first (needs Docker)
```

Run modules as `python -m docket.x.y`, **never** `python engine/docket/x/y.py` — the latter
puts the package directory on `sys.path` and shadows the third-party `agents` SDK. That has
bitten this repo before.

Tests are plain-assert scripts, no pytest. Each module carries a runnable `demo()`; add one
for anything non-trivial and register it in the `Makefile`'s `check` list, or it never runs.

Write a check that can *fail*. Two guards in this repo silently always passed — `make lint`
swallowed ruff's exit code, and a PoC emptiness check was satisfied by the string `"None"`.
Prove a new check catches the thing it exists to catch before you trust it.

The test target is `tests/fixtures/target_app.py`: self-contained, intentionally vulnerable,
loopback only. CI runs `make check` and `make test-fast` on every push, and builds the
sandbox image when it or the package changes — see [`.github/workflows.md`](.github/workflows.md)
for why the container-backed tests are local-only, and why there is no lint job yet.

## Adding a tool
1. Create `engine/docket/tools/<name>/` with `tool.py` (single tool) or `tools.py` (several),
   matching the existing convention.
2. Keep it **stdlib-only** if it will run inside the sandbox — the container has no
   project dependencies installed.
3. Add a `@function_tool` wrapper in `engine/docket/agents/factory.py` and put it in the right
   role's list. Tools that don't touch the target belong in `_COMMON_TOOLS`.
4. Add a `demo()` self-check and register the module in the `Makefile`'s `check` list.

## Adding a skill
Drop a markdown file in `engine/docket/skills/<category>/`. No code change — `load_skill` picks
it up as `<category>/<filename>`.

## Adding a specialist role
Extend the `Role`/`SpecialistRole` literals in `engine/docket/agents/factory.py`, add a
technique hint in `engine/docket/agents/prompts/specialist.py`, and grant only the tools that
role genuinely needs. Narrow tool sets are deliberate.

## Style
- Comments explain **why**, not what. If a decision looks odd, the comment should say
  what would break otherwise.
- Prefer stdlib. Every dependency here earns its place: `web_search` talks to five
  providers over plain `urllib` rather than pulling in five SDKs.
- Don't silently degrade. A tool that can't work returns an explicit error the agent
  can act on — never a fabricated result.

## Security
This tool exploits targets. Only point it at systems you own or are authorised to test.
Never commit `.env`, run artifacts, or anything under `docket_runs/`.
