# Contributing

## Setup
```bash
uv sync
cp .env.example .env      # then add your model + key
make image                # build the sandbox container (~1 min first time)
make check                # 43 self-checks, no Docker or key needed
```

## Adding a tool
1. Create `docket/tools/<name>/` with `tool.py` (single tool) or `tools.py` (several),
   matching the existing convention.
2. Keep it **stdlib-only** if it will run inside the sandbox — the container has no
   project dependencies installed.
3. Add a `@function_tool` wrapper in `docket/agents/factory.py` and put it in the right
   role's list. Tools that don't touch the target belong in `_COMMON_TOOLS`.
4. Add a `demo()` self-check and register the module in the `Makefile`'s `check` list.

## Adding a skill
Drop a markdown file in `docket/skills/<category>/`. No code change — `load_skill` picks
it up as `<category>/<filename>`.

## Adding a specialist role
Extend the `Role`/`SpecialistRole` literals in `docket/agents/factory.py`, add a
technique hint in `docket/agents/prompts/specialist.py`, and grant only the tools that
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
