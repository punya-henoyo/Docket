# CI

Two workflows, both passing.

## `ci.yml` — every push and PR

`make check` (43 module self-checks) and `make test-fast` (7 test scripts). Neither needs
Docker or an API key. `uv sync --frozen`, so a stale `uv.lock` fails the build instead of
quietly resolving something else.

## `sandbox-image.yml` — when the image or package changes

Builds `containers/Dockerfile`, starts the container, and asserts `/health` returns `ok`
with all 12 tools registered. Runs in about 1m20s.

This job exists because the image is where breakage hides silently: `make check` and
`make test-fast` both pass with a completely broken Dockerfile, since neither touches
Docker. Moving the package to `engine/docket/` changed the `COPY` source path, and nothing
but building the image would have caught it.

Path-filtered to `containers/**`, `engine/docket/**`, `pyproject.toml`, so a README edit
does not trigger a multi-minute Chromium pull. No layer caching; with those filters it
runs rarely enough that buildx plus a GHA cache is not worth the complexity.

## Action versions are pinned exactly, on purpose

`astral-sh/setup-uv@v9.0.0`, not `@v9`. astral-sh publishes `v9.0.0` as a full tag but
their **floating major tags stop at v7**, so `@v9` does not resolve and the job dies at
"Set up job" in six seconds. `actions/checkout` does publish a floating `v7`, but an exact
pin is what a gate wants regardless: it cannot drift underneath you.

Do not assume a floating `vN` exists because release `vN.0.0` does. Check:

    gh api repos/OWNER/REPO/git/matching-refs/tags/v --jq '.[].ref'

## Editing workflows requires the `workflow` scope

`git push` and the REST Contents API both refuse to create or update anything under
`.github/workflows/` unless the token carries `workflow`. The current `gh` token has
`gist, read:org, repo`, so these two files were added through the GitHub **web editor**,
which authenticates as the user's own session and is not subject to the rule.

To edit them from the CLI:

    gh auth refresh -h github.com -s workflow
    gh auth status          # 'workflow' MUST appear in the scopes line

Verify that line rather than assuming. `gh auth refresh` can report no error while leaving
scopes unchanged, for example if the browser tab is closed before Authorize is clicked.

## Why the container-backed tests are not in CI

`sandbox`, `proxy`, `browser`, `sdk_session`, and `full_run` need the container to reach a
target app on the **host**. The fixture binds `127.0.0.1`
(`tests/fixtures/target_app.py`), and the sandbox passes
`--add-host host.docker.internal:host-gateway`. On Docker Desktop for Mac that alias is
proxied to host loopback, so it works. On a Linux runner `host-gateway` resolves to the
docker bridge IP, and a socket bound to `127.0.0.1` refuses connections there.

An environment mismatch, not a code defect. Closing the gap means either binding the
fixture to `0.0.0.0` (which exposes a deliberately vulnerable app on the runner network)
or running the container with `--network=host` on Linux (which removes the `-p` mapping
the shim's port readback depends on). Neither is a workflow change. Run them locally with
`make test`.

## Why there is no lint job

ruff had never actually run in this repo. It was not installed locally, and the `make
lint` recipe used `A && B || echo`, which swallows a real failure and exits 0. A first
genuine run on ruff 0.16.2 reports 84 findings and 73 files the formatter would rewrite,
largely because this code runs to ~111 columns against ruff's default 88.

That is a real cleanup, not a CI detail. Adding lint later means: pin a ruff version,
commit a `[tool.ruff]` block with `line-length` and an explicit `select` (ruff 0.16 enables
far more rules by default than older versions, so an unpinned ruff makes the gate drift),
fix the findings, then add a job running `make lint`.
