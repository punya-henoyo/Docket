# CI

Two workflows exist in the working tree and are **not committed**. Pushing a workflow
file requires a token carrying the `workflow` scope, which the current `gh` token does
not have. Both routes are blocked by the same rule: `git push` is rejected outright, and
the REST Contents API returns a masked `404` for paths under `.github/workflows/`
(verified — the identical API call succeeds for this file, so it is the path, not the
payload).

To enable them:

    gh auth refresh -h github.com -s workflow
    gh auth status          # 'workflow' MUST appear in the scopes line
    git add .github && git commit -m "Add CI" && git push

Check `gh auth status` rather than assuming. `gh auth refresh` can report no error while
leaving scopes unchanged, for example if the browser tab is closed before Authorize is
clicked.

Alternatively paste them in through the GitHub web editor, which runs as your own session
rather than an OAuth token and is not subject to the restriction:
`github.com/punya-henoyo/Docket/new/main?filename=.github/workflows/ci.yml`

## `ci.yml` — every push and PR

`make check` (43 module self-checks) and `make test-fast` (7 test scripts). Neither needs
Docker or an API key. `uv sync --frozen` so a stale `uv.lock` fails the build instead of
quietly resolving something else.

## `sandbox-image.yml` — when the image or package changes

Builds `containers/Dockerfile`, then starts the container and asserts `/health` returns
`ok` **and** all 12 tools registered.

This job exists because the image is where breakage hides silently: `make check` and
`make test-fast` both pass with a completely broken Dockerfile, since neither touches
Docker. Moving the package to `engine/docket/` changed the `COPY` source path, and
nothing but building the image would have caught it.

Path-filtered to `containers/**`, `engine/docket/**`, `pyproject.toml`, so a README edit
does not trigger a multi-minute Chromium pull. No layer caching yet; with those filters
it runs rarely enough that buildx plus GHA cache is not worth the complexity.

## Why the container-backed tests are not in CI

`sandbox`, `proxy`, `browser`, `sdk_session`, and `full_run` need the container to reach a
target app on the **host**. The fixture binds `127.0.0.1`
(`tests/fixtures/target_app.py`), and the sandbox passes
`--add-host host.docker.internal:host-gateway`. On Docker Desktop for Mac that alias is
proxied to host loopback, so it works. On a Linux runner `host-gateway` resolves to the
docker bridge IP, and a socket bound to `127.0.0.1` refuses connections there.

So those tests fail on GitHub-hosted runners for an environment reason, not a code
defect. Closing the gap means either binding the fixture to `0.0.0.0` (which exposes a
deliberately vulnerable app on the runner network) or running the container with
`--network=host` on Linux (which removes the `-p` mapping the shim's port readback
depends on). Neither is a workflow change. Run them locally: `make test`.

## Why there is no lint job

ruff had never actually run in this repo. It was not installed locally, and the `make
lint` recipe used `A && B || echo`, which swallows a real failure and exits 0. A first
genuine run on ruff 0.16.2 reports 84 findings and 73 files the formatter would rewrite,
largely because this code runs to ~111 columns against ruff's default 88.

That is a real cleanup, not a CI detail. Adding lint later means: pin a ruff version,
commit a `[tool.ruff]` block with `line-length` and an explicit `select` (ruff 0.16
enables far more rules by default than older versions, so an unpinned ruff makes the gate
drift), fix the findings, then add a job running `make lint`.
