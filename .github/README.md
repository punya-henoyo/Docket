# CI

`workflows/ci.yml` exists in the working tree but is **not committed**. Pushing a
workflow file requires a token carrying the `workflow` scope, which the current `gh`
token does not have. Both routes are blocked by the same rule: `git push` is rejected
outright, and the REST Contents API returns a masked `404` for paths under
`.github/workflows/`.

To enable it:

    gh auth refresh -h github.com -s workflow
    gh auth status          # 'workflow' MUST appear in the scopes line
    git add .github && git commit -m "Add CI" && git push

Check `gh auth status` rather than assuming. `gh auth refresh` can report no error while
leaving the scopes unchanged, for example if the browser tab is closed before the
Authorize button is clicked.

Alternatively paste the file in through the GitHub web editor, which runs as your own
session rather than an OAuth token and is not subject to the restriction:
`github.com/punya-henoyo/Docket/new/main?filename=.github/workflows/ci.yml`

## What the workflow runs

`make check` (43 module self-checks) and `make test-fast` (7 test scripts), neither of
which needs Docker or an API key. Both are verified green.

The container-backed tests are excluded: they build a ~2.5GB Chromium image, a poor fit
for a per-push gate. Run those locally with `make test`.

## Why there is no lint job

ruff had never actually run in this repo. It was not installed locally, and the `make
lint` recipe used `A && B || echo`, which swallows a real failure and exits 0. A first
genuine run reports 84 findings and 73 files the formatter would rewrite, largely
because this code runs to ~111 columns against ruff's default 88.

That is a real cleanup, not a CI detail, so it is tracked separately. Adding lint later
means: pin a ruff version, commit a `[tool.ruff]` block with `line-length` and an
explicit `select` (ruff 0.16 enables far more rules by default than older versions, so
an unpinned ruff makes the gate drift), fix the findings, then add a job that runs
`make lint`.
