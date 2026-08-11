# CI

`ci.yml` is present in the working tree but intentionally not committed. Pushing a
workflow file requires a token carrying the `workflow` scope, which the current `gh`
token does not have.

To enable it:

    gh auth refresh -h github.com -s workflow
    gh auth status          # 'workflow' must appear in the scopes line
    git add .github && git commit -m "Add CI" && git push

What it runs: the 43 module self-checks (`make check`), which need neither Docker nor an
API key. The container-backed tests are excluded on purpose, since they build a ~2.5GB
Chromium image, a poor fit for a per-push gate. Run those locally with `make test`.
