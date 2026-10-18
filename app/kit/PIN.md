# Visual Kit pin

`frontend/src/components/webcomponents/henoyo*.ts` (and their helpers) are copied from
`plumcloud/henoyo-core`, branch `integ/visual-kit-review`, commit `c2a3ba4f495ac61a3c32d15d7c3165dcd912b75d`
(2026-10-12). That branch is 473 commits ahead of `release/v3`; the kit is not in v3 yet.

`docket*.ts` are Docket's own elements. They extend the kit's `HenoyoElement` and read the same `--h-*` tokens,
so they can be proposed into Core's Visual Kit by moving the files across.

`../frontend/public/kit/tokens.css` is `frontend/src/theme/tokens.css` from the same commit.
Re-pin: copy the files again, update the commit above, run `./build.sh`.

## Local patches (propose upstream)

- `henoyoRing.ts`: optional `finding` prop that replaces the computed "<largest part> is N%" title. A health ring must not headline the good news.
- `henoyoRecordBanner.ts`: optional per-row `word`, because the danger level is hard-coded to read "Overdue".
- `henoyoRing.ts`: `showPercent=false` drops the percentage column (counts of applications are not a distribution to rank).
