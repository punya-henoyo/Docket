---
name: fix-workflow
description: The four-phase remediation workflow - triage, fix, verify by re-scanning, report - with the rules that stop an unverified patch being called fixed
---

# Remediation workflow — triage, fix, verify, report

You are fixing a security finding in a repository you can read and edit. You execute no
exploits and you touch no network. Your output is a patch plus an honest verdict on
whether it worked.

Four phases, in order. **You may not skip phase 3.** A patch whose fix cannot be
demonstrated is reported as unverified, never as fixed.

---

## Phase 1 — Triage

Read the finding before you touch code:

- `docket_runs/<run>/report.json` → `findings[]` for the finding. A verdict already reached
  on it lives in one of two places, because two triage passes write two vocabularies:
  `findings[].triage` (`exploitable` / `not_reachable` / `uncertain`) or the top-level
  `triaged[]` (`CONFIRMED` / `FALSE_POSITIVE` / `UNCERTAIN`). **Read `triaged[]` — it is
  authoritative**: the report now derives those rows from `findings[].triage` whenever that
  is where the verdicts landed, so one list answers "what was judged" either way. An empty
  `triaged[]` means nobody judged this finding, not that it was cleared.
- The finding's `poc.request` for a static finding **is the matched source line**, and its
  `location.source_file` is `path:line`. That line is your anchor.

Work worst-first: critical → high → medium → low.

**Do not dismiss a finding as a false positive without reading the code yourself.** A
`not_reachable` / `FALSE_POSITIVE` triage verdict is *reasoning over source*, not proof — it is weaker than a
reproduction by design. If you disagree with it, say so and give the lines that changed
your mind. If you agree, stop and report `not_a_bug` with the guard you found quoted. Do
not patch something that was never broken; a needless diff spends a reviewer's trust.

Load the matching `triage/<class>` playbook first. Its "Not a bug when" list is the fastest
way to avoid fixing a non-bug, which is the most expensive mistake available to you.

**If the anchor is not in the file at the recorded commit**, stop: `not_reproducible`. The
repository moved and this finding is about code that is no longer there.

---

## Phase 2 — Fix

**Fix the root cause, not the payload.** If one query in the file interpolates user input,
check every query in that file. A patch that fixes the flagged line and leaves its three
siblings is a patch that closes a ticket without closing a hole.

**Prefer the framework's own defence over a hand-rolled sanitiser**, every time:

| Class | Do this | Not this |
|---|---|---|
| SQL injection | parameterised query / ORM binding at the sink | escaping or a blocklist of quotes |
| Command injection | `subprocess` with an argv **list**, `shell=False` | quoting the interpolated string |
| XSS | the template engine's autoescape, or `escape()` | stripping `<script>` |
| Path traversal | `safe_join`, or resolve-then-contain by parent walk | rejecting `..` |
| IDOR / broken access control | an object-level authorisation check | a check on the route only |
| SSRF | an allowlist, plus blocking internal ranges | a denylist of hostnames |
| Deserialisation | a safe loader (`yaml.safe_load`, `json`) | validating after loading |

A hand-rolled sanitiser is a promise to maintain a parser forever, and the reviewer knows it.

**Keep the diff minimal and in the codebase's own idiom.** Match the surrounding naming,
imports and comment density. Concretely:

- **Do not reformat.** A patch that reflows a file is rejected outright — it buries the one
  line that matters in noise, and the containment checks treat a whitespace-only change as
  a reformat and refuse it.
- Do not rename, do not refactor, do not add abstractions.
- Do not touch anything outside the finding's own file. Scope is derived from the finding,
  not from you, and an edit outside it is refused with `diff_out_of_bounds`.
- **Never edit CI config, `.github/`, lockfiles you were not asked to touch, or any secrets
  file.** Refused, and correctly.
- **Never weaken or silence the check instead of fixing it.** Adding `# nosemgrep`,
  `# noqa`, an exclusion, or a config downgrade is not a fix. It makes the scanner quiet
  and the bug permanent. If you cannot fix it safely, say `no_safe_fix` and why — that is a
  correct, expected, respected answer. A plausible-looking wrong fix is the worst thing you
  can produce.

If the repository has a test suite, the fix must leave it passing. A fix that breaks
behaviour is not a fix.

**Anchoring your edit.** File contents are shown to you with `NN: ` line-number prefixes.
Strip those when you quote text as an anchor — the anchor must match the file's real bytes,
not the display. Anchor on enough surrounding text to be unique; if the tool says your
anchor matches zero or several places, re-read the region and widen it rather than guessing.

---

## Phase 3 — Verify by re-scanning. Not optional.

Re-run the scanner on the patched tree and compare against the same scanner run on the
pristine tree at the same commit, same config, same image. Confirm the finding is gone.

**Absence of the finding is not sufficient evidence.** This is the whole trap. A patch that
breaks the file's syntax makes the scanner emit **zero** findings for that file, which reads
as a perfect fix and is the opposite of one. So a clean re-scan only counts alongside proof
that the scan actually happened and actually covered the file:

1. **Positive control** — the finding IS present in the pristine scan. If it is absent from
   the baseline, your comparison proves nothing: the scanner did not run, or its config
   changed, or the anchor was never there.
2. The finding is absent from the patched scan.
3. **Nothing else vanished.** Only the target should disappear. Other findings going away
   means the file stopped being parsed, or you deleted the vulnerable code rather than
   fixing it.
4. **No new findings appeared.** Your fix must not introduce one.
5. **Parse errors did not increase.** A rise means you broke the file.
6. **The file count scanned did not drop.** A drop means your file fell out of coverage,
   which is how a syntax error masquerades as a clean result.
7. The build and test suite still pass, where they exist.

A scanner that cannot fail loudly cannot supply a proof. Only a scanner that reports its own
errors counts here — one that returns an empty list on a crash makes "not reproduced" and
"crashed" the same answer, and that answer is worthless. If the scanner errors, the result is
`validation_inconclusive`, never `verified_fixed`.

An exit code of 0 is not a verdict. Check that the run completed and that it did not stop
early on a budget or turn ceiling; a truncated run reports clean because it never looked.

### Outcomes, and only these three

| Outcome | Requires |
|---|---|
| `verified_fixed` | every gate above |
| `unverified_plausible` | build and tests pass, but a gate could not be established — **must be labelled as unverified wherever it is shown** |
| `not_fixed` | the finding survives, or the patch breaks the build |

Only the first two are worth delivering, and the second must never be presented as fixed.

---

## Phase 4 — Report

For each finding, record:

- Severity and class.
- **Root cause in one paragraph** — why the code was wrong, not what the scanner said.
- The invariant the fix now enforces. "Untrusted input can no longer reach the query as
  syntax" beats "added parameterisation".
- `file:line`, at the base commit.
- **The verification outcome, with the before and after evidence**, and the failing gate
  named if it is not `verified_fixed`.
- **What to double-check**: any behaviour that might change. Say it plainly. A reviewer who
  finds a behaviour change you did not mention will not trust the next patch.

**Never put a live secret in the report.** If the finding is a leaked credential, the patch
removing it is not the fix — the credential is already public to anyone who saw the repo.
State that **rotation is required**, name what must be rotated, and do not reproduce the
value.

---

## Refusals

Stop and report, rather than proceeding, when:

- the anchor is absent at the base commit → `not_reproducible`
- the finding turns out not to be a bug → `not_a_bug`, with the guard quoted
- a safe minimal fix does not exist → `no_safe_fix`, with the reason
- the fix needs a file outside the finding's scope → `needs_wider_scope`, naming the file
- the scanner could not run → `validation_inconclusive`

Each of these is a successful outcome of your work. None of them is a failure. The only
failure available to you is a patch that looks right, cannot be shown to work, and is
reported as fixed anyway.

---

Adapted from the strix project's `skills/fix-security-vulnerabilities-with-strix`
(Apache-2.0), whose four-phase triage → fix → verify-by-re-running → report structure and
whose rules (root cause over payload, framework defences over custom sanitisation, minimal
diffs, re-scan to verify, no secrets in reports) this follows. Changes: adapted to docket's
source-only remediation, where findings carry a matched source line rather than a live
proof-of-concept, so phase 3 substitutes a pristine-versus-patched scanner comparison with
explicit coverage gates for strix's replay of a working exploit. See NOTICE.
