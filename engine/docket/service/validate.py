"""The seven gates. The only place `verified_fixed` is allowed to come from.

`service/delivery.py` opens a fix pull request on exactly one condition:
`patch.status == "verified_fixed"` (delivery.py:41). Nothing else in the codebase may
produce that string, and in particular no model may: an LLM asked whether its own patch
worked will say yes, and its answer is a claim, not a proof. This module is a pure
function over two directories.

THE TRAP THIS EXISTS TO CLOSE
-----------------------------
From skills/fix/workflow.md phase 3: "A patch that breaks the file's syntax makes the
scanner emit zero findings for that file, which reads as a perfect fix and is the opposite
of one." So absence of the finding is not evidence. A clean re-scan only counts alongside
proof that the scan happened and covered the file, which is why there are seven gates and
not one:

  1. positive_control            the target IS in the pristine scan
  2. target_absent               the target's rule fires nowhere in that file any more
  3. nothing_else_vanished       ONLY the target disappeared
  4. no_new_findings             the patch introduced none
  5. parse_errors_not_increased  a rise means you broke the file
  6. files_scanned_not_dropped   a drop means your file fell out of coverage
  7. tests_pass                  see GATE 7 below

Gates 3, 5 and 6 are three independent nets under the same syntax error, on purpose. A
broken file usually trips all three; a broken file that trips only one is still caught.

WHAT EACH GATE COMPARES, AND WHY THE LINE NUMBER IS NOT IN GATES 2, 3 AND 4
--------------------------------------------------------------------------
A finding key is `(rule_id, file, line)`. Gate 1 compares the WHOLE key, because that is
identification and it must be exact. Gates 2, 3 and 4 compare `(rule_id, file)` and the
per-`(rule_id, file)` COUNT, because a line number is noise for the question "did anything
else change" — and two live reproductions proved that comparing it there rejects correct
fixes:

  * `p/default` has overlapping rules by design. `os.system("ping " + host)` fires BOTH
    `os-system-injection` and `dangerous-system-call` on the same line. A correct fix clears
    both, and a key-level gate 3 read the second one as collateral damage. Two rules on one
    line are one defect seen twice, so gate 3 exempts any rule that fired at the target's
    EXACT `(file, line)` — that exact line only, nothing else in the file.
  * Adding an import (`import subprocess`, `import shlex`, `from markupsafe import escape`)
    is the most common shape a security fix takes, and it shifts every line below it down.
    A key-level comparison counted an untouched finding as BOTH vanished (at its old line)
    and new (at its new line), so gates 3 and 4 both failed. Between them these two shapes
    meant almost no real fix could ever reach `verified_fixed`.

The count is compared as well as the set, so losing one of three same-rule hits in a file
is still a visible disappearance rather than something dropping the line hides.

Gate 2 is `(rule_id, file)` for a second, independent reason, and it is a fail-open this
closes rather than a convenience: a patch that moves the vulnerable call to another line
without fixing it satisfies an exact-key gate 2, and once gates 3 and 4 stop comparing line
numbers nothing else notices either. File-level is also what workflow.md:50-52 asks for —
"A patch that fixes the flagged line and leaves its three siblings is a patch that closes a
ticket without closing a hole." The consequence is deliberate: a fix must clear that rule
from the whole file, and a partial fix reports `not_fixed`.

WHY A SCANNER ERROR IS ITS OWN OUTCOME
--------------------------------------
"A scanner that cannot fail loudly cannot supply a proof" (workflow.md:117). An empty
report from a crashed scanner is indistinguishable from a clean one, so every way the scan
can fail to happen — semgrep absent, timed out, unable to start, non-JSON output — returns
`validation_inconclusive`. Never `verified_fixed`, and never `not_fixed` either: you cannot
say a fix failed on evidence you do not have.

`static/engines.run_semgrep` cannot be used here for that reason and one other: it swallows
each of those failures into `report.notes` as a string and returns an empty report, and it
runs with `--sarif`, which carries findings but not the two coverage numbers gates 5 and 6
need. So the scan below runs semgrep once with `--json` — one invocation yields `results[]`,
`errors[]` and `paths.scanned`, so findings and coverage can never disagree — and reports
its own failures as a value. The args are derived from `engines.SEMGREP_ARGS` so the
config, the rule pack and the metrics-off promise stay identical to the pipeline's scan.

Both trees are scanned inside this one function, with the same args and the same timeout.
That is deliberate: a caller handed two scan results could mismatch their configs, and a
comparison between two different configs is not evidence of anything.

GATE 7, AND THE READING OF THE OUTCOME TABLE (workflow.md:126-132)
-----------------------------------------------------------------
The table says `verified_fixed` requires "every gate above", `unverified_plausible` is for
when "a gate could not be established", and `not_fixed` is "the finding survives, or the
patch breaks the build". Gate 7 itself reads "The build and test suite still pass, WHERE
THEY EXIST".

This module never runs a repository's tests, and that is not laziness: executing a test
command out of the pull request under review is arbitrary code execution from an untrusted
source on the host, which AGENTS.md rule 2 forbids outright. So gate 7 is recorded `None`,
honestly, in `gates` and in `evidence["tests"]`, and the report must say tests were not
run. It does NOT block `verified_fixed`, on the "where they exist" clause: treating it as
blocking would collapse every possible outcome to `unverified_plausible` and make the
other six gates decorative. The fix branch is cut from the pull request's own head
(delivery.py), so the repository's CI runs its tests on the fix commit anyway — by a
runner that is meant to execute that code, which this host is not.

A gate that is `None` for any OTHER reason does cap the outcome at
`unverified_plausible`: an unestablished gate is the absence of evidence, which is what
that status means. A gate that is `False` is evidence AGAINST, which is `not_fixed`. False
is checked before None, because a demonstrated failure outranks an unknown.
"""
from __future__ import annotations

import json
import subprocess
from collections import Counter
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from docket.static.engines import SEMGREP_ARGS, semgrep_available
from docket.tools.scanners.semgrep import parse_coverage

VERIFIED = "verified_fixed"
PLAUSIBLE = "unverified_plausible"
NOT_FIXED = "not_fixed"
INCONCLUSIVE = "validation_inconclusive"

# The workflow's order. This is the order the report shows, and `gates` is built in it.
GATES = ("positive_control", "target_absent", "nothing_else_vanished", "no_new_findings",
         "parse_errors_not_increased", "files_scanned_not_dropped", "callers_consistent",
         "tests_pass")

# Attribution order, which is NOT the display order: `failed_gate` must name the most
# DIAGNOSTIC failure, not the first one in the list. A broken file trips several gates at
# once, and "you broke the file" explains "other findings vanished" — the reverse is not
# true, so the coverage gates are named first. `positive_control` is absent because it
# returns before anything else is computed, and `tests_pass` because it is never False.
_DIAGNOSTIC_ORDER = ("callers_consistent", "parse_errors_not_increased",
                     "files_scanned_not_dropped",
                     "target_absent", "nothing_else_vanished", "no_new_findings")

# The pipeline's own semgrep invocation with --sarif swapped for --json. Derived rather
# than retyped so the two can never drift into scanning with different rules.
SEMGREP_JSON_ARGS = tuple("--json" if arg == "--sarif" else arg for arg in SEMGREP_ARGS)

# Long lists in `evidence` end up in a pull-request comment; the counts stay exact.
MAX_LISTED = 20

Key = tuple[str, str, int]


@dataclass
class Validation:
    status: str                       # verified_fixed | unverified_plausible |
                                      # not_fixed | validation_inconclusive
    gates: dict[str, bool | None]     # None = could not be established
    failed_gate: str | None
    evidence: dict                    # the before/after numbers, for the report


@dataclass(frozen=True)
class ScanOutcome:
    """One scan of one tree. `error` is the loud failure; when it is set nothing else
    here means anything. `files_scanned`/`parse_errors` are None when the scanner did not
    report coverage at all, which is different from reporting zero."""

    keys: frozenset[Key] = frozenset()
    files_scanned: int | None = None
    parse_errors: int | None = None
    error: str | None = None
    coverage: dict = field(default_factory=dict)


def _pair(key: Key) -> tuple[str, str]:
    """(rule_id, file) — a finding's identity with the line dropped. See the module
    docstring for why gates 2, 3 and 4 compare at this level."""
    return (key[0], key[1])


def _norm_key(key: tuple) -> Key:
    """Keys arrive from two vocabularies: `StaticFinding.key` carries semgrep's bare
    check_id, `report.models.Finding.rule_id` prefixes it with "semgrep/". Normalising
    both ends means a caller holding either shape still gets a positive control."""
    rule_id, file, line = key
    return (str(rule_id).removeprefix("semgrep/"),
            PurePosixPath(str(file)).as_posix(), int(line))


def _relative(path: str, root: Path) -> str:
    """Semgrep reports the path it was given, which is absolute here. Rebase it so keys
    from two different temporary trees are comparable at all."""
    try:
        return Path(path).resolve().relative_to(root.resolve()).as_posix()
    except (ValueError, OSError):
        return str(path)


def parse_scan_json(text: str, root: str | Path) -> ScanOutcome:
    """Semgrep `--json` output -> findings AND coverage. Pure, so it is demo-testable
    without semgrep installed."""
    try:
        doc = json.loads(text)
    except json.JSONDecodeError:
        return ScanOutcome(error="semgrep output was not valid JSON")
    if not isinstance(doc, dict):
        return ScanOutcome(error="semgrep output was not a JSON object")

    root = Path(root)
    keys = set()
    for result in doc.get("results") or []:
        if not isinstance(result, dict):
            continue
        line = (result.get("start") or {}).get("line")
        if not result.get("check_id") or not line:
            continue
        keys.add(_norm_key((result["check_id"],
                            _relative(str(result.get("path", "")), root), line)))

    coverage = parse_coverage(text)
    paths = doc.get("paths")
    scanned_reported = isinstance(paths, dict) and isinstance(paths.get("scanned"), list)
    return ScanOutcome(
        keys=frozenset(keys),
        files_scanned=coverage.get("files_scanned") if scanned_reported else None,
        parse_errors=coverage.get("error_count") if "errors" in doc else None,
        coverage=coverage,
    )


def scan_tree(root: str | Path, *, timeout_sec: int = 600) -> ScanOutcome:
    """One semgrep run, host-side, no Docker — `semgrep_available()` finds a real binary
    or uvx. Every failure is returned as `error`, never as an empty result."""
    root = Path(root)
    if not root.is_dir():
        return ScanOutcome(error=f"source path is not a directory: {root}")
    binary = semgrep_available()
    if binary is None:
        return ScanOutcome(error=(
            "semgrep is not installed, so nothing was verified. This is NOT a clean "
            "result. Install it (`uv tool install semgrep`)."))
    argv = ([binary, *SEMGREP_JSON_ARGS, str(root)] if binary != "uvx"
            else ["uvx", "semgrep", *SEMGREP_JSON_ARGS, str(root)])
    try:
        done = subprocess.run(argv, capture_output=True, text=True, timeout=timeout_sec)
    except subprocess.TimeoutExpired:
        return ScanOutcome(error=f"semgrep timed out after {timeout_sec}s on {root}")
    except OSError as exc:
        return ScanOutcome(error=f"could not start semgrep: {exc}")
    if not done.stdout.strip():
        # Exit 1 is normal (semgrep found something). No output at all is not.
        tail = (done.stderr or "").strip().splitlines()[-1:] or ["no diagnostics"]
        return ScanOutcome(error=(f"semgrep produced no JSON (exit {done.returncode}): "
                                  f"{tail[0][:200]}"))
    return parse_scan_json(done.stdout, root)



def _fn_defs(tree):  # ast.Module -> {name: FunctionDef}
    """Module-level function defs, by name. Methods are excluded on purpose: a call site
    for a method drops `self`, and resolving the receiver's class is more than a name
    match can do without false positives."""
    import ast as _ast
    return {n.name: n for n in tree.body
            if isinstance(n, (_ast.FunctionDef, _ast.AsyncFunctionDef))}


def _arity(fn):  # FunctionDef -> (min_pos, max_pos|None, required_kwonly)
    """(min required positional-or-keyword, max positional or None for *args,
    required keyword-only names). Defaults reduce the minimum."""
    a = fn.args
    pos = list(a.posonlyargs) + list(a.args)
    min_req = len(pos) - len(a.defaults)
    max_pos = None if a.vararg is not None else len(pos)
    kwreq = tuple(k.arg for k, d in zip(a.kwonlyargs, a.kw_defaults) if d is None)
    return min_req, max_pos, kwreq


def callers_consistent(base_root, patched_root) -> bool:
    """Every caller still matches the signature of a function the patch changed.

    A multi-file fix that gives a shared helper a new parameter but forgets one of its
    callers BREAKS THE BUILD at runtime — and no scanner and no parse check sees it,
    because the file is valid Python and semgrep does not model arity. This is the gate
    that makes coordinated multi-file fixes SAFE rather than merely possible: it re-reads
    every module-level function whose parameter list the patch altered, finds every call
    to it by name across the patched tree, and rejects the patch if any call can no longer
    satisfy the new signature.

    True when nothing applies (no signature changed) — so it never touches a one-file fix.
    Conservative on uncertainty: a call using * or ** unpacking is skipped, not failed.
    Name-based, module-level only; it can miss a caller in another namespace, but it does
    not invent one. Measured on the Mendor-lab two-file SQLi: run_select(sql) left calling
    a signature that grew a params argument is exactly what this catches.
    """
    import ast
    from pathlib import Path

    base_root, patched_root = Path(base_root), Path(patched_root)
    changed_sigs: dict[str, tuple] = {}
    for pf in patched_root.rglob("*.py"):
        rel = pf.relative_to(patched_root)
        bf = base_root / rel
        if not bf.is_file():
            continue
        try:
            pt = ast.parse(pf.read_text())
            bt = ast.parse(bf.read_text())
        except (SyntaxError, OSError, UnicodeDecodeError):
            continue
        pdefs, bdefs = _fn_defs(pt), _fn_defs(bt)
        for name, pfn in pdefs.items():
            if name in bdefs and _arity(pfn) != _arity(bdefs[name]):
                # A name defined with two different signatures anywhere is ambiguous to a
                # name match; refuse to reason about it rather than risk a false reject.
                changed_sigs[name] = None if name in changed_sigs else _arity(pfn)
    changed_sigs = {n: a for n, a in changed_sigs.items() if a is not None}
    if not changed_sigs:
        return True

    for pf in patched_root.rglob("*.py"):
        try:
            tree = ast.parse(pf.read_text())
        except (SyntaxError, OSError, UnicodeDecodeError):
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            fn = node.func
            name = fn.id if isinstance(fn, ast.Name) else None
            if name is None or name not in changed_sigs:
                continue
            if any(isinstance(a, ast.Starred) for a in node.args) or \
               any(k.arg is None for k in node.keywords):
                continue  # unpacking — cannot determine arity, do not fail on it
            min_req, max_pos, kwreq = changed_sigs[name]
            n_pos = len(node.args)
            kw = {k.arg for k in node.keywords}
            supplied = n_pos + len(kw)
            if supplied < min_req:
                return False
            if max_pos is not None and n_pos > max_pos:
                return False
            if any(r not in kw for r in kwreq):
                return False
    return True


def validate_patch(*, base_root: str | Path, patched_root: str | Path,
                   target_key: tuple[str, str, int],
                   in_scope_keys: Iterable[tuple[str, str, int]] | None = None,
                   timeout_sec: int = 600,
                   scan: Callable[..., ScanOutcome] = scan_tree) -> Validation:
    """target_key is StaticFinding.key — (rule_id, file, line).

    `scan` is injectable so the gates are testable with no semgrep installed. It is
    keyword-only and defaults to the real runner: a caller cannot accidentally supply a
    different scanner for one tree, because it is used for both.

    `in_scope_keys` IS WHAT MAKES A PULL-REQUEST FIX VERIFIABLE AT ALL
    -----------------------------------------------------------------
    Without it, gate 2 demands the target's rule fire NOWHERE in the file and gate 3
    forgives a co-vanishing hit only at the target's exact line. On a file with a
    backlog — which is every real file — that combination makes a CORRECT fix
    unverifiable, and this was measured, not predicted. On kaizenmantra/vulnshop#20 the
    pull request adds a `/coupon` route whose `cur.execute("... '%s'" % code)` fires five
    rules across app.py:64 (the taint source line) and app.py:66 (the sink). The same
    app.py ALREADY has SQL injection at lines 31, 32, 36 and 37, which #20 did not
    introduce and a fix to #20 must not touch. Hand-writing the textbook fix
    (`cur.execute("... = ?", (code,))`) and running the gates gave `not_fixed` /
    `target_absent` for ALL FIVE possible target keys, with `target_still_firing_at`
    [31, 32] or [36] or [37] — the backlog — plus gate 3 failing on the OTHER four hits
    the same one-line fix legitimately cleared. Nothing could ever have shipped.

    So the caller may name the keys THIS pull request introduced — `verdict["new"]`,
    expanded over `merged_rules` — and the two gates read them as follows:

      gate 2  the target's rule may still fire at a line where it ALREADY fired before
              the patch and which is out of scope. Anywhere else, including a NEW line,
              still fails: that is the moved-sink fail-open, and it stays closed.
      gate 3  each in-scope key is one hit that may legitimately vanish. Losing MORE
              hits of that rule than were in scope is still collateral and still fails,
              so a file that quietly stopped being parsed is still caught.

    Omitting it keeps the whole-file reading of workflow.md:50-52 ("fix the siblings
    too"), which is right for a repo-wide fix campaign and wrong for a diff gate.

    # ponytail: with a scope given, a patch that clears the target but leaves a DIFFERENT
    # in-scope finding alive still passes — gate 2 only ever looks at the target's own
    # rule. Accepted: fixes are attempted one finding at a time, the survivor is still
    # `new` so the check still blocks, and the next pass takes it. Tighten by failing on
    # any surviving in-scope key if one-pass-fixes-everything ever becomes the goal.
    """
    target = _norm_key(target_key)
    scope = (None if in_scope_keys is None
             else {_norm_key(key) for key in in_scope_keys} | {target})
    before = scan(base_root, timeout_sec=timeout_sec)
    after = scan(patched_root, timeout_sec=timeout_sec)

    evidence: dict = {
        "target": list(target),
        "scanner_args": list(SEMGREP_JSON_ARGS),
        "tests": ("not run — executing a pull request's own test command on this host is "
                  "arbitrary code execution from an untrusted source. Gate 7 is recorded "
                  "as not established; the repository's CI runs it on the fix branch."),
    }

    if before.error or after.error:
        evidence["scanner_error"] = {"pristine": before.error, "patched": after.error}
        # No gate was established, so no gate failed. The status carries the whole story.
        return Validation(INCONCLUSIVE, dict.fromkeys(GATES), None, evidence)

    evidence |= {
        "findings_before": len(before.keys), "findings_after": len(after.keys),
        "parse_errors_before": before.parse_errors,
        "parse_errors_after": after.parse_errors,
        "files_scanned_before": before.files_scanned,
        "files_scanned_after": after.files_scanned,
        "coverage_before": before.coverage, "coverage_after": after.coverage,
    }

    gates: dict[str, bool | None] = dict.fromkeys(GATES)
    gates["positive_control"] = target in before.keys
    if not gates["positive_control"]:
        # The bug was never measurable, so the comparison proves nothing in either
        # direction. Calling this not_fixed would blame a patch for a broken baseline.
        evidence["why"] = ("the target finding is absent from the PRISTINE scan, so this "
                           "comparison cannot prove anything: the scanner config changed, "
                           "the anchor was never there, or the key is wrong.")
        return Validation(INCONCLUSIVE, gates, "positive_control", evidence)

    before_pairs = Counter(_pair(key) for key in before.keys)
    after_pairs = Counter(_pair(key) for key in after.keys)

    # Rules that fired at the target's EXACT (file, line): one defect seen twice by two
    # overlapping rules. Their joint disappearance is corroboration, not collateral, so
    # gate 3 forgives one lost hit per rule — the one on that line. The same rule losing a
    # hit ELSEWHERE in the file is still a real disappearance and still fails.
    # ponytail: that exactness has a known cost. A root-cause fix that also clears a
    # DIFFERENT rule at OTHER lines in the same file fails gate 3 and reports not_fixed —
    # conservative (nothing ships, nothing is claimed) rather than fail-open. Widen the
    # exemption to the whole file only with evidence that it costs real fixes, because
    # doing so also stops gate 3 noticing a file that quietly stopped being parsed.
    exempt = Counter(_pair(key) for key in before.keys
                     if (key[1], key[2]) == (target[1], target[2]))
    target_pair = _pair(target)
    if scope is None:
        # The target's own rule in that file is gate 2's business, and gate 2 demands it
        # reach zero everywhere in the file (workflow.md:50-52, fix the siblings too).
        # Gate 3 must not punish the fix for obeying that.
        exempt[target_pair] = before_pairs[target_pair]
    else:
        # One forgiven hit per in-scope key, counted rather than blanket-exempted by pair:
        # clearing the two hits this pull request introduced is the fix, clearing a third
        # hit of the same rule from the backlog is collateral and must still fail.
        for key in scope:
            exempt[_pair(key)] += 1

    # Hits of the target's rule that were ALREADY in this file before the patch and are
    # not this pull request's to fix. Gate 2 forgives exactly these and nothing else — a
    # hit at a line that was not firing before is a moved sink, not a backlog entry.
    preexisting = (frozenset() if scope is None else
                   frozenset(key for key in before.keys
                             if _pair(key) == target_pair and key not in scope))

    lost = {pair: count - after_pairs[pair] for pair, count in before_pairs.items()
            if after_pairs[pair] < count}
    gained = {pair: count - before_pairs[pair] for pair, count in after_pairs.items()
              if count > before_pairs[pair]}
    unexpected = {pair: count for pair, count in lost.items() if count > exempt[pair]}
    still_firing = sorted(key for key in after.keys
                          if _pair(key) == target_pair and key not in preexisting)

    evidence |= {
        # [rule_id, file, how many hits were lost/gained], not keys: the comparison is at
        # pair level, so reporting keys here would imply a precision that is not there.
        "vanished_count": sum(lost.values()), "appeared_count": sum(gained.values()),
        "vanished": [[*pair, count] for pair, count in sorted(lost.items())[:MAX_LISTED]],
        "appeared": [[*pair, count] for pair, count in sorted(gained.items())[:MAX_LISTED]],
        "vanished_unexpected": [[*pair, count]
                                for pair, count in sorted(unexpected.items())[:MAX_LISTED]],
        "colocated_exempt": [list(pair) for pair in sorted(exempt)
                             if pair != target_pair],
        # The lines the target's rule still fires at, which is what gate 2 rejects and the
        # one thing the agent can act on.
        "target_still_firing_at": [key[2] for key in still_firing],
        # Named so a reader of the report can tell "gate 2 passed" from "gate 2 passed
        # because four hits of this rule were somebody else's backlog".
        "out_of_scope_preexisting_at": sorted(key[2] for key in preexisting),
        "in_scope_keys": ([] if scope is None
                          else [list(key) for key in sorted(scope)][:MAX_LISTED]),
    }

    gates["target_absent"] = not still_firing
    gates["nothing_else_vanished"] = not unexpected
    gates["no_new_findings"] = not gained
    if before.parse_errors is not None and after.parse_errors is not None:
        gates["parse_errors_not_increased"] = after.parse_errors <= before.parse_errors
    if before.files_scanned is not None and after.files_scanned is not None:
        gates["files_scanned_not_dropped"] = after.files_scanned >= before.files_scanned
    # No caller left on a changed signature — the gate that makes a coordinated multi-file
    # fix safe. True for a one-file fix (no signature changed), so it never interferes.
    gates["callers_consistent"] = callers_consistent(base_root, patched_root)
    # Gate 7 (tests_pass) stays None. See GATE 7 in the module docstring.

    # Diagnostic order first; the GATES fallback is the belt-and-braces that stops a gate
    # added later, and forgotten in _DIAGNOSTIC_ORDER, from falling through to VERIFIED.
    failed = next((name for name in _DIAGNOSTIC_ORDER if gates[name] is False),
                  next((name for name in GATES if gates[name] is False), None))
    if failed is not None:
        return Validation(NOT_FIXED, gates, failed, evidence)
    unestablished = next((name for name in _DIAGNOSTIC_ORDER if gates[name] is None), None)
    if unestablished is not None:
        return Validation(PLAUSIBLE, gates, unestablished, evidence)
    return Validation(VERIFIED, gates, None, evidence)


def validate_agent_patch(*, base_root: str | Path, patched_root: str | Path,
                         exploit_closed: bool, timeout_sec: int = 600,
                         scan: Callable[..., ScanOutcome] = scan_tree) -> Validation:
    """Verify a fix for an AGENT finding (recon/*), which no scanner can see.

    `validate_patch` proves a fix by a semgrep rule flipping from firing to silent. A
    logic bug — IDOR, privilege escalation, cross-tenant authz — fires no rule, so that
    path bails at `positive_control` and nothing ever ships. The ORACLE here is instead
    `exploit_closed`: the same agent judgement that FOUND the bug, re-run against the
    patched tree (core/triage via service/fix._verify_step), asked whether the patch shut
    the path. semgrep still runs, but ONLY as a regression guard — the fix must not add a
    new scanner finding or break the parse.

    Two honest tiers, and the evidence says which: a scanner-verified fix is proven by a
    rule going quiet; an agent-verified fix by an independent agent re-reading the code
    and finding the path closed. `verified_by` records it so a fix PR never overclaims.

    positive_control  triage already confirmed the finding exploitable on the base tree —
                      that IS the pre-fix control, so it is True by construction here.
    target_absent     the agent verdict: True only when the exploit path is now closed.
    Pairs, not keys, for the regression gates: a fix that inserts lines shifts unrelated
    findings down, which at key granularity reads as a vanish plus an appearance. At
    (rule, file) granularity the count is unchanged, so a real new/lost finding is caught
    and a line-shift is not.
    """
    before = scan(base_root, timeout_sec=timeout_sec)
    after = scan(patched_root, timeout_sec=timeout_sec)
    evidence: dict = {
        "verified_by": "agent",
        "tests": ("not run — executing a pull request's own test command on this host is "
                  "arbitrary code execution from an untrusted source. Gate 7 is recorded "
                  "as not established; the repository's CI runs it on the fix branch."),
    }
    if before.error or after.error:
        evidence["scanner_error"] = {"pristine": before.error, "patched": after.error}
        return Validation(INCONCLUSIVE, dict.fromkeys(GATES), None, evidence)

    before_pairs = Counter(_pair(key) for key in before.keys)
    after_pairs = Counter(_pair(key) for key in after.keys)
    gained = {p: after_pairs[p] - before_pairs[p]
              for p in after_pairs if after_pairs[p] > before_pairs[p]}
    lost = {p: before_pairs[p] - after_pairs[p]
            for p in before_pairs if after_pairs[p] < before_pairs[p]}

    gates: dict[str, bool | None] = dict.fromkeys(GATES)
    gates["positive_control"] = True            # triage confirmed it on base — see above
    gates["target_absent"] = bool(exploit_closed)
    gates["nothing_else_vanished"] = not lost
    gates["no_new_findings"] = not gained
    gates["parse_errors_not_increased"] = (
        before.parse_errors is None or after.parse_errors is None
        or after.parse_errors <= before.parse_errors)
    gates["files_scanned_not_dropped"] = (
        before.files_scanned is None or after.files_scanned is None
        or after.files_scanned >= before.files_scanned)
    gates["callers_consistent"] = callers_consistent(base_root, patched_root)
    # tests_pass stays None for the same reason validate_patch leaves it None.

    evidence |= {
        "exploit_closed": bool(exploit_closed),
        "findings_before": len(before.keys), "findings_after": len(after.keys),
        "appeared": [[*p, c] for p, c in sorted(gained.items())[:MAX_LISTED]],
        "vanished": [[*p, c] for p, c in sorted(lost.items())[:MAX_LISTED]],
    }

    failed = next((g for g in _DIAGNOSTIC_ORDER if gates.get(g) is False), None)
    if failed is None and gates["target_absent"] is False:
        failed = "target_absent"
    status = VERIFIED if failed is None and all(
        gates[g] for g in GATES if gates[g] is not None) else NOT_FIXED
    return Validation(status, gates, failed, evidence)


def demo() -> None:
    target: Key = ("python.lang.security.sqli", "app/db.py", 5)
    other: Key = ("python.lang.security.cmdi", "app/shell.py", 12)

    def scanner(pristine: ScanOutcome, patched: ScanOutcome) -> Callable[..., ScanOutcome]:
        seen: list[ScanOutcome] = [pristine, patched]
        return lambda root, *, timeout_sec=0: seen.pop(0)

    def outcome(*keys: Key, files: int = 10, errors: int = 0) -> ScanOutcome:
        return ScanOutcome(keys=frozenset(keys), files_scanned=files, parse_errors=errors)

    clean = outcome(target, other)

    # --- the honest fix ------------------------------------------------------------
    fixed = validate_patch(base_root="a", patched_root="b", target_key=target,
                           scan=scanner(clean, ScanOutcome(keys=frozenset({other}),
                                                           files_scanned=10,
                                                           parse_errors=0)))
    assert fixed.status == VERIFIED, fixed
    assert fixed.failed_gate is None and fixed.gates["tests_pass"] is None, fixed.gates
    assert "not run" in fixed.evidence["tests"]

    # --- the two shapes a key-level comparison rejected (see the module docstring) ---
    # Two overlapping rules on the target's own line; a correct fix clears both.
    twinned = ("python.lang.security.audit.dangerous-system-call", "app/db.py", 5)
    both = validate_patch(base_root="a", patched_root="b", target_key=target,
                          scan=scanner(outcome(target, twinned, other),
                                       outcome(other)))
    assert both.status == VERIFIED, both
    assert both.evidence["colocated_exempt"] == [list(_pair(twinned))], both.evidence

    # A fix that adds an import shifts every finding below it down one line.
    moved = (other[0], other[1], other[2] + 1)
    shifted = validate_patch(base_root="a", patched_root="b", target_key=target,
                             scan=scanner(outcome(target, other), outcome(moved)))
    assert shifted.status == VERIFIED, shifted
    assert shifted.evidence["appeared_count"] == 0, shifted.evidence

    # The same rule still firing in that file is NOT fixed, wherever it moved to.
    unfixed = validate_patch(base_root="a", patched_root="b", target_key=target,
                             scan=scanner(outcome(target, other),
                                          outcome((target[0], target[1], 9), other)))
    assert unfixed.status == NOT_FIXED and unfixed.failed_gate == "target_absent", unfixed
    assert unfixed.evidence["target_still_firing_at"] == [9], unfixed.evidence

    # --- in_scope_keys: a pull-request fix on a file that has a backlog -------------
    # The shape measured on kaizenmantra/vulnshop#20. The pull request introduces the
    # target plus a second rule on a NEARBY line (semgrep reports the taint source line
    # and the sink line separately); the same file already carries the target's own rule
    # at two OTHER lines, which the pull request did not add and its fix must not touch.
    sibling: Key = ("python.lang.security.cmdi", "app/db.py", 4)   # in scope, other line
    backlog_a: Key = (target[0], target[1], 31)                    # NOT in scope
    backlog_b: Key = (target[0], target[1], 32)
    dirty = outcome(target, sibling, backlog_a, backlog_b, other)
    after_fix = outcome(backlog_a, backlog_b, other)

    # Without a scope this correct fix is unverifiable, and that is the whole reason the
    # parameter exists: gate 2 sees the backlog and gate 3 sees the sibling.
    unscoped = validate_patch(base_root="a", patched_root="b", target_key=target,
                              scan=scanner(dirty, after_fix))
    assert unscoped.status == NOT_FIXED, unscoped
    assert unscoped.failed_gate == "target_absent", unscoped.failed_gate
    assert unscoped.evidence["target_still_firing_at"] == [31, 32], unscoped.evidence

    scoped = validate_patch(base_root="a", patched_root="b", target_key=target,
                            in_scope_keys=[target, sibling],
                            scan=scanner(dirty, after_fix))
    assert scoped.status == VERIFIED, scoped
    assert scoped.evidence["out_of_scope_preexisting_at"] == [31, 32], scoped.evidence

    # A MOVED SINK is still not a fix. The rule reappears at a line that was not firing
    # before, so it is not forgiven as backlog — this is the fail-open the scope must not
    # open, and it is the one thing the relaxation could plausibly have broken.
    relocated = validate_patch(
        base_root="a", patched_root="b", target_key=target,
        in_scope_keys=[target, sibling],
        scan=scanner(dirty, outcome((target[0], target[1], 77), backlog_a, backlog_b, other)))
    assert relocated.status == NOT_FIXED, relocated
    assert relocated.failed_gate == "target_absent", relocated.failed_gate
    assert relocated.evidence["target_still_firing_at"] == [77], relocated.evidence

    # Losing MORE hits of an in-scope rule than were in scope is still collateral: one
    # `cmdi` hit was introduced, so a patch that clears two of them broke something.
    extra_cmdi: Key = ("python.lang.security.cmdi", "app/db.py", 90)
    greedy = validate_patch(
        base_root="a", patched_root="b", target_key=target,
        in_scope_keys=[target, sibling],
        scan=scanner(outcome(target, sibling, extra_cmdi, backlog_a, backlog_b, other),
                     after_fix))
    assert greedy.status == NOT_FIXED, greedy
    assert greedy.failed_gate == "nothing_else_vanished", greedy.failed_gate

    # And a scope never rescues a broken file: gate 5 is measured, not scoped.
    still_broken = validate_patch(
        base_root="a", patched_root="b", target_key=target,
        in_scope_keys=[target, sibling],
        scan=scanner(dirty, ScanOutcome(keys=frozenset({backlog_a, backlog_b, other}),
                                        files_scanned=10, parse_errors=1)))
    assert still_broken.status == NOT_FIXED, still_broken
    assert still_broken.failed_gate == "parse_errors_not_increased", still_broken.failed_gate

    # --- THE TRAP: a syntax error makes the file report zero findings ---------------
    # Every finding in the file vanishes, so gate 3 catches what gate 2 alone would have
    # read as a perfect fix.
    broken = validate_patch(base_root="a", patched_root="b", target_key=target,
                            scan=scanner(clean, ScanOutcome(keys=frozenset(),
                                                            files_scanned=10,
                                                            parse_errors=0)))
    assert broken.status == NOT_FIXED, broken
    assert broken.failed_gate == "nothing_else_vanished", broken.failed_gate

    # A file that falls out of coverage is caught even when it held only the target.
    only_target = ScanOutcome(keys=frozenset({target}), files_scanned=10, parse_errors=0)
    dropped = validate_patch(base_root="a", patched_root="b", target_key=target,
                             scan=scanner(only_target,
                                          ScanOutcome(keys=frozenset(), files_scanned=9,
                                                      parse_errors=0)))
    assert dropped.failed_gate == "files_scanned_not_dropped", dropped
    assert dropped.status == NOT_FIXED, dropped

    # --- no positive control: inconclusive, never not_fixed ------------------------
    no_control = validate_patch(base_root="a", patched_root="b", target_key=target,
                                scan=scanner(ScanOutcome(keys=frozenset({other}),
                                                         files_scanned=10, parse_errors=0),
                                             ScanOutcome(keys=frozenset({other}),
                                                         files_scanned=10, parse_errors=0)))
    assert no_control.status == INCONCLUSIVE, no_control
    assert no_control.failed_gate == "positive_control"

    # --- a scanner that could not run is never a verdict --------------------------
    crashed = validate_patch(base_root="a", patched_root="b", target_key=target,
                             scan=scanner(ScanOutcome(error="semgrep is not installed"),
                                          clean))
    assert crashed.status == INCONCLUSIVE, crashed
    assert set(crashed.gates.values()) == {None}, crashed.gates

    # --- coverage the scanner never reported caps the outcome ---------------------
    unknown = validate_patch(base_root="a", patched_root="b", target_key=target,
                             scan=scanner(ScanOutcome(keys=frozenset({target, other})),
                                          ScanOutcome(keys=frozenset({other}))))
    assert unknown.status == PLAUSIBLE, unknown
    assert unknown.failed_gate == "parse_errors_not_increased", unknown.failed_gate

    # --- the real parser: findings AND coverage out of one --json run -------------
    document = json.dumps({
        "results": [{"check_id": "python.lang.security.sqli", "path": "/tmp/tree/app/db.py",
                      "start": {"line": 5}, "extra": {"lines": "q = f'...'"}}],
        "paths": {"scanned": ["app/db.py", "app/shell.py"]},
        "errors": [{"message": "Syntax error at line app/db.py:5"}],
    })
    parsed = parse_scan_json(document, "/tmp/tree")
    assert parsed.error is None, parsed.error
    assert parsed.keys == frozenset({("python.lang.security.sqli", "app/db.py", 5)}), parsed
    assert parsed.files_scanned == 2 and parsed.parse_errors == 1, parsed
    # A crashed scanner must not be mistaken for a clean tree.
    assert parse_scan_json("Traceback (most recent call last)", "/tmp").error
    assert parse_scan_json("[]", "/tmp").error
    # No paths key at all: coverage is UNKNOWN, not zero.
    assert parse_scan_json('{"results": []}', "/tmp").files_scanned is None

    # Every gate that can be False must have a place in the attribution order, or a
    # failure added later falls through to VERIFIED.
    # ── callers_consistent: the gate that makes multi-file fixes safe ───────────
    import tempfile as _tmp
    def _tree(files):
        d = Path(_tmp.mkdtemp())
        for n, c in files.items():
            (d / n).parent.mkdir(parents=True, exist_ok=True)
            (d / n).write_text(c)
        return d
    _base = _tree({"db.py": "def run(sql):\n    return x(sql)\n",
                   "t.py": "from db import run\ndef f(a):\n    return run('q'+a)\n"})
    # signature grew a required arg, caller not updated -> the build would break
    _bad = _tree({"db.py": "def run(sql, params):\n    return x(sql, params)\n",
                  "t.py": "from db import run\ndef f(a):\n    return run('q')\n"})
    assert callers_consistent(_base, _bad) is False, "a missing caller update must fail"
    # caller updated to the new contract -> consistent
    _good = _tree({"db.py": "def run(sql, params):\n    return x(sql, params)\n",
                   "t.py": "from db import run\ndef f(a):\n    return run('q', {'a': a})\n"})
    assert callers_consistent(_base, _good) is True, "an updated caller is consistent"
    # a one-file fix changes no signature -> the gate never interferes
    _one = _tree({"db.py": "def run(sql):\n    return x(sql)\n",
                  "t.py": "from db import run\ndef f(a):\n    return run('safe')\n"})
    assert callers_consistent(_base, _one) is True, "a one-file fix is untouched by this gate"

    assert set(_DIAGNOSTIC_ORDER) | {"positive_control", "tests_pass"} == set(GATES)

    # The scan config must stay the pipeline's, with json instead of sarif.
    assert "--json" in SEMGREP_JSON_ARGS and "--sarif" not in SEMGREP_JSON_ARGS
    assert "--metrics=off" in SEMGREP_JSON_ARGS, SEMGREP_JSON_ARGS
    assert "--config=p/default" in SEMGREP_JSON_ARGS, SEMGREP_JSON_ARGS

    # Only this module may produce the string delivery.py branches on.
    assert VERIFIED == "verified_fixed"

    # --- validate_agent_patch: the oracle for recon findings a scanner cannot see ------
    clean = ScanOutcome(keys=frozenset({target}), files_scanned=10, parse_errors=0)
    # Same scanner findings before and after (the logic fix touched no rule), and the
    # agent says the exploit path is closed -> verified.
    agent_ok = validate_agent_patch(base_root="b", patched_root="p", exploit_closed=True,
                                    scan=scanner(clean, clean))
    assert agent_ok.status == VERIFIED, agent_ok
    assert agent_ok.evidence["verified_by"] == "agent", agent_ok.evidence
    assert agent_ok.gates["positive_control"] is True and agent_ok.gates["tests_pass"] is None

    # The agent says the exploit still works -> not_fixed, whatever semgrep shows.
    agent_open = validate_agent_patch(base_root="b", patched_root="p", exploit_closed=False,
                                      scan=scanner(clean, clean))
    assert agent_open.status == NOT_FIXED and agent_open.failed_gate == "target_absent", agent_open

    # A patch that closes the target but ADDS a new scanner finding is refused as a
    # regression, even though the agent verified the original path.
    plus_bug = ScanOutcome(keys=frozenset({target, other}), files_scanned=10, parse_errors=0)
    regressed = validate_agent_patch(base_root="b", patched_root="p", exploit_closed=True,
                                     scan=scanner(clean, plus_bug))
    assert regressed.status == NOT_FIXED and regressed.gates["no_new_findings"] is False, regressed

    print("service.validate: ok")


if __name__ == "__main__":
    demo()
