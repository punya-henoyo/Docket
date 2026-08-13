"""Apply a proposed fix, then prove it worked — or refuse to call it fixed.

The verification is the product. Anyone can ask a model for a patch; the hard part is
knowing whether it worked, and the honest answer is usually "not proven". This
implements the gates in skills/fix/workflow.md, which exist because a patch that
BREAKS a file makes the scanner emit zero findings for it, and zero findings reads as
a perfect fix.

  1  positive control — the finding IS in the pristine scan
  2  the finding is absent after the patch
  3  nothing else vanished
  4  no new findings appeared
  5  parse errors did not increase
  6  the file count scanned did not drop
  7  the patched file still parses

Gates 1-4 fall straight out of diff_runs, which is what it was built for. Gates 5-6
come from the coverage block. Gate 7 is a language-specific syntax check.

THE AGENT NEVER WRITES
A patch is proposed as (path, old, new) and applied here by exact match. The agent
gets no write tool and no shell. That is not only safety: an exact-match replacement
that refuses an ambiguous or missing anchor catches a hallucinated patch before it
touches a file, whereas a freehand write silently produces something plausible.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from docket.report.diff import diff_runs, finding_key

# The three outcomes from the workflow skill, and only these three.
VERIFIED_FIXED = "verified_fixed"
UNVERIFIED_PLAUSIBLE = "unverified_plausible"
NOT_FIXED = "not_fixed"


@dataclass(frozen=True)
class Patch:
    """One exact-match replacement. `old` must appear exactly once in the file."""

    path: str          # repo-relative
    old: str
    new: str
    why: str = ""


class PatchError(Exception):
    """The patch could not be applied. Never partially applied."""


def apply_patch(root: Path, patch: Patch) -> str:
    """Apply one patch under `root`, returning the original text for rollback.

    Refuses rather than guesses. An anchor that is missing means the model invented
    it; an anchor appearing twice means the patch is ambiguous and could land on the
    wrong one. Both are the model being wrong, and both are cheaper to catch here than
    after a re-scan says something confusing.
    """
    if not patch.old:
        raise PatchError("patch has no anchor text to replace")
    if patch.old == patch.new:
        raise PatchError("patch changes nothing")

    cleaned = str(patch.path).strip().lstrip("/")
    if not cleaned or ".." in cleaned.split("/"):
        raise PatchError(f"refusing suspicious path: {patch.path!r}")

    target = (root / cleaned).resolve()
    if not str(target).startswith(str(root.resolve())):
        raise PatchError(f"patch escapes the repository: {patch.path!r}")
    if not target.is_file():
        raise PatchError(f"no such file: {cleaned}")

    original = target.read_text()
    occurrences = original.count(patch.old)
    if occurrences == 0:
        raise PatchError(
            f"the anchor text is not in {cleaned}. The patch was written against code "
            "that is not there."
        )
    if occurrences > 1:
        raise PatchError(
            f"the anchor text appears {occurrences} times in {cleaned}, so this patch "
            "is ambiguous. Quote more surrounding context to make it unique."
        )

    target.write_text(original.replace(patch.old, patch.new, 1))
    return original


def parses(root: Path, path: str) -> tuple[bool, str]:
    """(ok, detail) for a syntax check. Non-Python files are not checked, and say so.

    Gate 7. A patch that breaks the file is the failure mode this whole module exists
    to catch, and for Python it is catchable for free before any container starts.
    """
    target = root / path
    if not target.is_file():
        return False, f"{path} does not exist after patching"
    if target.suffix != ".py":
        return True, f"no syntax check available for {target.suffix or 'this file type'}"
    try:
        ast.parse(target.read_text())
    except SyntaxError as exc:
        return False, f"{path} no longer parses: line {exc.lineno}: {exc.msg}"
    return True, "parses"


def _coverage(report: dict[str, Any]) -> tuple[int, int]:
    """(files_scanned, error_count) from a report's semgrep coverage."""
    semgrep = ((report or {}).get("coverage") or {}).get("semgrep") or {}
    return int(semgrep.get("files_scanned") or 0), int(semgrep.get("error_count") or 0)


@dataclass
class Verification:
    outcome: str
    reasons: list[str] = field(default_factory=list)
    gates: dict[str, bool] = field(default_factory=dict)

    @property
    def fixed(self) -> bool:
        return self.outcome == VERIFIED_FIXED


def verify_fix(target_finding: dict[str, Any], pristine: dict[str, Any] | None,
               patched: dict[str, Any] | None, *, scope: list[str] | None = None,
               syntax_ok: bool = True, syntax_detail: str = "") -> Verification:
    """Did the patch fix the finding, and only the finding?

    Returns `not_fixed` when a gate proves it did not, and `unverified_plausible` when
    a gate could not be established at all — a scan that crashed cannot testify either
    way, and calling that "fixed" is the exact failure this guards against.
    """
    gates: dict[str, bool] = {}
    reasons: list[str] = []

    # A scan that did not complete cannot testify. An exit code is not a verdict.
    if pristine is None or patched is None:
        return Verification(UNVERIFIED_PLAUSIBLE,
                            ["a scan produced no report, so nothing can be compared"],
                            gates)

    diff = diff_runs(pristine, patched, scope=scope)
    if diff.caveats:
        return Verification(UNVERIFIED_PLAUSIBLE,
                            [f"the comparison is not trustworthy: {c}" for c in diff.caveats],
                            gates)

    key = finding_key(target_finding)

    # 1. Positive control. If the finding is not in the pristine scan, the comparison
    #    proves nothing — the scanner did not run, or the anchor was never there.
    present_before = any(finding_key(f) == key for f in pristine.get("findings", []))
    gates["positive_control"] = present_before
    if not present_before:
        return Verification(UNVERIFIED_PLAUSIBLE, [
            "the finding is not in the pristine scan, so its absence afterwards proves "
            "nothing — the scanner may not have run, or its configuration changed"
        ], gates)

    # 2. Gone afterwards.
    gone = not any(finding_key(f) == key for f in patched.get("findings", []))
    gates["finding_absent"] = gone
    if not gone:
        reasons.append("the finding is still reported after the patch")

    # 3. Nothing ELSE vanished. Other findings disappearing means the file stopped
    #    being parsed, or the vulnerable code was deleted rather than fixed.
    collateral = [f for f in diff.fixed if finding_key(f) != key]
    gates["no_collateral"] = not collateral
    if collateral:
        reasons.append(
            f"{len(collateral)} other finding(s) also disappeared, which usually means "
            "the file stopped being parsed or the code was deleted rather than fixed"
        )

    # 4. No new findings. A fix that introduces a different bug is not a fix.
    gates["no_new"] = not diff.new
    if diff.new:
        reasons.append(f"the patch introduced {len(diff.new)} new finding(s)")

    # 5 & 6. Coverage must not shrink: a syntax error masquerades as a clean result by
    #        dropping the file out of coverage entirely.
    before_files, before_errors = _coverage(pristine)
    after_files, after_errors = _coverage(patched)
    gates["coverage_held"] = after_files >= before_files
    if after_files < before_files:
        reasons.append(
            f"the scan covered {before_files} file(s) before and {after_files} after — "
            "the patched file fell out of coverage, which is how a broken file reads as clean"
        )
    gates["no_new_parse_errors"] = after_errors <= before_errors
    if after_errors > before_errors:
        reasons.append(
            f"parse errors rose from {before_errors} to {after_errors}, so the patch "
            "broke something"
        )

    # 7. Syntax.
    gates["syntax"] = syntax_ok
    if not syntax_ok:
        reasons.append(syntax_detail or "the patched file no longer parses")

    if all(gates.values()):
        return Verification(VERIFIED_FIXED, ["every gate passed"], gates)
    # A surviving finding or a broken file is a definite failure. A gate that merely
    # could not be established is not.
    definite = not gates["finding_absent"] or not gates["syntax"] or not gates["no_new"]
    return Verification(NOT_FIXED if definite else UNVERIFIED_PLAUSIBLE, reasons, gates)


PATCH_SCHEMA = {
    "type": "object",
    "required": ["path", "old", "new", "why"],
    "additionalProperties": False,
    "properties": {
        "path": {"type": "string"},
        "old": {"type": "string"},
        "new": {"type": "string"},
        "why": {"type": "string"},
    },
}

PATCH_PROMPT = """You are fixing ONE security finding in a file you can read.

Return a single exact-match replacement:
  path  the file, repo-relative, exactly as given below
  old   text copied VERBATIM from the file, including indentation. It must appear
        EXACTLY ONCE — quote enough surrounding lines to make it unique.
  new   the replacement
  why   one sentence on what the fix does

Rules, in order of importance:
- `old` must be a byte-for-byte copy from the file. A patch whose anchor is not found
  is rejected outright, so do not retype from memory or reformat.
- Fix the vulnerability. Do NOT delete the feature. Removing the route or the query
  makes the finding disappear and is not a fix; it is deleting the evidence.
- Change as little as possible. A large rewrite cannot be verified.
- Do not alter behaviour beyond the fix: same route, same response shape, same names.
- Prefer the boring, idiomatic fix for the framework — parameterised queries, the
  framework's own escaping, its own auth decorator as already used elsewhere in this
  file.
- If the correct fix needs context you cannot see, return an empty `old` and explain
  in `why`. An honest refusal beats a guess that breaks the build.

FINDING:
"""


def propose_patch(finding: dict[str, Any], source: str, path: str,
                  config: Any) -> tuple[Patch | None, str]:
    """(patch, note). One model call. Never raises.

    The model sees the file and the finding and nothing else — no shell, no write
    tool, no network. Its output is text that must match the file exactly, which is
    what makes a hallucinated patch fail loudly at apply_patch rather than quietly at
    runtime.
    """
    import json as _json

    import litellm

    triage = finding.get("triage") or {}
    described = _json.dumps({
        "rule": finding.get("rule_id"),
        "title": finding.get("title"),
        "severity": finding.get("severity"),
        "where": (finding.get("location") or {}).get("source_file"),
        "matched_code": (finding.get("poc") or {}).get("request"),
        "description": finding.get("description"),
        "reachability": triage.get("verdict"),
        "reasoning": triage.get("reasoning"),
    }, indent=1)

    try:
        response = litellm.completion(
            model=config.llm, api_key=config.llm_api_key, base_url=config.llm_base_url,
            messages=[{"role": "user", "content":
                       f"{PATCH_PROMPT}{described}\n\nFILE `{path}`:\n```\n{source}\n```"}],
            tools=[{"type": "function", "function": {
                "name": "write_patch", "description": "Return the replacement.",
                "parameters": PATCH_SCHEMA}}],
            tool_choice={"type": "function", "function": {"name": "write_patch"}},
            temperature=0.1,
        )
        raw = _json.loads(response.choices[0].message.tool_calls[0].function.arguments)
    except Exception as exc:  # noqa: BLE001 — a failed proposal is a normal outcome
        return None, f"the model did not return a patch: {type(exc).__name__}: {exc}"

    if not str(raw.get("old", "")).strip():
        return None, raw.get("why") or "the model declined to propose a fix"
    # The model does not get to choose which file it edits.
    return Patch(path=path, old=raw["old"], new=raw.get("new", ""),
                 why=raw.get("why", "")), "ok"


@dataclass
class FixAttempt:
    finding: dict[str, Any]
    patch: Patch | None = None
    verification: Verification | None = None
    note: str = ""

    @property
    def deliverable(self) -> bool:
        """Whether this is worth opening a pull request for.

        `unverified_plausible` is deliberately EXCLUDED. The workflow skill allows
        delivering it if it is labelled unverified, but a pull request is the wrong
        vehicle for that: a diff in a review queue reads as "this is the fix",
        whatever the description says, and a reviewer who trusts it once will trust
        the next one without reading.
        """
        return bool(self.patch) and bool(self.verification) and self.verification.fixed


def attempt_fix(finding: dict[str, Any], *, root: Path, config: Any,
                rescan: Any, scope: list[str] | None = None) -> FixAttempt:
    """Propose a fix, apply it, re-scan, and prove it — or roll back.

    `rescan(paths)` runs the scanner over `root` as it currently stands and returns a
    report. It is injected so the whole sequence is testable without Docker.

    The tree is ALWAYS left as it was found unless the fix verified. A half-applied
    patch that could not be proven is worse than no patch: the next finding would be
    diagnosed against code nobody validated.
    """
    location = (finding.get("location") or {}).get("source_file") or ""
    path = str(location).replace("/work/source/", "").split(":")[0]
    if not path:
        return FixAttempt(finding, note="the finding cites no file, so there is "
                                        "nothing to patch")

    target = root / path
    if not target.is_file():
        return FixAttempt(finding, note=f"{path} is not in the fetched source")

    pristine = rescan([path])
    patch, note = propose_patch(finding, target.read_text(), path, config)
    if patch is None:
        return FixAttempt(finding, note=note)

    try:
        original = apply_patch(root, patch)
    except PatchError as exc:
        return FixAttempt(finding, patch, note=str(exc))

    try:
        syntax_ok, syntax_detail = parses(root, path)
        # Re-scan even when the syntax check already failed: the verification record
        # should show every gate, not stop at the first one that tripped.
        patched = rescan([path])
        verification = verify_fix(finding, pristine, patched, scope=scope or [path],
                                  syntax_ok=syntax_ok, syntax_detail=syntax_detail)
    except Exception as exc:  # noqa: BLE001
        target.write_text(original)
        return FixAttempt(finding, patch, note=f"verification failed to run: {exc}")

    if not verification.fixed:
        # Rolled back. An unproven patch left on disk becomes the baseline for
        # everything that follows.
        target.write_text(original)
    return FixAttempt(finding, patch, verification,
                      note="; ".join(verification.reasons))


def demo() -> None:
    import tempfile

    def finding(rule, path, code, severity="high"):
        return {"rule_id": rule, "severity": severity, "discovered_by": "semgrep",
                "location": {"method": "STATIC", "path": path, "parameter": None,
                             "source_file": f"{path}:1"},
                "poc": {"request": code, "response": "match"}}

    def report(findings, files=10, errors=0, **kw):
        base = {"findings": findings, "success": True,
                "coverage": {"semgrep": {"files_scanned": files, "error_count": errors}}}
        base.update(kw)
        return base

    sqli = finding("semgrep/sqli", "app.py", 'cur.execute(f"SELECT {q}")')
    other = finding("semgrep/xss", "app.py", "render(q)", severity="medium")

    # ── applying a patch ────────────────────────────────────────────────────
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "app.py").write_text("a = 1\nb = 2\nb = 3\n")

        original = apply_patch(root, Patch("app.py", "a = 1", "a = 0"))
        assert (root / "app.py").read_text().startswith("a = 0")
        assert original.startswith("a = 1"), "the original is returned for rollback"

        # Ambiguous: the model must quote more context rather than land on the wrong one.
        try:
            apply_patch(root, Patch("app.py", "b = ", "c = "))
            raise AssertionError("an ambiguous anchor must be refused")
        except PatchError as exc:
            assert "ambiguous" in str(exc)

        # Missing: the model wrote the patch against code that is not there.
        try:
            apply_patch(root, Patch("app.py", "nonexistent", "x"))
            raise AssertionError("a missing anchor must be refused")
        except PatchError as exc:
            assert "not in" in str(exc)

        for bad in (Patch("../escape.py", "a", "b"), Patch("app.py", "", "x"),
                    Patch("app.py", "same", "same"), Patch("nope.py", "a", "b")):
            try:
                apply_patch(root, bad)
                raise AssertionError(f"should have refused {bad.path!r}")
            except PatchError:
                pass

        # ── the syntax gate ─────────────────────────────────────────────────
        (root / "ok.py").write_text("def f():\n    return 1\n")
        assert parses(root, "ok.py")[0]
        (root / "broken.py").write_text("def f(:\n")
        ok, detail = parses(root, "broken.py")
        assert not ok and "no longer parses" in detail
        # Not every language can be checked, and saying so beats a false pass.
        (root / "x.js").write_text("function f( {")
        assert parses(root, "x.js") == (True, "no syntax check available for .js")

    # ── the gates ───────────────────────────────────────────────────────────
    clean = verify_fix(sqli, report([sqli, other]), report([other]), scope=["app.py"])
    assert clean.fixed, clean.reasons
    assert all(clean.gates.values())

    # Still there.
    survived = verify_fix(sqli, report([sqli, other]), report([sqli, other]),
                          scope=["app.py"])
    assert survived.outcome == NOT_FIXED
    assert "still reported" in survived.reasons[0]

    # THE TRAP: the patch broke the file, so the scanner reports nothing for it. Zero
    # findings reads as a perfect fix and is the opposite of one.
    broke = verify_fix(sqli, report([sqli, other]), report([], files=9, errors=1),
                       scope=["app.py"], syntax_ok=False,
                       syntax_detail="app.py no longer parses: line 4")
    assert broke.outcome == NOT_FIXED, broke.reasons
    assert not broke.gates["syntax"] and not broke.gates["coverage_held"]
    assert not broke.gates["no_collateral"], "the other finding vanished too"
    assert any("fell out of coverage" in r for r in broke.reasons)
    assert any("no longer parses" in r for r in broke.reasons)

    # A fix that introduces a different bug is not a fix.
    swapped = finding("semgrep/cmdi", "app.py", "os.system(q)")
    regressed = verify_fix(sqli, report([sqli, other]), report([other, swapped]),
                           scope=["app.py"])
    assert regressed.outcome == NOT_FIXED and "introduced 1 new" in regressed.reasons[0]

    # Deleting the vulnerable code rather than fixing it takes its neighbours with it.
    nuked = verify_fix(sqli, report([sqli, other]), report([]), scope=["app.py"])
    assert nuked.outcome != VERIFIED_FIXED
    assert not nuked.gates["no_collateral"]

    # ── what cannot be proven is never "fixed" ──────────────────────────────
    # No positive control: the finding was not in the pristine scan, so its absence
    # afterwards is evidence of nothing.
    blind = verify_fix(sqli, report([other]), report([other]), scope=["app.py"])
    assert blind.outcome == UNVERIFIED_PLAUSIBLE
    assert "proves nothing" in blind.reasons[0]

    # A scan that did not complete cannot testify either way.
    stopped = verify_fix(sqli, report([sqli]), report([], success=False),
                         scope=["app.py"])
    assert stopped.outcome == UNVERIFIED_PLAUSIBLE
    assert stopped.outcome != VERIFIED_FIXED

    assert verify_fix(sqli, None, report([])).outcome == UNVERIFIED_PLAUSIBLE
    assert verify_fix(sqli, report([sqli]), None).outcome == UNVERIFIED_PLAUSIBLE

    # ── the whole sequence, with the model stubbed ──────────────────────────
    import docket.core.remediation as _self

    _g = globals()
    _saved = _g["propose_patch"]
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "app.py").write_text('q = f"SELECT {u}"\nrender(q)\n')
        target = finding("semgrep/sqli", "app.py", 'q = f"SELECT {u}"')
        target["location"]["source_file"] = "app.py:1"

        def good_patch(*_a, **_k):
            return Patch("app.py", 'q = f"SELECT {u}"', 'q = "SELECT ?"', "parameterise"), "ok"

        # A verified fix stays on disk.
        _g["propose_patch"] = good_patch
        scans = iter([report([target, other]), report([other])])
        got = attempt_fix(target, root=root, config=None,
                          rescan=lambda paths: next(scans))
        assert got.deliverable, got.note
        assert 'SELECT ?' in (root / "app.py").read_text(), "a proven fix is kept"

        # An UNPROVEN patch is rolled back. Leaving it would make unvalidated code the
        # baseline for every finding after it.
        (root / "app.py").write_text('q = f"SELECT {u}"\nrender(q)\n')
        scans = iter([report([target, other]), report([target, other])])
        failed = attempt_fix(target, root=root, config=None,
                             rescan=lambda paths: next(scans))
        assert not failed.deliverable
        assert (root / "app.py").read_text().startswith('q = f"SELECT {u}"'), "rolled back"

        # `unverified_plausible` is NOT deliverable: a diff in a review queue reads as
        # "this is the fix" whatever the description says.
        scans = iter([report([other]), report([other])])   # no positive control
        unproven = attempt_fix(target, root=root, config=None,
                               rescan=lambda paths: next(scans))
        assert unproven.verification.outcome == UNVERIFIED_PLAUSIBLE
        assert not unproven.deliverable

        # A hallucinated anchor never touches the file.
        _g["propose_patch"] = lambda *a, **k: (Patch("app.py", "not here", "x"), "ok")
        before = (root / "app.py").read_text()
        bad = attempt_fix(target, root=root, config=None, rescan=lambda p: report([]))
        assert not bad.deliverable and "not in" in bad.note
        assert (root / "app.py").read_text() == before

        # A refusal is a normal outcome, not an error.
        _g["propose_patch"] = lambda *a, **k: (None, "needs context I cannot see")
        declined = attempt_fix(target, root=root, config=None, rescan=lambda p: report([]))
        assert not declined.deliverable and "cannot see" in declined.note

        # A finding with no file cannot be patched.
        _g["propose_patch"] = good_patch
        nowhere = attempt_fix({"location": {}}, root=root, config=None,
                              rescan=lambda p: report([]))
        assert "cites no file" in nowhere.note
    _g["propose_patch"] = _saved

    print("core.remediation: ok")


if __name__ == "__main__":
    demo()
