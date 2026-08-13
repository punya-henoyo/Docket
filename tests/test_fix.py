"""Plain-assert checks for autofix. Run: uv run python tests/test_fix.py

No LLM and no scanner. `fix_findings` takes three injectable seams — `propose` (the agent
step), `collect` (the tree diff) and `validate` (the scanner re-run) — so the whole refusal
path is exercised with fakes, and the delivery half runs against the REAL `deliver()` over
the fake GitHub transport that service/delivery.py:199 already builds.

The load-bearing assertion is the first one: an agent that claims it fixed something whose
validation says otherwise must produce a patch nobody ships. That is the entire point of
the feature, so it is proved end to end rather than at the driver's edge.
"""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "engine"))

from docket.config.settings import Config
from docket.core.cancel import CancelToken
from docket.interface.scm import GitHubApp, _fake_config, _FakeTransport
from docket.service.delivery import deliver, fix_branch_name
from docket.service.fix import (
    INCONCLUSIVE,
    NOT_FIXED,
    UNVERIFIED,
    VERIFIED,
    fix_findings,
    report_for_fix,
)
from docket.service.store import Store, db_path
from docket.tools.fix.tool import OUTCOMES, build_fix_report

HEAD = "a" * 40
CONFIG = Config(llm="test/model", llm_api_key="k", max_cost_usd=1.0,
                max_child_cost_usd=0.5, max_agents=1)


# --- fixtures -------------------------------------------------------------------------

def report(*candidates) -> dict:
    """A report shaped like a --static-only one: every hit is an unproven candidate."""
    rows = candidates or (("x.sql-injection", "app.py", 3),)
    return {"findings": [], "flagged_not_proven": [
        {"rule_id": rule, "engine": "semgrep", "severity": "high", "cwe": "CWE-89",
         "message": "user input in a formatted SQL string", "snippet": "q = f'{u}'",
         "file": path, "line": line}
        for rule, path, line in rows
    ]}


def changes(path="app.py", added="cursor.execute(SQL, (u,))") -> list[dict]:
    return [{"path": path, "content": f"{added}\n", "added_lines": [added],
             "removed_lines": ["q = f'{u}'"]}]


def claims_patched(_tree, _finding) -> dict:
    """What a confident agent returns: it changed something and says what it changed."""
    return {"outcome": "patched",
            "root_cause": "The login query interpolated request.form['user'].",
            "invariant": "Untrusted input can no longer reach the query as syntax.",
            "evidence": "app.py:3  cursor.execute(SQL, (u,))  — no behaviour change"}


def validator(status, **extra):
    return lambda **_: {"status": status, "gates": {"positive_control": True},
                        "failed_gate": extra.pop("failed_gate", None), **extra}


def run(propose=claims_patched, collect=None, validate=None, rows=None, **kwargs):
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp) / "src"
        base.mkdir()
        (base / "app.py").write_text("q = f'{u}'\n")
        (base / "other.py").write_text("pass\n")
        return fix_findings(
            rows if rows is not None else report(),
            source_root=base, run_dir=Path(tmp) / "run", config=CONFIG,
            propose=propose,
            collect=collect if collect is not None else (lambda *_: changes()),
            validate=validate or validator(VERIFIED),
            **kwargs,
        )


def delivered(patches) -> tuple[dict, _FakeTransport]:
    """The REAL deliver() against the fake GitHub transport."""
    verdict = {"conclusion": "failure", "reasons": ["1 finding"], "annotations": []}
    with tempfile.TemporaryDirectory() as tmp:
        store = Store(db_path(cwd=Path(tmp)))
        try:
            store.watch("o/r")
            scan_id = store.enqueue("o/r", 7, HEAD, "b" * 40)
            store.claim(scan_id, "worker-1")
            fake = _FakeTransport(
                refs={"main": "z" * 40, "feature-7": HEAD}, default_branch="main",
                pulls={7: {"number": 7, "head": {"sha": HEAD, "ref": "feature-7"},
                           "base": {"sha": "b" * 40, "ref": "main"}}})
            app = GitHubApp(config=_fake_config(), transport=fake)
            return deliver(app, store, store.scan(scan_id), verdict, patches), fake
        finally:
            store.close()


# --- the point of the whole feature ---------------------------------------------------

def test_a_claimed_fix_that_does_not_validate_is_never_shipped() -> None:
    """The agent says it fixed it. The scanner says it did not. Nothing ships."""
    patches = run(validate=validator(NOT_FIXED, failed_gate="target_still_present"))
    assert len(patches) == 1, patches
    patch = patches[0]
    # The claim is kept AS a claim, and the status is the scanner's.
    assert patch.outcome == "patched", patch
    assert patch.status == NOT_FIXED, patch
    assert patch.status != VERIFIED
    assert "target_still_present" in patch.summary, patch.summary

    # ...and the real deliver() skips it: no branch, no commit, no pull request.
    out, fake = delivered([patch])
    assert out["fix_prs"] == [], out
    assert out["skipped"] == [{"key": patch.key, "status": NOT_FIXED}], out
    assert fake.commits == [] and fake.created_pulls == [], fake.commits
    assert fix_branch_name(7, patch.key) not in fake.refs, fake.refs
    # The check run still landed — the verdict is the part that blocks the merge.
    assert out["check_run_id"] == 1, out


def test_validation_inconclusive_gets_no_branch_either() -> None:
    """A scanner that could not run is not evidence of a fix. Neither is a plausible one."""
    for status in (INCONCLUSIVE, UNVERIFIED):
        patch = run(validate=validator(status))[0]
        assert patch.status == status, patch
        out, fake = delivered([patch])
        assert out["fix_prs"] == [], (status, out)
        assert out["skipped"] == [{"key": patch.key, "status": status}], out
        assert fake.commits == [] and fake.created_pulls == [], (status, fake.commits)
    # ...and unverified_plausible is LABELLED as unverified wherever it appears.
    plausible = run(validate=validator(UNVERIFIED))[0]
    assert "UNVERIFIED" in plausible.title, plausible.title
    assert "UNVERIFIED" in plausible.summary, plausible.summary


def test_only_verified_fixed_ships() -> None:
    """The other side of the gate: the one status that does open a branch."""
    patch = run(validate=validator(VERIFIED))[0]
    assert patch.status == VERIFIED and patch.files == [{"path": "app.py",
                                                          "content": "cursor.execute(SQL, (u,))\n"}]
    out, fake = delivered([patch])
    assert len(out["fix_prs"]) == 1 and out["skipped"] == [], out
    # It merges INTO the pull request, never into the default branch.
    assert fake.created_pulls[0]["base"] == "feature-7", fake.created_pulls


# --- the driver's own refusals --------------------------------------------------------

def test_an_edit_outside_the_findings_file_is_refused() -> None:
    """Scope comes from the finding, not from the model."""
    patches = run(collect=lambda *_: changes("other.py"))
    assert len(patches) == 1, patches
    assert patches[0].files == [], patches[0]
    assert patches[0].outcome == "needs_wider_scope", patches[0]
    assert patches[0].status == NOT_FIXED, patches[0]
    assert "other.py" in patches[0].summary, patches[0].summary
    # Even with a validator that would have said verified_fixed, nothing ships.
    out, fake = delivered([patches[0]])
    assert out["fix_prs"] == [] and fake.commits == [], out

    # A change to the finding's own file, spelled with a leading "./", is still in scope.
    same = run(collect=lambda *_: changes("./app.py"))
    assert same[0].outcome == "patched" and same[0].files, same


def test_an_added_line_that_looks_like_a_secret_refuses_the_patch() -> None:
    """A patch must not be the thing that publishes a credential."""
    token = "ghp_" + "b" * 32
    patches = run(collect=lambda *_: changes(added=f"GITHUB_TOKEN = '{token}'"))
    assert patches[0].files == [], patches[0]
    assert patches[0].outcome == "no_safe_fix", patches[0]
    # The value is named as a problem and NEVER reproduced — not in the title, not in the
    # summary, which is what delivery.py puts in a pull-request body.
    assert "ROTATION IS REQUIRED" in patches[0].summary, patches[0].summary
    assert token not in patches[0].summary, patches[0].summary
    assert token not in patches[0].title, patches[0].title
    assert token not in str(patches[0].validation), patches[0].validation
    # A legitimate fix in the same shape is NOT refused: real code is not a credential.
    assert run(collect=lambda *_: changes(added='cursor.execute(SQL, (form["user"],))'))[0].files


def test_a_refusal_is_not_reported_as_an_error() -> None:
    """A roster that paints an honest refusal red teaches the operator to distrust it."""
    events = []
    patches = run(propose=lambda *_: {"outcome": "no_safe_fix",
                                      "root_cause": "the query shape is the caller's",
                                      "evidence": "app.py:3 parameterising changes the API"},
                  collect=lambda *_: [], on_agent=events.append)
    assert patches[0].outcome == "no_safe_fix" and patches[0].files == []
    assert [e["status"] for e in events] == ["running", "done"], events
    assert events[0]["label"] == "app.py:3", events[0]

    # A crash IS an error, so the distinction above is a real one.
    crashed = []

    def boom(*_):
        raise RuntimeError("model went away")

    run(propose=boom, on_agent=crashed.append)
    assert [e["status"] for e in crashed] == ["running", "error"], crashed


def test_a_claimed_patch_with_an_unchanged_tree_is_a_contradiction() -> None:
    patch = run(collect=lambda *_: [])[0]
    assert patch.files == [] and patch.status == NOT_FIXED, patch
    assert "tree is unchanged" in patch.summary, patch.summary


# --- the finish tool's vocabulary -----------------------------------------------------

def test_build_fix_report_refuses_verified_fixed() -> None:
    """The agent does not decide whether its fix worked, and cannot say that it did."""
    assert "verified_fixed" not in OUTCOMES
    for claim in ("verified_fixed", "fixed", "verified", "unverified_plausible",
                  "not_fixed", "validation_inconclusive"):
        refused = build_fix_report(claim, "interpolated user input", "parameterised",
                                  "app.py:3  cursor.execute(SQL, (u,))")
        assert refused["ok"] is False, claim
        assert "not an outcome" in refused["error"], refused
    # A valid outcome still passes, so the check above is not refusing everything.
    assert build_fix_report("patched", "interpolated user input",
                            "input cannot reach the query as syntax",
                            "app.py:3  cursor.execute(SQL, (u,))")["ok"] is True


def test_build_fix_report_refuses_an_uncited_not_a_bug() -> None:
    """not_a_bug is the outcome that leaves a real bug in place if it is wrong."""
    refused = build_fix_report("not_a_bug", "the value never comes from a request", "",
                              "there is a guard further up, it looked fine")
    assert refused["ok"] is False and "QUOTE the guard" in refused["error"], refused
    cited = build_fix_report("not_a_bug", "the value never comes from a request", "",
                            "config.py:12  ROLE = 'admin'  — a module constant")
    assert cited["ok"] is True, cited
    # And every outcome needs a root cause and evidence at all.
    assert build_fix_report("patched", "", "i", "app.py:3 line")["ok"] is False
    assert build_fix_report("no_safe_fix", "raw SQL by design", "", "")["ok"] is False


# --- the budget checks ----------------------------------------------------------------

def test_cancel_stops_the_loop_before_the_second_agent() -> None:
    """Each agent costs money AND copies a repository, so the check is before each one."""
    cancel = CancelToken()
    seen = []

    def propose(tree, finding):
        seen.append(finding.get("location", {}).get("source_file"))
        cancel.cancel("operator pressed stop")
        return claims_patched(tree, finding)

    patches = run(propose=propose, cancel=cancel,
                  rows=report(("x.sql-injection", "app.py", 3),
                              ("y.command-injection", "app.py", 9)))
    assert len(seen) == 1, seen           # the second agent never ran
    assert len(patches) == 1, patches
    assert patches[0].line == 3, patches[0]

    # Cancelled before the first: nothing runs and nothing is copied.
    already = CancelToken()
    already.cancel()
    before = list(seen)
    assert run(propose=propose, cancel=already) == []
    assert seen == before, "no agent may run after a cancel"


def test_max_fixes_caps_the_spend() -> None:
    calls = []

    def propose(tree, finding):
        calls.append(finding)
        return claims_patched(tree, finding)

    patches = run(propose=propose, max_fixes=1,
                  rows=report(("x.sql-injection", "app.py", 3),
                              ("y.command-injection", "app.py", 9),
                              ("z.pickle", "app.py", 20)))
    assert len(calls) == 1 and len(patches) == 1, calls


def test_worst_first_and_already_cleared_findings_are_skipped() -> None:
    order = []

    def propose(tree, finding):
        order.append(finding.get("severity"))
        return claims_patched(tree, finding)

    rows = report()
    rows["flagged_not_proven"][0]["severity"] = "low"
    rows["flagged_not_proven"].append(
        {"rule_id": "c.command-injection", "engine": "semgrep", "severity": "critical",
         "file": "app.py", "line": 9, "message": "m", "snippet": "os.system(x)"})
    run(propose=propose, rows=rows)
    assert order == ["critical", "low"], order

    # A finding triage already ruled not reachable is not patched: a needless diff spends
    # a reviewer's trust, and both triage vocabularies mean the same thing here.
    for verdict in ("not_reachable", "FALSE_POSITIVE"):
        cleared = report()
        cleared["flagged_not_proven"][0]["triage"] = {"verdict": verdict, "reasoning": "r",
                                                       "evidence": "e"}
        assert run(rows=cleared) == [], verdict

    # A row whose location is not a file (a route) has no anchor to patch.
    routed = {"findings": [{"rule_id": "r", "location": {"path": "/", "source_file": "/"}}],
              "flagged_not_proven": []}
    assert run(rows=routed) == []


def test_static_only_findings_are_reachable_at_all() -> None:
    """The trap --triage hit: under --static-only `findings[]` is empty and every hit is a
    candidate, so a driver reading only `findings[]` would find nothing to fix."""
    class _Finding:
        rule_id, engine, severity, cwe = "x.sql-injection", "semgrep", "high", "CWE-89"
        message, snippet, file, line = "m", "q = f'{u}'", "app.py", 3

    class _Lead:
        finding = _Finding()

    rows = report_for_fix(None, [_Lead()])
    assert rows["findings"] == [], rows
    assert rows["flagged_not_proven"][0]["file"] == "app.py", rows
    assert len(run(rows=rows)) == 1, "a candidate-only report must still be fixable"


def test_the_run_dir_is_not_copied_into_the_copy() -> None:
    """`--source .` puts docket_runs/ inside the source tree, so a naive copytree would
    copy fix 1's copy into fix 2's, and fix 3 would copy both."""
    seen = []

    def propose(tree, finding):
        seen.append(sorted(p.name for p in Path(tree).iterdir()))
        return claims_patched(tree, finding)

    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)                      # the run dir lives INSIDE the source tree
        (base / "app.py").write_text("q = f'{u}'\n")
        fix_findings(report(("x.sql-injection", "app.py", 3),
                            ("y.command-injection", "app.py", 9)),
                     source_root=base, run_dir=base / "docket_runs" / "r",
                     config=CONFIG, propose=propose,
                     collect=lambda *_: changes(), validate=validator(VERIFIED))
    assert seen == [["app.py"], ["app.py"]], seen


def test_an_agent_that_crashes_does_not_sink_the_scan() -> None:
    def boom(_tree, _finding):
        raise RuntimeError("model went away")

    patches = run(propose=boom, rows=report(("x.sql-injection", "app.py", 3),
                                            ("y.pickle", "app.py", 9)))
    assert len(patches) == 2, patches
    assert all(p.files == [] and p.status == NOT_FIXED for p in patches), patches
    assert "model went away" in patches[0].summary, patches[0].summary


if __name__ == "__main__":
    test_a_claimed_fix_that_does_not_validate_is_never_shipped()
    test_validation_inconclusive_gets_no_branch_either()
    test_only_verified_fixed_ships()
    test_an_edit_outside_the_findings_file_is_refused()
    test_an_added_line_that_looks_like_a_secret_refuses_the_patch()
    test_a_refusal_is_not_reported_as_an_error()
    test_a_claimed_patch_with_an_unchanged_tree_is_a_contradiction()
    test_build_fix_report_refuses_verified_fixed()
    test_build_fix_report_refuses_an_uncited_not_a_bug()
    test_cancel_stops_the_loop_before_the_second_agent()
    test_max_fixes_caps_the_spend()
    test_worst_first_and_already_cleared_findings_are_skipped()
    test_static_only_findings_are_reachable_at_all()
    test_the_run_dir_is_not_copied_into_the_copy()
    test_an_agent_that_crashes_does_not_sink_the_scan()
    print("test_fix: ok")
