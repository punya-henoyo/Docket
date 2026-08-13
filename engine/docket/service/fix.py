"""Run a fix agent per finding, then let a scanner decide whether the patch worked.

The shape follows core/triage.py:79 `triage_findings`, which already solves the parts that
bite: one agent at a time so the budget gate is not racy, a cancel check BEFORE each agent
because each one costs money, `on_agent` announced before the agent runs, and a broad
`except` so one failure cannot sink the scan.

Three things are deliberately different from triage, and each is load-bearing.

1. THE AGENT EDITS A COPY. `shutil.copytree(source_root, run_dir/"fix"/<key>/"tree")` per
   finding; the pristine tree is never written. That is what makes
   `collect_changes(patched, base)` trivially honest — every difference between the two
   trees is the agent's, by construction rather than by trust.
2. THE AGENT'S CLAIM NEVER BECOMES THE STATUS. It reports `patched`, meaning "I changed
   this". Whether that is verified_fixed / unverified_plausible / not_fixed /
   validation_inconclusive is decided by `validate_patch`, and only verified_fixed is ever
   shipped (service/delivery.py:141). A model told to self-certify will self-certify.
3. IT GATES ON `source_root`, NOT ON A SANDBOX. `triage_findings` returns `{}` when
   `sandbox is None`; copying that would make `--fix` a silent no-op on the one shape a PR
   check uses, which is `--static-only --no-sandbox`. static/triage.py:98 gates on the
   source tree instead, and so does this.

`propose`, `collect` and `validate` are injectable seams, all defaulting to the real
thing and all imported lazily (the stance service/delivery.py:79 `_gate` documents): this
module imports, and its demo runs, whether or not source_write/validate exist yet, and the
tests exercise the whole refusal path with no LLM and no semgrep.
"""
from __future__ import annotations

import asyncio
import logging
import re
import shutil
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from docket.agents.factory import build_agent
from docket.agents.prompts.fix import build_fix_task
from docket.config.settings import Config
from docket.core.agents import AgentCoordinator
from docket.core.cancel import NEVER, CancelToken, ScanCancelled
from docket.core.execution import ScanContext, run_agent_loop
from docket.core.triage import order_for_triage
from docket.report.writer import parse_source_file
# `_all_rows` is imported deliberately, private name and all: it is the one place that
# normalises `findings[]` and `flagged_not_proven[]` into one list, and under --static-only
# every scanner hit is in the second one. A driver reading only `findings[]` would find
# nothing to fix on exactly the runs a PR check makes. See its docstring.
from docket.service.gate import _all_rows, normalise_verdict, rule_leaf
from docket.utils.secret_files import redact

logger = logging.getLogger(__name__)

DEFAULT_MAX_FIXES = 3

# Loose, for the reason core/triage.py:33-58 sets out at length: cost is the real bound
# and turns are a poor proxy for it. Above triage's 12 because this role reads, edits, and
# re-reads what it edited, which is a handful of turns more than reading alone.
FIX_TURNS = 18

# The verification vocabulary. Set by validate_patch, never by the agent.
VERIFIED = "verified_fixed"
UNVERIFIED = "unverified_plausible"
NOT_FIXED = "not_fixed"
INCONCLUSIVE = "validation_inconclusive"


@dataclass(slots=True)
class Patch:
    """One finding's outcome. `files` is what service/delivery.py:_file_changes wants.

    Every processed finding produces one of these, including the refusals — a refusal is a
    successful outcome of the agent's work (skills/fix/workflow.md:168) and dropping it
    would make "we looked and would not patch it" indistinguishable from "we never
    looked". A refusal carries `files == []` and a status that is not `verified_fixed`, so
    delivery skips it before it ever reads the file list.
    """

    key: str
    status: str                      # verified_fixed | unverified_plausible | not_fixed
    title: str                       #                                | validation_inconclusive
    summary: str
    files: list[dict]                # [{"path", "content"}]
    outcome: str                     # what the AGENT said, or the driver's refusal
    validation: dict
    rule_id: str
    path: str
    line: int


def fix_findings(
    report: dict,
    *,
    source_root: str | Path,
    run_dir: Path,
    config: Config,
    max_fixes: int = DEFAULT_MAX_FIXES,
    model_override: Callable[[str], Any] | None = None,
    cancel: CancelToken = NEVER,
    on_agent: Callable[[dict], None] | None = None,
    propose: Callable[[Path, dict], dict] | None = None,
    validate: Callable[..., Any] | None = None,
    collect: Callable[[Path, Path], list[dict]] | None = None,
) -> list[Patch]:
    """One Patch per finding attempted, worst-first. Never raises except ScanCancelled.

    `propose(patched_root, finding) -> dict` is the agent step, defaulting to a real
    `run_agent_loop` over the `fix` role; the dict it returns is the finish tool's output.
    `collect(patched_root, base_root) -> list[dict]` defaults to
    `source_write.collect_changes`. `validate(...)` defaults to `validate.validate_patch`.
    Injecting all three is what lets the tests prove the refusal paths with no LLM and no
    scanner — see tests/test_fix.py.
    """
    if not source_root or not report:
        return []
    base = Path(source_root)
    rows = [row for row in order_for_triage(_all_rows(report)) if _fixable(row)]
    if not rows:
        return []

    coordinator = AgentCoordinator(
        max_agents=1,  # sequential: concurrent agents make the budget gate racy
        budget_usd=config.max_cost_usd,
        per_agent_reserve_usd=config.max_child_cost_usd,
    )
    anchors = _anchors(report)
    patches: list[Patch] = []

    for index, row in enumerate(rows[:max_fixes]):
        # Before each agent, because each one costs real money AND copies a repository.
        # `cancel.cancelled` is a PROPERTY, not a method.
        if cancel.cancelled:
            break
        path, line = _where(row)
        rule = str(row.get("rule_id") or "?")
        key = f"{rule_leaf(rule)}:{path}:{line}"
        agent_id = f"fix-{index}"
        # Announced BEFORE the agent runs, not after: the point of a live roster is
        # seeing which file is being edited right now, not a receipt afterwards.
        if on_agent is not None:
            on_agent({"id": agent_id, "role": "fix", "status": "running",
                      "label": f"{path}:{line}", "detail": rule_leaf(rule)})

        errored = False
        try:
            patched = _copy_tree(base, run_dir, key)
            finding = row | anchors.get(f"{path}:{line}", {})
            step = propose or _agent_step(
                run_dir=run_dir, config=config, agent_id=agent_id,
                coordinator=coordinator, model_override=model_override,
                path=path, line=line,
            )
            output = step(patched, finding)
            patch = _assess(
                output if isinstance(output, dict) else {},
                key=key, rule=rule, path=path, line=line, base=base, patched=patched,
                collect=collect, validate=validate,
            )
        except ScanCancelled:
            # Must escape the broad handler below. Caught there it would read as "the fix
            # failed" and the loop would continue to the next finding, still spending money
            # and still copying trees for a scan the operator already stopped.
            break
        except Exception as exc:  # noqa: BLE001 — one failure must not sink the scan
            errored = True
            logger.warning("fix agent for %s failed: %s", key, exc)
            patch = _refused(
                key=key, rule=rule, path=path, line=line, outcome="no_safe_fix",
                note=f"the fix agent failed before producing a patch: {exc}",
            )
        patches.append(patch)
        if on_agent is not None:
            on_agent({"id": agent_id, "role": "fix",
                      # Only a CRASH is an error. A refusal — not_a_bug, no_safe_fix,
                      # needs_wider_scope — is a successful outcome of the agent's work
                      # (skills/fix/workflow.md:168), and a roster that paints it red
                      # teaches the operator to read honesty as failure.
                      "status": "error" if errored else "done",
                      "outcome": patch.outcome, "detail": patch.status})
    return patches


def report_for_fix(store: Any, leads: list | None) -> dict:
    """The two lists `fix_findings` reads, built from what a run has in hand.

    run_scan calls fix before report.json exists, and `_all_rows` wants both keys. Under
    --static-only `findings` is EMPTY — no sandbox means no Finding is ever constructed and
    every scanner hit is a candidate — which is exactly why the candidate half is not
    optional here.
    """
    return {
        "findings": ([f.model_dump(mode="json") for f in store.findings()]
                     if store is not None else []),
        "flagged_not_proven": [
            {"rule_id": lead.finding.rule_id, "engine": lead.finding.engine,
             "severity": lead.finding.severity, "cwe": lead.finding.cwe,
             "message": lead.finding.message, "snippet": lead.finding.snippet,
             "file": lead.finding.file, "line": lead.finding.line}
            for lead in leads or []
        ],
    }


# --- selecting what to fix ------------------------------------------------------------

def _where(row: dict) -> tuple[str, int]:
    parsed = parse_source_file((row.get("location") or {}).get("source_file"))
    return (parsed[0], parsed[1]) if parsed else ("", 0)


def _fixable(row: dict) -> bool:
    """Skip rows there is nothing honest to fix.

    Two kinds. A row whose location is not a file with a line (a route, "/") has no anchor
    to patch. A row triage already ruled not reachable should not be patched at all —
    skills/fix/workflow.md:33-37: a needless diff spends a reviewer's trust.
    `normalise_verdict` collapses the two triage vocabularies (`not_reachable` and
    `FALSE_POSITIVE` are the same answer) so this reads one word.
    """
    if normalise_verdict((row.get("triage") or {}).get("verdict")) == "FALSE_POSITIVE":
        return False
    return bool(_where(row)[0])


def _anchors(report: dict) -> dict[str, dict]:
    """`{"app.py:34": {"message": ..., "snippet": ...}}` from the candidate rows.

    `_all_rows` normalises a candidate down to rule/severity/location and drops its
    matched source line, which for a static finding IS the anchor
    (skills/fix/workflow.md:28-29). Handing it back is cheaper than making the agent
    guess which line the rule matched.
    """
    found: dict[str, dict] = {}
    for cand in report.get("flagged_not_proven") or []:
        if not isinstance(cand, dict):
            continue
        extra = {k: cand[k] for k in ("message", "snippet", "cwe") if cand.get(k)}
        if extra:
            found[f"{cand.get('file')}:{cand.get('line')}"] = extra
    return found


# --- the agent step ------------------------------------------------------------------

def _copy_tree(base: Path, run_dir: Path, key: str) -> Path:
    """A fresh copy of the repository for this one finding to edit.

    The pristine tree is never written to, which is what makes collect_changes(patched,
    base) honest by construction instead of by trust.

    # ponytail: a full copytree per finding is the accepted ceiling — one repo copy per
    # fix, bounded by max_fixes (3). Swap for `git worktree add` if a large repo makes the
    # copy hurt; nothing else here cares how the copy was made.
    """
    tree = run_dir / "fix" / _safe(key) / "tree"
    if tree.exists():
        shutil.rmtree(tree)
    tree.parent.mkdir(parents=True, exist_ok=True)

    # Never copy the run directory into the copy. `docket_runs/` is created under the CWD
    # (config/settings.py:RUNS_DIR), so on the ordinary `--source .` invocation the run dir
    # sits INSIDE the source tree: without this the second fix copies the first fix's copy,
    # the third copies both, and collect_changes then reports the copies as changes.
    ignore = None
    runs, root = run_dir.resolve(), base.resolve()
    if root in runs.parents:
        # The top-level entry that CONTAINS our output (normally "docket_runs"), skipped
        # whole — a copy of somebody's source has no business carrying run artifacts.
        ignore = _skip(root / runs.relative_to(root).parts[0])
    shutil.copytree(base, tree, symlinks=True, ignore=ignore)
    return tree


def _skip(excluded: Path) -> Callable[[str, list[str]], set[str]]:
    def ignore(directory: str, names: list[str]) -> set[str]:
        here = Path(directory).resolve()
        return {name for name in names if here / name == excluded}

    return ignore


def _safe(key: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", key)[:80] or "fix"


def _agent_step(*, run_dir: Path, config: Config, agent_id: str,
                coordinator: AgentCoordinator, model_override: Callable | None,
                path: str, line: int) -> Callable[[Path, dict], dict]:
    """The default `propose`: one real fix agent over the copied tree."""

    def step(patched: Path, finding: dict) -> dict:
        context = ScanContext(
            target_url="",          # a fix reads and edits source; it dials nothing
            run_dir=run_dir,
            agent_id=agent_id,
            role="fix",
            coordinator=coordinator,
            config=config,
            model_override=model_override,
            sandbox=None,           # source-only: no shell, no browser, no container
            # THE COPY. Every file tool and propose_edit is rooted here, so the agent
            # cannot reach the operator's tree even if it tries.
            source_root=str(patched),
        )
        agent = build_agent(
            "fix", config, model=model_override("fix") if model_override else None,
        )
        task = build_fix_task(finding, path=path, line=line, source_root=str(patched))
        return asyncio.run(run_agent_loop(agent, context, task, max_turns=FIX_TURNS))

    return step


# --- turning the agent's claim into a Patch ------------------------------------------

def _assess(output: dict, *, key: str, rule: str, path: str, line: int,
            base: Path, patched: Path,
            collect: Callable[[Path, Path], list[dict]] | None,
            validate: Callable[..., Any] | None) -> Patch:
    outcome = str(output.get("outcome") or "").strip() or "no_safe_fix"
    root_cause = str(output.get("root_cause") or "").strip()
    invariant = str(output.get("invariant") or "").strip()
    evidence = str(output.get("evidence") or "").strip()
    changes = (collect or _collect_changes)(patched, base)

    # Every refusal below produces a record with NO files, so nothing can be shipped from
    # it — and the reason is recorded, because "we looked and would not patch it" must not
    # read like "we never looked".
    if outcome != "patched":
        return _refused(key=key, rule=rule, path=path, line=line, outcome=outcome,
                        note=("the agent did not patch this" if not changes else
                              f"the agent reported `{outcome}` but left {len(changes)} "
                              "changed file(s); nothing is shipped from a refusal"),
                        root_cause=root_cause, invariant=invariant, evidence=evidence)

    if not changes:
        # A contradiction, not a fix: it claimed to have patched something and the tree is
        # identical. Recorded as such rather than silently dropped.
        return _refused(key=key, rule=rule, path=path, line=line, outcome=outcome,
                        note="claimed `patched` but the tree is unchanged, so there is "
                             "nothing to ship.",
                        root_cause=root_cause, invariant=invariant, evidence=evidence)

    # SCOPE COMES FROM THE FINDING, NOT FROM THE MODEL.
    stray = sorted({str(c.get("path")) for c in changes
                    if _norm(c.get("path")) != _norm(path)})
    if stray:
        return _refused(key=key, rule=rule, path=path, line=line,
                        outcome="needs_wider_scope",
                        note=("edits landed outside the finding's own file, which is the "
                              f"only file in scope: {', '.join(stray)}"),
                        root_cause=root_cause, invariant=invariant, evidence=evidence)
    denied = sorted({str(c.get("path")) for c in changes if _denied(str(c.get("path")))})
    if denied:
        return _refused(key=key, rule=rule, path=path, line=line, outcome="no_safe_fix",
                        note=f"edits landed on a path that is never patchable: {', '.join(denied)}",
                        root_cause=root_cause, invariant=invariant, evidence=evidence)

    # Before ANYTHING leaves this process — the report, a PR body, a commit.
    secrets = _secret_lines(changes)
    if secrets:
        return _refused(key=key, rule=rule, path=path, line=line, outcome="no_safe_fix",
                        note=("refused: an added line matches a secret pattern, so this "
                              f"patch would publish a credential ({'; '.join(secrets)}). "
                              "The value is NOT reproduced here. If the finding is a "
                              "leaked credential, removing it is not the fix — ROTATION "
                              "IS REQUIRED."),
                        root_cause=root_cause, invariant=invariant, evidence=evidence)

    # THE AGENT'S CLAIM NEVER BECOMES THE STATUS. It said `patched`, which is a claim about
    # what it changed; whether that is verified_fixed, unverified_plausible, not_fixed or
    # validation_inconclusive is decided here, by a scanner re-run over the copy.
    validation = _validation(
        (validate or _validate_patch)(
            base_root=base, patched_root=patched, target_key=(rule, path, int(line)),
        )
    )
    status = validation["status"]
    files = [{"path": c["path"], "content": c.get("content")} for c in changes]
    return Patch(
        key=key, status=status,
        title=_title(status, outcome, key, root_cause),
        summary=_summary(rule=rule, path=path, line=line, outcome=outcome, status=status,
                         root_cause=root_cause, invariant=invariant, evidence=evidence,
                         validation=validation, notes=[]),
        files=files, outcome=outcome, validation=validation,
        rule_id=rule, path=path, line=int(line),
    )


def _refused(*, key: str, rule: str, path: str, line: int, outcome: str, note: str,
             root_cause: str = "", invariant: str = "", evidence: str = "") -> Patch:
    validation = {"status": NOT_FIXED, "gates": {}, "failed_gate": None,
                  "evidence": {"driver": note}}
    return Patch(
        key=key, status=NOT_FIXED,
        title=_title(NOT_FIXED, outcome, key, root_cause),
        summary=_summary(rule=rule, path=path, line=line, outcome=outcome,
                         status=NOT_FIXED, root_cause=root_cause, invariant=invariant,
                         evidence=evidence, validation=validation, notes=[note]),
        files=[], outcome=outcome, validation=validation,
        rule_id=rule, path=path, line=int(line),
    )


def _title(status: str, outcome: str, key: str, root_cause: str) -> str:
    head = _first_sentence(root_cause) or key
    if status == UNVERIFIED:
        # workflow.md:130 — unverified_plausible must be labelled as unverified WHEREVER it
        # appears, and delivery.py puts this string in a commit message and a PR title.
        return redact(f"fix (UNVERIFIED): {head}")[:120]
    if outcome != "patched":
        return redact(f"{outcome}: {head}")[:120]
    return redact(f"fix: {head}")[:120]


def _summary(*, rule: str, path: str, line: int, outcome: str, status: str,
             root_cause: str, invariant: str, evidence: str, validation: dict,
             notes: list[str]) -> str:
    lines = [
        f"Finding: {rule} at {path}:{line}",
        f"Agent outcome: {outcome} — a claim about what it changed, not a verdict.",
        f"Validation: {status} (decided by a scanner re-run, not by the agent).",
    ]
    if status == UNVERIFIED:
        lines.append(
            "UNVERIFIED: the build and tests pass, but a verification gate could not be "
            "established. This is a suggestion, not a demonstrated fix."
        )
    if status != VERIFIED and validation.get("failed_gate"):
        lines.append(f"Failing gate: {validation['failed_gate']}")
    if status != VERIFIED:
        lines.append("Not shipped as a fix: only verified_fixed opens a branch.")
    if root_cause:
        lines.append(f"Root cause: {root_cause}")
    if invariant:
        lines.append(f"Invariant now enforced: {invariant}")
    if evidence:
        lines.append(f"Evidence the agent cited: {evidence}")
    gates = validation.get("gates") or {}
    if gates:
        lines.append("Gates: " + ", ".join(f"{k}={v}" for k, v in sorted(gates.items())))
    lines += notes
    # Redacted HERE, not only at the report boundary: delivery.py puts this whole string
    # into a pull-request body, which is not a path report/writer.py's redact_document
    # ever sees. The agent is told never to put a live secret in its evidence; this is the
    # boundary that does not depend on it having listened.
    return redact("\n".join(lines))


def _first_sentence(text: str) -> str:
    head = re.split(r"(?<=[.!?])\s", text.strip(), maxsplit=1)[0]
    return head.strip().rstrip(".")[:100]


def _norm(path: object) -> str:
    text = str(path or "").replace("\\", "/").strip()
    return text[2:] if text.startswith("./") else text


def _secret_lines(changes: list[dict]) -> list[str]:
    """Which added lines change under redaction, named by file — never quoted.

    `redact` is best-effort pattern matching (utils/secret_files.py), so this is a refusal
    trigger and not a licence: a patch whose ADDED lines look like a credential does not
    get shipped, and the value never enters the report, the PR body or the log. Only added
    lines, deliberately: a file that already contains a secret elsewhere is not this
    patch's doing, and refusing on it would block every legitimate fix in that file.
    """
    hits: list[str] = []
    for change in changes:
        for added in change.get("added_lines") or []:
            if redact(str(added)) != str(added):
                hits.append(f"{change.get('path')} adds a line matching a secret pattern")
                break
    return hits


# --- the seams (lazily imported; see the module docstring) -----------------------------

def _collect_changes(patched: Path, base: Path) -> list[dict]:
    from docket.tools.source_write.tools import collect_changes

    return collect_changes(patched, base)


def _denied(path: str) -> str | None:
    """`scope_denied`, or None when source_write is not importable.

    Defence in depth rather than the boundary: the finding's-own-file check above already
    means the only writable file is the one the finding names, so a missing source_write
    cannot widen what a patch may touch. It only loses the extra refusal for a finding that
    IS in .github/ or a lockfile.
    """
    try:
        from docket.tools.source_write.tools import scope_denied
    except ImportError:  # pragma: no cover - the module lands with the other half
        return None
    return scope_denied(path)


def _validate_patch(**kwargs: Any) -> Any:
    from docket.service.validate import validate_patch

    return validate_patch(**kwargs)


def _validation(result: Any) -> dict:
    """A Validation, a dict, or anything carrying the four attributes — duck-typed for the
    same reason delivery.py:_gate is: the producer is a different phase and this should not
    care which shape it settled on.

    An unreadable status becomes `validation_inconclusive`, never `verified_fixed`: the one
    direction a missing answer must never fall.
    """
    if isinstance(result, dict):
        get = result.get
    else:
        def get(name: str, default: Any = None) -> Any:
            return getattr(result, name, default)
    status = str(get("status") or "").strip() or INCONCLUSIVE
    if status not in (VERIFIED, UNVERIFIED, NOT_FIXED, INCONCLUSIVE):
        status = INCONCLUSIVE
    return {"status": status, "gates": dict(get("gates") or {}),
            "failed_gate": get("failed_gate"), "evidence": dict(get("evidence") or {})}


def demo() -> None:
    import tempfile

    cfg = Config(llm="x", llm_api_key="k", max_cost_usd=1.0, max_child_cost_usd=0.5,
                 max_agents=1)

    def report(rule: str = "x.sql-injection", verdict: str | None = None) -> dict:
        row: dict = {"rule_id": rule, "engine": "semgrep", "severity": "high",
                     "file": "app.py", "line": 3, "message": "m", "snippet": "q = f'{u}'"}
        if verdict:
            row["triage"] = {"verdict": verdict, "reasoning": "r", "evidence": "e"}
        return {"findings": [], "flagged_not_proven": [row]}

    def changes(path: str = "app.py", added: str = "cursor.execute(SQL, (u,))") -> list[dict]:
        return [{"path": path, "content": f"{added}\n", "added_lines": [added],
                 "removed_lines": ["q = f'{u}'"]}]

    def patched_claim(_tree: Path, _finding: dict) -> dict:
        return {"outcome": "patched", "root_cause": "The query interpolated user input.",
                "invariant": "Untrusted input can no longer reach the query as syntax.",
                "evidence": "app.py:3 cursor.execute(SQL, (u,))"}

    def verdict(status: str, **extra) -> Callable[..., dict]:
        return lambda **_: {"status": status, "gates": {"positive_control": True},
                            "failed_gate": None, **extra}

    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp) / "src"
        base.mkdir()
        (base / "app.py").write_text("q = f'{u}'\n")
        runs = Path(tmp) / "run"

        # THE WHOLE POINT: the agent claims it patched; the validator says not_fixed; the
        # patch carries not_fixed, so delivery skips it. The claim is never the status.
        got = fix_findings(report(), source_root=base, run_dir=runs, config=cfg,
                          propose=patched_claim, collect=lambda *_: changes(),
                          validate=verdict(NOT_FIXED, failed_gate="target_still_present"))
        assert len(got) == 1 and got[0].status == NOT_FIXED, got
        assert got[0].outcome == "patched", got[0]          # the claim is kept, as a claim
        assert "target_still_present" in got[0].summary, got[0].summary
        assert got[0].key == "sql-injection:app.py:3", got[0].key

        # verified_fixed is the only status that ships, and it carries the files.
        shipped = fix_findings(report(), source_root=base, run_dir=runs, config=cfg,
                              propose=patched_claim, collect=lambda *_: changes(),
                              validate=verdict(VERIFIED))
        assert shipped[0].status == VERIFIED and shipped[0].files, shipped
        assert shipped[0].files[0]["path"] == "app.py"

        # unverified_plausible is labelled as unverified wherever it appears.
        plausible = fix_findings(report(), source_root=base, run_dir=runs, config=cfg,
                                propose=patched_claim, collect=lambda *_: changes(),
                                validate=verdict(UNVERIFIED))
        assert "UNVERIFIED" in plausible[0].title, plausible[0].title
        assert "UNVERIFIED" in plausible[0].summary, plausible[0].summary

        # An edit outside the finding's own file: no patch, and the scope refusal is the
        # driver's, not the model's.
        strayed = fix_findings(report(), source_root=base, run_dir=runs, config=cfg,
                              propose=patched_claim, collect=lambda *_: changes("other.py"),
                              validate=verdict(VERIFIED))
        assert strayed[0].files == [] and strayed[0].outcome == "needs_wider_scope", strayed
        assert strayed[0].status == NOT_FIXED

        # An added line that looks like a live credential: refused, and the value is not
        # reproduced anywhere in the record.
        leak = "TOKEN = 'ghp_" + "a" * 30 + "'"
        leaked = fix_findings(report(), source_root=base, run_dir=runs, config=cfg,
                             propose=patched_claim, collect=lambda *_: changes(added=leak),
                             validate=verdict(VERIFIED))
        assert leaked[0].files == [] and "ROTATION IS REQUIRED" in leaked[0].summary
        assert "ghp_" not in leaked[0].summary, leaked[0].summary

        # Claiming `patched` with an unchanged tree is a contradiction, not a fix.
        empty = fix_findings(report(), source_root=base, run_dir=runs, config=cfg,
                            propose=patched_claim, collect=lambda *_: [],
                            validate=verdict(VERIFIED))
        assert empty[0].files == [] and "tree is unchanged" in empty[0].summary

        # A refusal is still recorded, with its reason.
        refused = fix_findings(report(), source_root=base, run_dir=runs, config=cfg,
                              propose=lambda *_: {"outcome": "not_a_bug",
                                                  "root_cause": "constant",
                                                  "evidence": "config.py:1 ROLE='admin'"},
                              collect=lambda *_: [], validate=verdict(VERIFIED))
        assert refused[0].outcome == "not_a_bug" and refused[0].files == []

        # Already ruled not reachable: not patched at all. A needless diff spends trust.
        assert fix_findings(report(verdict="not_reachable"), source_root=base,
                           run_dir=runs, config=cfg, propose=patched_claim,
                           collect=lambda *_: changes(), validate=verdict(VERIFIED)) == []

        # No source tree means nothing to fix — and NOT the sandbox check triage uses,
        # because the PR path runs --static-only with no sandbox at all.
        assert fix_findings(report(), source_root="", run_dir=runs, config=cfg) == []
        assert fix_findings({}, source_root=base, run_dir=runs, config=cfg) == []

    # An unreadable validation falls to inconclusive, never to verified.
    assert _validation(None)["status"] == INCONCLUSIVE
    assert _validation({"status": "looks good"})["status"] == INCONCLUSIVE
    assert _validation({"status": VERIFIED})["status"] == VERIFIED
    print("service.fix: ok")


if __name__ == "__main__":
    demo()
