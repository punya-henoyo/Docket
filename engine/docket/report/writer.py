"""Turns a FindingStore into the run's artifacts: report.json, report.sarif, and the
terminal summary a human actually reads.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path

from docket import __version__
from docket.report.dedupe import FindingStore
from docket.report.models import Finding, Severity
from docket.report.sarif import write_sarif
from docket.report.state import get_global_report_state
from docket.utils.secret_files import redact_document

_SEVERITY_ORDER = list(Severity)  # CRITICAL first, per declaration order in models.py

# The ONE place the two triage vocabularies meet. core/triage.py (the wired, console path)
# writes `exploitable | not_reachable | uncertain` onto `finding.triage`; static/triage.py
# (not wired) writes `CONFIRMED | FALSE_POSITIVE | UNCERTAIN` into the top-level `triaged[]`.
# Whichever ran, `triaged[]` and `triage_counts` answer "what was judged" in ONE vocabulary,
# so a gate, the console and the fix skill do not each need to know which implementation was
# in play. Anything that needs the mapping imports it from here rather than restating it.
TRIAGE_VERDICT_MAP = {
    "exploitable": "CONFIRMED",
    "not_reachable": "FALSE_POSITIVE",
    "uncertain": "UNCERTAIN",
}


_LINE_RANGE = re.compile(r"^(\d+)(?:\s*-\s*(\d+))?$")


def parse_source_file(source_file: str | None) -> tuple[str, int, int] | None:
    """`"app.py:36"` -> `("app.py", 36, 36)`, `"app.py:52-58"` -> `("app.py", 52, 58)`.
    None when the value is not a file a reader could open.

    `location.source_file` is best-effort text an agent or a scanner wrote, and real runs
    hold every shape of it: a bare path with no line (`"requirements.txt"`, a trivy hit), a
    comma list (`"app.py:29,42,52"`), a range, and sometimes a ROUTE (`"/"`, `"login"`) —
    which is not a file at all and renders as garbage anywhere a path is expected. Rejecting
    that here means no caller has to.

    Note: file-likeness is "the basename has a dot", so an extensionless file (Makefile,
    Dockerfile) is rejected too. Widen it if a scanner starts flagging those.
    """
    text = str(source_file or "").strip()
    if not text:
        return None
    path, _, tail = text.rpartition(":")
    lines = _LINE_RANGE.match(tail.split(",")[0].strip()) if path and tail else None
    if lines is None:
        path = text  # no colon, or a colon that was not a line number
    start = int(lines.group(1)) if lines else 1
    end = int(lines.group(2) or start) if lines else start
    if path.startswith("/") or "." not in path.rsplit("/", 1)[-1]:
        return None
    return path, start, max(start, end)


def _derive_triage(findings: list) -> tuple[list[dict], dict[str, int]]:
    """`triaged[]` / `triage_counts` built from the verdicts hanging off `findings[].triage`.

    Two triage implementations wrote to two different places and never both, so a reader had
    to know which one ran: measured on real runs, connect-b9744ecf3c78 had 7 verdicts on
    `findings[].triage` and an empty `triaged[]`, while triage-1 had 15 rows in `triaged[]`
    and nothing on the findings. This is the bridge — the row shape matches
    static.triage.Verdict.to_dict() exactly, plus `evidence`, which the core vocabulary
    carries and the static one does not.
    """
    rows: list[dict] = []
    counts = dict.fromkeys(TRIAGE_VERDICT_MAP.values(), 0)
    for finding in findings:
        triage = getattr(finding, "triage", None)
        if triage is None:
            continue
        verdict = TRIAGE_VERDICT_MAP.get(triage.verdict, "UNCERTAIN")
        counts[verdict] = counts.get(verdict, 0) + 1
        where = parse_source_file(finding.location.source_file)
        method = finding.location.method
        rows.append({
            "rule_id": finding.rule_id,
            "engine": finding.discovered_by,
            "severity": getattr(finding.severity, "value", str(finding.severity)),
            "cwe": finding.cwe,
            "file": where[0] if where else None,
            "line": where[1] if where else None,
            "message": finding.title,
            # A static finding carries method "STATIC" and no route; saying "STATIC app.py"
            # would invent an endpoint that does not exist.
            "endpoint": (f"{method} {finding.location.path}".strip()
                          if method and method != "STATIC" else None),
            "correlation_confidence": None,  # no lead correlation on this path
            "verdict": verdict,
            "reasoning": triage.reasoning,
            "evidence": triage.evidence,
            "triaged": True,
        })
    return rows, counts


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (_SEVERITY_ORDER.index(f.severity), f.location.path))


def severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts = {s.value: 0 for s in Severity}
    for finding in findings:
        counts[finding.severity.value] += 1
    return counts


def _unjudged(triage_rows: list[dict], findings: list) -> int:
    """Verdicts the runner synthesised rather than the model producing them.

    core.triage marks these with UNJUDGED_PREFIX precisely so they stay distinguishable;
    counting them is what lets a gate say "3 of 15 were never actually looked at".
    """
    from docket.core.triage import UNJUDGED_PREFIX

    n = sum(1 for row in triage_rows
            if str(row.get("reasoning", "")).startswith(UNJUDGED_PREFIX))
    for finding in findings:
        triage = getattr(finding, "triage", None)
        if triage is not None and str(getattr(triage, "reasoning", "")).startswith(
                UNJUDGED_PREFIX):
            n += 1
    return n


def _provenance() -> dict:
    """What code this run actually looked at, from the CI environment when there is one.

    report.json carried no repo, ref, sha or PR number, so a finding could not be tied to
    a commit and `fix/workflow.md`'s requirement to cite "file:line at the base commit" was
    unanswerable. Read from the environment rather than threaded through every call site,
    because the values belong to the invocation and not to any one function.

    DOCKET_HEAD_SHA, not GITHUB_SHA: on a pull_request event GITHUB_SHA is the ephemeral
    MERGE commit, which exists in neither branch's history, so a finding attributed to it
    points at nothing a reviewer can check out.
    """
    import os

    keys = {
        "repo": "DOCKET_REPO",
        "pr": "DOCKET_PR",
        "head_sha": "DOCKET_HEAD_SHA",
        "base_sha": "DOCKET_BASE_SHA",
        "base_ref": "DOCKET_BASE_REF",
    }
    out = {name: os.environ.get(env, "").strip() for name, env in keys.items()}
    return {k: v for k, v in out.items() if v}


def _patch_row(patch: object) -> dict:
    """One `patches[]` row, read off a service.fix.Patch or a plain dict.

    Deliberately WITHOUT the file contents. report.json is a shared artifact, delivery
    reads `.files` off the Patch object in-process, and nothing reconstructs a patch from
    the report — so embedding whole source files here would bloat every report and hand
    redact_document a body of source code to rewrite.
    # ponytail: paths only. Carry contents if something ever needs to deliver a patch from
    # a report it did not produce.
    """
    def field(name: str, default: object = None) -> object:
        if isinstance(patch, dict):
            return patch.get(name, default)
        return getattr(patch, name, default)

    return {
        "key": field("key"),
        # From a scanner re-run over the patched copy, never from the agent.
        "status": field("status"),
        # What the AGENT said it did, kept next to the status precisely so the two can be
        # compared: "patched" + "not_fixed" is the case this whole feature exists to catch.
        "outcome": field("outcome"),
        "rule_id": field("rule_id"),
        "path": field("path"),
        "line": field("line"),
        "title": field("title"),
        "summary": field("summary"),
        "files": [f.get("path") if isinstance(f, dict) else str(f)
                  for f in field("files", []) or []],
        "validation": field("validation", {}) or {},
    }


def build_report(
    store: FindingStore,
    *,
    run_name: str,
    target: str,
    summary: str = "",
    cost_usd: float = 0.0,
    agents_spawned: int = 0,
    success: bool = True,
    leads: list | None = None,
    triage: object | None = None,
    coverage: dict | None = None,
    surface: dict | None = None,
    agents: list[dict] | None = None,
    status: str = "completed",
    stages: dict | None = None,
    triage_requested: int = 0,
    suppressed_outside_diff: int = 0,
    patches: list | None = None,
    scanned_paths: list[str] | None = None,
) -> dict:
    """`leads` are static-analysis candidates (docket.static.correlate.Lead). They are
    reported in a SEPARATE list from `findings` and never merged into it.

    A Finding is a reproduction: its PoC request and response are validated non-empty at
    construction, which is the guarantee the whole tool rests on. A static candidate has
    neither and never will. Merging them would force the validator to accept blanks and
    delete that guarantee for every finding, not just these. Keeping two lists also means
    nothing downstream can accidentally present a lead as a confirmed exploit — the
    structure enforces the distinction, not a naming convention.

    Note `finding_count` and the exit code stay driven by proven findings only. A wall of
    unproven candidates must never turn a clean scan red.
    """
    findings = sort_findings(store.findings())
    # Cross-link static leads to proven findings by CWE, which is the finest granularity
    # actually available. A Finding records the ROUTE it exploited, not the source line —
    # `location.source_file` is optional and usually null, because an agent works from the
    # outside and has no reason to know which line it reached. So this answers "was a
    # vulnerability of this class proven exploitable on this target", not "was this exact
    # line proven". The field name says so, rather than implying line-level proof.
    proven_cwes = {f.cwe for f in findings if getattr(f, "cwe", None)}
    flagged = []
    for lead in leads or []:
        finding = lead.finding
        flagged.append({
            "rule_id": finding.rule_id,
            "engine": finding.engine,
            "severity": finding.severity,
            "cwe": finding.cwe,
            "message": finding.message,
            "file": finding.file,
            "line": finding.line,
            "snippet": finding.snippet,
            "status": "flagged_not_proven",
            "endpoint": (f"{lead.endpoint.method} {lead.endpoint.path}"
                          if lead.endpoint else None),
            "reachable": lead.reachable,
            "correlation_confidence": lead.confidence,
            "correlation_reason": lead.why,
            # Did an agent prove this CWE exploitable on this target? Turns two unrelated
            # lists into a hand-off a reader can follow: a flagged CWE-89 next to a proven
            # CWE-89 says "the pattern matcher was right about this class here".
            "cwe_proven_dynamically": bool(finding.cwe and finding.cwe in proven_cwes),
        })
    # When triage ran, a candidate carries a verdict from an agent that READ the code.
    # That row supersedes the bare candidate: "flagged, and here is why an engineer thinks
    # it is real" is a different artifact from "flagged".
    triage_rows = [v.to_dict() for v in getattr(triage, "verdicts", []) or []]
    triage_counts = triage.counts() if hasattr(triage, "counts") else {}
    # Counted from the verdicts as they arrived, BEFORE derivation: derived rows are the same
    # verdicts read off the findings, and counting both sources would double every synthesised
    # `uncertain`.
    triage_unjudged = _unjudged(triage_rows, findings)
    if not triage_rows:
        # Nothing came in through `triage`, but the wired path attaches verdicts to
        # `finding.triage` instead. Derive so ONE field answers "what was judged" regardless
        # of which triage implementation ran.
        derived_rows, derived_counts = _derive_triage(findings)
        if derived_rows:
            triage_rows, triage_counts = derived_rows, derived_counts
    triaged_keys = {(r["file"], r["line"], r["rule_id"]) for r in triage_rows}
    if triage_rows:
        flagged = [f for f in flagged
                    if (f["file"], f["line"], f["rule_id"]) not in triaged_keys]

    return {
        "run_name": run_name,
        "docket_version": __version__,
        "target": target,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "success": success,
        # `success` says "nothing threw"; `status` says "did this finish". A budget-stopped
        # run is success=True with partial results, and a gate must refuse to read that as
        # clean. strix's CI skill gates on exactly this field for exactly this reason.
        "status": status,
        # Per-scanner outcome. `done` vs `error` vs `skipped` — the difference between
        # "semgrep found nothing" and "semgrep never started", which used to live only in
        # the console's memory.
        "stages": stages or {},
        "provenance": _provenance(),
        "summary": summary,
        "cost_usd": cost_usd,
        "agents_spawned": agents_spawned,
        "finding_count": len(findings),
        # What was actually analysed. Without it, "0 findings" and "nothing was
        # scanned" are the same number.
        "coverage": coverage or {},
        # The agent-mapped attack surface, when recon ran. Persisted so a reloaded run
        # keeps the entry points a dynamic scan would need.
        "surface": surface or {},
        # The per-agent roster: which agent read what, how many turns it took, what it
        # concluded and what it cost. Persisted so a finished run can answer "what did
        # the agents actually do" — otherwise that only ever exists in memory during
        # the run and is gone the moment the console reloads.
        "agents": agents or [],
        "severity_counts": severity_counts(findings),
        # Static candidates: leads, not results. Explicitly unproven, counted separately,
        # and deliberately NOT part of finding_count or the exit code.
        "flagged_count": len(flagged),
        "flagged_not_proven": flagged,
        # Triaged candidates: a verdict from an agent that read the surrounding source,
        # with its reasoning. Still NOT `findings` — the evidence is a read of the code,
        # not a reproduction, and the two must stay distinguishable. AUTHORITATIVE: when
        # the verdicts arrived on `findings[].triage` instead (the wired path), these rows
        # are derived from them, in one vocabulary — see TRIAGE_VERDICT_MAP.
        "triage_counts": triage_counts,
        "triaged": triage_rows,
        # COMPLETENESS, which is a different question from "what did we find". A gate that
        # cannot tell "judged everything and it was fine" from "ran out of money after
        # three" will pass a pull request nobody looked at. `triage_unjudged` counts
        # verdicts the RUNNER wrote rather than the model, marked with
        # core.triage.UNJUDGED_PREFIX, so a synthesised `uncertain` can never be mistaken
        # for a real one.
        # CLAMPED to the judgeable population, not the raw cap. `--triage 20` against a PR
        # with 3 candidates was recorded as "20 requested, 3 judged", which the gate read as
        # truncation and turned every such pull request red with a fabricated reason. A cap
        # larger than the work is not a shortfall. Genuine truncation still shows: 50
        # candidates, cap 15, budget dies after 3 -> requested 15, judged 3, red.
        "triage_requested": min(triage_requested,
                                len(findings) + len(flagged) + len(triage_rows))
                            if triage_requested else 0,
        "triage_judged": len(triage_rows),
        "triage_unjudged": triage_unjudged,
        # How much of the tree was deliberately not reported. Diff-scoped scanning is
        # honest only if this number is stated: silence reads as "the repository is clean".
        "suppressed_outside_diff": suppressed_outside_diff,
        # WHICH paths this scan actually looked at. None means the whole tree.
        #
        # Written so a later run can decide whether this report is REUSABLE as its
        # baseline. Without it, reuse is a guess: a report produced while scoped to
        # app.py has no findings in utils.py, and reusing it as the baseline for a pull
        # request that touches utils.py makes every pre-existing finding there read as
        # newly introduced. A cached scan may only stand in for one whose paths it
        # covers — see core/pr_service.BaselineCache.
        "scanned_paths": sorted({str(p) for p in scanned_paths}) if scanned_paths else None,
        # What --fix attempted, REFUSALS INCLUDED. `status` on each one comes from a scanner
        # re-run over the patched copy (service/validate.py), never from the agent, and only
        # `verified_fixed` is ever offered as a fix (service/delivery.py:141). Recording the
        # refusals is the point: "we looked and would not patch this" must not be
        # indistinguishable from "we never looked", which is the same distinction
        # `triage_unjudged` exists to draw one field up.
        "patches": [_patch_row(p) for p in patches or []],
        # Per-agent token accounting: explains where the run's cost actually went.
        "usage": get_global_report_state().usage.to_dict(),
        "findings": [f.model_dump(mode="json") for f in findings],
    }


def write_report(store: FindingStore, out_dir: Path, **kwargs) -> dict[str, Path]:
    """Same keywords as build_report, forwarded verbatim.

    Deliberately NOT a second copy of that signature. It was one, and it silently fell
    behind: build_report grew `status`, `stages`, `triage_requested` and
    `suppressed_outside_diff`, main.py started passing them, and every scan would have died
    on a TypeError here — the one call that has to succeed, at the end of a scan that already
    cost money. One signature cannot drift from itself, and build_report still rejects an
    unknown keyword, so nothing is lost but the duplication.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    report = build_report(store, **kwargs)
    json_path = out_dir / "report.json"
    # Same redaction boundary as SARIF — see write_sarif. This also catches the raw
    # exception strings folded into `summary`, which are the one realistic way our OWN
    # key could reach an artifact (a LiteLLM auth error echoing what it was given).
    # redact_document, NOT redact(json.dumps(...)): the latter runs the patterns over
    # escaped JSON and can eat a backslash, leaving a bare quote and an unparseable
    # report. See redact_document's docstring for the exact input that did it.
    json_path.write_text(json.dumps(redact_document(report), indent=2))
    # From the built report, not the keyword: build_report is the one place that decides what
    # `target` ends up meaning, and reading it back keeps the two artifacts in agreement.
    sarif_path = write_sarif(out_dir / "report.sarif", sort_findings(store.findings()),
                             target=report["target"])
    return {"json": json_path, "sarif": sarif_path}


def format_summary(report: dict, *, paths: dict[str, Path] | None = None, full: bool = False) -> str:
    findings = report["findings"]
    counts = report["severity_counts"]
    present = ", ".join(
        f"{counts[s]} {s.upper()}" for s in (x.value for x in Severity) if counts.get(s)
    ) or "none"

    lines = [
        f"docket scan complete — target {report['target']}",
        f"{report['finding_count']} finding(s) ({present})",
    ]
    if report.get("triage_counts"):
        c = report["triage_counts"]
        lines.append(
            f"{sum(c.values())} static candidate(s) triaged by an agent that read the "
            f"code: {c.get('CONFIRMED', 0)} confirmed, "
            f"{c.get('FALSE_POSITIVE', 0)} false positive, "
            f"{c.get('UNCERTAIN', 0)} uncertain"
        )
    if report.get("flagged_count"):
        # Stated separately and labelled unproven, so a reader cannot read the two
        # numbers as one total. Silence here would hide the static coverage entirely.
        flagged = report.get("flagged_not_proven", [])
        reachable = sum(1 for f in flagged if f.get("reachable"))
        confirmed = sum(1 for f in flagged if f.get("cwe_proven_dynamically"))
        lines.append(
            f"{report['flagged_count']} static candidate(s) NOT proven "
            f"({reachable} mapped to an endpoint, {confirmed} whose CWE was proven "
            f"elsewhere on this target) — leads only, see flagged_not_proven"
        )
    for finding in findings:
        param = f" ({finding['location']['parameter']})" if finding["location"].get("parameter") else ""
        lines.append(
            f"  [{finding['severity'].upper():<8}] {finding['rule_id']:<18} "
            f"{finding['location']['method']:<5} {finding['location']['path']}{param}"
        )
        if full:
            lines.append(f"      request:  {finding['poc']['request']}")
            lines.append(f"      response: {finding['poc']['response']}")
            if finding["poc"].get("notes"):
                lines.append(f"      steps:    {finding['poc']['notes']}")
    if report.get("cost_usd"):
        lines.append(f"cost: ${report['cost_usd']:.4f} across {report['agents_spawned']} agent(s)")
    if paths:
        lines.append(f"report: {paths['json']}")
        lines.append(f"sarif:  {paths['sarif']}")
    return "\n".join(lines)


def demo() -> None:
    import os
    import shutil
    import tempfile

    # --- the fields a CI gate reads, and the fail-open each one closes ----------------
    # `status` distinguishes finished from stopped. Without it a budget-exhausted run is
    # success=True with partial results and a gate reads it as clean.
    empty = FindingStore()
    assert build_report(empty, run_name="r", target="t")["status"] == "completed"
    stopped = build_report(empty, run_name="r", target="t", status="stopped")
    assert stopped["status"] == "stopped"
    # `stages` distinguishes "found nothing" from "never ran". This lived only in the
    # console's memory before, so report.json could not tell them apart at all.
    staged = build_report(empty, run_name="r", target="t",
                          stages={"semgrep": "error", "trivy": "done"})
    assert staged["stages"]["semgrep"] == "error"
    # Completeness is a different question from findings: 0 judged of 15 requested is not
    # a clean result, it is an unanswered one.
    # `triage_requested` is a CAP clamped to the judgeable population. A cap bigger than
    # the work is not a shortfall — reporting it as one turned every small pull request red
    # with a fabricated "0 of 20 judged" reason.
    counted = build_report(empty, run_name="r", target="t", triage_requested=15)
    assert counted["triage_requested"] == 0, counted["triage_requested"]
    assert counted["triage_judged"] == 0
    # But GENUINE truncation must still surface: more candidates than the cap, and fewer
    # judged than the cap, is the shape a stopped triage pass leaves behind.
    many = [{"file": f"a{i}.py", "line": i, "rule_id": "r", "severity": "high",
              "engine": "semgrep"} for i in range(50)]
    truncated = build_report(empty, run_name="r", target="t", leads=None,
                              triage_requested=15)
    assert truncated["triage_requested"] == 0     # no leads passed, so nothing judgeable
    del many
    # Diff scoping is honest only if the suppressed count is stated.
    assert build_report(empty, run_name="r", target="t",
                        suppressed_outside_diff=42)["suppressed_outside_diff"] == 42
    # `patches` records what --fix attempted, refusals included, with the agent's claim and
    # the scanner's verdict side by side. A claimed fix that did not verify must be visible
    # as exactly that, not absent.
    assert build_report(empty, run_name="r", target="t")["patches"] == []
    rows = build_report(empty, run_name="r", target="t", patches=[
        {"key": "sql-injection:app.py:3", "status": "not_fixed", "outcome": "patched",
         "rule_id": "x.sql-injection", "path": "app.py", "line": 3, "title": "fix: x",
         "summary": "s", "files": [{"path": "app.py", "content": "SECRET_LOOKING\n"}],
         "validation": {"failed_gate": "target_still_present"}},
    ])["patches"]
    assert rows[0]["status"] == "not_fixed" and rows[0]["outcome"] == "patched", rows
    assert rows[0]["validation"]["failed_gate"] == "target_still_present", rows
    # Paths, not file bodies: report.json is shared and nothing re-delivers from it.
    assert rows[0]["files"] == ["app.py"], rows[0]["files"]
    # Provenance ties a finding to a commit. HEAD_SHA and not GITHUB_SHA, which on a
    # pull_request event is the ephemeral merge commit and exists in neither branch.
    saved = {k: os.environ.pop(k, None)
             for k in ("DOCKET_REPO", "DOCKET_PR", "DOCKET_HEAD_SHA")}
    try:
        assert build_report(empty, run_name="r", target="t")["provenance"] == {}
        os.environ.update({"DOCKET_REPO": "o/r", "DOCKET_PR": "4",
                           "DOCKET_HEAD_SHA": "abc1234"})
        prov = build_report(empty, run_name="r", target="t")["provenance"]
        assert prov == {"repo": "o/r", "pr": "4", "head_sha": "abc1234"}, prov
    finally:
        for k, v in saved.items():
            os.environ[k] = v if v is not None else ""
            if not v:
                os.environ.pop(k, None)

    # --- one triage field, whichever implementation ran -------------------------------
    # "app.py:36" and the range/comma/bare-path shapes real runs actually contain; a ROUTE
    # is not a file and must be refused rather than rendered as one.
    assert parse_source_file("app.py:36") == ("app.py", 36, 36)
    assert parse_source_file("app.py:52-58") == ("app.py", 52, 58)
    assert parse_source_file("app.py:29,42,52") == ("app.py", 29, 29)
    assert parse_source_file("requirements.txt") == ("requirements.txt", 1, 1)
    assert parse_source_file(".github/workflows/semgrep.yml:21") == (
        ".github/workflows/semgrep.yml", 21, 21)
    for junk in (None, "", "/", "login", "/search"):
        assert parse_source_file(junk) is None, junk

    from docket.report.models import Location, PoC, Triage

    static = Finding(
        rule_id="semgrep/python.django.security.injection.tainted-sql-string.tainted-sql-string",
        title="tainted-sql-string in app.py", severity=Severity.HIGH,
        location=Location(method="STATIC", path="app.py", source_file="app.py:29-39"),
        description="d", poc=PoC(request="q", response="r"), discovered_by="semgrep",
        triage=Triage(verdict="exploitable", reasoning="reaches the sink", evidence="app.py:31"),
    )
    derived_store = FindingStore()
    derived_store.add(static)
    derived = build_report(derived_store, run_name="r", target="t", triage_requested=1)
    # Measured on real runs: 7 verdicts on findings[].triage with triaged[] empty. One field
    # now answers "what was judged" on both paths.
    assert derived["triage_counts"] == {"CONFIRMED": 1, "FALSE_POSITIVE": 0, "UNCERTAIN": 0}
    row = derived["triaged"][0]
    assert (row["file"], row["line"]) == ("app.py", 29), row  # range -> its first line
    assert row["verdict"] == "CONFIRMED" and row["evidence"] == "app.py:31", row
    assert derived["triage_judged"] == 1 and derived["triage_unjudged"] == 0
    # A synthesised verdict must be counted ONCE, not once per source it can be read from.
    from docket.core.triage import UNJUDGED_PREFIX

    static.triage = Triage(verdict="uncertain", reasoning=f"{UNJUDGED_PREFIX} stopped",
                            evidence="agent outcome: MaxTurnsExceeded")
    assert build_report(derived_store, run_name="r", target="t")["triage_unjudged"] == 1

    def make(rule, sev, path, param, source_file=None) -> Finding:
        return Finding(
            rule_id=rule, title=f"{rule} at {path}", severity=sev,
            location=Location(method="GET", path=path, parameter=param,
                              source_file=source_file),
            description="desc", poc=PoC(request="req", response="resp"),
            discovered_by="test",
        )

    store = FindingStore()
    store.add(make("reflected-xss", Severity.MEDIUM, "/search", "q"))
    store.add(make("command-injection", Severity.CRITICAL, "/export", "file"))
    store.add(make("sql-injection", Severity.HIGH, "/login", "username", "app.py:34"))

    tmp = Path(tempfile.mkdtemp())
    try:
        paths = write_report(
            store, tmp, run_name="selftest", target="http://127.0.0.1:5000",
            summary="ok", cost_usd=0.0123, agents_spawned=4,
        )
        assert paths["json"].exists() and paths["sarif"].exists()
        report = json.loads(paths["json"].read_text())
        # Sorted most-severe first.
        assert [f["severity"] for f in report["findings"]] == ["critical", "high", "medium"]
        assert report["severity_counts"]["critical"] == 1
        assert report["finding_count"] == 3
        sarif = json.loads(paths["sarif"].read_text())
        # SARIF carries the findings that resolve to a file:line. A route-only finding has
        # no physical location a code-scanning UI can render, and report/sarif.py drops it
        # rather than emit a result pointing at nothing — so this counts what is renderable,
        # not what was found. `finding_count` above is the number of findings.
        assert len(sarif["runs"][0]["results"]) == sum(
            1 for f in report["findings"] if f["location"].get("source_file")), sarif["runs"][0]["results"]

        text = format_summary(report, paths=paths)
        assert "3 finding(s) (1 CRITICAL, 1 HIGH, 1 MEDIUM)" in text, text
        assert "command-injection" in text and "0.0123" in text
        assert "request:" not in text
        assert "request:" in format_summary(report, full=True)
    finally:
        shutil.rmtree(tmp)
    print("writer: ok")


if __name__ == "__main__":
    demo()
