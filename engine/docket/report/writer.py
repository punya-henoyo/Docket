"""Turns a FindingStore into the run's artifacts: report.json, report.sarif, and the
terminal summary a human actually reads.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from docket import __version__
from docket.report.dedupe import FindingStore
from docket.report.models import Finding, Severity
from docket.report.sarif import write_sarif
from docket.report.state import get_global_report_state
from docket.utils.secret_files import redact_document

_SEVERITY_ORDER = list(Severity)  # CRITICAL first, per declaration order in models.py


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
        # not a reproduction, and the two must stay distinguishable.
        "triage_counts": triage_counts,
        "triaged": triage_rows,
        # COMPLETENESS, which is a different question from "what did we find". A gate that
        # cannot tell "judged everything and it was fine" from "ran out of money after
        # three" will pass a pull request nobody looked at. `triage_unjudged` counts
        # verdicts the RUNNER wrote rather than the model, marked with
        # core.triage.UNJUDGED_PREFIX, so a synthesised `uncertain` can never be mistaken
        # for a real one.
        "triage_requested": triage_requested,
        "triage_judged": len(triage_rows),
        "triage_unjudged": _unjudged(triage_rows, findings),
        # How much of the tree was deliberately not reported. Diff-scoped scanning is
        # honest only if this number is stated: silence reads as "the repository is clean".
        "suppressed_outside_diff": suppressed_outside_diff,
        # Per-agent token accounting: explains where the run's cost actually went.
        "usage": get_global_report_state().usage.to_dict(),
        "findings": [f.model_dump(mode="json") for f in findings],
    }


def write_report(
    store: FindingStore,
    out_dir: Path,
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
) -> dict[str, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    report = build_report(
        store, run_name=run_name, target=target, summary=summary,
        cost_usd=cost_usd, agents_spawned=agents_spawned, success=success, leads=leads,
        triage=triage, coverage=coverage, surface=surface, agents=agents,
    )
    json_path = out_dir / "report.json"
    # Same redaction boundary as SARIF — see write_sarif. This also catches the raw
    # exception strings folded into `summary`, which are the one realistic way our OWN
    # key could reach an artifact (a LiteLLM auth error echoing what it was given).
    # redact_document, NOT redact(json.dumps(...)): the latter runs the patterns over
    # escaped JSON and can eat a backslash, leaving a bare quote and an unparseable
    # report. See redact_document's docstring for the exact input that did it.
    json_path.write_text(json.dumps(redact_document(report), indent=2))
    sarif_path = write_sarif(out_dir / "report.sarif", sort_findings(store.findings()), target=target)
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
    counted = build_report(empty, run_name="r", target="t", triage_requested=15)
    assert counted["triage_requested"] == 15 and counted["triage_judged"] == 0
    # Diff scoping is honest only if the suppressed count is stated.
    assert build_report(empty, run_name="r", target="t",
                        suppressed_outside_diff=42)["suppressed_outside_diff"] == 42
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

    from docket.report.models import Location, PoC

    def make(rule, sev, path, param) -> Finding:
        return Finding(
            rule_id=rule, title=f"{rule} at {path}", severity=sev,
            location=Location(method="GET", path=path, parameter=param),
            description="desc", poc=PoC(request="req", response="resp"),
            discovered_by="test",
        )

    store = FindingStore()
    store.add(make("reflected-xss", Severity.MEDIUM, "/search", "q"))
    store.add(make("command-injection", Severity.CRITICAL, "/export", "file"))
    store.add(make("sql-injection", Severity.HIGH, "/login", "username"))

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
        assert len(sarif["runs"][0]["results"]) == 3

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
