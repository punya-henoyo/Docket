"""Applications, runs and findings, derived from what is on disk.

The one place that decides:

  - which application a run belongs to (provenance.repo, else the owner/name in `target`,
    else `target`),
  - what PROOF each finding carries, and
  - whether a run's coverage was full, partial or failed.

PROOF is the distinction the whole console exists to keep (AGENTS.md rules 1 and 10):

  reproduced     an AGENT found it and it has a PoC. Not trivy/semgrep/nuclei/apisec, and not
                 recon, whose candidates enter the store with status OPEN after reading the
                 code, not exploiting it. The contract also says "or status validated", but
                 `validated` is the DEFAULT status of every Finding including scanner ones, so
                 reading it as proof would promote every Semgrep hit to an exploit. The source
                 is what decides; an agent finding is reproduced unless it is marked `open`.
  deterministic  a hardcoded secret or other credential rule on `service/gate.py`'s floor.
                 It needs no exploit and no model verdict: the gate does not defer to one.
  candidate      a scanner finding or flagged_not_proven lead. Triage CONFIRMED/UNCERTAIN or
                 untriaged. A lead, never a finding.
  not_reachable  triage read the code and judged it unreachable.

A dependency CVE is a CANDIDATE however severe. It goes to triage; reachable and unproven it
is an attention reason, never a stop (docs/ui/api-contract.md, "What blocks").

Nothing is invented: an item with no PoC has `poc: null`, a verdict nobody gave is `null`.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from docket.portfolio import timeutil
from docket.portfolio.catalog import BY_ID, SPECIALISTS, Source, classify_source
from docket.portfolio.model import disk
from docket.portfolio.policy import Policy, load_policies, policy_for, requires_pr
from docket.report.writer import parse_source_file
from docket.service.gate import floor_reason

SEVERITIES = ("critical", "high", "medium", "low", "info")
_VERDICTS = {"confirmed": "exploitable", "exploitable": "exploitable",
             "false_positive": "not_reachable", "not_reachable": "not_reachable",
             "uncertain": "uncertain"}
_SHORT = 140


def verdict_of(raw: object) -> str | None:
    """Either triage vocabulary in, the lower-case core one out. Unknown stays None."""
    return _VERDICTS.get(str(raw or "").strip().lower())


def _sev(raw: object) -> str:
    text = str(raw or "").strip().lower()
    return text if text in SEVERITIES else "info"


def _short(text: object, n: int = _SHORT) -> str:
    one = " ".join(str(text or "").split())
    return one if len(one) <= n else one[: n - 1].rstrip() + "…"


def _key(*parts: object) -> str:
    return hashlib.sha1("|".join(str(p) for p in parts).encode()).hexdigest()[:16]


def _safe_floor(row: dict[str, Any]) -> str | None:
    try:
        return floor_reason(row)
    except (TypeError, ValueError):
        return None


@dataclass(slots=True)
class Item:
    """One finding-shaped thing in one run: a Finding, a flagged lead or a triage row."""

    key: str
    run: str
    sev: str
    title: str
    sub: str
    rule_id: str | None
    cwe: str | None
    location: str | None
    file: str | None
    line: int | None
    proof: str
    reach: str | None
    source: Source
    verdict: str | None
    status: str
    fixed: bool = False
    blocks: bool = False
    is_secret: bool = False
    is_dep_cve: bool = False
    poc: dict[str, Any] | None = None
    triage: dict[str, Any] | None = None
    fix: dict[str, Any] | None = None
    evidence_ref: str | None = None

    @property
    def open(self) -> bool:
        return not self.fixed

    def finding(self, application: str, age_days: int | None) -> dict[str, Any]:
        """The contract's Finding object."""
        return {
            "id": f"{self.run}:{self.key}", "run": self.run, "application": application,
            "sev": self.sev, "title": self.title, "sub": self.sub, "proof": self.proof,
            "reach": self.reach, "by": {"origin": self.source.origin, "name": self.source.name},
            "age_days": age_days, "status": self.status, "rule_id": self.rule_id,
            "cwe": self.cwe, "location": self.location, "poc": self.poc,
            "triage": self.triage, "fix": self.fix, "evidence_ref": self.evidence_ref,
        }


def _reach(verdict: str | None, lead_reachable: object = None) -> str | None:
    if verdict == "exploitable" or lead_reachable is True:
        return "Reachable"
    if verdict == "uncertain":
        return "Uncertain"
    if verdict == "not_reachable":
        return "Not reachable"
    return None


def _status(fixed: bool, patched: bool, verdict: str | None, has_triage: bool) -> str:
    if fixed:
        return "Fixed"
    if patched:
        return "Fix proposed"
    if verdict == "not_reachable":
        return "Triaged: not reachable"
    return "Triaged" if has_triage else "Open"


def _patches(report: dict[str, Any]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for row in report.get("patches") or []:
        if isinstance(row, dict) and row.get("key"):
            out[str(row["key"])] = row
    return out


def _fix_view(row: dict[str, Any] | None) -> dict[str, Any] | None:
    """Only a patch the validator verified counts as a proposed fix (service/delivery.py);
    `diff` is null unless the row carries one, since report.json rows hold paths, not text."""
    if not row or row.get("status") != "verified_fixed":
        return None
    return {"summary": row.get("summary"), "diff": row.get("diff")}


def _from_finding(run: str, f: dict[str, Any], patches: dict[str, dict[str, Any]]) -> Item:
    loc = f.get("location") if isinstance(f.get("location"), dict) else {}
    src = classify_source(f.get("discovered_by"))
    raw_triage = f.get("triage") if isinstance(f.get("triage"), dict) else None
    verdict = verdict_of(raw_triage.get("verdict")) if raw_triage else None
    rule_id = str(f.get("rule_id") or "") or None
    floor = _safe_floor(f)
    secret_floor = bool(floor and floor.startswith("hardcoded"))
    is_secret = (secret_floor or f.get("cwe") == "CWE-798"
                 or "/secret/" in str(rule_id or "").lower())
    is_dep = loc.get("method") == "DEPENDENCY" or (src.engine == "trivy" and not is_secret)
    status = str(f.get("status") or "").lower()
    fixed = status == "fixed"
    if src.kind == "agent":
        proof = "reproduced" if status != "open" else "candidate"
    elif secret_floor:
        proof = "deterministic"
    elif verdict == "not_reachable":
        proof = "not_reachable"
    else:
        proof = "candidate"
    floor_non_cve = bool(floor and not floor.startswith("dependency CVE"))
    blocks = (proof in ("reproduced", "deterministic") or floor_non_cve
              or (verdict == "exploitable" and not is_dep and proof != "not_reachable"))
    key = str(f.get("dedupe_key") or f.get("id") or _key(rule_id, loc.get("path"),
                                                         loc.get("source_file")))
    parsed = parse_source_file(loc.get("source_file"))
    where = loc.get("source_file") or (
        f"{loc.get('method') or ''} {loc.get('path') or ''}".strip() or None)
    cwe = f.get("cwe") or None
    sub = " · ".join(p for p in (cwe, _short(f.get("description"))) if p)
    poc = None
    if proof == "reproduced" and isinstance(f.get("poc"), dict):
        p = f["poc"]
        poc = {"request": p.get("request"), "response": p.get("response"),
               "notes": p.get("notes")}
    triage = None
    if raw_triage:
        triage = {"verdict": verdict, "reasoning": raw_triage.get("reasoning"),
                  "evidence": raw_triage.get("evidence")}
    patch = patches.get(key)
    evidence_ref = (f"docket_runs/{run}/report.json#{key}" if proof == "reproduced"
                    else (raw_triage or {}).get("evidence") or loc.get("source_file"))
    return Item(
        key=key, run=run, sev=_sev(f.get("severity")), title=str(f.get("title") or rule_id or "Finding"),
        sub=sub, rule_id=rule_id, cwe=cwe, location=where,
        file=parsed[0] if parsed else None, line=parsed[1] if parsed else None,
        proof=proof, reach=_reach(verdict), source=src, verdict=verdict,
        status=_status(fixed, bool(_fix_view(patch)), verdict, raw_triage is not None),
        fixed=fixed, blocks=blocks, is_secret=is_secret, is_dep_cve=is_dep, poc=poc,
        triage=triage, fix=_fix_view(patch), evidence_ref=evidence_ref)


def _from_lead(run: str, lead: dict[str, Any], verdict_row: dict[str, Any] | None = None) -> Item:
    """A flagged_not_proven entry (or a triage row with no finding behind it)."""
    rule_id = str(lead.get("rule_id") or "") or None
    engine = str(lead.get("engine") or "semgrep")
    src = classify_source(engine)
    file, line = lead.get("file"), lead.get("line")
    raw_triage = verdict_row if verdict_row is not None else (
        lead.get("triage") if isinstance(lead.get("triage"), dict) else None)
    verdict = verdict_of((raw_triage or {}).get("verdict"))
    floor = _safe_floor({"rule_id": rule_id, "discovered_by": engine, "cvss": lead.get("cvss")})
    secret_floor = bool(floor and floor.startswith("hardcoded"))
    if secret_floor:
        proof = "deterministic"
    elif verdict == "not_reachable":
        proof = "not_reachable"
    else:
        proof = "candidate"
    floor_non_cve = bool(floor and not floor.startswith("dependency CVE"))
    blocks = (proof == "deterministic" or floor_non_cve or verdict == "exploitable")
    message = str(lead.get("message") or "").strip().rstrip(".")
    leaf = str(rule_id or "").rsplit(".", 1)[-1].replace("-", " ").replace("_", " ")
    what = _short(message, 90) if message else (leaf.capitalize() or "Finding")
    title = f"{what} in {file}:{line}" if file and line else (
        f"{what} in {file}" if file else what)
    bare_rule = str(rule_id or "").split("/", 1)[-1]
    sub = " · ".join(p for p in (lead.get("cwe"), f"{engine} {bare_rule}".strip()) if p)
    triage = None
    if raw_triage:
        triage = {"verdict": verdict, "reasoning": raw_triage.get("reasoning"),
                  "evidence": raw_triage.get("evidence")}
    key = _key(rule_id, file, line)
    return Item(
        key=key, run=run, sev=_sev(lead.get("severity")), title=title, sub=sub,
        rule_id=rule_id, cwe=lead.get("cwe") or None,
        location=f"{file}:{line}" if file and line else file,
        file=file if isinstance(file, str) else None, line=line if isinstance(line, int) else None,
        proof=proof, reach=_reach(verdict, lead.get("reachable")), source=src, verdict=verdict,
        status=_status(False, False, verdict, raw_triage is not None), blocks=blocks,
        is_secret=secret_floor or lead.get("cwe") == "CWE-798",
        is_dep_cve=False, triage=triage,
        evidence_ref=(raw_triage or {}).get("evidence") or (f"{file}:{line}" if file and line else None))


def build_items(run: str, report: dict[str, Any]) -> list[Item]:
    """Every finding-shaped thing in a report, de-duplicated by (file, line, rule)."""
    patches = _patches(report)
    items: list[Item] = []
    seen: set[tuple[Any, Any, Any]] = set()
    for f in report.get("findings") or []:
        if isinstance(f, dict):
            item = _from_finding(run, f, patches)
            items.append(item)
            seen.add((item.file, item.line, item.rule_id))
    rows = {(r.get("file"), r.get("line"), r.get("rule_id")): r
            for r in report.get("triaged") or [] if isinstance(r, dict)}
    for lead in report.get("flagged_not_proven") or []:
        if isinstance(lead, dict):
            # A lead that triage judged carries the verdict (the writer normally moves it
            # out of flagged_not_proven; if both exist, the judged one wins).
            sig = (lead.get("file"), lead.get("line"), lead.get("rule_id"))
            item = _from_lead(run, lead, verdict_row=rows.get(sig))
            if (item.file, item.line, item.rule_id) not in seen:
                items.append(item)
                seen.add((item.file, item.line, item.rule_id))
    # Triage rows for leads that left flagged_not_proven (writer supersedes them). Rows that
    # merely restate a findings[].triage verdict match an existing item and are skipped.
    for sig, row in rows.items():
        if sig in seen:
            continue
        items.append(_from_lead(run, row, verdict_row=row))
        seen.add(sig)
    return items


@dataclass(slots=True)
class RunView:
    """One report.json, read once and described."""

    name: str
    directory: Path
    report: dict[str, Any]
    at: float
    started: float | None
    ended: float | None
    kind: str
    label: str | None
    repo: str
    items: list[Item]
    stages: dict[str, str]
    timings: dict[str, dict[str, float]]
    ran: frozenset[str]
    errored: bool
    finished: bool
    sample: bool = False

    @property
    def open_items(self) -> list[Item]:
        return [i for i in self.items if i.open]


def app_key(report: dict[str, Any], name: str) -> str:
    prov = report.get("provenance") if isinstance(report.get("provenance"), dict) else {}
    if prov.get("repo"):
        return str(prov["repo"])
    target = str(report.get("target") or "").strip()
    if target.startswith("github:"):
        target = target[len("github:"):]
    target = target.partition("@")[0]
    return target if target and target != "(static-only)" else name


def _num(value: object) -> float | None:
    return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else None


def _ran(report: dict[str, Any], stages: dict[str, str],
         timings: dict[str, dict[str, float]]) -> frozenset[str]:
    """Catalog ids with EVIDENCE of having run to completion. Absence of a stage record is
    not evidence: an old report with no `stages` yields an empty set, so coverage reads
    partial rather than claiming scanners ran that nothing says ran."""
    ran: set[str] = set()
    for sid, scanner in BY_ID.items():
        if scanner.stage is None:
            continue
        state = stages.get(scanner.stage)
        stamp = timings.get(scanner.stage) or {}
        if state == "done" or (state is None and "ended" in stamp):
            ran.add(sid)
    agents = [a for a in (report.get("agents") or []) if isinstance(a, dict)]
    usage = (report.get("usage") or {}).get("agents") if isinstance(report.get("usage"), dict) else []
    roles = {str(a.get("role")) for a in agents} | {
        str(a.get("role")) for a in usage or [] if isinstance(a, dict)}
    if (_num(report.get("agents_spawned")) or 0) > 0 or roles & ({"root"} | set(SPECIALISTS)):
        ran.add("swarm")
    return frozenset(ran)


def load_run(name: str, directory: Path) -> RunView | None:
    report = disk.read_report(directory)
    if report is None:
        return None
    timing = report.get("run_timing") if isinstance(report.get("run_timing"), dict) else {}
    started, ended = _num(timing.get("started")), _num(timing.get("ended"))
    at = ended or started or timeutil.parse_iso(report.get("generated_at"))
    if at is None:
        try:
            at = (directory / "report.json").stat().st_mtime
        except OSError:
            at = 0.0
    raw_stages = report.get("stages") if isinstance(report.get("stages"), dict) else {}
    stages = {str(k): str(v) for k, v in raw_stages.items()}
    timings: dict[str, dict[str, float]] = {}
    for k, v in (report.get("stage_timings") or {}).items() if isinstance(
            report.get("stage_timings"), dict) else []:
        if isinstance(v, dict) and _num(v.get("started")) is not None:
            timings[str(k)] = {"started": float(v["started"])}
            if _num(v.get("ended")) is not None:
                timings[str(k)]["ended"] = float(v["ended"])
    prov = report.get("provenance") if isinstance(report.get("provenance"), dict) else {}
    pr = prov.get("pr")
    kind = "pr" if pr or name.startswith("pr-") else "scan"
    return RunView(
        name=name, directory=directory, report=report, at=at, started=started, ended=ended,
        kind=kind, label=f"PR #{pr}" if pr else None, repo=app_key(report, name),
        items=build_items(name, report), stages=stages, timings=timings,
        ran=_ran(report, stages, timings),
        errored=any(v == "error" for v in stages.values()),
        finished=str(report.get("status") or "completed") == "completed",
        sample=bool(report.get("sample")))


def coverage(run: RunView, policy: Policy) -> str:
    """full | partial | failed, against the policy's REQUIRED steps.

    failed  a stage errored, or the run did not finish (the gate's action_required)
    partial a required step that applies to this kind of scan did not run
    full    otherwise
    """
    if run.errored or not run.finished:
        return "failed"
    missing = [s for s in policy.required_ids() if requires_pr(s, run.kind) and s not in run.ran]
    return "partial" if missing else "full"


@dataclass(slots=True)
class AppState:
    id: str
    label: str
    repo: str
    tier: str | None
    owner: str | None
    lang: str | None
    policy: Policy
    runs: list[RunView] = field(default_factory=list)      # ascending by time, scans and PRs

    @property
    def scans(self) -> list[RunView]:
        """Whole-repository scans only: a pull-request check is scoped, so its counts are
        not comparable with a scan's and it is kept out of state and trends."""
        return [r for r in self.runs if r.kind == "scan"]

    @property
    def latest(self) -> RunView | None:
        scans = self.scans
        if scans:
            return scans[-1]
        return self.runs[-1] if self.runs else None

    def first_seen(self) -> dict[str, float]:
        seen: dict[str, float] = {}
        for run in self.scans or self.runs:
            for item in run.items:
                seen.setdefault(item.key, run.at)
        return seen

    def last_ran(self, step_id: str) -> float | None:
        """When this step last ran in a scan of the matching kind (None: never)."""
        for run in reversed(self.runs):
            if step_id in run.ran and requires_pr(step_id, run.kind):
                return run.at
        return None


@dataclass(slots=True)
class Model:
    apps: list[AppState]
    policies: list[Policy]
    warnings: list[str]
    organization: str | None
    cadence_days: int
    sample: bool
    now: float

    def app(self, app_id: str) -> AppState | None:
        return next((a for a in self.apps if a.id == app_id), None)

    def run(self, name: str) -> tuple[AppState, RunView] | None:
        for a in self.apps:
            for r in a.runs:
                if r.name == name:
                    return a, r
        return None


def build_model(cwd: Path | None = None, now: float | None = None) -> Model:
    import time as _time

    now = float(now if now is not None else _time.time())
    cfg = disk.read_portfolio(cwd)
    policies, warnings, _from_file = load_policies(cwd)
    cadence = cfg.get("cadence_days")
    cadence = cadence if isinstance(cadence, int) and not isinstance(cadence, bool) and 0 < cadence < 366 else 7

    apps: dict[str, AppState] = {}
    for entry in cfg.get("applications") or []:
        if not isinstance(entry, dict) or not isinstance(entry.get("repo"), str) or not entry["repo"].strip():
            continue
        repo = entry["repo"].strip()
        row = {k: (str(entry[k]) if entry.get(k) is not None else None)
               for k in ("label", "tier", "owner", "lang", "policy")}
        apps[repo.lower()] = AppState(
            id=repo, label=row["label"] or repo.rsplit("/", 1)[-1], repo=repo, tier=row["tier"],
            owner=row["owner"], lang=row["lang"], policy=policy_for(row, policies))
    sample = bool(cfg.get("sample"))
    for name, directory in disk.list_runs(cwd):
        run = load_run(name, directory)
        if run is None:
            continue
        sample = sample or run.sample
        state = apps.get(run.repo.lower())
        if state is None:
            state = AppState(id=run.repo, label=run.repo.rsplit("/", 1)[-1], repo=run.repo,
                             tier=None, owner=None, lang=None,
                             policy=policy_for({}, policies))
            apps[run.repo.lower()] = state
        state.runs.append(run)
    for state in apps.values():
        state.runs.sort(key=lambda r: (r.at, r.name))
    org = cfg.get("organization")
    return Model(apps=list(apps.values()), policies=policies, warnings=warnings,
                 organization=str(org) if org else None, cadence_days=cadence,
                 sample=sample, now=now)


def demo() -> None:
    import json
    import tempfile

    # --- app_key: provenance, then target, then the target text itself -------------------
    assert app_key({"provenance": {"repo": "o/r"}, "target": "github:x/y@main"}, "n") == "o/r"
    assert app_key({"target": "github:x/y@main"}, "n") == "x/y"
    assert app_key({"target": "http://t.example"}, "n") == "http://t.example"
    assert app_key({"target": "(static-only)"}, "scan-1") == "scan-1"

    def finding(**kw: Any) -> dict[str, Any]:
        base = {"rule_id": "x", "title": "T", "severity": "high", "description": "d. more",
                "location": {"method": "POST", "path": "/p"}, "discovered_by": "semgrep",
                "status": "validated", "poc": {"request": "r", "response": "s"},
                "dedupe_key": "k" + str(len(kw)), "corroborating_evidence": []}
        base.update(kw)
        return base

    secret = finding(rule_id="trivy/secret/generic-api-key", cwe="CWE-798", discovered_by="trivy",
                     location={"method": "STATIC", "path": "c.py", "source_file": "c.py:14"},
                     dedupe_key="sec")
    maybe = finding(rule_id="trivy/secret/cloud-key", cwe="CWE-798", discovered_by="trivy",
                    location={"method": "STATIC", "path": "d.yml", "source_file": "d.yml:22"},
                    triage={"verdict": "uncertain", "reasoning": "r", "evidence": "d.yml:22"},
                    dedupe_key="maybe")
    cve = finding(rule_id="trivy/CVE-2021-44228", discovered_by="trivy", severity="critical",
                  location={"method": "DEPENDENCY", "path": "pom.xml", "source_file": "pom.xml"},
                  cvss={"score": 10.0, "source": "nvd"},
                  triage={"verdict": "exploitable", "reasoning": "r", "evidence": "A.java:3"},
                  dedupe_key="cve")
    agent = finding(rule_id="sql-injection", discovered_by="sqli-agent", dedupe_key="sqli")
    recon = finding(rule_id="recon/candidate", discovered_by="recon", status="open", dedupe_key="rc")
    fp = finding(rule_id="semgrep/debug", discovered_by="semgrep", dedupe_key="fp",
                 triage={"verdict": "not_reachable", "reasoning": "r", "evidence": "e"})
    items = {i.key: i for i in build_items("r1", {"findings": [
        secret, maybe, cve, agent, recon, fp,
        finding(status="fixed", discovered_by="sqli-agent", dedupe_key="gone")]})}
    assert items["sec"].proof == "deterministic" and items["sec"].blocks
    # A possible secret that is not a floor rule stays a candidate: this is what lets
    # "triage could not decide" be an attention reason rather than a stop.
    assert items["maybe"].proof == "candidate" and items["maybe"].is_secret and not items["maybe"].blocks
    # A reachable critical CVE is a candidate that does NOT block, however severe.
    assert items["cve"].proof == "candidate" and items["cve"].reach == "Reachable"
    assert items["cve"].is_dep_cve and not items["cve"].blocks
    assert items["sqli"].proof == "reproduced" and items["sqli"].poc["request"] == "r"
    # `validated` is every scanner finding's default status and proves nothing.
    assert items["fp"].proof == "not_reachable" and items["fp"].poc is None
    assert items["rc"].proof == "candidate", "recon reads code; it does not exploit"
    assert items["gone"].fixed and items["gone"].status == "Fixed"

    # --- leads and triage rows, de-duplicated ----------------------------------------------
    rep = {"flagged_not_proven": [{"rule_id": "py.sqli.formatted-sql-query", "engine": "semgrep",
                                   "severity": "medium", "cwe": "CWE-89", "file": "a.py",
                                   "line": 64, "message": "Formatted SQL query.", "reachable": True}],
           "triaged": [{"rule_id": "py.sqli.formatted-sql-query", "file": "a.py", "line": 64,
                        "verdict": "CONFIRMED", "reasoning": "r", "evidence": "a.py:64"},
                       {"rule_id": "py.xss", "file": "b.py", "line": 2, "engine": "semgrep",
                        "severity": "low", "verdict": "FALSE_POSITIVE", "reasoning": "r",
                        "evidence": "b.py:2"}]}
    lead_items = build_items("r2", rep)
    assert len(lead_items) == 2, [i.title for i in lead_items]
    assert lead_items[0].title == "Formatted SQL query in a.py:64" and lead_items[0].reach == "Reachable"
    assert lead_items[0].blocks, "a floor rule blocks"
    assert lead_items[1].proof == "not_reachable"

    # --- a whole model from disk -------------------------------------------------------------
    with tempfile.TemporaryDirectory() as tmp:
        cwd = Path(tmp)
        (cwd / "docket_portfolio.json").write_text(json.dumps({
            "organization": "Acme", "applications": [
                {"repo": "o/a", "label": "A", "tier": "Tier 1"}, {"repo": "o/never"}]}))
        for n, at, extra in (("s1", 1000.0, {}), ("s2", 2000.0, {"provenance": {"repo": "o/a", "pr": 7}})):
            d = cwd / "docket_runs" / n
            d.mkdir(parents=True)
            (d / "report.json").write_text(json.dumps({
                "target": "github:o/a@main", "run_timing": {"started": at - 5, "ended": at},
                "stages": {"trivy": "done", "semgrep": "done"}, "findings": [], **extra}))
        d = cwd / "docket_runs" / "orphan"
        d.mkdir()
        (d / "report.json").write_text(json.dumps({"target": "github:z/z@x", "sample": True}))
        model = build_model(cwd, now=3000.0)
        assert model.organization == "Acme" and model.sample
        a = model.app("o/a")
        assert [r.name for r in a.runs] == ["s1", "s2"] and a.runs[1].kind == "pr"
        assert a.runs[1].label == "PR #7" and a.latest.name == "s1"   # PRs never become "latest"
        assert coverage(a.runs[0], a.policy) == "full"
        assert model.app("o/never").runs == [] and model.app("z/z") is not None
        assert model.run("s2")[0].id == "o/a" and model.run("nope") is None
        assert coverage(load_run("orphan", d), a.policy) == "partial"   # no stage evidence
    print("portfolio.model.derive: ok")


if __name__ == "__main__":
    demo()
