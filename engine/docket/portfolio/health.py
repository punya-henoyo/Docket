"""Health: the one place an application becomes `action`, `attention`, `clear` or `unknown`.

`classify()` is a PURE function of a `Metrics` record, so the rule is readable in one screen
and unit-tested below; everything else in this module just measures an application into
that record or lays the measurements out for the console.

  unknown    no report
  action     a proven (reproduced) exploit is open, OR a deterministic-floor secret is in
             source, OR the gate would block the latest scan: the same three things
             `service/gate.py` stops a pull request for (floor rule, triage CONFIRMED,
             reproduced exploit). A critical dependency CVE is NOT among them.
  attention  not action, and any of: a required scanner never ran, is stale (older than its
             window) or missed the latest scan; a reachable critical CVE; triage UNCERTAIN on
             a high or critical finding; partial or failed coverage; no scan inside the
             cadence
  clear      otherwise

`reason` is ONE plain sentence naming the worst cause. It never contains a percentage and
never the word "compliant" (AGENTS.md rule 14): a number that rewards giving up on the hard
controls is exactly what this product refuses to show.

Compliance feeds one annunciator, flagged `advisory` and never red, because compliance never
gates (rule 15). An annunciator's `state` is its analyte's `flag`: one fact, one colour.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any

from docket.portfolio import timeutil
from docket.portfolio.catalog import BY_ID
from docket.portfolio.model.derive import AppState, Item, RunView, coverage

DEFAULT_THRESHOLDS = {"reach": 3, "age": 7, "triage": 2}
_TREND_SCANS = 8
_ACTIVE_EXCLUDED = "not_reachable"


@dataclass(slots=True)
class Metrics:
    has_scan: bool = False
    proven: int = 0
    deterministic: int = 0
    blockers: int = 0               # open items the gate would block on (superset of the two above)
    secrets: int = 0
    critical_cves: int = 0
    reachable: int = 0              # candidates triage traced to an endpoint
    reachable_critical_cve: int = 0
    uncertain: int = 0
    uncertain_high: int = 0         # uncertain AND high or critical
    oldest_critical_days: int | None = None
    req_ran: int = 0
    req_total: int = 0
    coverage: str = "full"
    scan_age_days: int | None = None
    cadence_days: int = 7
    never: list[str] = field(default_factory=list)     # required scanner names that never ran
    stale: list[tuple[str, int, int]] = field(default_factory=list)   # (name, days, window)
    missed: list[str] = field(default_factory=list)    # ran before, missed the latest scan
    cve_title: str | None = None         # the first reachable critical CVE, for the sentence
    uncertain_title: str | None = None   # the first high/critical triage could not decide
    skipped_always: set[str] = field(default_factory=set)


@dataclass(slots=True)
class Cause:
    level: str          # "action" | "attention"
    kind: str
    text: str


def classify(m: Metrics) -> tuple[str, list[Cause]]:
    """(level, causes in priority order). The single rule; see the module docstring."""
    if not m.has_scan:
        return "unknown", []
    causes: list[Cause] = []
    if m.proven:
        causes.append(Cause("action", "proven",
                            f"{m.proven} exploit{'s' if m.proven != 1 else ''} reproduced and still open"))
    if m.deterministic:
        causes.append(Cause("action", "secret", f"{m.deterministic} secret{'s' if m.deterministic != 1 else ''} "
                            "committed to source"))
    other = m.blockers - m.proven - m.deterministic
    if other > 0:
        causes.append(Cause("action", "gate", f"The gate would block {other} more finding{'s' if other != 1 else ''}"))
    for name in m.never:
        tail = "was skipped on every scan" if name in m.skipped_always else "has never run"
        causes.append(Cause("attention", "never", f"{name} {tail}; the policy requires it"))
    for name in m.missed:
        causes.append(Cause("attention", "missed", f"{name} did not run in the latest scan"))
    if m.reachable_critical_cve:
        causes.append(Cause("attention", "cve",
                            f"Reachable critical CVE: {m.cve_title}" if m.cve_title
                            else "A critical dependency CVE is reachable from the application"))
    if m.uncertain_high:
        causes.append(Cause("attention", "uncertain",
                            f"Triage could not decide: {m.uncertain_title}" if m.uncertain_high == 1
                            and m.uncertain_title else
                            f"Triage could not decide {m.uncertain_high} high or critical findings"))
    overdue = m.scan_age_days is not None and m.scan_age_days > m.cadence_days
    # Every required scanner stale AND the scan overdue is ONE fact, not six: say it once.
    collapse = overdue and m.req_total > 1 and len(m.stale) == m.req_total
    if not collapse:
        for name, days, window in m.stale:
            causes.append(Cause("attention", "stale",
                                f"{name} has not run for {days} days; the policy requires it every {window}"))
    if overdue:
        causes.append(Cause("attention", "overdue",
                            f"No scan for {m.scan_age_days} days; the policy asks for one every {m.cadence_days}"))
    if m.coverage == "failed":
        causes.append(Cause("attention", "failed", "The latest scan did not finish or a stage errored"))
    elif m.coverage == "partial" and not (m.never or m.stale or m.missed):
        causes.append(Cause("attention", "partial", "The latest scan covered only part of the policy"))
    if any(c.level == "action" for c in causes):
        return "action", causes
    return ("attention" if causes else "clear"), causes


def _active(items: list[Item]) -> list[Item]:
    """Open items that still count: triage-cleared (not_reachable) ones do not, but a
    deterministic floor hit does, because the gate does not defer to a verdict."""
    return [i for i in items if i.open and (i.proof != _ACTIVE_EXCLUDED)]


def _name(step_id: str) -> str:
    s = BY_ID[step_id]
    return s.tool or s.label


def measure(app: AppState, run: RunView, first_seen: dict[str, float], at: float,
            now: float | None = None, *, history: bool = False) -> Metrics:
    """Measure one scan. `at` is the instant ages are taken against (the scan's own time
    for a trend point, now for the current state); `history` skips the staleness walk,
    which only means something for the current state."""
    pol = app.policy
    items = _active(run.items)
    m = Metrics(has_scan=True, cadence_days=pol.cadence_days)
    m.proven = sum(i.proof == "reproduced" for i in items)
    m.deterministic = sum(i.proof == "deterministic" for i in items)
    m.blockers = sum(i.blocks for i in items)
    m.secrets = sum(i.is_secret for i in items)
    m.critical_cves = sum(i.is_dep_cve and i.sev == "critical" for i in items)
    m.reachable = sum(i.proof == "candidate" and i.reach == "Reachable" for i in items)
    m.reachable_critical_cve = sum(i.is_dep_cve and i.sev == "critical" and i.reach == "Reachable"
                                   for i in items)
    m.uncertain = sum(i.verdict == "uncertain" for i in items)
    m.uncertain_high = sum(i.verdict == "uncertain" and i.sev in ("critical", "high") for i in items)
    m.cve_title = next((i.title for i in items if i.is_dep_cve and i.sev == "critical"
                        and i.reach == "Reachable"), None)
    m.uncertain_title = next((i.title for i in items if i.verdict == "uncertain"
                              and i.sev in ("critical", "high")), None)
    ages = [timeutil.whole_days(at - first_seen.get(i.key, run.at))
            for i in items if i.sev == "critical"]
    m.oldest_critical_days = max(ages) if ages else None
    required = [s for s in pol.required_ids() if "scan" in BY_ID[s].kinds]
    m.req_total = len(required)
    m.req_ran = sum(s in run.ran for s in required)
    m.coverage = coverage(run, pol)
    if not history and now is not None:
        m.scan_age_days = timeutil.whole_days(now - run.at)
        for step in required:
            last = app.last_ran(step)
            name = _name(step)
            window = pol.window_days(step)
            if last is None:
                m.never.append(name)
                scans = app.scans or app.runs
                stage = BY_ID[step].stage
                if stage and scans and all(r.stages.get(stage) == "skipped" for r in scans):
                    m.skipped_always.add(name)
            elif now - last > window * timeutil.DAY:
                m.stale.append((name, timeutil.whole_days(now - last), window))
            elif step not in run.ran:
                m.missed.append(name)
    return m


# --- laying the measurements out for the console ---------------------------------------


def _scale(base: int, value: float) -> int:
    return max(base, int(math.ceil(value * 1.5)))


def _flag_word(flag: str, higher_is_better: bool = False) -> str:
    return {"ok": "In range", "bad": "Out of range", "unknown": "No data",
            "warn": "Low" if higher_is_better else "High"}[flag]


def _analyte(key: str, label: str, hint: str, value: int | None, display: str, scale: int,
             bands: list[dict[str, Any]], ref: str, flag: str, trend: list[Any] | None,
             previous: str | None, higher_is_better: bool = False) -> dict[str, Any]:
    out: dict[str, Any] = {"key": key, "label": label, "hint": hint, "value": value,
                           "display": display, "scaleMax": scale, "bands": bands, "ref": ref,
                           "flag": flag, "flagWord": _flag_word(flag, higher_is_better)}
    if trend is not None:
        out["trend"] = trend
        out["previous"] = previous
    if higher_is_better:
        out["higherIsBetter"] = True
    return out


def _zero_ref(key: str, label: str, hint: str, value: int, trend: list[int] | None,
              base: int) -> dict[str, Any]:
    scale = _scale(base, value)
    return _analyte(key, label, hint, value, str(value), scale,
                    [{"from": 0, "to": 0.4, "tone": "ok"}, {"from": 0.4, "to": scale, "tone": "bad"}],
                    "0", "ok" if value == 0 else "bad",
                    trend, str(trend[-2]) if trend and len(trend) > 1 else None)


def _show(key: str, v: int | None, m: Metrics) -> str:
    if key == "age":
        return "None" if not v else f"{v} d"
    if key == "cov":
        return f"{v} of {m.req_total}"
    return str(v or 0)


def analytes(app: AppState, current: Metrics, history: list[Metrics]) -> list[dict[str, Any]]:
    """The fixed analyte set, each with a policy-derived reference and an 8-scan trend
    (omitted below two scans)."""
    th = {**DEFAULT_THRESHOLDS, **app.policy.thresholds}
    pts = history[-_TREND_SCANS:]
    have_trend = len(pts) >= 2

    def trend(attr: str) -> list[int] | None:
        return [int(getattr(p, attr) or 0) for p in pts] if have_trend else None

    out: list[dict[str, Any]] = []
    out.append(_zero_ref("proven", "Proven exploitable", "Reproduced with a working request",
                         current.proven, trend("proven"), 6))
    t = th["reach"]
    scale = _scale(4 * t, current.reachable)
    tr = trend("reachable")
    out.append(_analyte(
        "reach", "Reachable, not yet proven", "Scanner hits that triage could trace to an endpoint",
        current.reachable, str(current.reachable), scale,
        [{"from": 0, "to": t, "tone": "ok"}, {"from": t, "to": scale, "tone": "warn"}],
        f"{t} or fewer", "ok" if current.reachable <= t else "warn", tr,
        str(tr[-2]) if tr and len(tr) > 1 else None))
    out.append(_zero_ref("secrets", "Secrets in source", "Credentials committed to the repository",
                         current.secrets, trend("secrets"), 4))
    out.append(_zero_ref("cves", "Critical dependency CVEs",
                         "CVSS 9.0 or higher, in a shipped package", current.critical_cves,
                         trend("critical_cves"), 6))
    # Age
    t = th["age"]
    age = current.oldest_critical_days
    val = age or 0
    scale = _scale(30, val)
    flag = "ok" if val <= t else ("warn" if val <= 2 * t else "bad")
    ages = [p.oldest_critical_days or 0 for p in pts] if have_trend else None
    out.append(_analyte(
        "age", "Oldest open critical", "Days since it was first seen", val, _show("age", age, current),
        scale, [{"from": 0, "to": t, "tone": "ok"}, {"from": t, "to": 2 * t, "tone": "warn"},
                {"from": 2 * t, "to": scale, "tone": "bad"}],
        f"{t} days or fewer", flag, ages,
        _show("age", ages[-2], current) if ages and len(ages) > 1 else None))
    # Required scanners that ran
    total = current.req_total
    if total:
        flag = ("ok" if current.req_ran >= total else "warn" if current.req_ran == total - 1 else "bad")
        bands = [{"from": 0, "to": max(total - 1, 0), "tone": "bad"},
                 {"from": max(total - 1, 0), "to": total - 0.1, "tone": "warn"},
                 {"from": total - 0.1, "to": total, "tone": "ok"}]
        tr = trend("req_ran")
        out.append(_analyte(
            "cov", "Required scanners that ran", f"Against the {app.policy.name} policy",
            current.req_ran, f"{current.req_ran} of {total}", total, bands, f"{total} of {total}", flag, tr,
            f"{tr[-2]} of {total}" if tr and len(tr) > 1 else None, higher_is_better=True))
    else:
        out.append(_analyte("cov", "Required scanners that ran", f"Against the {app.policy.name} policy",
                            None, "none required", 1, [], "none required", "unknown", None, None,
                            higher_is_better=True))
    t = th["triage"]
    scale = _scale(3 * t, current.uncertain)
    flag = "ok" if current.uncertain <= t else ("warn" if current.uncertain <= 2 * t else "bad")
    tr = trend("uncertain")
    out.append(_analyte(
        "triage", "Triage uncertain", "Findings triage left for a person to judge",
        current.uncertain, str(current.uncertain), scale,
        [{"from": 0, "to": t, "tone": "ok"}, {"from": t, "to": 2 * t, "tone": "warn"},
         {"from": 2 * t, "to": scale, "tone": "bad"}],
        f"{t} or fewer", flag, tr, str(tr[-2]) if tr and len(tr) > 1 else None))
    return out


def _compliance_rows(run: RunView) -> list[dict[str, Any]]:
    rows = []
    for pack in run.report.get("compliance") or []:
        if not isinstance(pack, dict):
            continue
        counts = {"pass": 0, "fail": 0, "unknown": 0, "not_observable": 0, "not_applicable": 0}
        for res in pack.get("results") or []:
            if isinstance(res, dict) and res.get("status") in counts:
                counts[res["status"]] += 1
        rows.append({"pack_id": pack.get("pack_id"), "title": pack.get("pack_title"),
                     "met": counts["pass"], "not_met": counts["fail"],
                     "unknown": counts["unknown"], "not_observable": counts["not_observable"],
                     "not_applicable": counts["not_applicable"],
                     "requested": pack.get("requested") or 0})
    return rows


def annunciators(app: AppState, run: RunView, current: Metrics, ans: list[dict[str, Any]],
                 now: float) -> list[dict[str, Any]]:
    by_key = {a["key"]: a for a in ans}

    def state(key: str) -> str:
        flag = by_key[key]["flag"]
        return "off" if flag == "unknown" else flag

    items = _active(run.items)
    secret_item = next((i for i in items if i.is_secret), None)
    out: list[dict[str, Any]] = []
    out.append({"key": "proven", "label": "Proven exploits", "state": state("proven"),
                "value": str(current.proven),
                "hint": "reproduced, still open" if current.proven else "none reproduced", "advisory": False})
    out.append({"key": "secrets", "label": "Secrets in code", "state": state("secrets"),
                "value": str(current.secrets),
                "hint": (secret_item.file or secret_item.location or "in source") if secret_item
                else "none found", "advisory": False})
    reach_cve = current.reachable_critical_cve
    out.append({"key": "deps", "label": "Critical CVEs", "state": state("cves"),
                "value": str(current.critical_cves),
                "hint": (f"{reach_cve} reachable" if reach_cve
                         else "none reachable yet" if current.critical_cves else "none found"),
                "advisory": False})
    missing = [n for n in current.never + [n for n, _, _ in current.stale] + current.missed]
    out.append({"key": "coverage", "label": "Required scanners", "state": state("cov"),
                "value": by_key["cov"]["display"] if current.req_total else "none",
                "hint": (f"{', '.join(missing)} did not run" if missing
                         else "all ran" if current.req_total else "the policy requires none"),
                "advisory": False})
    days = timeutil.whole_days(now - run.at)
    cad = app.policy.cadence_days
    fresh = "ok" if days <= cad else ("warn" if days <= 2 * cad else "bad")
    out.append({"key": "fresh", "label": "Last scan", "state": fresh, "value": f"{days} d",
                "hint": (f"inside the {cad}-day window" if days <= cad
                         else f"outside the {cad}-day window"), "advisory": False})
    rows = _compliance_rows(run)
    if rows:
        worst = max(rows, key=lambda r: r["not_met"])
        pid = str(worst["pack_id"] or "").upper().replace("-", " ")
        out.append({"key": "comp", "label": f"{pid} (advisory)", "state": "off",
                    "value": f"{worst['not_met']} not met",
                    "hint": f"of {worst['requested']} readable from code", "advisory": True})
    else:
        out.append({"key": "comp", "label": "Compliance (advisory)", "state": "off",
                    "value": "Not run", "hint": "no control pack was requested", "advisory": True})
    fixes = fix_rows(app)
    open_prs = [f for f in fixes if f.get("url") and f.get("pr_state") != "merged"]
    if open_prs:
        num = open_prs[0].get("pr_number")
        hint = (f"PR #{num} awaiting review" if len(open_prs) == 1 and num
                else f"{len(open_prs)} awaiting review")
        out.append({"key": "fix", "label": "Fix pull requests", "state": "ok",
                    "value": f"{len(open_prs)} open", "hint": hint, "advisory": False})
    elif fixes:
        out.append({"key": "fix", "label": "Fix pull requests", "state": "ok",
                    "value": f"{len(fixes)} proposed", "hint": "no pull request opened yet",
                    "advisory": False})
    else:
        out.append({"key": "fix", "label": "Fix pull requests", "state": "off",
                    "value": "None", "hint": "no fix proposed", "advisory": False})
    return out


def fix_rows(app: AppState) -> list[dict[str, Any]]:
    """Verified patches from the latest scan, newest first. A PR url/number/state is shown
    only if the patch row carries one; docket_runs does not record it today, so for a real
    run `url` is null rather than a guess."""
    run = app.latest
    if run is None:
        return []
    out = []
    for row in run.report.get("patches") or []:
        if not isinstance(row, dict) or row.get("status") != "verified_fixed":
            continue
        out.append({"title": row.get("title") or row.get("summary") or "Proposed fix",
                    "fixes": row.get("rule_id") or row.get("key"), "status": row.get("status"),
                    "url": row.get("pr_url"), "opened_at": timeutil.iso(run.at),
                    "pr_number": row.get("pr_number"), "pr_state": row.get("pr_state")})
    return out


@dataclass(slots=True)
class Health:
    level: str
    reason: str
    reasons: list[str]
    verdict: str
    banner: list[dict[str, Any]]
    annunciators: list[dict[str, Any]]
    analytes: list[dict[str, Any]]
    metrics: Metrics


def _sentence(text: str) -> str:
    return text if text.endswith(".") else text + "."


def evaluate(app: AppState, now: float) -> Health:
    run = app.latest
    if run is None:
        return Health("unknown", "Never scanned", ["Never scanned."], "No scan has run for this application yet.",
                      [{"id": "b1", "level": "info", "word": "Never scanned",
                        "message": "No scan has run for this application yet.",
                        "reason": "There is no report to read.", "actionLabel": None, "href": None}],
                      [], [], Metrics())
    seen = app.first_seen()
    cur = measure(app, run, seen, now, now)
    hist = [measure(app, r, seen, r.at, history=True) for r in app.scans[-_TREND_SCANS:]]
    if hist and app.scans[-1] is run:
        hist[-1] = cur      # the last point of a trend IS the current value, not a lookalike
    level, causes = classify(cur)

    # Reasons: the per-item facts first (what a person acts on), then the process causes.
    items = _active(run.items)
    reasons: list[str] = []
    for i in [i for i in items if i.proof == "reproduced"][:3]:
        reasons.append(_sentence(f"{i.title} was reproduced; the proof is attached"))
    for i in [i for i in items if i.proof == "deterministic"][:2]:
        reasons.append(_sentence(f"{i.title}; a deterministic rule, no exploit needed"))
    for i in [i for i in items if i.blocks and i.proof not in ("reproduced", "deterministic")][:2]:
        reasons.append(_sentence(f"{i.title} would block a pull request"))
    for c in causes:
        if c.kind not in ("proven", "secret", "gate"):
            reasons.append(_sentence(c.text))
    if level == "clear":
        reasons = ["Nothing open that was proven, and every required scanner ran inside its window."]

    if level == "unknown":
        reason = "Never scanned"
    elif level == "clear":
        reason = "Nothing open that was proven"
    else:
        reason = causes[0].text
        # A single proven item reads better by name than as a count.
        if causes[0].kind == "proven" and cur.proven == 1:
            reason = next(i.title for i in items if i.proof == "reproduced") + " was reproduced"
    verdict = " ".join(reasons[:2]) if reasons else reason
    ans = analytes(app, cur, hist)
    return Health(level, reason, reasons, verdict, banner(level, causes, items),
                  annunciators(app, run, cur, ans, now), ans, cur)


def banner(level: str, causes: list[Cause], items: list[Item]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []

    def add(lvl: str, word: str, message: str, reason: str, action: str | None = None) -> None:
        out.append({"id": f"b{len(out) + 1}", "level": lvl, "word": word, "message": message,
                    "reason": reason, "actionLabel": action, "href": None})

    proven = [i for i in items if i.proof == "reproduced"]
    if proven:
        add("danger", "Exploit proven",
            f"{len(proven)} exploit{'s were' if len(proven) != 1 else ' was'} reproduced and "
            f"{'are' if len(proven) != 1 else 'is'} still open.",
            "; ".join(i.title for i in proven[:3]), "Review the proof")
    secrets = [i for i in items if i.proof == "deterministic"]
    if secrets:
        add("danger", "Secret in source", "A credential is committed to the repository.",
            "; ".join(i.title for i in secrets[:3]), "Rotate it")
    for c in causes:
        if c.kind == "gate":
            add("danger", "Gate would block", c.text + ".", "A floor rule or a confirmed triage verdict.")
        elif c.kind in ("never", "stale", "missed"):
            add("warning", "Scanner out of policy", c.text + ".", "A required scanner is not current.")
        elif c.kind == "cve":
            add("warning", "Reachable critical CVE", c.text + ".", "Triage traced it to an endpoint; it is not proven exploitable.")
        elif c.kind == "uncertain":
            add("info", "Needs a person", c.text + ".", "Triage left these for a person to judge.")
        elif c.kind == "overdue":
            add("warning", "Scan overdue", c.text + ".", "The last scan is older than the policy cadence.")
        elif c.kind in ("failed", "partial"):
            add("warning", "Coverage gap", c.text + ".", "Results may be incomplete.")
    if not out:
        add("success", "Nothing proven open", "Nothing open that was proven.",
            "Every required scanner ran inside its window.")
    return out


def demo() -> None:
    base = dict(has_scan=True, cadence_days=7)
    assert classify(Metrics())[0] == "unknown"
    assert classify(Metrics(**base))[0] == "clear"
    # action: each of the three ways in
    for kw in ({"proven": 1, "blockers": 1}, {"deterministic": 1, "blockers": 1}, {"blockers": 1}):
        assert classify(Metrics(**base, **kw))[0] == "action", kw
    # A critical CVE that is reachable is attention, never action, however severe.
    assert classify(Metrics(**base, critical_cves=2, reachable_critical_cve=1))[0] == "attention"
    # Each attention cause on its own
    for kw in ({"never": ["API Security engine"]}, {"stale": [("Trivy", 9, 7)]}, {"missed": ["Semgrep"]},
               {"uncertain_high": 1}, {"scan_age_days": 12}, {"coverage": "partial"},
               {"coverage": "failed"}):
        assert classify(Metrics(**base, **kw))[0] == "attention", kw
    # ...and the things that must NOT raise it
    assert classify(Metrics(**base, uncertain=5, reachable=9, secrets=0, critical_cves=3))[0] == "clear"
    assert classify(Metrics(**base, scan_age_days=7))[0] == "clear"        # exactly on cadence
    # All required scanners stale on an overdue scan is one cause, not one per scanner.
    lvl, cs = classify(Metrics(**base, scan_age_days=11, req_total=2,
                               stale=[("Trivy", 11, 7), ("Semgrep", 11, 7)]))
    assert lvl == "attention" and [c.kind for c in cs] == ["overdue"], cs
    # Action wins and the worst cause leads.
    level, causes = classify(Metrics(**base, proven=2, blockers=2, stale=[("Trivy", 9, 7)]))
    assert level == "action" and causes[0].kind == "proven" and causes[1].kind == "stale"
    text = " ".join(c.text for c in causes)
    assert "compliant" not in text.lower() and "%" not in text and "percent" not in text.lower()
    # Reference bands and flags
    z = _zero_ref("proven", "p", "h", 2, [0, 1, 2], 6)
    assert z["flag"] == "bad" and z["previous"] == "1" and z["bands"][1]["to"] == 6
    assert _zero_ref("proven", "p", "h", 0, None, 6)["flag"] == "ok"
    assert "trend" not in _zero_ref("proven", "p", "h", 0, None, 6)
    assert _flag_word("warn", True) == "Low" and _flag_word("warn") == "High"
    print("portfolio.health: ok")


if __name__ == "__main__":
    demo()
