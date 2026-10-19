"""The console's read endpoints, as plain `(status, dict)` functions.

Same shape as `compliance/service.py` and for the same reason: connect.py's handler has no
exception handler to turn a raise into a response, so nothing here raises for an expected
failure. Each function builds the whole read model from disk (see `model/disk.py` for the
mtime memo that keeps that cheap) and returns a JSON-safe dict whose shape is
docs/ui/api-contract.md.

The URL-borne inputs (application id, run name, policy id) are NEVER used to build a path:
an application id and a policy id are only compared for equality against what was derived
from disk, and a run name is shape-checked by `disk.valid_run_name` and then looked up among
the runs already loaded. A name that is not on that list is a 404, whatever it contains.
"""
from __future__ import annotations

import time

import statistics
from pathlib import Path
from typing import Any

from docket.portfolio import health as health_mod
from docket.portfolio import timeutil
from docket.portfolio.catalog import BY_ID, CATALOG, GROUPS, SPECIALISTS
from docket.portfolio.model import disk
from docket.portfolio.model.derive import AppState, Item, Model, RunView, build_model, coverage
from docket.portfolio.policy import GATE, Policy, default_policy

WINDOW_DAYS = 28
_LEVEL_RANK = {"action": 0, "attention": 1, "clear": 2, "unknown": 3}
_PROOF_RANK = {"reproduced": 0, "deterministic": 1, "candidate": 2, "not_reachable": 3}
_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_AGE_COLUMNS = (("0-30", 0, 30), ("31-90", 31, 90), ("91-180", 91, 180), ("181+", 181, None))
_OLD_CRITICAL_DAYS = 14
_MAX_SCANS = 50


# --- shared helpers ----------------------------------------------------------------------


def _counts(run: RunView) -> tuple[int, int]:
    """(proven, candidates) of a run. Proven = open reproduced exploits. Candidates = every
    other open lead the run produced, triaged-out ones included: it counts what the
    scanners raised, not what survived triage."""
    open_items = run.open_items
    proven = sum(i.proof == "reproduced" for i in open_items)
    return proven, len(open_items) - proven


def _event(app: AppState, run: RunView) -> dict[str, Any]:
    proven, candidates = _counts(run)
    return {"id": run.name, "at": timeutil.iso(run.at), "coverage": coverage(run, app.policy),
            "proven": proven, "candidates": candidates, "kind": run.kind, "label": run.label}


def _application(app: AppState, h: health_mod.Health, now: float) -> dict[str, Any]:
    latest = app.latest
    since = now - WINDOW_DAYS * timeutil.DAY
    return {
        "id": app.id, "label": app.label, "repo": app.repo, "tier": app.tier,
        "owner": app.owner, "lang": app.lang, "policy": app.policy.id,
        "level": h.level, "reason": h.reason,
        "age_days": timeutil.whole_days(now - latest.at) if latest else None,
        "last_scan_at": timeutil.iso(latest.at) if latest else None,
        "events": [_event(app, r) for r in app.runs if r.at >= since],
    }


def _all(model: Model, now: float) -> list[tuple[AppState, health_mod.Health]]:
    rows = [(a, health_mod.evaluate(a, now)) for a in model.apps]
    rows.sort(key=lambda r: (_LEVEL_RANK[r[1].level], r[0].label.lower()))
    return rows


def _now(now: float | None) -> float:
    import time

    return float(now if now is not None else time.time())


def _active(run: RunView | None) -> list[Item]:
    return health_mod._active(run.items) if run else []


def _step_days(app: AppState, step_id: str, now: float) -> tuple[str, str]:
    """(state, ago) of one required scanner for one application."""
    last = app.last_ran(step_id)
    if last is None:
        return "missing", "never"
    age = now - last
    state = "ok" if age <= app.policy.window_days(step_id) * timeutil.DAY else "stale"
    return state, timeutil.ago(age)


def _model_policies(model: Model) -> list[Policy]:
    """File policies, plus the built-in default when nothing in the file covers someone."""
    pols = list(model.policies)
    used = {a.policy.id for a in model.apps}
    if (not pols or "default" in used) and all(p.id != "default" for p in pols):
        pols.append(default_policy())
    return pols


def _primary_policy(model: Model) -> Policy:
    """The default (first matching) policy: the first in file order that has an application
    under it, else the first policy, else the built-in default."""
    pols = _model_policies(model)
    for pol in pols:
        if any(a.policy.id == pol.id for a in model.apps):
            return pol
    return pols[0]


# --- /api/portfolio ----------------------------------------------------------------------


def _trend(model: Model, now: float) -> dict[str, Any]:
    periods, crit, high, med = [], [], [], []
    for i in range(8):
        end = now - (7 - i) * 7 * timeutil.DAY
        # A date, not "3 w ago": the kit sets axis labels side by side and long ones collide.
        periods.append({"key": f"w{i}", "label": "Today" if i == 7 else time.strftime("%d %b", time.gmtime(end)).lstrip("0")})
        counts = dict.fromkeys(("critical", "high", "medium"), 0)
        for app in model.apps:
            # The latest scan at or before that week's end: what was open then, as the
            # scans of the time saw it.
            upto = [r for r in app.scans if r.at <= end]
            for item in health_mod._active(upto[-1].items) if upto else []:
                if item.sev in counts:
                    counts[item.sev] += 1
        crit.append(counts["critical"])
        high.append(counts["high"])
        med.append(counts["medium"])
    return {"periods": periods, "series": [
        {"key": "critical", "label": "Critical", "values": crit},
        {"key": "high", "label": "High", "values": high},
        {"key": "medium", "label": "Medium", "values": med}]}


def _severity_age(model: Model, now: float) -> dict[str, Any]:
    cells = {(s, c[0]): 0 for s in ("critical", "high", "medium", "low") for c in _AGE_COLUMNS}
    old = 0
    for app in model.apps:
        seen = app.first_seen()
        for item in _active(app.latest):
            if item.sev not in ("critical", "high", "medium", "low"):
                continue
            age = timeutil.whole_days(now - seen.get(item.key, now))
            for label, lo, hi in _AGE_COLUMNS:
                if age >= lo and (hi is None or age <= hi):
                    cells[(item.sev, label)] += 1
                    break
            if item.sev == "critical" and age > _OLD_CRITICAL_DAYS:
                old += 1
    return {"old_critical": old, "old_age": f"{_OLD_CRITICAL_DAYS} days",
            "rows": ["critical", "high", "medium", "low"],
            "columns": [c[0] for c in _AGE_COLUMNS],
            "cells": [{"row": r, "col": c, "value": v} for (r, c), v in cells.items()]}


def _scanner_coverage(model: Model, now: float) -> list[dict[str, Any]]:
    pol = _primary_policy(model)
    under = [a for a in model.apps if a.policy.id == pol.id]
    out = []
    for step in pol.steps:
        if not step["required"]:
            continue
        s = BY_ID[step["id"]]
        current = sum(_step_days(a, s.id, now)[0] == "ok" for a in under)
        out.append({"id": s.id, "label": s.label, "tool": s.tool, "origin": s.origin,
                    "required": True, "current": current, "of": len(under)})
    return out


def portfolio_payload(cwd: Path | None = None, now: float | None = None) -> tuple[int, dict[str, Any]]:
    now = _now(now)
    model = build_model(cwd, now)
    rows = _all(model, now)
    counts = dict.fromkeys(("action", "attention", "clear", "unknown"), 0)
    for _, h in rows:
        counts[h.level] += 1
    return 200, {
        "generated_at": timeutil.iso(now), "window_days": WINDOW_DAYS,
        "cadence_days": model.cadence_days, "organization": model.organization,
        "sample": model.sample, "counts": counts,
        "applications": [_application(a, h, now) for a, h in rows],
        "scanner_coverage": _scanner_coverage(model, now),
        "trend": _trend(model, now), "severity_age": _severity_age(model, now),
    }


# --- /api/pipeline/<run> and the lane builder --------------------------------------------


def _role_cost(run: RunView, roles: set[str]) -> float | None:
    usage = run.report.get("usage") if isinstance(run.report.get("usage"), dict) else {}
    rows = [r for r in usage.get("agents") or [] if isinstance(r, dict) and r.get("role") in roles]
    if not rows:
        return None
    return round(sum(float(r.get("cost_usd") or 0) for r in rows), 2)


def _required_by(policy: Policy, step: dict[str, Any]) -> list[str]:
    sec = next((w["text"] for w in step["why"] if w["kind"] == "security"), None)
    out = [f"{policy.name}: {sec[0].lower() + sec[1:]}" if sec else policy.name]
    # Pack citations already begin with the authority ("RBI Cyber Security Framework, ..."),
    # so it is prefixed only when the text does not carry it.
    out += [w["text"] if not w.get("authority") or w["text"].startswith(w["authority"])
            else f"{w['authority']} {w['text']}"
            for w in step["why"] if w["kind"] == "regulatory"]
    return out


def _swarm_children(run: RunView, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    spawned: dict[str, dict[str, Any]] = {}
    finished: dict[str, dict[str, Any]] = {}
    for ev in events:
        data = ev.get("data") if isinstance(ev.get("data"), dict) else {}
        agent = str(ev.get("agent_id") or "")
        ts = ev.get("ts") if isinstance(ev.get("ts"), (int, float)) else None
        if ev.get("type") == "agent_spawned" and ts is not None:
            role = str(ev.get("role") or data.get("role") or "")
            if role in SPECIALISTS:
                spawned.setdefault(agent, {"ts": ts, "role": role})
        elif ev.get("type") == "agent_finished" and ts is not None:
            finished.setdefault(agent, {"ts": ts, "status": str(data.get("status") or "")})
    kids = [{"agent": a, **v, "end": finished.get(a)} for a, v in spawned.items()]
    if not kids:     # no events: fall back to the roster, without times
        kids = [{"agent": str(a.get("id")), "ts": None, "role": a["role"], "end": None}
                for a in run.report.get("agents") or []
                if isinstance(a, dict) and a.get("role") in SPECIALISTS]
    kids.sort(key=lambda k: (k["ts"] is None, k["ts"] or 0))
    return kids


def build_lanes(app: AppState, run: RunView) -> dict[str, Any]:
    """Lanes in catalog order from `stages`/`stage_timings`, the swarm from agent events."""
    policy = app.policy
    steps = {s["id"]: s for s in policy.steps}
    events = disk.read_events(run.directory)
    ev_ts = [e["ts"] for e in events if isinstance(e.get("ts"), (int, float))]
    t0 = run.started
    if t0 is None:
        starts = [t["started"] for t in run.timings.values()] + ev_ts[:1]
        t0 = min(starts) if starts else None

    def rel(t: float | None) -> float | None:
        return None if t is None or t0 is None else round(t - t0, 1)

    kids = _swarm_children(run, events)
    items = run.items
    proven_by_role: dict[str, int] = {}
    for i in items:
        if i.proof == "reproduced" and i.source.role:
            proven_by_role[i.source.role] = proven_by_role.get(i.source.role, 0) + 1
    proven = sum(i.proof == "reproduced" for i in items)

    def history_slot(stage: str) -> float | None:
        durs = [t["ended"] - t["started"] for r in app.runs for k, t in r.timings.items()
                if k == stage and "ended" in t]
        return round(statistics.mean(durs), 1) if durs else None

    lanes: list[dict[str, Any]] = []
    for sc in CATALOG:
        step = steps.get(sc.id)
        required = bool(step and step["required"])
        lane: dict[str, Any] = {"id": sc.id, "label": sc.label, "origin": sc.origin,
                                "group": sc.phase, "icon": sc.icon, "required": required}
        if sc.tool:
            lane["tool"] = sc.tool
        state: str | None = None
        timing: dict[str, float] = {}
        if sc.stage is not None:
            st, timing = run.stages.get(sc.stage), run.timings.get(sc.stage) or {}
            if timing:
                state = st if st in ("done", "error", "running") else (
                    "done" if "ended" in timing else "running")
            elif st == "skipped" and not required:
                state = "skipped"
            elif st in ("done", "error", "running"):
                # A report written before stage timings existed knows the state but not the
                # times. It still ran: saying "not run" here would be a false policy breach.
                state = st
        elif sc.id in run.ran:
            state = "done"
        if state is None:
            if not required:
                continue
            state = "not_run"
        lane["state"] = state
        if sc.id == "swarm" and state != "not_run":
            starts = [k["ts"] for k in kids if k["ts"] is not None]
            ends = [k["end"]["ts"] for k in kids if k["end"]]
            if starts:
                lane["start"] = rel(min(starts))
                if ends and len(ends) == len(starts):
                    lane["end"] = rel(max(ends))
        elif timing:
            lane["start"] = rel(timing.get("started"))
            if "ended" in timing:
                lane["end"] = rel(timing["ended"])
        if state == "not_run":
            same_group = [x for x in lanes if x["group"] == sc.phase and x.get("end") is not None]
            begin = same_group[-1]["end"] if same_group else 0.0
            width = history_slot(sc.stage or sc.id)
            if width is None:
                done = [x["end"] - x["start"] for x in lanes
                        if x.get("start") is not None and x.get("end") is not None
                        and x["group"] == sc.phase]
                width = round(statistics.median(done), 1) if done else None
            if t0 is not None:
                lane["start"] = begin
                if width is not None:
                    lane["end"] = round(begin + width, 1)
            lane["slot"] = True
        if required and step:
            lane["requiredBy"] = _required_by(policy, step)
        _decorate(lane, sc.id, run, items, proven, kids)
        lanes.append(lane)
        if sc.id == "swarm" and state != "not_run":
            used: dict[str, int] = {}
            for k in kids:
                n = used[k["role"]] = used.get(k["role"], 0) + 1
                child: dict[str, Any] = {
                    "id": f"sw-{k['role']}" + (f"-{n}" if n > 1 else ""),
                    "label": SPECIALISTS[k["role"]]["label"], "origin": "henoyo", "group": "agents",
                    "icon": "crosshair", "parentId": "swarm",
                    "proven": proven_by_role.get(k["role"], 0)}
                end = k["end"]
                if end is None and k["ts"] is None:
                    child["state"] = "done"
                elif end is None:
                    child["state"] = "done" if run.finished else "running"
                else:
                    child["state"] = "error" if end["status"] in ("error", "failed") else "done"
                if k["ts"] is not None:
                    child["start"] = rel(k["ts"])
                if end:
                    child["end"] = rel(end["ts"])
                lanes.append(child)
    return {"lanes": lanes, "groups": [dict(g) for g in GROUPS], "events": events, "t0": t0,
            "ev_ts": ev_ts}


def _decorate(lane: dict[str, Any], sid: str, run: RunView, items: list[Item], proven: int,
              kids: list[dict[str, Any]]) -> None:
    """candidates / proven / summary / cost for one lane, every one computed from the report."""
    report = run.report
    if sid in ("trivy", "semgrep", "nuclei", "apisec"):
        mine = [i for i in items if i.source.engine == sid]
        if lane["state"] != "not_run":
            lane["candidates"] = len(mine)
        if sid == "trivy":
            cves = sum(i.is_dep_cve and i.sev == "critical" for i in mine)
            secrets = sum(i.is_secret for i in mine)
            parts = ([f"{cves} critical CVE{'s' if cves != 1 else ''}"] if cves else []) + (
                [f"{secrets} secret{'s' if secrets != 1 else ''}"] if secrets else [])
            if parts:
                lane["summary"] = ", ".join(parts)
    elif sid == "recon":
        surface = report.get("surface") if isinstance(report.get("surface"), dict) else {}
        eps = surface.get("endpoints")
        if isinstance(eps, list) and eps:
            lane["summary"] = f"{len(eps)} routes mapped"
    elif sid == "triage":
        v = [i.verdict for i in items if i.verdict]
        if v:
            lane["summary"] = (f"{len(v)} judged: {v.count('exploitable')} exploitable, "
                               f"{v.count('not_reachable')} not reachable, {v.count('uncertain')} unsure")
    elif sid == "compliance":
        packs = [p for p in report.get("compliance") or [] if isinstance(p, dict)]
        if packs:
            judged = sum(int(p.get("judged") or 0) for p in packs)
            total = sum(int(p.get("total_controls") or 0) for p in packs)
            lane["summary"] = f"{judged} of {total} controls read (advisory)"
    elif sid == "swarm":
        if lane["state"] != "not_run":
            lane["proven"] = proven
            n = len(kids)
            if n:
                lane["summary"] = (f"{n} specialist{'s' if n != 1 else ''}, "
                                   f"{proven} exploit{'s' if proven != 1 else ''} proven")
    elif sid == "fix":
        rows = [r for r in report.get("patches") or [] if isinstance(r, dict)]
        ok = [r for r in rows if r.get("status") == "verified_fixed"]
        prs = [r for r in ok if r.get("pr_url")]
        if ok:
            lane["summary"] = (f"{len(ok)} patch{'es' if len(ok) != 1 else ''}"
                               + (f", {len(prs)} pull request{'s' if len(prs) != 1 else ''}" if prs else ""))
        elif rows:
            lane["summary"] = f"{len(rows)} attempted, none verified"
    roles = {"recon": {"recon"}, "triage": {"triage", "triage_static"}, "compliance": {"compliance"},
             "fix": {"fix"}, "swarm": {"root"} | set(SPECIALISTS)}.get(sid)
    if roles and lane["state"] != "not_run":
        cost = _role_cost(run, roles)
        if cost is not None:
            lane["cost"] = cost


def _pipeline_block(app: AppState, run: RunView) -> dict[str, Any]:
    built = build_lanes(app, run)
    return {"run": run.name, "lanes": built["lanes"], "groups": built["groups"],
            "policy": app.policy.name, "_built": built}


def pipeline_payload(run_name: str, cwd: Path | None = None, now: float | None = None) -> tuple[int, dict[str, Any]]:
    if not disk.valid_run_name(run_name):
        return 400, {"error": "bad run name"}
    model = build_model(cwd, _now(now))
    found = model.run(run_name)
    # Looked up among the runs already read from docket_runs, so a name that is not one of
    # them is a 404 whatever it contains.
    if found is None:
        return 404, {"error": f"no run named {run_name}"}
    app, run = found
    block = _pipeline_block(app, run)
    built = block.pop("_built")
    report = run.report
    usage = report.get("usage") if isinstance(report.get("usage"), dict) else {}
    totals = usage.get("totals") if isinstance(usage.get("totals"), dict) else {}
    ev_ts = built["ev_ts"]
    started = run.started if run.started is not None else (min(ev_ts) if ev_ts else None)
    ended = run.ended
    prov = report.get("provenance") if isinstance(report.get("provenance"), dict) else {}
    cost = totals.get("cost_usd", report.get("cost_usd"))
    required = [s for s in app.policy.required_ids() if run.kind in BY_ID[s].kinds]
    agents = report.get("agents_spawned")
    return 200, {
        "run": run.name, "application": app.id, "kind": run.kind,
        "started_at": timeutil.iso(started), "ended_at": timeutil.iso(ended),
        "elapsed": round(ended - started, 1) if started is not None and ended is not None else None,
        "commit": str(prov["head_sha"])[:7] if prov.get("head_sha") else None,
        "cost_usd": round(float(cost), 2) if isinstance(cost, (int, float)) else None,
        "agents": agents if isinstance(agents, int) else None,
        "tokens": {"input": totals.get("input_tokens"), "output": totals.get("output_tokens")},
        "policy": app.policy.name,
        "required": {"ran": sum(s in run.ran for s in required), "of": len(required)},
        "coverage": coverage(run, app.policy),
        "lanes": block["lanes"], "groups": block["groups"],
    }


# --- /api/application/<id> ---------------------------------------------------------------


def _lifecycle(app: AppState, h: health_mod.Health) -> dict[str, Any]:
    run = app.latest
    if run is None:
        return {"current": "onboarded", "since": None, "owner": app.owner}
    seen = app.first_seen()
    items = _active(run)
    fixes = health_mod.fix_rows(app)
    hot = [i for i in items if i.proof in ("reproduced", "deterministic") or i.blocks]
    since = run.at
    if any(i.fixed for i in run.items):
        current = "verified"
    elif any(f.get("pr_state") == "merged" for f in fixes):
        current = "fix_merged"
    elif fixes and hot:
        current = "fix_proposed"
    elif hot:
        current = "proven"
        since = min(seen.get(i.key, run.at) for i in hot)
    else:
        current = "scanned"
        since = (app.scans or app.runs)[0].at
    return {"current": current, "since": timeutil.iso(since), "owner": app.owner}


def application_payload(app_id: str, cwd: Path | None = None, now: float | None = None) -> tuple[int, dict[str, Any]]:
    now = _now(now)
    model = build_model(cwd, now)
    app = model.app(app_id)          # equality against derived ids; never a path
    if app is None:
        return 404, {"error": "no such application"}
    h = health_mod.evaluate(app, now)
    run = app.latest
    seen = app.first_seen()
    findings = []
    if run is not None:
        findings = [i.finding(app.id, timeutil.whole_days(now - seen.get(i.key, now)))
                    for i in run.open_items]
        findings.sort(key=lambda f: (_PROOF_RANK[f["proof"]], _SEV_RANK[f["sev"]], f["title"]))
    pipeline: dict[str, Any] = {"run": None, "lanes": [], "groups": [dict(g) for g in GROUPS],
                                "policy": app.policy.name}
    compliance_rows: list[dict[str, Any]] = []
    if run is not None:
        block = _pipeline_block(app, run)
        block.pop("_built")
        pipeline = block
        compliance_rows = [{k: v for k, v in r.items() if k != "requested"}
                           for r in health_mod._compliance_rows(run)]
    scans = [{"id": r.name, "at": timeutil.iso(r.at), "kind": r.kind,
              "coverage": coverage(r, app.policy), "proven": _counts(r)[0],
              "candidates": _counts(r)[1]} for r in reversed(app.runs)][:_MAX_SCANS]
    return 200, {
        "application": _application(app, h, now),
        "health": {"level": h.level, "verdict": h.verdict, "reasons": h.reasons,
                   "annunciators": h.annunciators, "analytes": h.analytes},
        "banner": h.banner, "lifecycle": _lifecycle(app, h), "pipeline": pipeline,
        "findings": findings, "scans": scans,
        "fixes": [{k: v for k, v in f.items() if k not in ("pr_number", "pr_state")}
                  for f in health_mod.fix_rows(app)],
        "compliance": compliance_rows, "sample": model.sample,
    }


# --- /api/findings -----------------------------------------------------------------------


def findings_payload(cwd: Path | None = None, now: float | None = None) -> tuple[int, dict[str, Any]]:
    now = _now(now)
    model = build_model(cwd, now)
    rows: list[dict[str, Any]] = []
    for app in model.apps:
        run = app.latest
        if run is None:
            continue
        seen = app.first_seen()
        rows += [i.finding(app.id, timeutil.whole_days(now - seen.get(i.key, now)))
                 for i in run.open_items]
    rows.sort(key=lambda f: (_PROOF_RANK[f["proof"]], _SEV_RANK[f["sev"]], f["application"], f["title"]))
    return 200, {"generated_at": timeutil.iso(now), "sample": model.sample, "count": len(rows),
                 "findings": rows}


# --- /api/policy -------------------------------------------------------------------------


def _step_view(policy: Policy, n: int, step: dict[str, Any]) -> dict[str, Any]:
    sc = BY_ID[step["id"]]
    days = step["cadence_days"] or policy.cadence_days
    if step["cadence"]:
        cadence = step["cadence"]
    elif step["required"]:
        cadence = f"At least every {days} days" + (", and on every pull request" if "pr" in sc.kinds else "")
    else:
        cadence = "When it applies"
    if step["on_fail"]:
        on_fail = step["on_fail"]
    elif sc.id == "compliance":
        on_fail = "Advises only. Never blocks."
    else:
        on_fail = "Flags the application as out of policy" if step["required"] else "None. Optional."
    group = next(g["label"] for g in GROUPS if g["key"] == sc.phase)
    return {"n": n, "id": sc.id, "label": sc.label, "tool": sc.tool, "origin": sc.origin,
            "phase": group, "required": step["required"], "cadence": cadence, "on_fail": on_fail,
            "why": [dict(w) for w in step["why"]]}


def _policy_view(model: Model, pol: Policy) -> dict[str, Any]:
    return {
        "id": pol.id, "name": pol.name,
        "applies": pol.applies, "applies_count": sum(a.policy.id == pol.id for a in model.apps),
        "version": pol.version, "approved": pol.approved, "cadence_days": pol.cadence_days,
        "steps": [_step_view(pol, n, s) for n, s in enumerate(pol.steps, 1)],
        "regulatory": [{"authority": w.get("authority"), "text": w["text"],
                        "obligation_ref": w.get("obligation_ref"), "clause": w.get("clause"),
                        "source_url": w.get("source_url")} for w in pol.regulatory],
        "security": [dict(s) for s in pol.security],
        "gate": [dict(g) for g in GATE],
    }


def _consequence(app: AppState, run: RunView | None, now: float) -> dict[str, Any]:
    """What the policy does about this application, scanner coverage first (that is what the
    matrix columns show): a stale or missing required scanner FLAGS; otherwise open blocking
    findings BLOCK; otherwise nothing."""
    pol = app.policy
    states = [(s, *_step_days(app, s, now)) for s in pol.required_ids()]
    bad = [(s, st, ago) for s, st, ago in states if st != "ok"]
    if bad:
        if len(bad) == len(states) and len(states) > 1 and all(st == "stale" for _, st, _ in bad):
            worst = max(timeutil.whole_days(now - (app.last_ran(s) or now)) for s, _, _ in bad)
            text = f"Nothing has run for {worst} days"
        elif len(bad) == 1:
            s, st, _ = bad[0]
            name = health_mod._name(s)
            days = timeutil.whole_days(now - (app.last_ran(s) or now))
            text = f"{name} has never run" if st == "missing" else f"{name} is {days} days stale"
        else:
            text = f"{len(bad)} required scanners are stale or missing"
        return {"effect": "flags", "text": text}
    blockers = [i for i in _active(run) if i.blocks]
    if blockers:
        n = len(blockers)
        text = (f"Reproduced exploit is open: {blockers[0].title}" if n == 1 and blockers[0].proof == "reproduced"
                else f"{n} finding{'s' if n != 1 else ''} would block a pull request")
        return {"effect": "blocks", "text": text}
    return {"effect": None, "text": None}


def _coverage_block(model: Model, pol: Policy, now: float) -> dict[str, Any]:
    scanners = [{"id": s["id"], "label": BY_ID[s["id"]].label, "tool": BY_ID[s["id"]].tool,
                 "origin": BY_ID[s["id"]].origin, "icon": BY_ID[s["id"]].icon}
                for s in pol.steps if s["required"]]
    rows = []
    for app in model.apps:
        if app.policy.id != pol.id:
            continue
        cells = {}
        for sc in scanners:
            state, ago = _step_days(app, sc["id"], now)
            cells[sc["id"]] = {"state": state, "ago": ago}
        rows.append({"id": app.id, "label": app.label, "tier": app.tier, "cells": cells,
                     "consequence": _consequence(app, app.latest, now)})
    return {"policy": pol.id, "window_days": pol.cadence_days, "scanners": scanners, "rows": rows}


def policy_payload(policy_id: str | None = None, cwd: Path | None = None,
                   now: float | None = None) -> tuple[int, dict[str, Any]]:
    now = _now(now)
    model = build_model(cwd, now)
    pols = _model_policies(model)
    chosen = _primary_policy(model)
    if policy_id:
        found = next((p for p in pols if p.id == policy_id), None)
        if found is None:
            return 404, {"error": "no such policy"}
        chosen = found
    body: dict[str, Any] = {
        "policies": [_policy_view(model, p) for p in pols],
        "coverage": _coverage_block(model, chosen, now), "sample": model.sample}
    if model.warnings:
        body["warnings"] = list(model.warnings)
    return 200, body


def demo() -> None:
    # The full scenario is exercised in tests/test_portfolio.py against the seeded data;
    # here: the empty case and the URL-input guards, which need no fixtures.
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        cwd = Path(tmp)
        status, body = portfolio_payload(cwd, now=1_000_000.0)
        assert status == 200 and body["counts"] == {"action": 0, "attention": 0, "clear": 0, "unknown": 0}
        assert body["sample"] is False and body["applications"] == []
        assert len(body["trend"]["periods"]) == 8 and body["trend"]["periods"][-1]["label"] == "Today"
        assert application_payload("nope/x", cwd)[0] == 404
        assert pipeline_payload("../../etc", cwd)[0] == 400
        assert pipeline_payload("..", cwd)[0] == 400
        assert pipeline_payload("missing", cwd)[0] == 404
        assert findings_payload(cwd)[1]["findings"] == []
        status, pol = policy_payload(None, cwd)
        assert status == 200 and pol["policies"][0]["id"] == "default"
        assert [s["id"] for s in pol["policies"][0]["steps"]] == [s.id for s in CATALOG]
        assert pol["coverage"]["rows"] == [] and policy_payload("zzz", cwd)[0] == 404
    print("portfolio.api: ok")


if __name__ == "__main__":
    demo()
