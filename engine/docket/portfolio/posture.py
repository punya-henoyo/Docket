"""Posture: where every application sits on the two-by-two, and how that is evolving.

docs/ui/policy-and-posture.md section 4 is the contract. The one idea: the QUADRANT is decided
by RULE from facts the health card already uses, and the number only places a dot inside its
cell. Nothing here is a grade.

  x  assurance   right half iff every policy-required step finished inside its window in a
                 FULL scan (a pull-request check does not refresh a step); left half
                 otherwise, placed by how many required steps are current (a step inside
                 twice its window counts half).
  y  standing    lower half iff a PROVEN or CONFIRMED problem is open; ordinal bands, lowest
                 first: reproduced exploit or deterministic secret, then triage-CONFIRMED but
                 not reproduced. Upper half: an UNCERTAIN high or critical a person must
                 judge (never counted as clean, never as confirmed: AGENTS.md rule 12), then
                 nothing open.

Candidates never move a dot (AGENTS.md rule 10): a lead nobody has confirmed is in the weekly
outcome counts and nowhere else. Compliance results are not an input at all (rules 13, 14).
There is no composite number, no percentage, and the payload has no field for either.

Proven items persist: reproduced exploits are read from the latest run in which the exploit
lane ran (`AppState.standing_items`), so a later static-only scan cannot make an application
look better for running less. The health card and this map read the same function.

Replay: a position at a past instant is the same computation over the runs known by then,
judged against TODAY's policy and profile (policies have no history yet).

Everything is deterministic given `now`.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from docket.portfolio import health as health_mod
from docket.portfolio import timeutil
from docket.portfolio.catalog import BY_ID
from docket.portfolio.model.derive import AppState, Item, Model, RunView, coverage
from docket.portfolio.policy import Policy, assign

DAY = timeutil.DAY
HISTORY_DAYS = 28
SNAPSHOTS = 5                 # weekly, oldest first, the last one is `now`
DAYS_IN_CELL_CAP = 28
MOVE_BASELINE_DAYS = 14       # "moved" compares with the snapshot at least this old

# x placement (assurance), y placement (standing)
LEFT_LO, LEFT_HI = 4.0, 46.0
RIGHT_LO, RIGHT_HI = 54.0, 96.0
UNCERTAIN_TOP, UNCERTAIN_BOTTOM = 64.0, 52.0
NOTHING_OPEN = 90.0

_LEVEL_RANK = {"action": 0, "attention": 1, "clear": 2, "unknown": 3}
_CELL_RANK = {"bl": 0, "br": 1, "tl": 2, "tr": 3}

QUADRANTS: tuple[dict[str, str], ...] = (
    {"key": "tl", "title": "Checks overdue, nothing proven",
     "note": "Quiet is not safe: a required check is missing or stale"},
    {"key": "tr", "title": "Checks current, nothing proven",
     "note": "Required checks are current and no proven problem is open. "
             "That is not a promise of safety"},
    {"key": "bl", "title": "Checks overdue, problems proven",
     "note": "Proven problems and gaps in coverage. Look here first"},
    {"key": "br", "title": "Checks current, problems proven",
     "note": "The risk is real and well evidenced. Fix it"},
)


@dataclass(slots=True, frozen=True)
class Position:
    """One application at one instant."""

    at: float
    assurance: float
    standing: float
    cell: str
    right: bool
    upper: bool
    credit: float                    # left-half progress: current steps (a late one counts half)
    band: int                        # 1 exploit/secret, 2 confirmed, 3 uncertain, 4 nothing open
    current: int                     # required steps current
    total: int                       # required steps (not applicable ones excluded)
    assurance_note: str
    assurance_detail: str
    standing_note: str
    proven_as_of: float | None       # the exploit run the proven count is carried from


# --- steps -------------------------------------------------------------------------------


def _required(app: AppState) -> list[str]:
    """Required steps that apply to a full scan. A step that does not (`na`) is excluded
    from both N and M, exactly as the health card does."""
    return [s for s in app.policy.required_ids() if "scan" in BY_ID[s].kinds]


def step_state(app: AppState, step_id: str, asof: float, policy: Policy | None = None
               ) -> tuple[str, float | None]:
    """("ok" | "late" | "stale" | "missing", age / window).

    `ok`: finished inside the window, which is the matrix's "ok" (api._step_days) to the
    letter. `late`: inside twice the window (half credit on the left of the map). Both read
    `AppState.last_ran`, the one definition of "ran"."""
    pol = policy or app.policy
    last = app.last_ran(step_id, asof)
    if last is None:
        return "missing", None
    window = pol.window_days(step_id) * DAY
    age = asof - last
    ratio = age / window
    if age <= window:
        return "ok", ratio
    return ("late" if age <= 2 * window else "stale"), ratio


def meets_policy(app: AppState, asof: float) -> bool:
    """Every required step finished inside its window (and there is at least one)."""
    req = _required(app)
    return bool(req) and all(step_state(app, s, asof)[0] == "ok" for s in req)


# --- one position ------------------------------------------------------------------------


def _plural(n: int, one: str, many: str | None = None) -> str:
    return f"{n} {one if n == 1 else (many or one + 's')}"


def _standing(items: list[Item]) -> tuple[int, float, dict[str, int]]:
    """(band, y, counts) from the open items that count. Candidates are not read at all
    except through a triage verdict a person can act on."""
    proven = [i for i in items if i.proof == "reproduced"]
    secrets = [i for i in items if i.proof == "deterministic"]
    rest = [i for i in items if i.proof not in ("reproduced", "deterministic")]
    confirmed = [i for i in rest if i.verdict == "exploitable"]
    unsure = [i for i in rest if i.verdict == "uncertain" and i.sev in ("critical", "high")]
    counts = {"reproduced": len(proven), "secrets": len(secrets),
              "confirmed": len(confirmed), "uncertain": len(unsure)}
    n1 = len(proven) + len(secrets)
    if n1:
        return 1, max(4.0, 26.0 - 3.0 * n1), counts
    if confirmed:
        return 2, max(26.0, 46.0 - 3.0 * (len(confirmed) - 1)), counts
    if unsure:
        return 3, max(UNCERTAIN_BOTTOM, UNCERTAIN_TOP - 3.0 * (len(unsure) - 1)), counts
    return 4, NOTHING_OPEN, counts


def position(app: AppState, asof: float) -> Position | None:
    """Where `app` sat at `asof`, or None when it had no run by then (never plotted)."""
    run = app.latest_asof(asof)
    if run is None:
        return None
    required = _required(app)
    states = [step_state(app, s, asof) for s in required]
    total = len(required)
    current = sum(st == "ok" for st, _ in states)
    credit = current + 0.5 * sum(st == "late" for st, _ in states)
    right = total > 0 and current == total
    if right:
        worst = max(r for _, r in states if r is not None)
        x = RIGHT_HI - (RIGHT_HI - RIGHT_LO) * min(1.0, max(0.0, worst))
    else:
        x = LEFT_LO + (LEFT_HI - LEFT_LO) * (credit / total if total else 0.0)

    items, exploit = app.standing_items(run, asof)
    band, y, c = _standing(items)
    upper = band >= 3
    carried = exploit is not None and exploit is not run and c["reproduced"] > 0
    since = f" (as of the {timeutil.short_date(exploit.at)} exploit run)" if carried else ""
    if band == 1:
        parts = ([_plural(c["reproduced"], "reproduced exploit") + " open" + since]
                 if c["reproduced"] else []) + (
            [_plural(c["secrets"], "secret") + " committed to source"] if c["secrets"] else [])
        note = " and ".join(parts)
    elif band == 2:
        note = _plural(c["confirmed"], "triage-confirmed problem") + " open, not reproduced"
    elif band == 3:
        note = f"needs a person to judge: {c['uncertain']} uncertain high"
    else:
        note = "No proven or confirmed problem is open"
    if band >= 3 and exploit is None:
        note += "; the exploit lane has not run"
    pol = app.policy
    return Position(
        at=asof, assurance=round(x, 1), standing=round(y, 1),
        cell=("t" if upper else "b") + ("r" if right else "l"), right=right, upper=upper,
        credit=credit, band=band, current=current, total=total,
        assurance_note=(f"{current} of {total} required scanners current" if total
                        else "the policy requires no scanners"),
        assurance_detail=f"{pol.name} policy requires {_plural(total, 'step')}",
        standing_note=note,
        proven_as_of=exploit.at if carried else None)


def _moved(then: Position | None, now: Position) -> dict[str, str] | str:
    """Per axis, never summed. A half change or a band change is a move; inside the right half
    the dot only drifts with the clock, which is not a move."""
    if then is None:
        return "new"
    if then.right != now.right:
        a = "up" if now.right else "down"
    elif now.right:
        a = "steady"
    else:
        a = "up" if now.credit > then.credit else "down" if now.credit < then.credit else "steady"
    if then.upper != now.upper:
        s = "up" if now.upper else "down"
    else:
        s = "up" if now.standing > then.standing else "down" if now.standing < then.standing else "steady"
    return {"assurance": a, "standing": s}


def _days_in_cell(app: AppState, now: float, cell: str) -> int:
    """Consecutive days (today counts) the dot has sat in `cell`, replayed daily, capped."""
    n = 0
    for d in range(DAYS_IN_CELL_CAP):
        p = position(app, now - d * DAY)
        if p is None or p.cell != cell:
            break
        n += 1
    return n


def _level_asof(app: AppState, asof: float, seen: dict[str, float]) -> str:
    run = app.latest_asof(asof)
    if run is None:
        return "unknown"
    level, _ = health_mod.classify(health_mod.measure(app, run, seen, asof, asof, asof=asof))
    if level == "clear" and (app.assignment or {}).get("incomplete"):
        return "attention"          # the profile-gap rule of api._health, replayed
    return level


# --- the payload -------------------------------------------------------------------------


def _assignment(app: AppState, policies: list[Policy]) -> dict[str, Any]:
    found = app.assignment or assign({"category": app.category, "exposure": app.exposure,
                                      "stack": app.stack, "tier": app.tier}, policies)
    return {"policy": app.policy.id, "via": found["via"], "incomplete": list(found["incomplete"]),
            "overrides": found["overrides"]}


def _outcome(app: AppState, run: RunView) -> str:
    """The worst that applies to one assessment: proven, else incomplete, else candidates,
    else clean."""
    open_items = run.open_items
    if any(i.proof in ("reproduced", "deterministic") for i in open_items):
        return "proven"
    if coverage(run, app.policy) != "full":
        return "incomplete"
    return "candidates" if open_items else "clean"


def _assessments(model: Model, now: float, snaps: list[float]) -> dict[str, Any]:
    since = now - HISTORY_DAYS * DAY
    weeks = [{"label": timeutil.short_date(snaps[i]), "from": timeutil.date(snaps[i]),
              "at": timeutil.date(snaps[i + 1]),
              "proven": 0, "candidates": 0, "clean": 0, "incomplete": 0}
             for i in range(len(snaps) - 1)]
    outcomes = {"proven": 0, "candidates": 0, "clean": 0, "incomplete": 0}
    kinds = {"scan": 0, "pr": 0}
    for app in model.apps:
        for run in app.runs:
            if not since <= run.at <= now:
                continue
            kinds[run.kind] += 1
            out = _outcome(app, run)
            outcomes[out] += 1
            week = min(len(weeks) - 1, int((run.at - since) // (7 * DAY)))
            weeks[week][out] += 1
    return {"days": HISTORY_DAYS, "total": kinds["scan"] + kinds["pr"], "scan": kinds["scan"],
            "pr": kinds["pr"], "outcomes": outcomes, "weekly": weeks}


def _category_key(app: AppState) -> str:
    if not app.category and not app.exposure:
        return "Not profiled"
    return f"{app.category or 'Category not set'} · {app.exposure or 'Exposure not set'}"


def build_posture(model: Model, policies: list[Policy], now: float,
                  levels: dict[str, tuple[str, str]] | None = None) -> dict[str, Any]:
    """The `posture` object of the portfolio payload.

    `levels` maps application id to its current (level, reason). The api passes the ones it
    already computed, profile-gap rule included; without it they are computed here the same
    way, so the two cannot disagree."""
    if levels is None:
        from docket.portfolio.api import _health      # lazy: api imports this module

        levels = {a.id: (h.level, h.reason) for a in model.apps for h in [_health(a, now)]}
    snaps = [now - (SNAPSHOTS - 1 - k) * 7 * DAY for k in range(SNAPSHOTS)]
    baseline = max(k for k, t in enumerate(snaps) if t <= now - MOVE_BASELINE_DAYS * DAY)
    apps = sorted(model.apps, key=lambda a: a.id.lower())

    points: list[dict[str, Any]] = []
    unassessed: list[dict[str, Any]] = []
    by_snapshot = [{"at": timeutil.date(t), "tl": 0, "tr": 0, "bl": 0, "br": 0, "unassessed": 0}
                   for t in snaps]
    for app in apps:
        level, reason = levels.get(app.id, ("unknown", "Never scanned"))
        seen = app.first_seen()
        cur = position(app, now)
        past = [cur if k == len(snaps) - 1 else position(app, t) for k, t in enumerate(snaps)]
        for k, p in enumerate(past):
            by_snapshot[k][p.cell if p else "unassessed"] += 1
        if cur is None:
            unassessed.append({"id": app.id, "label": app.label, "tier": app.tier,
                               "category": app.category, "exposure": app.exposure,
                               "reason": "Never scanned"})
            continue
        trail: list[dict[str, Any] | None] = []
        for k, p in enumerate(past):
            if p is None:
                trail.append(None)
                continue
            trail.append({
                "at": timeutil.date(p.at), "assurance": p.assurance, "standing": p.standing,
                "cell": p.cell, "level": level if k == len(snaps) - 1 else _level_asof(app, p.at, seen),
                "assurance_note": p.assurance_note, "standing_note": p.standing_note})
        then = past[baseline]
        points.append({
            "id": app.id, "label": app.label, "tier": app.tier, "category": app.category,
            "exposure": app.exposure, "policy": app.policy.id, "policy_name": app.policy.name,
            "level": level, "reason": reason, "assurance": cur.assurance, "standing": cur.standing,
            "cell": cur.cell, "days_in_cell": _days_in_cell(app, now, cur.cell),
            "assignment": _assignment(app, policies),
            "assurance_note": cur.assurance_note, "assurance_detail": cur.assurance_detail,
            "standing_note": cur.standing_note,
            "proven_as_of": timeutil.iso(cur.proven_as_of),
            "trail": trail, "moved": _moved(then, cur),
            "moved_since": timeutil.date(then.at) if then is not None else None})

    def row(p: dict[str, Any]) -> dict[str, Any]:
        return {k: p[k] for k in ("id", "label", "tier", "level", "reason", "cell", "assurance",
                                  "standing", "days_in_cell", "moved", "moved_since")}

    worst = sorted((p for p in points if p["level"] in ("action", "attention")),
                   key=lambda p: (_LEVEL_RANK[p["level"]], _CELL_RANK[p["cell"]], p["standing"],
                                  p["label"].lower()))
    best = sorted((p for p in points if p["cell"] == "tr" and p["level"] == "clear"),
                  key=lambda p: (-p["assurance"], p["label"].lower()))
    groups: dict[str, dict[str, Any]] = {}
    for app in apps:
        g = groups.setdefault(_category_key(app), {
            "key": _category_key(app), "category": app.category, "exposure": app.exposure,
            "apps": 0, "checks_current": 0,
            "levels": dict.fromkeys(("action", "attention", "clear", "unknown"), 0)})
        g["apps"] += 1
        g["checks_current"] += meets_policy(app, now)
        g["levels"][levels.get(app.id, ("unknown", ""))[0]] += 1
    return {
        "as_of": timeutil.iso(now), "history_days": HISTORY_DAYS,
        "snapshots": [timeutil.date(t) for t in snaps],
        "points": points, "by_snapshot": by_snapshot, "unassessed": unassessed,
        "quadrants": [dict(q) for q in QUADRANTS],
        "leaders": {"worst": [row(p) for p in worst[:3]], "best": [row(p) for p in best[:3]]},
        "assessments": _assessments(model, now, snaps),
        "categories": [groups[k] for k in sorted(groups)],
    }


# --- self-check --------------------------------------------------------------------------


def demo() -> None:
    import json
    import tempfile
    from pathlib import Path

    from docket.portfolio.model.derive import build_model

    now = 100 * DAY
    app_id = "o/a"

    def write(cwd: Path, name: str, days_ago: float, *, stages: dict, findings: list | None = None,
              swarm: bool = False, pr: int | None = None) -> None:
        d = cwd / "docket_runs" / name
        d.mkdir(parents=True)
        at = now - days_ago * DAY
        rep: dict[str, Any] = {"target": f"github:{app_id}@main", "stages": stages,
                               "run_timing": {"started": at - 5, "ended": at},
                               "findings": findings or []}
        if swarm:
            rep["agents_spawned"] = 2
        if pr:
            rep["provenance"] = {"repo": app_id, "pr": pr}
        (d / "report.json").write_text(json.dumps(rep))

    def exploit(key: str) -> dict[str, Any]:
        return {"rule_id": "sqli", "title": "SQLi", "severity": "high", "description": "d",
                "location": {"method": "POST", "path": "/p"}, "discovered_by": "sqli-agent",
                "status": "validated", "poc": {"request": "r", "response": "s"}, "dedupe_key": key}

    base = {"trivy": "done", "semgrep": "done", "triage": "done"}
    with tempfile.TemporaryDirectory() as tmp:
        cwd = Path(tmp)
        (cwd / "docket_portfolio.json").write_text(json.dumps({"applications": [
            {"repo": app_id, "label": "A", "tier": "Tier 1", "category": "Banking",
             "exposure": "Customer-facing"}, {"repo": "o/never", "label": "Never"}]}))
        # An exploit run 20 days ago; a static-only scan yesterday that does not list it.
        write(cwd, "s1", 20, stages=base, findings=[exploit("k1")], swarm=True)
        write(cwd, "s2", 1, stages=base)
        model = build_model(cwd, now)
        a = model.app(app_id)
        # Required steps are trivy, semgrep (default policy); both ran yesterday: right half.
        p = position(a, now)
        assert p.right and p.cell == "br" and p.band == 1, p
        assert "as of the" in p.standing_note and "exploit run" in p.standing_note, p.standing_note
        assert p.standing < 50 and p.assurance > 54
        # Before the first run there is no position at all.
        assert position(a, now - 30 * DAY) is None
        post = build_posture(model, model.policies, now, levels={app_id: ("action", "r"),
                                                                 "o/never": ("unknown", "Never scanned")})
        assert [u["id"] for u in post["unassessed"]] == ["o/never"] and len(post["points"]) == 1
        pt = post["points"][0]
        assert pt["trail"][0] is None and pt["trail"][-1]["cell"] == pt["cell"] == "br"
        assert pt["moved"] in ("new",) or isinstance(pt["moved"], dict)
        assert len(post["snapshots"]) == 5 and len(post["by_snapshot"]) == 5
        text = json.dumps(post).lower()
        assert "compliant" not in text and '"score"' not in text and "percent" not in text
        assert post["quadrants"][1]["title"] == "Checks current, nothing proven"
    print("portfolio.posture: ok")


if __name__ == "__main__":
    demo()
