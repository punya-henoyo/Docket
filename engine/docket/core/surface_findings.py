"""Turn recon's `candidates` into Findings, and its `entry_points` into an attack plan.

WHY CANDIDATES BELONG IN THE FINDINGS LIST
------------------------------------------
Recon's candidates are the most valuable thing docket produces, and they were the
hardest to find in the console: buried on a separate tab while twenty low-value
pattern matches filled the page a security lead actually reads. The candidates are
the ones no rule encodes — a missing decorator, an ownership check absent from one
handler out of twelve, a password reset with no identity check.

They are NOT scanner matches, and this module does not pretend otherwise:

  discovered_by  "recon", never a scanner name
  status         OPEN, never VALIDATED — nothing was reproduced
  rule_id        "recon/<slug>", so the source is legible in every export
  severity       from the agent when it gave one, otherwise medium and marked as
                 unrated rather than silently invented

The PoC field carries the cited code and the agent's reasoning. That is the same
shape trivy and semgrep findings already use — for a static finding, `poc.request`
has always been "the evidence", not "a reproduced request". A candidate with no
cited file is dropped, exactly as record_surface already refuses uncited entry
points: a suspicion nobody can point at is not a finding.
"""
from __future__ import annotations

import re
from typing import Any

from docket.report.models import Finding, FindingStatus, Location, PoC, Severity

_SLUG = re.compile(r"[^a-z0-9]+")

# Words in a candidate's own title that reliably indicate how bad it is. Used ONLY
# when the agent gave no severity — a keyword is a weak signal and a stated severity
# from something that read the code is a strong one.
_HIGH_SIGNALS = ("rce", "remote code", "deserial", "pickle", "unauthenticated",
                 "auth bypass", "authentication bypass", "sql injection", "command "
                 "injection", "ssrf", "traversal", "takeover", "secret", "hardcoded")
_LOW_SIGNALS = ("verbose", "disclosure of version", "banner", "informational")


def _slug(title: str) -> str:
    return _SLUG.sub("-", title.lower()).strip("-")[:60] or "candidate"


def _severity(candidate: dict[str, Any]) -> tuple[Severity, bool]:
    """(severity, rated_by_agent). Never guesses silently — the caller marks the
    difference in the description so a reader knows which number came from where."""
    raw = str(candidate.get("severity", "")).strip().lower()
    if raw in {s.value for s in Severity}:
        return Severity(raw), True
    text = f"{candidate.get('title', '')} {candidate.get('why', '')}".lower()
    if any(signal in text for signal in _HIGH_SIGNALS):
        return Severity.HIGH, False
    if any(signal in text for signal in _LOW_SIGNALS):
        return Severity.LOW, False
    return Severity.MEDIUM, False


def candidates_to_findings(surface: dict[str, Any] | None) -> list[Finding]:
    """Findings for every candidate that cites a file. Never raises."""
    if not isinstance(surface, dict):
        return []
    out: list[Finding] = []
    for candidate in surface.get("candidates") or []:
        if not isinstance(candidate, dict):
            continue
        title = str(candidate.get("title", "")).strip()
        where = str(candidate.get("file", "")).strip().replace("/work/source/", "")
        why = str(candidate.get("why", "")).strip()
        # A candidate nobody can point at is not a finding. Same rule record_surface
        # already applies to entry points, for the same reason.
        if not title or not where:
            continue

        # May point OUTSIDE the diff, deliberately — see Finding.root_cause. Only the
        # anchor above is scoped; this is display-only, so citing the true cause can no
        # longer get the whole finding dropped.
        cause = str(candidate.get("cause", "")).strip().replace("/work/source/", "")
        origin = str(candidate.get("origin", "")).strip().lower()
        origin = origin if origin in ("introduced", "pre-existing") else None

        severity, rated = _severity(candidate)
        note = "" if rated else (
            " Severity was not set by the agent; this is docket's own reading of the "
            "candidate and should be re-judged."
        )
        out.append(Finding(
            rule_id=f"recon/{_slug(title)}",
            title=title,
            severity=severity,
            location=Location(
                method="STATIC",
                path=where.split(":")[0],
                source_file=where,
            ),
            description=(
                "Found by the AI recon agent reading source — NOT a scanner match and "
                "not reproduced. No rule encodes this; it was identified by comparing "
                f"handlers and noticing what is absent. {why}"
                + (f" Root cause: {cause}." if cause else "")
                + (" The agent judged this PRE-EXISTING, not introduced by this change."
                   if origin == "pre-existing" else "")
                + f"{note}"
            ).strip(),
            poc=PoC(
                request=f"{where} — {title}",
                response=why or "See the agent's reasoning; no request was sent.",
                notes="Reasoning over source. Nothing was executed.",
            ),
            root_cause=cause or None,
            origin=origin,
            discovered_by="recon",
            # OPEN, not the model default VALIDATED: VALIDATED means a PoC was
            # reproduced, and nothing here was.
            status=FindingStatus.OPEN,
        ))
    return out


def render_attack_plan(surface: dict[str, Any] | None, limit: int = 25) -> list[str]:
    """Route lines for the exploitation agents, derived from what recon actually read.

    This replaces the fixture's hardcoded three routes (see prompts/root.py), which
    were asserted as fact for any target. That failure mode was worse than an empty
    list: root was handed fiction confidently and went looking for routes that do not
    exist. Returning [] here is meaningful and the caller must say "no routes
    discovered" rather than substituting a guess.
    """
    if not isinstance(surface, dict):
        return []
    entries = surface.get("entry_points") or []
    # kind='none' is record_surface's way of saying "this repository exposes nothing".
    # That is an answer, and it must not be rendered as a route to attack.
    if len(entries) == 1 and str(entries[0].get("kind", "")).lower() == "none":
        return []

    lines: list[str] = []
    for entry in entries[:limit]:
        if not isinstance(entry, dict):
            continue
        path = str(entry.get("path", "")).strip()
        if not path or path == "-":
            continue
        method = str(entry.get("method", "GET")).strip() or "GET"
        params = [str(p) for p in (entry.get("params") or []) if str(p).strip()]
        auth = str(entry.get("auth", "")).strip()
        source = str(entry.get("file", "")).replace("/work/source/", "").strip()

        line = f"- {method} {path}"
        if params:
            line += f" (params: {', '.join(params[:8])})"
        # Whether a route is guarded changes what is worth trying against it, and an
        # unguarded one is where an exploit agent should start.
        if auth:
            line += f" [auth: {auth}]"
        if source:
            line += f" [from {source}]"
        lines.append(line)
    return lines


def demo() -> None:
    surface = {
        "entry_points": [
            {"method": "POST", "path": "/login", "params": ["username", "password"],
             "auth": "none", "file": "/work/source/app/auth.py:31"},
            {"method": "GET", "path": "/admin/logs", "params": [],
             "auth": "NONE — @require_admin MISSING", "file": "app/admin.py:52"},
            {"method": "GET", "path": "-", "file": "x.py:1"},  # no usable route
        ],
        "candidates": [
            {"title": "Missing admin guard on /admin/logs", "file": "app/admin.py:52-58",
             "why": "siblings carry @require_admin, this one does not"},
            {"title": "Pickle RCE on /whoami via remember cookie",
             "file": "app/auth.py:94", "why": "pickle.loads on a cookie value"},
            {"title": "Uncited suspicion", "why": "no file, so not a finding"},
            {"title": "Rated by the agent", "file": "a.py:1", "why": "x",
             "severity": "critical"},
        ],
    }

    findings = candidates_to_findings(surface)
    # The uncited one is dropped, exactly as record_surface drops uncited entries.
    assert len(findings) == 3, [f.title for f in findings]
    assert all(f.discovered_by == "recon" for f in findings)
    # Never VALIDATED: nothing here was reproduced.
    assert all(f.status == FindingStatus.OPEN for f in findings)
    assert findings[0].rule_id == "recon/missing-admin-guard-on-admin-logs"
    assert findings[0].location.source_file == "app/admin.py:52-58"
    assert "NOT a scanner match" in findings[0].description

    # Keyword fallback, and it must announce itself as a fallback.
    pickle_finding = next(f for f in findings if "Pickle" in f.title)
    assert pickle_finding.severity == Severity.HIGH, pickle_finding.severity
    assert "not set by the agent" in pickle_finding.description
    # A severity the agent DID state is used as-is and not second-guessed.
    rated = next(f for f in findings if f.title == "Rated by the agent")
    assert rated.severity == Severity.CRITICAL
    assert "not set by the agent" not in rated.description

    # The mount prefix never reaches a location a reader sees.
    assert all("/work/source/" not in (f.location.source_file or "") for f in findings)

    plan = render_attack_plan(surface)
    assert len(plan) == 2, plan  # the "-" path is not a route
    assert plan[0].startswith("- POST /login (params: username, password)")
    assert "[auth: none]" in plan[0] and "app/auth.py:31" in plan[0]
    assert "@require_admin MISSING" in plan[1]

    # "No HTTP surface" must render as no routes, never as something to attack.
    assert render_attack_plan({"entry_points": [{"kind": "none", "path": "-"}]}) == []
    assert render_attack_plan(None) == [] and render_attack_plan({}) == []
    assert candidates_to_findings(None) == []
    # ── a cause outside the diff, and an origin the agent set ──────────────────
    # Mendor-lab#2 changed app/services/db.py alone; the missing authorization was in
    # app/profiles.py:47. Anchoring on the changed line keeps the finding in scope,
    # while `cause` sends the reviewer to the right file.
    split = candidates_to_findings({"candidates": [{
        "title": "no owner check on invoice results", "file": "app/services/db.py:59",
        "why": "the helper returns rows for any email",
        "cause": "app/profiles.py:47", "origin": "pre-existing", "severity": "high",
    }]})
    assert len(split) == 1, split
    assert split[0].location.source_file == "app/services/db.py:59"
    assert split[0].root_cause == "app/profiles.py:47", split[0].root_cause
    assert split[0].origin == "pre-existing", split[0].origin
    assert "app/profiles.py:47" in split[0].description
    assert "PRE-EXISTING" in split[0].description

    # Omitted or nonsense values stay None rather than becoming a label nobody set.
    plain = candidates_to_findings({"candidates": [{
        "title": "t", "file": "a.py:1", "why": "w", "origin": "probably?"}]})
    assert plain[0].root_cause is None and plain[0].origin is None, plain[0]

    # The container prefix comes off the cause too, or it names a path that only
    # existed inside the sandbox.
    pref = candidates_to_findings({"candidates": [{
        "title": "t", "file": "a.py:1", "why": "w",
        "cause": "/work/source/app/routes.py:9"}]})
    assert pref[0].root_cause == "app/routes.py:9", pref[0].root_cause

    print("core.surface_findings: ok")


if __name__ == "__main__":
    demo()
