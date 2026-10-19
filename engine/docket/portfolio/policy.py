"""Policies: which scanners an application must run, how often, and what the gate does.

A policy is a sequence of STEPS (catalog ids, in the order they run), each marked
`required` or not. The required steps are THE definition of "required scanner" across the
console: the pipeline's "N of M required ran", the health card's "Required scanners that
ran", the coverage matrix columns and a scan's `full`/`partial` coverage all read the same
set, from here. A second definition anywhere is how two screens show two different truths.

The compliance reader is ALWAYS optional. Compliance is advisory and never gates (AGENTS.md
rule 15), so a policy that marks it required is normalised to optional and warned about
rather than letting "advisory" quietly become a precondition.

The gate wording is fixed to what `service/gate.py` really does, and a policy file cannot
rewrite it:

  blocks   a reproduced exploit, a hardcoded secret or other deterministic-floor rule, a
           triage verdict of CONFIRMED
  flags    a required scanner that did not run inside its window
  advises  compliance results

A critical dependency CVE is deliberately NOT on the blocks list. It goes to triage, and
reachable-but-unproven it is an `attention` reason, not a stop.

Regulatory reasons point at the compliance packs by `obligation_ref` ("rbi-csf:vapt") and
are RESOLVED against the pack: authority, citation text, source URL and clause all come from
the pack data, so a policy cannot cite a clause the pack does not carry. A clause is null
unless the pack supplies one. An unresolvable ref is kept as written and warned about; it is
never "fixed up".
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from docket.portfolio.catalog import BY_ID, CATALOG

POLICY_FILE = "docket_policy.json"
DEFAULT_CADENCE_DAYS = 7
MAX_POLICY_BYTES = 1_000_000
_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
EFFECTS = ("blocks", "flags", "advises")

# Fixed on purpose; see the module docstring.
GATE: tuple[dict[str, str], ...] = (
    {"effect": "blocks",
     "text": "A reproduced exploit, a secret in source or another deterministic rule, or a "
             "triage verdict of confirmed."},
    {"effect": "flags", "text": "A required scanner that did not run inside its window."},
    {"effect": "advises",
     "text": "Compliance results. They annotate the pull request and never block it: a "
             "control that cannot be judged must not turn every pull request red."},
)


@dataclass(slots=True)
class Policy:
    id: str
    name: str
    applies: str
    applies_tier: list[str]
    version: int
    approved: str | None
    cadence_days: int
    steps: list[dict[str, Any]]
    regulatory: list[dict[str, Any]] = field(default_factory=list)
    security: list[dict[str, Any]] = field(default_factory=list)
    default: bool = False
    # Reference values for the health card, overridable per policy.
    thresholds: dict[str, int] = field(default_factory=dict)

    def step(self, step_id: str) -> dict[str, Any] | None:
        return next((s for s in self.steps if s["id"] == step_id), None)

    def required_ids(self) -> list[str]:
        return [s["id"] for s in self.steps if s["required"]]

    def window_days(self, step_id: str) -> int:
        step = self.step(step_id)
        return int((step or {}).get("cadence_days") or self.cadence_days)


def _step(id_: str, required: bool, **extra: Any) -> dict[str, Any]:
    return {"id": id_, "required": required, "cadence_days": None, "cadence": None,
            "on_fail": None, "why": [], **extra}


def default_policy() -> Policy:
    """Applies when there is no docket_policy.json, or an application matches nothing in it.

    All nine steps so the pipeline shows the whole sequence; only the two scanners a static
    scan always has are required, because requiring the agents would mark every plain scan
    `partial` for a reason the operator never chose.
    """
    required = {"trivy", "semgrep"}
    return Policy(
        id="default", name="Default baseline",
        applies="Every application (no docket_policy.json applies)",
        applies_tier=[], version=1, approved=None, cadence_days=DEFAULT_CADENCE_DAYS,
        steps=[_step(s.id, s.id in required) for s in CATALOG],
        security=[
            {"text": "No credentials in source",
             "detail": "A deterministic rule: a secret in code blocks the pull request."},
            {"text": "Only proof blocks a release",
             "detail": "A reproduced exploit, a triage verdict of confirmed, or a "
                       "deterministic rule such as a secret. A scanner hit alone does not."},
        ],
        default=True,
    )


def _resolve_ref(ref: str, cwd: Path | None) -> dict[str, Any] | None:
    """(authority, text, clause, source_url) for `pack` or `pack:control`, or None."""
    from docket.compliance.packs import PackError, load_pack

    pack_id, _, control_id = str(ref).partition(":")
    try:
        pack = load_pack(pack_id, cwd=cwd)
    except PackError:
        return None
    if not control_id:
        return {"authority": pack.authority, "text": pack.title, "clause": None,
                "source_url": pack.source_url or None}
    control = next((c for c in pack.controls if c.id == f"{pack_id}:{control_id}"), None)
    if control is None:
        return None
    return {"authority": pack.authority, "text": control.citation or control.title,
            "clause": control.clause, "source_url": pack.source_url or None}


def _why(raw: Any, cwd: Path | None, warn: list[str], where: str) -> dict[str, Any] | None:
    if not isinstance(raw, dict):
        warn.append(f"{where}: a reason must be an object")
        return None
    ref = raw.get("obligation_ref")
    resolved = _resolve_ref(ref, cwd) if ref else None
    if ref and resolved is None:
        warn.append(f"{where}: obligation_ref {ref!r} matches no compliance pack control")
    kind = raw.get("kind") or ("regulatory" if ref else "security")
    if kind not in ("security", "regulatory"):
        warn.append(f"{where}: kind must be security or regulatory")
        return None
    resolved = resolved or {}
    text = raw.get("text") or resolved.get("text")
    if not text:
        warn.append(f"{where}: a reason needs text or a resolvable obligation_ref")
        return None
    # The pack wins for clause and source_url: those are facts the pack author recorded.
    return {
        "kind": kind, "text": str(text),
        "authority": raw.get("authority") or resolved.get("authority"),
        "obligation_ref": ref or None,
        "clause": resolved.get("clause", raw.get("clause")),
        "source_url": resolved.get("source_url", raw.get("source_url")),
    }


def parse_policy(raw: Any, cwd: Path | None, warn: list[str]) -> Policy | None:
    """One policy from file JSON, or None (with the reason appended to `warn`)."""
    if not isinstance(raw, dict):
        warn.append("a policy must be an object")
        return None
    pid = str(raw.get("id") or "")
    if not _ID.match(pid):
        warn.append(f"policy id {pid!r} must be lowercase [a-z0-9._-]")
        return None
    where = f"policy {pid}"
    name = str(raw.get("name") or "").strip()
    if not name:
        warn.append(f"{where}: a name is required")
        return None
    cadence = raw.get("cadence_days", DEFAULT_CADENCE_DAYS)
    if not isinstance(cadence, int) or isinstance(cadence, bool) or not 1 <= cadence <= 365:
        warn.append(f"{where}: cadence_days must be a whole number from 1 to 365")
        return None
    steps_raw = raw.get("steps")
    if not isinstance(steps_raw, list) or not steps_raw:
        warn.append(f"{where}: steps must be a non-empty list")
        return None
    steps: list[dict[str, Any]] = []
    seen: set[str] = set()
    for i, item in enumerate(steps_raw, 1):
        item = {"id": item} if isinstance(item, str) else item
        sid = item.get("id") if isinstance(item, dict) else None
        if sid not in BY_ID:
            warn.append(f"{where}: step {i} has unknown id {sid!r}; known: {', '.join(BY_ID)}")
            return None
        if sid in seen:
            warn.append(f"{where}: step {sid} is listed twice")
            return None
        seen.add(sid)
        required = item.get("required", False)
        if not isinstance(required, bool):
            warn.append(f"{where}: step {sid}: required must be true or false")
            return None
        if sid == "compliance" and required:
            warn.append(f"{where}: the compliance reader is always optional (advisory); "
                        "treated as not required")
            required = False
        step_days = item.get("cadence_days")
        if step_days is not None and (not isinstance(step_days, int) or not 1 <= step_days <= 365):
            warn.append(f"{where}: step {sid}: cadence_days must be 1 to 365")
            return None
        why = [w for w in (_why(w, cwd, warn, f"{where}: step {sid}")
                           for w in item.get("why") or []) if w]
        steps.append(_step(sid, required, cadence_days=step_days,
                           cadence=item.get("cadence"), on_fail=item.get("on_fail"), why=why))
    regulatory = [w for w in (_why({**w, "kind": "regulatory"} if isinstance(w, dict) else w,
                                   cwd, warn, f"{where}: regulatory")
                              for w in raw.get("regulatory") or []) if w]
    security = [{"text": str(s.get("text")), "detail": str(s.get("detail") or "")}
                for s in raw.get("security") or [] if isinstance(s, dict) and s.get("text")]
    tiers = raw.get("applies_tier") or []
    thresholds = {k: int(v) for k, v in (raw.get("thresholds") or {}).items()
                  if isinstance(v, int) and not isinstance(v, bool) and v >= 0}
    return Policy(
        id=pid, name=name, applies=str(raw.get("applies") or ""),
        applies_tier=[str(t) for t in tiers] if isinstance(tiers, list) else [],
        version=int(raw["version"]) if isinstance(raw.get("version"), int) else 1,
        approved=str(raw["approved"]) if raw.get("approved") else None,
        cadence_days=cadence, steps=steps, regulatory=regulatory, security=security,
        default=bool(raw.get("default")), thresholds=thresholds)


def load_policies(cwd: Path | None = None) -> tuple[list[Policy], list[str], bool]:
    """(policies, warnings, from_file). A bad policy is dropped with a warning, never fatal:
    one typo must not blank the console. With nothing valid the built-in default applies."""
    path = (cwd or Path.cwd()) / POLICY_FILE
    warn: list[str] = []
    if not path.is_file():
        return [], warn, False
    try:
        if path.stat().st_size > MAX_POLICY_BYTES:
            raise ValueError("larger than 1 MB")
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return [], [f"{POLICY_FILE} could not be read ({exc}); the built-in default applies"], True
    items = raw.get("policies") if isinstance(raw, dict) else None
    if not isinstance(items, list):
        return [], [f"{POLICY_FILE} must be an object with a policies list"], True
    policies: list[Policy] = []
    for item in items:
        pol = parse_policy(item, cwd, warn)
        if pol is None:
            continue
        if any(p.id == pol.id for p in policies):
            warn.append(f"policy {pol.id} appears twice; the first is used")
            continue
        policies.append(pol)
    return policies, warn, True


def policy_for(app: dict[str, Any], policies: list[Policy]) -> Policy:
    """Explicit `policy` id, else the first policy that lists the application's tier, else
    a policy marked default, else the built-in default."""
    by_id = {p.id: p for p in policies}
    if app.get("policy") in by_id:
        return by_id[app["policy"]]
    tier = app.get("tier")
    for pol in policies:
        if tier and tier in pol.applies_tier:
            return pol
    for pol in policies:
        if pol.default:
            return pol
    return default_policy()


def requires_pr(step_id: str, kind: str) -> bool:
    """Is this step expected on a scan of this kind? See catalog.Scanner.kinds."""
    return kind in BY_ID[step_id].kinds


def demo() -> None:
    import tempfile

    d = default_policy()
    assert [s["id"] for s in d.steps] == [s.id for s in CATALOG]      # nine, pipeline order
    assert d.required_ids() == ["trivy", "semgrep"] and d.cadence_days == 7
    assert [g["effect"] for g in GATE] == ["blocks", "flags", "advises"]
    assert "CVE" not in GATE[0]["text"], "a dependency CVE is never listed as blocking"

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        assert load_policies(root) == ([], [], False)
        good = {"id": "t1", "name": "Tier 1", "applies_tier": ["Tier 1"], "cadence_days": 7,
                "steps": [{"id": "trivy", "required": True,
                           "why": [{"obligation_ref": "rbi-csf:secrets"}]},
                          {"id": "compliance", "required": True},
                          {"id": "swarm", "required": True,
                           "why": [{"obligation_ref": "rbi-csf:vapt"}]}],
                "regulatory": [{"obligation_ref": "owasp-api-2023"}]}
        bad = [{"id": "Bad Id", "name": "x", "steps": ["trivy"]},
               {"id": "ok", "name": "x", "steps": [{"id": "nope"}]},
               {"id": "ok2", "name": "x", "steps": ["trivy"], "cadence_days": 0},
               {"id": "ok3", "name": "x", "steps": ["trivy", "trivy"]},
               {"id": "ok4", "name": "x", "steps": []}, "not an object"]
        (root / POLICY_FILE).write_text(json.dumps({"policies": [good, *bad]}))
        pols, warns, from_file = load_policies(root)
        assert from_file and [p.id for p in pols] == ["t1"], pols
        assert len(warns) >= len(bad), warns
        t1 = pols[0]
        assert t1.required_ids() == ["trivy", "swarm"]        # compliance forced optional
        assert any("always optional" in w for w in warns)
        secrets = t1.step("trivy")["why"][0]
        # Resolved from the pack, never invented: the citation is the pack's own string and
        # the clause is null because rbi-csf supplies none.
        assert secrets["authority"] == "RBI" and "Secure configuration" in secrets["text"], secrets
        assert secrets["clause"] is None and secrets["source_url"].startswith("https://"), secrets
        assert "VAPT" in t1.step("swarm")["why"][0]["text"]
        assert t1.regulatory[0]["authority"] == "OWASP"
        assert policy_for({"tier": "Tier 1"}, pols).id == "t1"
        assert policy_for({"tier": "Tier 3"}, pols).id == "default"
        assert policy_for({"policy": "t1", "tier": "Tier 3"}, pols).id == "t1"
        (root / POLICY_FILE).write_text("{broken")
        assert load_policies(root)[0] == [] and "built-in default" in load_policies(root)[1][0]
    assert requires_pr("trivy", "pr") and not requires_pr("swarm", "pr")
    print("portfolio.policy: ok")


if __name__ == "__main__":
    demo()
