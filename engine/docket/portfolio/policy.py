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

from docket.portfolio.catalog import BY_ID, CATALOG, PROFILE_VOCAB, tool_availability

POLICY_FILE = "docket_policy.json"
DEFAULT_CADENCE_DAYS = 7
MAX_POLICY_BYTES = 1_000_000
_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
EFFECTS = ("blocks", "flags", "advises")
PROFILE_FIELDS = tuple(PROFILE_VOCAB)          # category, exposure, stack, tier
STATUSES = ("saved", "draft")

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
    # Which applications it is for: field -> accepted values; an empty list leaves the field
    # unconstrained. v1 `applies_tier` is read as `applies_when["tier"]`.
    applies_when: dict[str, list[str]] = field(
        default_factory=lambda: {k: [] for k in PROFILE_FIELDS})
    # Compliance pack ids the policy advises against (advisory only; AGENTS.md rule 15).
    guidelines: list[str] = field(default_factory=list)
    status: str = "saved"

    def specificity(self) -> int:
        """How many profile fields the policy constrains: more is more specific."""
        return sum(1 for v in self.applies_when.values() if v)

    def step(self, step_id: str) -> dict[str, Any] | None:
        return next((s for s in self.steps if s["id"] == step_id), None)

    def required_ids(self) -> list[str]:
        return [s["id"] for s in self.steps if s["required"]]

    def window_days(self, step_id: str) -> int:
        step = self.step(step_id)
        return int((step or {}).get("cadence_days") or self.cadence_days)


def _step(id_: str, required: bool, **extra: Any) -> dict[str, Any]:
    return {"id": id_, "required": required, "cadence_days": None, "cadence": None,
            "on_fail": None, "why": [], "tool": None, **extra}


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


def _applies_when(raw: dict[str, Any], where: str, warn: list[str]) -> dict[str, list[str]] | None:
    """`applies_when` (and the v1 `applies_tier`, read as its tier list), or None to drop.

    An unknown key drops the policy: a typo such as "exposures" would otherwise leave the field
    unconstrained, and the policy would silently apply to every application."""
    given = raw.get("applies_when")
    if given is None:
        given = {}
    if not isinstance(given, dict):
        warn.append(f"{where}: applies_when must be an object")
        return None
    unknown = sorted(set(given) - set(PROFILE_FIELDS))
    if unknown:
        warn.append(f"{where}: applies_when has unknown field {unknown[0]!r}; "
                    f"known: {', '.join(PROFILE_FIELDS)}")
        return None
    when: dict[str, list[str]] = {}
    for key in PROFILE_FIELDS:
        values = given.get(key) or []
        if not isinstance(values, list) or not all(isinstance(v, str) and v.strip() for v in values):
            warn.append(f"{where}: applies_when.{key} must be a list of non-empty strings")
            return None
        when[key] = list(dict.fromkeys(v.strip() for v in values))
    legacy = raw.get("applies_tier") or []
    if isinstance(legacy, list) and not when["tier"]:
        when["tier"] = [str(t) for t in legacy]
    return when


def _guidelines(raw: Any, cwd: Path | None, where: str, warn: list[str]) -> list[str] | None:
    if raw is None:
        return []
    if not isinstance(raw, list) or not all(isinstance(g, str) for g in raw):
        warn.append(f"{where}: guidelines must be a list of compliance pack ids")
        return None
    out: list[str] = []
    for gid in dict.fromkeys(raw):
        if _resolve_ref(gid, cwd) is None or ":" in gid:
            warn.append(f"{where}: guideline {gid!r} matches no compliance pack")
            return None
        out.append(gid)
    return out


def _describe(when: dict[str, list[str]]) -> str:
    """A sentence for a policy that did not write one."""
    parts = [" or ".join(when[k]) for k in ("category", "exposure", "stack", "tier") if when.get(k)]
    return ("Applications that are " + ", ".join(parts)) if parts else "Every application"


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
        tool = item.get("tool")
        if tool is not None:
            avail = tool_availability(sid, tool) if isinstance(tool, str) else None
            if avail is None:
                warn.append(f"{where}: step {sid}: {tool!r} is not a tool that can fill this slot")
                return None
            if avail == "planned":
                warn.append(f"{where}: step {sid}: {tool} is planned, not available yet; "
                            "choose a tool Docket runs or imports")
                return None
        why = [w for w in (_why(w, cwd, warn, f"{where}: step {sid}")
                           for w in item.get("why") or []) if w]
        steps.append(_step(sid, required, cadence_days=step_days,
                           cadence=item.get("cadence"), on_fail=item.get("on_fail"), why=why,
                           tool=tool))
    if not any(st["required"] for st in steps):
        warn.append(f"{where}: at least one step must be required; a policy that requires nothing "
                    "would put every application in the 'checks current' half")
        return None
    when = _applies_when(raw, where, warn)
    if when is None:
        return None
    guidelines = _guidelines(raw.get("guidelines"), cwd, where, warn)
    if guidelines is None:
        return None
    explicit = [w for w in (_why({**w, "kind": "regulatory"} if isinstance(w, dict) else w,
                                 cwd, warn, f"{where}: regulatory")
                            for w in raw.get("regulatory") or []) if w]
    from_guidelines = [w for w in (_why({"kind": "regulatory", "obligation_ref": g},
                                        cwd, warn, f"{where}: guidelines") for g in guidelines) if w]
    from_steps = [w for st in steps for w in st["why"] if w["kind"] == "regulatory"]
    regulatory: list[dict[str, Any]] = []
    for w in [*from_guidelines, *explicit, *from_steps]:        # one row per obligation
        if not any(w["obligation_ref"] and w["obligation_ref"] == r["obligation_ref"]
                   for r in regulatory):
            regulatory.append(w)
    security = [{"text": str(s.get("text")), "detail": str(s.get("detail") or "")}
                for s in raw.get("security") or [] if isinstance(s, dict) and s.get("text")]
    status = raw.get("status")
    if status is not None and status not in STATUSES:
        warn.append(f"{where}: status must be one of {', '.join(STATUSES)}")
        return None
    thresholds = {k: int(v) for k, v in (raw.get("thresholds") or {}).items()
                  if isinstance(v, int) and not isinstance(v, bool) and v >= 0}
    return Policy(
        id=pid, name=name, applies=str(raw.get("applies") or "") or _describe(when),
        applies_tier=list(when["tier"]), applies_when=when, guidelines=guidelines,
        status=status or "saved",
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


def profile_of(app: dict[str, Any]) -> dict[str, str | None]:
    """The application's value for each profile field, None when missing or blank."""
    out: dict[str, str | None] = {}
    for key in PROFILE_FIELDS:
        value = app.get(key)
        out[key] = str(value).strip() if value is not None and str(value).strip() else None
    return out


def _matches(pol: Policy, profile: dict[str, str | None]) -> bool:
    return all(not allowed or profile[key] in allowed for key, allowed in pol.applies_when.items())


def assign(app: dict[str, Any], policies: list[Policy]) -> dict[str, Any]:
    """The one assignment function (spec section 3), used everywhere.

    Returns `{policy, via, incomplete, overrides, tie}`; `policy` is the Policy object.

    * an explicit `policy` id wins: via "pinned", and `overrides` is the id the profile would
      otherwise have matched when that differs
    * else the most specific matching policy (most constrained fields): via "matched"
    * else a policy marked `default`, else the built-in default: via "default"
    * `incomplete` lists profile fields the application lacks that some policy constrains.
      It still gets the best policy; the health card says so (fail closed on gaps)
    * `tie` names the other policies equally specific for this application. The first in file
      order is used; saving a policy that creates one is refused (see `find_ties`)
    """
    profile = profile_of(app)
    by_id = {p.id: p for p in policies}
    constrained = {key for p in policies for key, allowed in p.applies_when.items() if allowed}
    incomplete = [k for k in PROFILE_FIELDS if k in constrained and profile[k] is None]

    candidates = [p for p in policies if _matches(p, profile)]
    top = max((p.specificity() for p in candidates), default=-1)
    best = [p for p in candidates if p.specificity() == top]
    if best:
        chosen, via, tie = best[0], "matched", [p.id for p in best[1:]]
    else:
        chosen = next((p for p in policies if p.default), None) or default_policy()
        via, tie = "default", []
    pinned = by_id.get(app.get("policy"))
    if pinned is not None:
        return {"policy": pinned, "via": "pinned", "incomplete": incomplete, "tie": [],
                "overrides": chosen.id if chosen.id != pinned.id else None}
    return {"policy": chosen, "via": via, "incomplete": incomplete, "overrides": None, "tie": tie}


def policy_for(app: dict[str, Any], policies: list[Policy]) -> Policy:
    """The policy that governs `app`; see `assign`."""
    return assign(app, policies)["policy"]


def find_ties(policies: list[Policy]) -> list[tuple[str, str]]:
    """Pairs of policies that could both match one application at equal specificity.

    Decided on the policies alone, not on today's applications, so a tie does not wait for the
    first application that exposes it. Two policies are jointly satisfiable when every field
    both constrain shares a value; equal specificity then means neither outranks the other."""
    pairs: list[tuple[str, str]] = []
    for i, a in enumerate(policies):
        for b in policies[i + 1:]:
            if a.specificity() != b.specificity():
                continue
            if all(not a.applies_when[k] or not b.applies_when[k]
                   or set(a.applies_when[k]) & set(b.applies_when[k]) for k in PROFILE_FIELDS):
                pairs.append((a.id, b.id))
    return pairs


def floor_warnings(policy: Policy) -> list[str]:
    """Where a policy is thinner than the baseline (a warning, never a block).

    A policy whose `applies_when` can match customer-facing applications must require trivy,
    semgrep and triage; one that can match customer-facing BANKING applications must also
    require the exploit swarm. This stops an author raising every dot by requiring less."""
    exposure = policy.applies_when.get("exposure") or []
    category = policy.applies_when.get("category") or []
    if exposure and "Customer-facing" not in exposure:
        return []
    banking = not category or "Banking" in category
    need = ["trivy", "semgrep", "triage"] + (["swarm"] if banking else [])
    have = set(policy.required_ids())
    missing = [BY_ID[s].label for s in need if s not in have]
    if not missing:
        return []
    scope = "customer-facing banking applications" if banking else "customer-facing applications"
    return [f"Thinner than the baseline for {scope}: it does not require "
            + ", ".join(missing[:-1]) + (" or " if len(missing) > 1 else "") + missing[-1]]


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
    _demo_assign()
    print("portfolio.policy: ok")


def _demo_assign() -> None:
    def pol(pid: str, when: dict[str, list[str]], **extra: Any) -> Policy:
        warn: list[str] = []
        got = parse_policy({"id": pid, "name": pid, "applies_when": when,
                            "steps": [{"id": "trivy", "required": True}], **extra}, None, warn)
        assert got is not None, warn
        return got

    bank = pol("bank", {"category": ["Banking"]})
    bank_cust = pol("bank-cust", {"category": ["Banking"], "exposure": ["Customer-facing"]})
    internal = pol("internal", {"exposure": ["Internal"]})
    pols = [bank, bank_cust, internal]
    app = {"category": "Banking", "exposure": "Customer-facing", "tier": "Tier 1"}
    got = assign(app, pols)
    assert (got["policy"].id, got["via"], got["incomplete"], got["overrides"]) == (
        "bank-cust", "matched", [], None), got                      # most specific wins
    pinned = assign({**app, "policy": "internal"}, pols)
    assert (pinned["policy"].id, pinned["via"], pinned["overrides"]) == ("internal", "pinned", "bank-cust")
    assert assign({**app, "policy": "bank-cust"}, pols)["overrides"] is None
    gap = assign({"category": "Banking"}, pols)                     # exposure is missing
    assert gap["policy"].id == "bank" and gap["incomplete"] == ["exposure"], gap
    assert assign({"category": "Non-banking", "exposure": "Partner-facing"}, pols)["via"] == "default"
    assert assign({}, [])["incomplete"] == [] and assign({}, [])["policy"].id == "default"
    twin = pol("twin", {"category": ["Banking"]})
    assert assign(app, [bank, twin])["tie"] == ["twin"]
    assert find_ties([bank, twin]) == [("bank", "twin")] and find_ties(pols) == [("bank", "internal")]   # a Banking internal app fits both
    # Equal specificity but never both at once: no tie.
    assert find_ties([pol("a", {"category": ["Banking"]}), pol("b", {"category": ["Non-banking"]})]) == []
    legacy = pol("legacy", {}, applies_tier=["Tier 2"])
    assert legacy.applies_when["tier"] == ["Tier 2"] and legacy.applies_tier == ["Tier 2"]
    warns: list[str] = []
    assert parse_policy({"id": "x", "name": "x", "steps": ["trivy"],
                         "applies_when": {"exposures": ["Internal"]}}, None, warns) is None
    assert parse_policy({"id": "x", "name": "x", "steps": [{"id": "trivy", "tool": "grype"}]},
                        None, warns) is None and "planned" in warns[-1]
    assert parse_policy({"id": "x", "name": "x", "steps": [{"id": "trivy", "tool": "codeql"}]},
                        None, warns) is None and "can fill" in warns[-1]
    assert parse_policy({"id": "x", "name": "x", "steps": ["trivy"], "guidelines": ["nope"]},
                        None, warns) is None
    thin = pol("thin", {"exposure": ["Customer-facing"], "category": ["Banking"]})
    assert "Thinner than the baseline" in floor_warnings(thin)[0] and "Exploit swarm" in floor_warnings(thin)[0]
    assert floor_warnings(internal) == []
    full = parse_policy({"id": "full", "name": "f", "applies_when": {"category": ["Non-banking"]},
                         "guidelines": ["owasp-api-2023"],
                         "steps": [{"id": s, "required": True} for s in ("trivy", "semgrep", "triage")]},
                        None, [])
    assert full is not None and floor_warnings(full) == []
    assert full.regulatory[0]["authority"] == "OWASP" and full.regulatory[0]["clause"] is None


if __name__ == "__main__":
    demo()
