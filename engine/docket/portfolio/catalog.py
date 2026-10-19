"""The scanner catalog: what Docket can run, who made it, and where it sits in a scan.

One table, in code, because the console draws a pipeline from it and a policy refers to
its ids. A policy file names steps by `id`; everything else about a step (label, tool,
origin, phase, icon) is looked up here so a policy cannot misspell a tool or claim a
third-party scanner is a Henoyo engine.

ORIGIN IS A CLAIM ABOUT WHO WROTE THE DETECTION, and the console shows it. `third_party`
is Trivy, Semgrep and Nuclei, whose output Docket orchestrates. `henoyo` is everything
Henoyo wrote: the agents, and the API Security engine, which reports through the same
shapes when it is wired in (Docket does not run it yet, so for a real run it is absent).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class Scanner:
    id: str
    label: str
    tool: str | None
    origin: str          # "third_party" | "henoyo"
    phase: str           # "pre" | "agents"
    stage: str | None    # key in report.json `stages` / `stage_timings`; None for the swarm
    icon: str
    # Which kinds of scan the step normally applies to. A pull-request check is scoped and
    # static, so the API Security engine and the exploit swarm are not expected on one;
    # without this every PR would read as "partial coverage" for a reason nobody can act on.
    kinds: tuple[str, ...] = ("scan",)


CATALOG: tuple[Scanner, ...] = (
    Scanner("trivy", "Dependencies and secrets", "Trivy", "third_party", "pre", "trivy",
            "package", ("scan", "pr")),
    Scanner("semgrep", "Static analysis", "Semgrep", "third_party", "pre", "semgrep",
            "file-code", ("scan", "pr")),
    Scanner("nuclei", "Web templates", "Nuclei", "third_party", "pre", "nuclei", "radar"),
    Scanner("apisec", "API Security engine", None, "henoyo", "pre", "apisec", "shield-alert"),
    Scanner("recon", "Attack-surface recon", None, "henoyo", "agents", "recon", "crosshair"),
    Scanner("triage", "Triage", None, "henoyo", "agents", "triage", "brain", ("scan", "pr")),
    Scanner("compliance", "Compliance reader", None, "henoyo", "agents", "compliance",
            "scroll-text"),
    Scanner("swarm", "Exploit swarm", None, "henoyo", "agents", None, "crosshair"),
    Scanner("fix", "Fix proposals", None, "henoyo", "agents", "fix", "wrench"),
)

BY_ID: dict[str, Scanner] = {s.id: s for s in CATALOG}

GROUPS: tuple[dict[str, str], ...] = (
    {"key": "pre", "label": "Before the agents",
     "sub": "Deterministic scanners, run in policy order"},
    {"key": "agents", "label": "Docket agents",
     "sub": "Henoyo exploit validation: recon, triage, compliance, exploit, fix"},
)

# The exploit specialists the root agent can spawn (agents/factory.py SpecialistRole).
# `label` names a lane, `by` names the author of a finding.
SPECIALISTS: dict[str, dict[str, str]] = {
    "sqli": {"label": "SQL injection", "by": "Docket SQLi specialist"},
    "cmdi": {"label": "Command injection", "by": "Docket command-injection specialist"},
    "xss": {"label": "Cross-site scripting", "by": "Docket XSS specialist"},
    "idor": {"label": "Object-level authorisation", "by": "Docket IDOR specialist"},
    "ssrf": {"label": "SSRF", "by": "Docket SSRF specialist"},
}

# Engines whose output is a PATTERN MATCH or advisory, never a reproduction. `recon` is in
# here deliberately: its candidates enter the store with status OPEN and discovered_by
# "recon" (core/runner.py), and an agent that merely read the code has not exploited it.
NON_REPRODUCING = frozenset({"trivy", "semgrep", "nuclei", "apisec", "recon", "triage"})

AGENTS_BUCKET = "Docket agents"


@dataclass(frozen=True, slots=True)
class Source:
    """Who produced a finding, in the two vocabularies the console needs."""

    kind: str            # "engine" | "agent"
    engine: str | None   # catalog id for an engine, else None
    role: str | None     # specialist role for a swarm agent, else None
    origin: str          # "third_party" | "henoyo"
    name: str            # shown next to the finding
    bucket: str          # the by_origin row it rolls up into


def classify_source(discovered_by: object, *, imported: bool = False) -> Source:
    """Map report.json `discovered_by` onto a Source.

    `discovered_by` is free text an agent chose ("sqli-agent"), so an agent is recognised
    by a role keyword inside it. Anything unrecognised is still a Henoyo agent: the only
    non-agent sources are the named engines, and a name docket does not know must not be
    credited to a third party.

    The one exception is a label that is KNOWN to be a tool name: `imported=True` is for
    static candidates from an ingested SARIF, whose `engine` is the file's own
    `tool.driver.name` ("CodeQL", "Bandit"). Such a name that is not in the catalog is
    credited to that third party, under its own name, and not to Docket's agents. Free text
    on a proven finding (`discovered_by`) never passes `imported`, so it keeps the rule above.
    """
    raw = str(discovered_by or "").strip().lower()
    if raw in BY_ID and BY_ID[raw].id in NON_REPRODUCING:
        scanner = BY_ID[raw]
        name = scanner.tool or scanner.label
        bucket = scanner.tool or scanner.label
        if scanner.origin == "henoyo":
            bucket = AGENTS_BUCKET if scanner.id in ("recon", "triage") else scanner.label
        return Source("engine", scanner.id, None, scanner.origin,
                      name if scanner.origin == "third_party" else f"Docket {scanner.label.lower()}"
                      if scanner.id != "apisec" else scanner.label, bucket)
    if imported and raw:
        name = str(discovered_by).strip()
        return Source("engine", None, None, "third_party", name, name)
    keys = {"sqli": ("sqli", "sql-injection", "sql_injection"),
            "cmdi": ("cmdi", "command"),
            "xss": ("xss",),
            "idor": ("idor", "bola"),
            "ssrf": ("ssrf",)}
    for role, needles in keys.items():
        if any(n in raw for n in needles):
            return Source("agent", None, role, "henoyo", SPECIALISTS[role]["by"], AGENTS_BUCKET)
    return Source("agent", None, None, "henoyo", "Docket agents", AGENTS_BUCKET)


# --- slots, tools and the catalog payload (docs/ui/policy-and-posture.md, section 3) -----------
#
# A policy step's `id` names a SLOT; `tool` picks the vendor that fills it. Availability is a
# statement about Docket today, not about the vendor:
#   runs      Docket runs it
#   imports   Docket ingests its SARIF results and records that the slot ran (spec 3a)
#   planned   visible and disabled, never selectable, never saved
# `imports` is honest only for the static-analysis slot, and only once the SARIF path records
# a stage. That work lands separately; the engine owner flips this flag when it does. Until
# then every SARIF-importing alternative reads `planned`.
SARIF_STAGE_RECORDED = True

PROFILE_VOCAB: dict[str, tuple[str, ...]] = {
    "category": ("Banking", "Non-banking"),
    "exposure": ("Customer-facing", "Partner-facing", "Internal"),
    "stack": ("Web", "API", "Mobile", "Batch"),
    "tier": ("Tier 1", "Tier 2", "Tier 3"),
}

# (what it does, what it produces, the command Docket really issues). Text is true to the code
# in tools/scanners and core/: it describes the run, not the marketing.
_SLOT_TEXT: dict[str, tuple[str, str, str]] = {
    "trivy": ("Reads dependency manifests for known CVEs and the tree for hardcoded secrets.",
              "Dependency advisories and secret candidates (never findings until triaged or deterministic)",
              "trivy fs --scanners vuln,secret --format json --quiet --skip-dirs docket_runs /work/source"),
    "semgrep": ("Reads source for injection and unsafe patterns.",
                "Static candidates (never findings until proven)",
                "semgrep scan --config p/default --json --quiet --metrics=off /work/source"),
    "nuclei": ("Probes a running staging site with known-exposure templates.",
               "Exposure candidates against the staging URL",
               "nuclei -u <staging url> -jsonl -irr -silent -duc -severity low,medium,high,critical"),
    "apisec": ("Tests every exposed endpoint for authentication, rate limits and CORS.",
               "API weaknesses, reported through the same shapes as the other scanners",
               "Henoyo API Security engine (not wired into Docket runs yet)"),
    "recon": ("Maps the routes and sinks the exploit agents will try.",
              "An attack-surface map and ranked leads",
              "Docket recon agent (reads the source and the discovered surface)"),
    "triage": ("Reads each scanner hit against the source and judges it.",
               "A verdict per lead: confirmed, not reachable, or uncertain",
               "Docket triage agent (source reads only, no network)"),
    "compliance": ("Reads the code against the selected guideline packs, control by control.",
                   "Cited control results (advisory; never findings, never a score)",
                   "Docket compliance agent (source-observable controls only)"),
    "swarm": ("Exploit specialists try to reproduce each lead against the running target.",
              "Findings with a reproduced proof of concept",
              "Docket root agent and specialists (sqli, cmdi, xss, idor, ssrf) in the sandbox"),
    "fix": ("Proposes a patch for each proven exploit and checks that the reproduction closes.",
            "A patch and a pull request per proven exploit",
            "Docket fix agent (writes a patched copy, re-runs the proof)"),
}

# Alternatives per slot: (tool id, display name, origin, availability or None for "decided by
# the SARIF flag"). The first entry of each slot is its default.
_SARIF_TOOLS: tuple[tuple[str, str], ...] = (
    ("codeql", "CodeQL"), ("sonarqube", "SonarQube"), ("checkmarx", "Checkmarx"),
    ("snyk-code", "Snyk Code"), ("veracode", "Veracode"), ("sarif", "Any SARIF 2.1.0 tool"))
_ALTERNATIVES: dict[str, tuple[tuple[str, str, str, str | None], ...]] = {
    "trivy": (("trivy", "Trivy", "third_party", "runs"),
              ("grype", "Grype", "third_party", "planned"),
              ("snyk-oss", "Snyk Open Source", "third_party", "planned"),
              ("gitleaks", "Gitleaks", "third_party", "planned"),
              ("dependency-check", "OWASP Dependency-Check", "third_party", "planned")),
    "semgrep": (("semgrep", "Semgrep", "third_party", "runs"),
                *((i, n, "third_party", None) for i, n in _SARIF_TOOLS)),
    "nuclei": (("nuclei", "Nuclei", "third_party", "runs"),
               ("zap", "OWASP ZAP", "third_party", "planned")),
    "apisec": (("henoyo-apisec", "Henoyo API Security engine", "henoyo", "planned"),),
    "recon": (("docket-recon", "Docket recon agent", "henoyo", "runs"),),
    "triage": (("docket-triage", "Docket triage agent", "henoyo", "runs"),),
    "compliance": (("docket-compliance", "Docket compliance reader", "henoyo", "runs"),),
    "swarm": (("docket-swarm", "Docket exploit swarm", "henoyo", "runs"),),
    "fix": (("docket-fix", "Docket fix agent", "henoyo", "runs"),),
}

STARTS: tuple[dict[str, str], ...] = (
    {"kind": "manual", "label": "Run now", "availability": "works"},
    {"kind": "pull_request", "label": "Pull request", "availability": "works",
     "note": "where the repository is watched"},
    {"kind": "schedule", "label": "Every N days", "availability": "planned",
     "note": "the cadence is judged, not started"},
    {"kind": "release", "label": "Release tag", "availability": "planned"},
)


def slot_tools(slot_id: str) -> list[dict[str, Any]]:
    """The tools that can fill a slot, availability resolved (the SARIF flag applied)."""
    out: list[dict[str, Any]] = []
    for n, (tid, name, origin, avail) in enumerate(_ALTERNATIVES.get(slot_id, ())):
        if avail is None:
            avail = "imports" if SARIF_STAGE_RECORDED else "planned"
        row: dict[str, Any] = {"id": tid, "name": name, "origin": origin, "availability": avail}
        if n == 0:
            row["default"] = True
        out.append(row)
    return out


def slot_text(slot_id: str) -> tuple[str, str, str]:
    """(what it does, what it produces, the command) for a slot."""
    return _SLOT_TEXT[slot_id]


def tool_availability(slot_id: str, tool_id: str) -> str | None:
    """`runs` | `imports` | `planned`, or None when `tool_id` is not an alternative of the slot."""
    return next((t["availability"] for t in slot_tools(slot_id) if t["id"] == tool_id), None)


def default_tool(slot_id: str) -> dict[str, Any] | None:
    return next((t for t in slot_tools(slot_id) if t.get("default")), None)


def slots() -> list[dict[str, Any]]:
    out = []
    for sc in CATALOG:
        what, produces, command = _SLOT_TEXT[sc.id]
        out.append({"id": sc.id, "label": sc.label, "capability": _CAPABILITY[sc.id],
                    "phase": sc.phase, "icon": sc.icon, "origin": sc.origin, "what": what,
                    "produces": produces, "command": command, "tools": slot_tools(sc.id)})
    return out


_CAPABILITY = {"trivy": "sca", "semgrep": "sast", "nuclei": "dast", "apisec": "api",
               "recon": "recon", "triage": "triage", "compliance": "compliance",
               "swarm": "exploit", "fix": "fix"}


def profile_options(cwd: Any = None) -> dict[str, list[str]]:
    """Option lists for the profile chips: the fixed vocabulary first, then any other value
    that appears in the portfolio or in a policy's `applies_when`, so the picker never hides
    a value somebody already used."""
    from docket.portfolio.model import disk
    from docket.portfolio.policy import load_policies

    seen: dict[str, list[str]] = {k: list(v) for k, v in PROFILE_VOCAB.items()}
    extras: dict[str, set[str]] = {k: set() for k in PROFILE_VOCAB}
    for entry in disk.read_portfolio(cwd).get("applications") or []:
        if isinstance(entry, dict):
            for key in PROFILE_VOCAB:
                if isinstance(entry.get(key), str) and entry[key].strip():
                    extras[key].add(entry[key].strip())
    for pol in load_policies(cwd)[0]:
        for key in PROFILE_VOCAB:
            extras[key].update(pol.applies_when.get(key, []))
    for key, more in extras.items():
        seen[key] += sorted(v for v in more if v not in seen[key])
    return seen


def guidelines(cwd: Any = None) -> list[dict[str, Any]]:
    """Compliance packs a policy can select, with the honest headline: how many of the
    controls an agent can answer from source (`observable`), not just how many exist."""
    from docket.compliance.packs import list_packs

    return [{"id": r["id"], "authority": r["authority"], "title": r["title"],
             "version": r.get("version") or None, "controls": r["total_controls"],
             "observable": r["source_controls"], "source_url": r.get("source_url") or None,
             "origin": r.get("origin")}
            for r in list_packs(cwd=cwd) if r.get("usable")]


def catalog_payload(cwd: Any = None) -> tuple[int, dict[str, Any]]:
    """GET /api/catalog."""
    return 200, {"slots": slots(), "starts": [dict(s) for s in STARTS],
                 "profile": profile_options(cwd), "guidelines": guidelines(cwd)}


def _demo_catalog() -> None:
    ids = [s["id"] for s in slots()]
    assert ids == [s.id for s in CATALOG]
    for slot in slots():
        tools = slot["tools"]
        assert sum(1 for t in tools if t.get("default")) == 1, slot["id"]
        assert slot["what"] and slot["produces"] and slot["command"]
        assert all(t["availability"] in ("runs", "imports", "planned") for t in tools)
    assert tool_availability("trivy", "trivy") == "runs"
    assert tool_availability("trivy", "grype") == "planned"
    assert tool_availability("trivy", "codeql") is None             # not an alternative here
    assert tool_availability("semgrep", "codeql") == ("imports" if SARIF_STAGE_RECORDED else "planned")
    assert tool_availability("apisec", "henoyo-apisec") == "planned"
    # Imports are honest only for static analysis.
    assert not any(t["availability"] == "imports" for s in slots() if s["id"] != "semgrep"
                   for t in s["tools"])
    assert [s["kind"] for s in STARTS] == ["manual", "pull_request", "schedule", "release"]
    assert [s["availability"] for s in STARTS if s["kind"] in ("schedule", "release")] == ["planned"] * 2
    status, body = catalog_payload(None)
    assert status == 200 and set(body) == {"slots", "starts", "profile", "guidelines"}
    assert body["profile"]["category"][:2] == ["Banking", "Non-banking"]
    packs = {g["id"]: g for g in body["guidelines"]}
    assert packs["rbi-csf"]["authority"] == "RBI" and 0 < packs["rbi-csf"]["observable"] <= packs["rbi-csf"]["controls"]


def demo() -> None:
    assert [s.id for s in CATALOG] == ["trivy", "semgrep", "nuclei", "apisec", "recon",
                                       "triage", "compliance", "swarm", "fix"]
    assert BY_ID["trivy"].origin == "third_party" and BY_ID["apisec"].origin == "henoyo"
    assert {s.phase for s in CATALOG} == {g["key"] for g in GROUPS}
    # Only the swarm has no stage key: its times come from agent events.
    assert [s.id for s in CATALOG if s.stage is None] == ["swarm"]

    t = classify_source("trivy")
    assert (t.kind, t.engine, t.origin, t.name, t.bucket) == (
        "engine", "trivy", "third_party", "Trivy", "Trivy"), t
    assert classify_source("Semgrep").bucket == "Semgrep"
    a = classify_source("apisec")
    assert (a.origin, a.name, a.bucket) == ("henoyo", "API Security engine", "API Security engine")
    # Recon candidates are a read of the code, not an exploit, and roll up with the agents.
    r = classify_source("recon")
    assert r.kind == "engine" and r.bucket == AGENTS_BUCKET and r.origin == "henoyo", r
    s = classify_source("sqli-agent")
    assert (s.kind, s.role, s.name, s.bucket) == (
        "agent", "sqli", "Docket SQLi specialist", AGENTS_BUCKET), s
    assert classify_source("idor-agent").role == "idor"
    # Unknown text is credited to Docket's agents, never to a third party.
    u = classify_source("mystery-bot")
    assert (u.kind, u.origin, u.role) == ("agent", "henoyo", None), u
    assert classify_source(None).kind == "agent"
    # An imported SARIF names its own tool: unknown names go to that third party, by name.
    c = classify_source("CodeQL", imported=True)
    assert (c.kind, c.engine, c.origin, c.name, c.bucket) == (
        "engine", None, "third_party", "CodeQL", "CodeQL"), c
    assert classify_source("Semgrep OSS", imported=True).origin == "third_party"
    # Known catalog ids keep their catalog row, and empty text is still not a tool.
    assert classify_source("semgrep", imported=True).engine == "semgrep"
    assert classify_source("", imported=True).origin == "henoyo"
    # Without `imported`, an unknown name is still an agent (proven-finding free text).
    assert classify_source("CodeQL").origin == "henoyo"
    _demo_catalog()
    print("portfolio.catalog: ok")


if __name__ == "__main__":
    demo()
