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


def classify_source(discovered_by: object) -> Source:
    """Map report.json `discovered_by` onto a Source.

    `discovered_by` is free text an agent chose ("sqli-agent"), so an agent is recognised
    by a role keyword inside it. Anything unrecognised is still a Henoyo agent: the only
    non-agent sources are the named engines, and a name docket does not know must not be
    credited to a third party.
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
    keys = {"sqli": ("sqli", "sql-injection", "sql_injection"),
            "cmdi": ("cmdi", "command"),
            "xss": ("xss",),
            "idor": ("idor", "bola"),
            "ssrf": ("ssrf",)}
    for role, needles in keys.items():
        if any(n in raw for n in needles):
            return Source("agent", None, role, "henoyo", SPECIALISTS[role]["by"], AGENTS_BUCKET)
    return Source("agent", None, None, "henoyo", "Docket agents", AGENTS_BUCKET)


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
    print("portfolio.catalog: ok")


if __name__ == "__main__":
    demo()
