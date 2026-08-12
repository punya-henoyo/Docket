"""The finding model — the trust boundary where an LLM agent's tool call becomes a
structured, report-worthy record.

PoC.request/response are validated non-empty on purpose: a Finding cannot be
constructed without real reproduced evidence. That's what makes a finding
"validated" rather than "flagged" — enforced here, not by convention or review.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from enum import Enum
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(str, Enum):
    OPEN = "open"
    VALIDATED = "validated"  # PoC reproduced, not yet re-checked after a fix
    FIXED = "fixed"  # absent on a re-scan after being open on a prior scan


class Location(BaseModel):
    method: str  # "POST"
    path: str  # "/login" — route, not full URL; stable across host/port
    parameter: str | None = None  # "username"
    source_file: str | None = None  # "app.py:34", if the agent mapped route -> source


class PoC(BaseModel):
    request: str  # literal repro (curl command or raw HTTP text) — must be real
    response: str  # truncated real evidence (response body / stdout) — must be real
    notes: str | None = None

    @field_validator("request", "response")
    @classmethod
    def _non_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("PoC must contain real request/response evidence, not a claim")
        return v


class Triage(BaseModel):
    """An agent's judgement on whether a STATIC finding is reachable.

    Deliberately not folded into `poc`. A PoC is a reproduction — the thing that makes
    a finding "validated" rather than "flagged". Triage is weaker: it is reasoning over
    source about whether untrusted input can arrive, with no exploitation attempted.
    Keeping them separate stops a read-and-judge verdict from ever being mistaken for
    a reproduction.
    """

    verdict: Literal["exploitable", "not_reachable", "uncertain"]
    reasoning: str
    evidence: str  # file:line references the agent actually read


class Cvss(BaseModel):
    """A CVSS score docket RECEIVED. Never one docket computed.

    Scores here come from a scoring body (NVD, GHSA, a distro vendor) via trivy, or
    from a nuclei template's own classification. Docket does not derive CVSS for
    semgrep matches and must not: a CVSS vector encodes attack vector, privileges
    required, user interaction and CIA impact, none of which a pattern match knows.
    A guessed 9.8 is indistinguishable on screen from a measured one, so the guess is
    simply not made and the field stays None.

    `source` and `vector` are carried alongside the number on purpose. Scoring bodies
    disagree — CVE-2024-56201 is 8.8 from NVD and 7.3 from Red Hat, with different
    vectors — so a bare number with no attribution is not auditable.

    IMPORTANT: this rates the vulnerability CLASS, not this codebase's exposure to it.
    A 9.8 in a dependency the application never calls is still published as 9.8.
    Finding.triage is the counterweight; the two answer different questions.
    """

    score: float = Field(ge=0.0, le=10.0)
    vector: str | None = None  # "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N"
    version: str = "3.1"  # "3.1" | "3.0" | "4.0"
    source: str  # "nvd" | "ghsa" | "redhat" | "nuclei-template"

    @property
    def rating(self) -> str:
        """CVSS v3.1 qualitative severity bands (spec section 5)."""
        if self.score == 0:
            return "none"
        if self.score < 4.0:
            return "low"
        if self.score < 7.0:
            return "medium"
        if self.score < 9.0:
            return "high"
        return "critical"


class Finding(BaseModel):
    id: str = Field(default_factory=lambda: uuid4().hex)  # internal only, not report-facing
    rule_id: str  # "sql-injection" | "command-injection" | "reflected-xss"
    cwe: str | None = None  # "CWE-89"
    title: str
    severity: Severity
    location: Location
    description: str
    poc: PoC
    discovered_by: str  # agent/role name, e.g. "sqli-agent"
    discovered_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    status: FindingStatus = FindingStatus.VALIDATED
    corroborating_evidence: list[PoC] = Field(default_factory=list)  # filled by dedupe merges
    # Set by the triage pass (core/triage.py) for static findings. None means
    # nobody looked, which is different from "looked and was unsure" (uncertain).
    triage: Triage | None = None
    # Published by a scoring body, not computed here. None for semgrep matches,
    # which have no CVSS and must not be given an invented one.
    cvss: Cvss | None = None
    # Set by merge_static() when several rules matched one line and were folded into
    # this finding. Empty on an unmerged finding.
    merged_rules: list[str] = Field(default_factory=list)
    # Only populated when the merged rules DISAGREED about the weakness. Semgrep's
    # CWE metadata is wrong often enough that a single confident CWE on a folded
    # finding would be a claim docket cannot support.
    merged_cwes: list[str] = Field(default_factory=list)

    @property
    def dedupe_key(self) -> str:
        """Same (rule, route, param) from two agents/payloads -> same key. Reused verbatim
        as the SARIF partialFingerprints value (docket/report/sarif.py)."""
        raw = f"{self.rule_id}|{self.location.method}|{self.location.path}|{self.location.parameter or ''}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]


def demo() -> None:
    from pydantic import ValidationError

    f = Finding(
        rule_id="sql-injection",
        title="SQLi in /login",
        severity=Severity.HIGH,
        location=Location(method="POST", path="/login", parameter="username"),
        description="username is f-string'd into the SQL query",
        poc=PoC(request="curl -d \"username=' OR '1'='1\" ...", response="200 Welcome"),
        discovered_by="sqli-agent",
    )
    assert f.dedupe_key == Finding(
        rule_id="sql-injection",
        title="different title, same route/param",
        severity=Severity.LOW,
        location=Location(method="POST", path="/login", parameter="username"),
        description="...",
        poc=PoC(request="x", response="y"),
        discovered_by="other-agent",
    ).dedupe_key

    try:
        PoC(request="curl ...", response="")
        raise AssertionError("should have rejected empty response")
    except ValidationError:
        pass

    # Triage is optional and separate from the PoC: a verdict is reasoning, never a
    # reproduction, and must not be able to masquerade as one.
    assert f.triage is None
    f.triage = Triage(verdict="not_reachable", reasoning="only called from tests",
                      evidence="tests/conftest.py:14")
    dumped = f.model_dump(mode="json")
    assert dumped["triage"]["verdict"] == "not_reachable"
    assert "triage" not in dumped["poc"]
    print("models: ok")


if __name__ == "__main__":
    demo()
