"""Control results: judgements, not reproductions, and not even candidates.

Docket already has two kinds of claim and keeps them in two lists on purpose. A
`Finding` (report/models.py) is a REPRODUCTION — its `PoC.request`/`PoC.response` are
validated non-empty because the guarantee that a finding was actually exploited is the
product. A `StaticFinding` (static/models.py) is a PATTERN MATCH, which is why it got its
own type rather than a Finding with empty fields.

A `ControlResult` is a third thing: an agent's reading of whether a codebase satisfies a
written requirement. Its evidence is a CITATION — the same currency as `Triage.evidence`,
a file:line somebody read — and the ceiling on what it can ever claim is set here rather
than argued about downstream. It lives in its own module for the same reason
static/models.py does: report/models.py IS the statement of the evidence invariant, and a
weaker claim living in that file is how the PoC validator eventually gets loosened "just
for this one case".

Three consequences are enforced by the types below rather than by convention:

  - a status that CLAIMS something about this codebase (pass/fail/not_applicable) cannot
    be constructed without at least one citation, on any code path and not just the
    tool path;
  - a control nobody can answer by reading source (`observability != SOURCE`) is never
    handed to an agent at all — its result is written by code as NOT_OBSERVABLE, so the
    model never gets the chance to invent a board minute out of a README;
  - there is no `score` field and no `percent` field on the rollup. See PackResult.
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from docket.report.models import Severity


class Observability(str, Enum):
    """Can reading this repository answer the control AT ALL?

    The single most load-bearing field in a pack. "The board shall review the cyber
    security policy annually" is PROCESS: no scanner, at any budget, ever answers it.
    Marking that honestly when the pack is authored is what keeps an agent from being
    asked a question it can only bluff, and what keeps the clause out of the score's
    denominator (see PackResult.assessed).

    Most of RBI's and SEBI's frameworks are PROCESS. Saying so is the honest product.
    """

    SOURCE = "source"  # the repository answers it: code, config, IaC, CI, manifests
    RUNTIME = "runtime"  # needs the deployed system (TLS at the load balancer, WAF rules)
    PROCESS = "process"  # an organisational artifact: a policy, a board minute, a drill


class ControlStatus(str, Enum):
    PASS = "pass"  # observed satisfied, cited
    FAIL = "fail"  # observed violated, cited
    NOT_APPLICABLE = "not_applicable"  # the precondition does not exist here, cited
    UNKNOWN = "unknown"  # looked, could not settle it. The safe default.
    NOT_OBSERVABLE = "not_observable"  # out of scope for source reading. Set by CODE only.


# Statuses that assert something about THIS codebase, and therefore owe evidence.
CLAIMS = frozenset({ControlStatus.PASS, ControlStatus.FAIL, ControlStatus.NOT_APPLICABLE})
# What a model is allowed to emit. NOT_OBSERVABLE is a deterministic property of the
# control, never a verdict, so it is deliberately absent.
AGENT_STATUSES = CLAIMS | frozenset({ControlStatus.UNKNOWN})


def parse_status(raw: object) -> ControlStatus:
    """Anything unrecognised is UNKNOWN. The same three-valued discipline as
    core.triage.parse_verdict, for the same reason (AGENTS.md rule 12).

    Never PASS: that is compliance's FALSE_POSITIVE — the value that makes a real gap
    disappear. Never FAIL: a false accusation about a customer's codebase, which in a
    regulated pack is one they may have to explain to a regulator. Never NOT_OBSERVABLE:
    a model may not claim that a question was out of scope for the work it skipped.

    UNKNOWN is the only value that is wrong in neither direction.
    """
    try:
        status = ControlStatus(str(raw or "").strip().lower())
    except ValueError:
        return ControlStatus.UNKNOWN
    return status if status in AGENT_STATUSES else ControlStatus.UNKNOWN


class Control(BaseModel):
    """One requirement. Authored by us in a pack file, or extracted from a policy upload."""

    model_config = ConfigDict(extra="forbid")  # a typo'd pack key must not be silently dropped

    id: str  # "owasp-api-2023:API1" | "sebi-cscrf:GV.PO.S1"
    title: str
    # The obligation itself, quoted verbatim where docket has the authority's text (every
    # uploaded policy) and stated plainly where it does not (the built-in packs, which say
    # so in `ControlPack.notes`). Either way `citation` locates the clause, so an auditor
    # asking "where does docket get this from" is answerable without guessing.
    requirement: str
    observability: Observability = Observability.PROCESS  # failure-safe: assume unanswerable
    severity: Severity = Severity.MEDIUM
    # Where this came from in the authority document. Non-negotiable for an uploaded
    # policy: a control nobody can trace back to a clause is our invention, not theirs.
    citation: str = ""
    evidence_hint: str = ""  # what to look for. Free help, no claim attached.
    # Deterministic cross-link keys, matched by CODE at report-build time (never by the
    # agent). See compliance.link.link_findings.
    cwe: list[str] = Field(default_factory=list)  # ["CWE-89"]
    rule_ids: list[str] = Field(default_factory=list)  # rule LEAVES: ["sql-injection"]

    @field_validator("id", "title", "requirement")
    @classmethod
    def _non_empty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("a control needs an id, a title and its verbatim requirement")
        return value


class ControlPack(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    title: str
    authority: str  # "OWASP" | "RBI" | "SEBI" | "customer"
    version: str = ""
    origin: Literal["builtin", "uploaded"] = "builtin"
    source_url: str = ""
    notes: str = ""
    controls: list[Control] = Field(default_factory=list)

    def source_controls(self) -> list[Control]:
        """The only controls an agent is ever shown."""
        return [c for c in self.controls if c.observability is Observability.SOURCE]


class Citation(BaseModel):
    """The compliance analogue of PoC — weaker on purpose, and named so.

    `PoC` is request/response: something that HAPPENED. This is file/line/quote:
    something that was READ. Triage draws the same line for reachability, and it is drawn
    again here so a control verdict can never be mistaken for a reproduction.

    The quote is deliberately NOT required to match the file byte for byte: models
    normalise whitespace, and rejecting that would downgrade honest work. File existence
    is the hard check (verified against the scanned tree by the finish tool); the quote is
    what a human opens to check for themselves.
    """

    model_config = ConfigDict(extra="forbid")

    file: str
    line: int | None = None
    quote: str = ""

    @field_validator("file")
    @classmethod
    def _non_empty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("a citation must name a file")
        return value

    def __str__(self) -> str:
        return f"{self.file}:{self.line}" if self.line else self.file


class ControlResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    control_id: str
    status: ControlStatus = ControlStatus.UNKNOWN  # the safe default, even as a field default
    rationale: str
    citations: list[Citation] = Field(default_factory=list)
    # For UNKNOWN: what was searched before giving up. Mirrors triage's rule that
    # `uncertain` still owes you its evidence — it is an answer, not a way to skip work.
    looked_at: str = ""
    judged_by: str = ""  # agent id, or "" when the runner synthesised this
    judged_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    # Set by CODE at report-build time, never by the agent. dedupe_keys of findings that
    # independently PROVED / CONTRADICTED this control's weakness class.
    proven_findings: list[str] = Field(default_factory=list)
    contradicted_by: list[str] = Field(default_factory=list)
    # Audit trail when the finish tool refused to take a claim at face value.
    downgraded_from: ControlStatus | None = None
    # True once a second, focused agent looked at this control again.
    escalated: bool = False

    @model_validator(mode="after")
    def _evidence_discipline(self) -> ControlResult:
        """The PoC validator's analogue. Necessary but not sufficient — the finish tool
        does the legible refusal — but this means no code path anywhere in docket can
        build an uncited claim about a customer's codebase, not merely the tool path."""
        if not self.rationale.strip():
            raise ValueError("a control result must say why")
        if self.status in CLAIMS and not self.citations:
            raise ValueError(
                f"status={self.status.value} claims something about this codebase and must "
                "cite at least one file that was read"
            )
        if self.status is ControlStatus.UNKNOWN and not (
            self.looked_at.strip() or self.citations
        ):
            raise ValueError("`unknown` must record what was looked at")
        return self


class PackResult(BaseModel):
    """One pack's outcome for one run.

    NOTE WHAT IS ABSENT: no `score`, no `percent`, no `compliant`. Not an oversight — a
    field is an invitation, and the first dashboard that finds one divides by the pack
    size. The two honest ratios move in OPPOSITE directions (an agent that gives up on
    every hard control scores 100% on what is left), so any single number rewards exactly
    the failure mode you most need to see. `coverage` and `label` exist instead.
    """

    model_config = ConfigDict(extra="forbid")

    pack_id: str
    pack_title: str
    authority: str
    version: str = ""
    origin: Literal["builtin", "uploaded"] = "builtin"
    total_controls: int  # every control in the pack, process ones included
    results: list[ControlResult] = Field(default_factory=list)
    # Completeness, which is a different question from "what did we find" — the same
    # question triage_requested/judged/unjudged answers one field up.
    requested: int = 0  # source-observable controls handed to an agent
    judged: int = 0  # results an agent actually produced
    unjudged: int = 0  # results the RUNNER synthesised because the agent never got there

    @property
    def counts(self) -> dict[str, int]:
        out = {status.value: 0 for status in ControlStatus}
        for result in self.results:
            out[result.status.value] += 1
        return out

    @property
    def assessed(self) -> int:
        """The ONLY honest denominator: controls where an agent actually cited code.

        Not the pack size, and not the judged count. `not_observable` is excluded because
        it was never in scope; `not_applicable` is excluded because "you are not exposed
        to this" is not "you satisfy this", and folding the two together is the single
        easiest way to manufacture a 94%.
        """
        counts = self.counts
        return counts["pass"] + counts["fail"]

    @property
    def coverage(self) -> float:
        """How much of the pack was answerable AND answered. Falls when the agent flails,
        which is the property a single pass-rate does not have."""
        return self.assessed / self.total_controls if self.total_controls else 0.0

    @property
    def label(self) -> str:
        """The one sentence every surface renders. A property rather than a template in
        the frontend, so nobody does their own arithmetic on the way to a tile."""
        counts = self.counts
        if not self.assessed:
            return (
                f"{self.pack_title}: no control could be assessed from source "
                f"({self.total_controls} in the pack)."
            )
        return (
            f"{self.pack_title}: {counts['pass']} of {self.assessed} source-checkable "
            f"controls satisfied, {counts['fail']} not. "
            f"{counts['not_observable']} cannot be answered from code, "
            f"{counts['unknown']} inconclusive, "
            f"{counts['not_applicable']} do not apply. "
            f"Pack has {self.total_controls}."
        )


def demo() -> None:
    # --- parse_status: the two dangerous directions, and the one safe landing ----------
    assert parse_status("fail") is ControlStatus.FAIL
    assert parse_status("PASS") is ControlStatus.PASS
    assert parse_status("  Not_Applicable ") is ControlStatus.NOT_APPLICABLE
    # Free text must never resolve to a claim. "definitely compliant" is exactly the kind
    # of thing a model says when it is guessing.
    assert parse_status("definitely compliant") is ControlStatus.UNKNOWN
    assert parse_status(None) is ControlStatus.UNKNOWN
    assert parse_status("") is ControlStatus.UNKNOWN
    # A model may not claim a question was out of scope for work it skipped.
    assert parse_status("not_observable") is ControlStatus.UNKNOWN

    # --- Control -----------------------------------------------------------------------
    control = Control(
        id="owasp-api-2023:API1",
        title="Broken Object Level Authorization",
        requirement="APIs must verify the caller is authorised for the object requested.",
        observability=Observability.SOURCE,
        severity=Severity.HIGH,
        cwe=["CWE-639"],
        rule_ids=["idor"],
    )
    assert control.severity is Severity.HIGH
    # Unanswerable unless the pack author says otherwise: the failure-safe default.
    assert Control(id="x", title="t", requirement="r").observability is Observability.PROCESS
    for bad in ({"id": " ", "title": "t", "requirement": "r"},
                {"id": "x", "title": "t", "requirement": ""}):
        try:
            Control(**bad)
            raise AssertionError(f"accepted an empty required field: {bad}")
        except ValueError:
            pass

    pack = ControlPack(
        id="demo", title="Demo pack", authority="docket",
        controls=[control, Control(id="demo:P1", title="Board review", requirement="annual")],
    )
    # Only SOURCE controls are ever shown to an agent.
    assert [c.id for c in pack.source_controls()] == ["owasp-api-2023:API1"], pack

    # --- ControlResult: a claim without a citation cannot be CONSTRUCTED ----------------
    try:
        ControlResult(control_id="c", status=ControlStatus.PASS, rationale="looks fine")
        raise AssertionError("built an uncited pass")
    except ValueError:
        pass
    try:
        ControlResult(control_id="c", status=ControlStatus.FAIL, rationale="bad")
        raise AssertionError("built an uncited fail")
    except ValueError:
        pass
    # ...and "not exposed to this" is a claim too: it needs the absence shown somewhere.
    try:
        ControlResult(control_id="c", status=ControlStatus.NOT_APPLICABLE, rationale="n/a")
        raise AssertionError("built an uncited not_applicable")
    except ValueError:
        pass
    try:
        ControlResult(control_id="c", status=ControlStatus.PASS, rationale="",
                      citations=[Citation(file="app.py", line=1)])
        raise AssertionError("built a result with no rationale")
    except ValueError:
        pass
    # `unknown` still owes its work: it is an answer, not a way to skip one.
    try:
        ControlResult(control_id="c", status=ControlStatus.UNKNOWN, rationale="dunno")
        raise AssertionError("built an unknown that recorded nothing")
    except ValueError:
        pass
    ok_unknown = ControlResult(control_id="c", rationale="no auth layer found",
                               looked_at="grepped for @login_required, middleware/")
    assert ok_unknown.status is ControlStatus.UNKNOWN, ok_unknown  # the default
    assert Citation(file="app.py").line is None
    try:
        Citation(file="   ")
        raise AssertionError("accepted a citation naming no file")
    except ValueError:
        pass

    passed = ControlResult(control_id="owasp-api-2023:API1", status=ControlStatus.PASS,
                           rationale="every handler filters by owner_id",
                           citations=[Citation(file="app/views.py", line=42,
                                               quote="Order.objects.get(id=pk, owner=request.user)")])
    assert str(passed.citations[0]) == "app/views.py:42"

    # --- PackResult: the score that does not exist --------------------------------------
    assert not hasattr(PackResult, "score"), "a score field is an invitation; see the docstring"
    failed = ControlResult(control_id="demo:F", status=ControlStatus.FAIL,
                           rationale="DEBUG=True in settings",
                           citations=[Citation(file="settings.py", line=7)])
    na = ControlResult(control_id="demo:N", status=ControlStatus.NOT_APPLICABLE,
                       rationale="no object storage in this repo",
                       citations=[Citation(file="requirements.txt")])
    unobs = ControlResult(control_id="demo:P1", status=ControlStatus.NOT_OBSERVABLE,
                          rationale="organisational control; source cannot answer it")
    result = PackResult(pack_id="demo", pack_title="Demo pack", authority="docket",
                        total_controls=10,
                        results=[passed, failed, na, unobs, ok_unknown],
                        requested=4, judged=4, unjudged=0)
    counts = result.counts
    assert counts["pass"] == 1 and counts["fail"] == 1, counts
    # Neither not_applicable nor not_observable may inflate the denominator.
    assert result.assessed == 2, result.assessed
    assert result.coverage == 0.2, result.coverage

    # The label is the product promise, so it is asserted rather than trusted.
    label = result.label
    assert "1 of 2 source-checkable controls satisfied" in label, label
    assert "1 cannot be answered from code" in label, label
    # The word that must never appear: it is what turns an evidence-based review into an
    # attestation nobody can defend to a regulator.
    assert "compliant" not in label.lower(), label

    # A pack where nothing could be assessed says so, rather than dividing by zero or
    # rendering a perfect 100% over an empty set.
    empty = PackResult(pack_id="e", pack_title="Empty", authority="x", total_controls=45,
                       results=[unobs])
    assert "no control could be assessed" in empty.label, empty.label
    assert "compliant" not in empty.label.lower(), empty.label
    assert empty.assessed == 0 and empty.coverage == 0.0
    # ...and a pack with no controls at all must not raise on the division.
    assert PackResult(pack_id="z", pack_title="Z", authority="x", total_controls=0).coverage == 0.0

    print("compliance.models: ok")


if __name__ == "__main__":
    demo()
