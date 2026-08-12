"""Run a triage agent per static candidate and collect its verdict.

The product this replaces is a list of 40 maybes. What comes out is the same 40 rows with
a verdict, a reason, and quoted source, so the reader starts with the ones an engineer that
read the code thinks are real.

Concurrency is bounded and candidates are capped. A repo can produce hundreds of Semgrep
hits, and one agent per hit is one model conversation per hit — left unbounded that is an
unpriced, unbounded bill. The cap is REPORTED when it bites, never silent: a truncated
triage pass that reads as a complete one is the same lie as a truncated scan that does.
"""
from __future__ import annotations

import asyncio
from dataclasses import asdict, dataclass, field

from docket.agents.factory import build_agent
from docket.agents.prompts.triage import build_task
from docket.core.execution import ScanContext, run_agent_loop
from docket.static.correlate import Lead

MAX_CANDIDATES = 40
MAX_CONCURRENT = 4
TRIAGE_TURNS = 14

VERDICTS = ("CONFIRMED", "FALSE_POSITIVE", "UNCERTAIN")


@dataclass(slots=True)
class Verdict:
    lead: Lead
    verdict: str                      # one of VERDICTS
    reasoning: str
    ok: bool = True                   # False if the agent failed rather than ruled

    def to_dict(self) -> dict:
        finding = self.lead.finding
        return {
            "rule_id": finding.rule_id, "engine": finding.engine,
            "severity": finding.severity, "cwe": finding.cwe,
            "file": finding.file, "line": finding.line, "message": finding.message,
            "endpoint": (f"{self.lead.endpoint.method} {self.lead.endpoint.path}"
                          if self.lead.endpoint else None),
            "correlation_confidence": self.lead.confidence,
            "verdict": self.verdict, "reasoning": self.reasoning,
            "triaged": self.ok,
        }


@dataclass(slots=True)
class TriageReport:
    verdicts: list[Verdict] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def counts(self) -> dict[str, int]:
        out = {v: 0 for v in VERDICTS}
        for verdict in self.verdicts:
            out[verdict.verdict] = out.get(verdict.verdict, 0) + 1
        return out

    def summary(self) -> str:
        c = self.counts()
        return (f"{len(self.verdicts)} candidate(s) triaged: {c['CONFIRMED']} confirmed, "
                f"{c['FALSE_POSITIVE']} false positive, {c['UNCERTAIN']} uncertain")


def parse_verdict(output: dict) -> tuple[str, str]:
    """Pull a verdict out of the finish tool's summary.

    The agent ends via `agent_finish`, whose contract is a free-text summary — so the
    verdict is read out of that text rather than a dedicated field. Anything unrecognised
    becomes UNCERTAIN, never CONFIRMED and never FALSE_POSITIVE: an unparseable answer must
    not silently become the verdict that gets someone breached, nor inflate the confirmed
    count.
    """
    text = str((output or {}).get("summary") or "")
    upper = text.upper()
    # FALSE_POSITIVE is checked first: "not a false positive" is rare, but "CONFIRMED it is
    # a FALSE_POSITIVE" is not, and the more specific token should win.
    for token in ("FALSE_POSITIVE", "FALSE POSITIVE"):
        if token in upper:
            return "FALSE_POSITIVE", text
    if "CONFIRMED" in upper:
        return "CONFIRMED", text
    if "UNCERTAIN" in upper:
        return "UNCERTAIN", text
    return "UNCERTAIN", text or "agent produced no verdict"


async def triage_all(
    leads: list[Lead], context: ScanContext, *, max_candidates: int = MAX_CANDIDATES,
    max_concurrent: int = MAX_CONCURRENT,
) -> TriageReport:
    report = TriageReport()
    if not leads:
        report.notes.append("no static candidates to triage")
        return report
    if not context.source_root:
        report.notes.append("no source tree available, so nothing could be triaged")
        return report

    selected = leads[:max_candidates]
    if len(leads) > max_candidates:
        report.notes.append(
            f"triaged the first {max_candidates} of {len(leads)} candidates; "
            f"{len(leads) - max_candidates} were NOT looked at"
        )

    gate = asyncio.Semaphore(max_concurrent)

    async def one(index: int, lead: Lead) -> Verdict:
        async with gate:
            child = ScanContext(
                target_url=context.target_url, run_dir=context.run_dir,
                on_finding=None,              # triage files nothing; it rules on candidates
                agent_id=f"triage-{index}", role="triage",
                coordinator=context.coordinator, config=context.config,
                model_override=context.model_override, sandbox=context.sandbox,
                source_root=context.source_root,
            )
            model = context.model_override("triage") if context.model_override else None
            agent = build_agent("triage", context.config, model=model)
            # asdict, not __dict__: StaticFinding is slots=True and has no __dict__.
            task = build_task(asdict(lead.finding) | {
                "endpoint": (f"{lead.endpoint.method} {lead.endpoint.path}"
                              if lead.endpoint else None),
            }, context.source_root)
            try:
                output = await run_agent_loop(agent, child, task, max_turns=TRIAGE_TURNS)
            except Exception as exc:
                return Verdict(lead, "UNCERTAIN", f"triage failed: {exc!r}", ok=False)
            verdict, reasoning = parse_verdict(output)
            return Verdict(lead, verdict, reasoning, ok=bool(output.get("success", True)))

    report.verdicts = list(await asyncio.gather(
        *(one(i, lead) for i, lead in enumerate(selected))
    ))
    return report


def demo() -> None:
    from docket.discovery.models import Endpoint
    from docket.static.models import StaticFinding

    # --- verdict parsing: the load-bearing bit ---------------------------------------
    assert parse_verdict({"summary": "CONFIRMED: reaches the sink unguarded"})[0] == "CONFIRMED"
    assert parse_verdict({"summary": "FALSE_POSITIVE — escaped at a.py:3"})[0] == "FALSE_POSITIVE"
    assert parse_verdict({"summary": "false positive, see line 3"})[0] == "FALSE_POSITIVE"
    assert parse_verdict({"summary": "UNCERTAIN, could not follow the helper"})[0] == "UNCERTAIN"
    # The specific token wins over the generic one when both appear.
    assert parse_verdict({"summary": "CONFIRMED it is a FALSE_POSITIVE"})[0] == "FALSE_POSITIVE"
    # Anything unrecognised is UNCERTAIN — never CONFIRMED (which would inflate the count)
    # and never FALSE_POSITIVE (which is the verdict that gets someone breached).
    for junk in ("", "I had a look and it seems fine", None):
        assert parse_verdict({"summary": junk})[0] == "UNCERTAIN", junk
    assert parse_verdict({})[0] == "UNCERTAIN"
    assert parse_verdict(None)[0] == "UNCERTAIN"

    # --- aggregation ------------------------------------------------------------------
    lead = Lead(StaticFinding("r", "m", "a.py", 3, "high", "CWE-89"),
                 Endpoint("POST", "/login"), "high", "1 line above")
    report = TriageReport(verdicts=[
        Verdict(lead, "CONFIRMED", "x"), Verdict(lead, "CONFIRMED", "y"),
        Verdict(lead, "FALSE_POSITIVE", "z"), Verdict(lead, "UNCERTAIN", "w"),
    ])
    assert report.counts() == {"CONFIRMED": 2, "FALSE_POSITIVE": 1, "UNCERTAIN": 1}
    assert "2 confirmed, 1 false positive, 1 uncertain" in report.summary()

    row = report.verdicts[0].to_dict()
    assert row["file"] == "a.py" and row["line"] == 3 and row["cwe"] == "CWE-89"
    assert row["endpoint"] == "POST /login" and row["verdict"] == "CONFIRMED"

    # --- the caps are reported, never silent -----------------------------------------
    async def check_caps() -> None:
        ctx = ScanContext(target_url="", run_dir=__import__("pathlib").Path("."))
        empty = await triage_all([], ctx)
        assert "no static candidates" in empty.notes[0]
        # A source-less run cannot triage, and says so rather than returning zero verdicts
        # that would read as "nothing to worry about".
        no_source = await triage_all([lead], ctx)
        assert no_source.verdicts == []
        assert "no source tree available" in no_source.notes[0]

    asyncio.run(check_caps())

    # The task-building path, which the caps check above never reaches. This is where
    # `lead.finding.__dict__` failed live: StaticFinding is slots=True, so it has no
    # __dict__ at all, and the whole scan died with an AttributeError after Semgrep had
    # already run. Exercise it here rather than discovering it in a scan again.
    rendered = build_task(asdict(lead.finding) | {"endpoint": "POST /login"}, "/work/source")
    assert "a.py:3" in rendered and "POST /login" in rendered, rendered
    assert "CWE-89" in rendered

    print("static.triage: ok")


if __name__ == "__main__":
    demo()
