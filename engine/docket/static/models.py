"""Static findings: candidates, not results.

The distinction is the whole point. A `report.models.Finding` is a reproduction — its
PoC request and response are validated non-empty at construction, which is why nothing
unproven can enter a docket report. A StaticFinding has neither, and never will: no
request was sent and no response observed. It is a *lead*.

So it gets its own type rather than a Finding with empty fields. Two reasons. A shared
type would force the evidence validator to accept blanks, which deletes the guarantee for
every finding, not just these. And it keeps the report honest structurally: proven and
flagged are different lists, so nothing downstream can accidentally present a lead as a
confirmed exploit.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path

# Semgrep/SARIF severities mapped onto ours. Deliberately conservative: a static tool's
# "ERROR" means "this pattern is dangerous", not "this is exploitable here", so nothing
# static is ever admitted as `critical`. Critical is reserved for proven exploitation.
_SARIF_LEVEL_TO_SEVERITY = {"error": "high", "warning": "medium", "note": "low",
                            "none": "info"}


@dataclass(frozen=True, slots=True)
class StaticFinding:
    rule_id: str
    message: str
    file: str
    line: int
    severity: str = "medium"
    cwe: str | None = None
    snippet: str | None = None
    engine: str = "sarif"
    end_line: int | None = None

    @property
    def key(self) -> tuple[str, str, int]:
        return (self.rule_id, self.file, self.line)

    def describe(self) -> str:
        bits = [f"{self.file}:{self.line}", self.rule_id]
        if self.cwe:
            bits.append(self.cwe)
        bits.append(self.message.strip().replace("\n", " ")[:160])
        return " | ".join(bits)


@dataclass(slots=True)
class StaticReport:
    findings: list[StaticFinding] = field(default_factory=list)
    engines: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def add(self, finding: StaticFinding) -> bool:
        """Dedupe on (rule, file, line). Two engines flagging the same line is one lead."""
        if any(f.key == finding.key for f in self.findings):
            return False
        self.findings.append(finding)
        return True

    def __len__(self) -> int:
        return len(self.findings)

    def to_dict(self) -> dict:
        return {"engines": self.engines, "notes": self.notes,
                "finding_count": len(self.findings),
                "findings": [asdict(f) for f in self.findings]}

    def save(self, run_dir: Path) -> Path:
        path = Path(run_dir) / "static.json"
        path.write_text(json.dumps(self.to_dict(), indent=2))
        return path


def cwe_from_tags(tags: list) -> str | None:
    """SARIF tools put CWEs in rule tags in several shapes: "CWE-89", "cwe-89",
    "external/cwe/cwe-89". Normalised to "CWE-89"."""
    for tag in tags or []:
        text = str(tag)
        lowered = text.lower()
        if "cwe-" not in lowered:
            continue
        digits = lowered.split("cwe-", 1)[1]
        number = ""
        for char in digits:                     # stop at the first non-digit, so
            if not char.isdigit():              # "cwe-89-improper" gives 89, not 89
                break
            number += char
        if number:
            # int() drops leading zeros: tools emit "cwe-079", the canonical form is
            # CWE-79, and docket's own SARIF tags must match for these to correlate.
            return f"CWE-{int(number)}"
    return None


def parse_sarif(document: dict, *, engine: str | None = None) -> StaticReport:
    """Ingest any SAST tool's SARIF 2.x. Semgrep, CodeQL, Bandit, gosec all fit.

    Reading the standard rather than one tool's native JSON is what makes this work with
    whatever the team already runs in CI, at no extra cost — and docket already emits
    SARIF, so the format was in the codebase before this module existed.
    """
    report = StaticReport()
    for run in document.get("runs") or []:
        driver = ((run.get("tool") or {}).get("driver") or {})
        name = engine or driver.get("name") or "sarif"
        if name not in report.engines:
            report.engines.append(name)

        # Rule metadata lives separately from results and carries the CWE tags.
        rules: dict[str, dict] = {}
        for rule in driver.get("rules") or []:
            if isinstance(rule, dict) and rule.get("id"):
                rules[rule["id"]] = rule

        for result in run.get("results") or []:
            if not isinstance(result, dict):
                continue
            rule_id = result.get("ruleId") or "unknown"
            rule = rules.get(rule_id, {})
            locations = result.get("locations") or []
            physical = ((locations[0] if locations else {}) or {}).get("physicalLocation") or {}
            artifact = (physical.get("artifactLocation") or {}).get("uri") or ""
            region = physical.get("region") or {}
            tags = ((rule.get("properties") or {}).get("tags")) or []
            report.add(StaticFinding(
                rule_id=rule_id,
                message=((result.get("message") or {}).get("text")
                          or (rule.get("shortDescription") or {}).get("text") or ""),
                file=artifact.removeprefix("file://").lstrip("/") or "unknown",
                line=int(region.get("startLine") or 0),
                end_line=int(region["endLine"]) if region.get("endLine") else None,
                severity=_SARIF_LEVEL_TO_SEVERITY.get(
                    str(result.get("level") or rule.get("defaultConfiguration", {}).get("level")
                        or "warning").lower(), "medium"),
                cwe=cwe_from_tags(tags),
                snippet=(region.get("snippet") or {}).get("text"),
                engine=name,
            ))
    return report


def demo() -> None:
    import shutil
    import tempfile

    sarif = {
        "runs": [{
            "tool": {"driver": {"name": "semgrep", "rules": [
                {"id": "python.lang.security.sqli",
                 "properties": {"tags": ["security", "external/cwe/cwe-89"]},
                 "shortDescription": {"text": "SQL injection"}},
                {"id": "python.lang.security.cmdi",
                 "properties": {"tags": ["CWE-78"]}},
            ]}},
            "results": [
                {"ruleId": "python.lang.security.sqli", "level": "error",
                 "message": {"text": "user input in query"},
                 "locations": [{"physicalLocation": {
                     "artifactLocation": {"uri": "file:///app/app.py"},
                     "region": {"startLine": 34, "endLine": 34,
                                 "snippet": {"text": "query = f\"...{username}...\""}}}}]},
                {"ruleId": "python.lang.security.cmdi", "level": "warning",
                 "message": {"text": "os.system with user input"},
                 "locations": [{"physicalLocation": {
                     "artifactLocation": {"uri": "app.py"},
                     "region": {"startLine": 47}}}]},
                # A true duplicate of the first: SAME rule, file and line, as a second
                # engine (or a second semgrep rule pack) would report it.
                {"ruleId": "python.lang.security.sqli", "level": "error",
                 "message": {"text": "again"},
                 "locations": [{"physicalLocation": {
                     "artifactLocation": {"uri": "file:///app/app.py"},
                     "region": {"startLine": 34}}}]},
            ],
        }],
    }
    report = parse_sarif(sarif)
    assert report.engines == ["semgrep"]
    # The duplicate rule+file+line collapsed, so 3 results become 2 findings.
    assert len(report) == 2, [f.key for f in report.findings]
    by_line = {f.line: f for f in report.findings}
    # file:// stripped. Note the two entries keep DIFFERENT paths on purpose: without a
    # source root there is no safe way to decide that "app.py" and "/app/app.py" are the
    # same file, and merging them on a guess would hide a real second finding.
    assert by_line[34].file == "app/app.py" and by_line[34].cwe == "CWE-89"
    assert by_line[47].file == "app.py"
    assert by_line[47].cwe == "CWE-78"
    # error -> high, warning -> medium. NOTHING static becomes critical.
    assert by_line[34].severity == "high" and by_line[47].severity == "medium"
    assert all(f.severity != "critical" for f in report.findings)
    assert "username" in by_line[34].snippet

    assert cwe_from_tags(["CWE-89"]) == "CWE-89"
    assert cwe_from_tags(["external/cwe/cwe-079"]) == "CWE-79"
    assert cwe_from_tags(["security", "audit"]) is None
    assert cwe_from_tags([]) is None

    # Malformed SARIF yields an empty report rather than raising into a scan.
    assert len(parse_sarif({})) == 0
    assert len(parse_sarif({"runs": [{}]})) == 0
    assert len(parse_sarif({"runs": [{"results": [{"ruleId": "x"}]}]})) == 1

    line = by_line[34].describe()
    assert "app/app.py:34" in line and "CWE-89" in line

    tmp = Path(tempfile.mkdtemp())
    try:
        path = report.save(tmp)
        assert path.name == "static.json"
        back = json.loads(path.read_text())
        assert back["finding_count"] == 2 and back["engines"] == ["semgrep"]
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print("static.models: ok")


if __name__ == "__main__":
    demo()
