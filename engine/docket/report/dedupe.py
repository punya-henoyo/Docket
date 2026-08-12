"""FindingStore: the whole de-dupe engine. Two agents (or two payloads) hitting the
same rule/route/param collapse to one Finding with corroborating evidence appended,
keeping the more severe verdict.

Static findings need a second pass, because their duplicates do not share a rule id.
Semgrep ships the same check under several framework namespaces, so one line of code
comes back three times:

    app/api/v1.py:37
      python.sqlalchemy.security.audit.avoid-sqlalchemy-text   CWE-89
      python.django.security.injection.tainted-sql-string      CWE-915
      python.flask.security.injection.tainted-sql-string       CWE-704

That is one SQL injection, not three vulnerabilities, and the django rule should not
have fired on a Flask app at all. Note also that two of those CWEs are simply wrong —
CWE-915 and CWE-704 are semgrep metadata errors on the tainted-sql-string rules, and
they are why a SQLi rendered as "Uncontrolled object attribute modification".

merge_static() collapses these, but only on POSITIVE evidence that two matches are the
same issue: the same file:line AND (the same CWE OR the same rule leaf). Location
alone is deliberately not enough — app/search.py:32 carries both a template-injection
match and an XSS match, which really are two different weaknesses on one line, and
merging them would delete a finding.
"""
from __future__ import annotations

from docket.report.models import Finding


class FindingStore:
    def __init__(self) -> None:
        self._by_key: dict[str, Finding] = {}

    def add(self, finding: Finding) -> None:
        existing = self._by_key.get(finding.dedupe_key)
        if existing is None:
            self._by_key[finding.dedupe_key] = finding
            return
        existing.corroborating_evidence.append(finding.poc)
        # Severity is an ordered str Enum by declaration order (CRITICAL first) — lower
        # index in the enum members list is more severe.
        order = list(type(existing.severity))
        if order.index(finding.severity) < order.index(existing.severity):
            existing.severity = finding.severity

    def findings(self) -> list[Finding]:
        return list(self._by_key.values())

    def __len__(self) -> int:
        return len(self._by_key)


def rule_leaf(rule_id: str) -> str:
    """`semgrep/python.flask.security.injection.tainted-sql-string.tainted-sql-string`
    -> `tainted-sql-string`. Mirrors ruleLeaf() in the console so both halves group
    findings the same way."""
    return rule_id.rsplit("/", 1)[-1].rsplit(".", 1)[-1]


def _same_issue(a: Finding, b: Finding) -> bool:
    """Positive evidence that two matches at one location are one vulnerability."""
    if a.cwe and b.cwe and a.cwe == b.cwe:
        return True
    return rule_leaf(a.rule_id) == rule_leaf(b.rule_id)


def merge_static(findings: list[Finding]) -> list[Finding]:
    """Collapse same-location matches of the same issue. Input order is preserved.

    Only findings carrying a `source_file` participate: that field is `path:line`, so
    it identifies a location precisely. Dynamic findings are returned untouched — they
    are keyed by route and parameter and FindingStore already handles them.
    """
    groups: dict[str, list[list[Finding]]] = {}
    order: list[tuple[str, int]] = []  # (location, bucket index), in first-seen order
    passthrough: list[tuple[int, Finding]] = []

    for position, finding in enumerate(findings):
        location = finding.location.source_file
        if not location:
            passthrough.append((position, finding))
            continue
        buckets = groups.setdefault(location, [])
        for index, bucket in enumerate(buckets):
            # Transitive by design: flask+django tainted-sql-string share a leaf, and a
            # third match sharing a CWE with either joins the same bucket.
            if any(_same_issue(finding, member) for member in bucket):
                bucket.append(finding)
                break
        else:
            buckets.append([finding])
            order.append((location, len(buckets) - 1))

    merged: list[Finding] = []
    for location, index in order:
        bucket = groups[location][index]
        merged.append(bucket[0] if len(bucket) == 1 else _fold(bucket))

    # Rebuild in something close to the original order: passthrough findings keep their
    # relative position at the front, merged static findings follow in first-seen order.
    return [f for _, f in sorted(passthrough)] + merged if passthrough else merged


def _fold(bucket: list[Finding]) -> Finding:
    """One finding from many. Nothing is discarded: every merged rule id and every CWE
    claimed for the location is recorded on the survivor, because the rules disagree and
    hiding the disagreement would be the same mistake as reporting it three times."""
    order = list(type(bucket[0].severity))
    primary = min(bucket, key=lambda f: (order.index(f.severity), f.rule_id))
    others = [f for f in bucket if f is not primary]

    primary.corroborating_evidence.extend(f.poc for f in others)
    primary.merged_rules = sorted({f.rule_id for f in bucket})

    claimed = sorted({f.cwe for f in bucket if f.cwe})
    if len(claimed) > 1:
        # The rules disagree about the weakness, and docket cannot referee that.
        # Keeping one would mean picking arbitrarily: the survivor is chosen by
        # severity then rule id, which on a Flask project happens to favour the
        # django rule (it sorts first) and its metadata is the wrong one. Real case:
        # tainted-sql-string is asserted as CWE-915 "Uncontrolled object attribute
        # modification" and CWE-704 "Incorrect type conversion" for what is plainly
        # CWE-89. Showing "disputed" is worse-looking and more truthful than showing
        # a confident wrong answer.
        primary.cwe = None
        primary.merged_cwes = claimed
    else:
        primary.merged_cwes = []
    # A merged finding inherits the most severe verdict in the bucket, which `min`
    # above already selected; severity is not recomputed from the others.
    return primary


def demo() -> None:
    from docket.report.models import Location, PoC, Severity

    def make(rule: str, path: str, param: str, severity: Severity = Severity.HIGH) -> Finding:
        return Finding(
            rule_id=rule,
            title=f"{rule} at {path}",
            severity=severity,
            location=Location(method="POST", path=path, parameter=param),
            description="...",
            poc=PoC(request="req", response="resp"),
            discovered_by="test-agent",
        )

    store = FindingStore()
    store.add(make("sql-injection", "/login", "username"))
    store.add(make("sql-injection", "/login", "username", severity=Severity.CRITICAL))
    assert len(store) == 1
    only = store.findings()[0]
    assert len(only.corroborating_evidence) == 1
    assert only.severity == Severity.CRITICAL  # more severe verdict won

    store.add(make("command-injection", "/export", "file"))
    assert len(store) == 2

    # ── static merge ────────────────────────────────────────────────────────
    assert rule_leaf("semgrep/python.flask.security.injection.tainted-sql-string"
                     ".tainted-sql-string") == "tainted-sql-string"
    assert rule_leaf("trivy/CVE-2024-56201") == "CVE-2024-56201"

    def static(rule: str, at: str, cwe: str | None, severity: Severity = Severity.HIGH) -> Finding:
        return Finding(
            rule_id=rule, title=rule, severity=severity, cwe=cwe,
            location=Location(method="STATIC", path=at.split(":")[0], source_file=at),
            description="...", poc=PoC(request="code", response="match"),
            discovered_by="semgrep",
        )

    # The real shape from app/api/v1.py:37. The two tainted-sql-string rules share a
    # leaf despite disagreeing on CWE; avoid-sqlalchemy-text shares neither and stays.
    sqli = merge_static([
        static("semgrep/python.sqlalchemy.security.audit.avoid-sqlalchemy-text"
               ".avoid-sqlalchemy-text", "app/api/v1.py:37", "CWE-89"),
        static("semgrep/python.django.security.injection.tainted-sql-string"
               ".tainted-sql-string", "app/api/v1.py:37", "CWE-915"),
        static("semgrep/python.flask.security.injection.tainted-sql-string"
               ".tainted-sql-string", "app/api/v1.py:37", "CWE-704"),
    ])
    assert len(sqli) == 2, [f.rule_id for f in sqli]
    folded = [f for f in sqli if f.merged_rules]
    assert len(folded) == 1
    assert len(folded[0].merged_rules) == 2
    # The disagreement is recorded, not silently resolved.
    assert folded[0].merged_cwes == ["CWE-704", "CWE-915"], folded[0].merged_cwes
    assert folded[0].cwe is None, "a disputed weakness must not be asserted as fact"
    assert len(folded[0].corroborating_evidence) == 1

    # Same CWE, different leaves: one command injection, matched twice.
    cmd = merge_static([
        static("semgrep/python.flask.security.injection.os-system-injection"
               ".os-system-injection", "app/api/v1.py:46", "CWE-78"),
        static("semgrep/python.lang.security.dangerous-system-call"
               ".dangerous-system-call", "app/api/v1.py:46", "CWE-78"),
    ])
    assert len(cmd) == 1, [f.rule_id for f in cmd]
    assert cmd[0].merged_cwes == [], "one agreed CWE is not a disagreement"
    assert cmd[0].cwe == "CWE-78", "an agreed CWE survives the fold"

    # Two genuinely different weaknesses on one line must BOTH survive. This is why
    # location alone is not a merge key.
    mixed = merge_static([
        static("semgrep/python.flask.security.audit.render-template-string"
               ".render-template-string", "app/search.py:32", "CWE-96"),
        static("semgrep/python.django.security.injection.raw-html-format"
               ".raw-html-format", "app/search.py:32", "CWE-79"),
        static("semgrep/python.flask.security.injection.raw-html-concat"
               ".raw-html-format", "app/search.py:32", "CWE-79"),
    ])
    assert len(mixed) == 2, [f.rule_id for f in mixed]

    # Different files never merge, however alike the rules.
    apart = merge_static([
        static("semgrep/a.tainted-sql-string", "app/a.py:1", "CWE-89"),
        static("semgrep/b.tainted-sql-string", "app/b.py:1", "CWE-89"),
    ])
    assert len(apart) == 2

    # The more severe verdict survives a fold.
    sev = merge_static([
        static("semgrep/x.sqli", "app/c.py:9", "CWE-89", Severity.MEDIUM),
        static("semgrep/y.sqli", "app/c.py:9", "CWE-89", Severity.CRITICAL),
    ])
    assert len(sev) == 1 and sev[0].severity == Severity.CRITICAL

    # Findings with no source_file (dynamic) pass through untouched.
    dynamic = [make("sql-injection", "/login", "username")]
    assert merge_static(dynamic) == dynamic
    assert merge_static([]) == []

    print("dedupe: ok")


if __name__ == "__main__":
    demo()
