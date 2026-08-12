"""Correlate a static finding to the HTTP endpoint that reaches it.

This is the whole point of pairing SAST with docket. Semgrep says "line 34 concatenates
input into SQL". That is a maybe until somebody works out which request reaches line 34,
and that triage is the expensive part — it is what the README's first section says the
tool exists to delete. Give a specialist the pair (endpoint, sink) and it can go prove or
disprove it.

The heuristic is deliberately framework-agnostic: find the route path literal nearest
ABOVE the flagged line in the same file. It works for Flask decorators, FastAPI, Express,
Django and Rails alike, because all of them write the path as a string literal near the
handler, and none of them write it below the body. No AST, no per-framework plugin.

It is a heuristic, and it says so: every pairing carries a confidence and the reason, and
an unmatched finding is reported as unmatched rather than guessed onto the nearest
endpoint. A wrong pairing wastes a specialist's whole turn budget chasing the wrong route.

# ponytail: nearest-literal-above, no dataflow. A real call-graph would catch a sink in a
# helper module three files from its route; this will not. Upgrade when findings in shared
# helpers start mattering more than the endpoints themselves.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from docket.discovery.models import AttackSurface, Endpoint
from docket.static.models import StaticFinding

# How far above the flagged line a route literal can sit and still plausibly own it. A
# handler body longer than this usually means the sink lives in a helper, which this
# heuristic cannot follow anyway.
MAX_LOOKBACK_LINES = 120


@dataclass(frozen=True, slots=True)
class Lead:
    """A static finding plus the endpoint that probably reaches it."""
    finding: StaticFinding
    endpoint: Endpoint | None
    confidence: str            # "high" | "medium" | "none"
    why: str

    @property
    def reachable(self) -> bool:
        return self.endpoint is not None

    def describe(self) -> str:
        if self.endpoint is None:
            return f"{self.finding.describe()} — NO endpoint mapped ({self.why})"
        return (f"{self.endpoint.method} {self.endpoint.path} reaches "
                f"{self.finding.file}:{self.finding.line} "
                f"[{self.finding.rule_id}{', ' + self.finding.cwe if self.finding.cwe else ''}] "
                f"confidence {self.confidence} ({self.why})")


def _comment_starts_at(line: str) -> int:
    """Index where a line comment begins, or len(line) if there is none.

    Handles `#` (Python, Ruby, shell) and `//` (JS, Go, Java, PHP). `//` preceded by `:`
    is skipped so a URL literal like "http://host/login" is not mistaken for a comment.
    """
    best = len(line)
    hash_at = line.find("#")
    if hash_at != -1:
        best = hash_at
    start = 0
    while (slashes := line.find("//", start)) != -1:
        if slashes == 0 or line[slashes - 1] != ":":
            best = min(best, slashes)
            break
        start = slashes + 2
    return best


def _path_literal_lines(text: str, path: str) -> list[int]:
    """1-indexed lines where `path` appears as a quoted literal in CODE.

    Quoted and exact, so "/login" does not match "/login/callback". And not in a comment:
    a docstring or `# see /search` used to pair a finding with a route it has nothing to
    do with, which sends a specialist to spend its whole turn budget on the wrong endpoint.
    Caught by this module's own demo, which is the only reason it is handled.
    """
    if not path:
        return []
    pattern = re.compile(r"""['"`]""" + re.escape(path) + r"""(?:/)?['"`]""")
    lines = []
    for i, line in enumerate(text.splitlines(), start=1):
        match = pattern.search(line)
        if match and match.start() < _comment_starts_at(line):
            lines.append(i)
    return lines


def correlate(
    findings: list[StaticFinding],
    surface: AttackSurface | None,
    source_root: str | Path | None,
) -> list[Lead]:
    """Pair each static finding with an endpoint, or explicitly with none."""
    endpoints = list(getattr(surface, "endpoints", []) or [])
    root = Path(source_root) if source_root else None
    leads: list[Lead] = []
    cache: dict[str, str | None] = {}

    for finding in findings:
        if not endpoints:
            leads.append(Lead(finding, None, "none", "no discovered endpoints to match against"))
            continue
        if root is None:
            leads.append(Lead(finding, None, "none", "no --source, cannot read the file"))
            continue

        if finding.file not in cache:
            try:
                cache[finding.file] = (root / finding.file).read_text(errors="replace")
            except OSError:
                cache[finding.file] = None
        text = cache[finding.file]
        if text is None:
            leads.append(Lead(finding, None, "none", f"could not read {finding.file}"))
            continue

        best: tuple[int, Endpoint] | None = None
        for endpoint in endpoints:
            for line in _path_literal_lines(text, endpoint.path):
                distance = finding.line - line
                # At or above only. A route declared BELOW the sink does not own it, and
                # allowing it would pair a finding with whatever route happened to be next
                # in the file.
                if 0 <= distance <= MAX_LOOKBACK_LINES:
                    if best is None or distance < best[0]:
                        best = (distance, endpoint)

        if best is None:
            leads.append(Lead(
                finding, None, "none",
                "no discovered route path appears as a literal above this line — the sink "
                "may live in a helper, or the route may not have been discovered",
            ))
            continue
        distance, endpoint = best
        # Same line or a decorator directly above is about as certain as this gets.
        confidence = "high" if distance <= 8 else "medium"
        leads.append(Lead(finding, endpoint, confidence,
                           f"'{endpoint.path}' appears {distance} line(s) above"))
    return leads


def summarise(leads: list[Lead]) -> str:
    reachable = sum(1 for lead in leads if lead.reachable)
    return (f"{len(leads)} static candidate(s), {reachable} mapped to a discovered "
            f"endpoint, {len(leads) - reachable} unmapped")


def demo() -> None:
    import shutil
    import tempfile

    from docket.discovery.models import Param

    source = '''\
from flask import Flask, request
app = Flask(__name__)

@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    query = f"SELECT 1 FROM users WHERE username = '{username}'"   # line 7
    return run(query)

@app.route("/export")
def export():
    os.system("cat " + request.args["file"])                       # line 12

# a comment mentioning "/search" should not create a pairing
def helper():
    return dangerous(1)                                            # line 16
'''
    tmp = Path(tempfile.mkdtemp())
    try:
        (tmp / "app.py").write_text(source)
        surface = AttackSurface(target="http://t.test")
        surface.add(Endpoint("POST", "/login", params=(Param("username", "form"),)))
        surface.add(Endpoint("GET", "/export", params=(Param("file", "query"),)))
        surface.add(Endpoint("GET", "/search", params=(Param("q", "query"),)))

        sqli = StaticFinding("sqli", "sql injection", "app.py", 7, "high", "CWE-89")
        cmdi = StaticFinding("cmdi", "os.system", "app.py", 12, "high", "CWE-78")
        orphan = StaticFinding("orphan", "weak call", "app.py", 16, "medium")
        leads = {lead.finding.rule_id: lead for lead in
                 correlate([sqli, cmdi, orphan], surface, tmp)}

        assert leads["sqli"].endpoint.path == "/login", leads["sqli"].describe()
        assert leads["sqli"].confidence == "high"
        assert leads["cmdi"].endpoint.path == "/export"

        # A quoted path inside a COMMENT must not pair. Without this the orphan below
        # `# ... "/search" ...` was confidently mapped to GET /search.
        assert leads["orphan"].endpoint is None or leads["orphan"].endpoint.path != "/search", \
            leads["orphan"].describe()

        # KNOWN LIMITATION, pinned deliberately rather than wished away: `helper()` at
        # line 16 belongs to no route, but it sits 6 lines under the /export decorator, so
        # nearest-literal-above claims it. There is no dataflow here to know otherwise.
        # This is why every Lead carries a confidence and a reason, and why a specialist
        # is told to verify rather than trust the pairing.
        assert leads["orphan"].endpoint is not None
        assert leads["orphan"].endpoint.path == "/export"
        assert "line(s) above" in leads["orphan"].why

        # A finding with NO route literal above it anywhere is honestly unmapped.
        (tmp / "lonely.py").write_text("import os\nos.system(x)\n")
        lonely = correlate([StaticFinding("l", "m", "lonely.py", 2)], surface, tmp)[0]
        assert lonely.endpoint is None
        assert "no discovered route path" in lonely.why

        # A route declared BELOW the sink must not claim it.
        below = StaticFinding("x", "m", "app.py", 3, "low")
        assert correlate([below], surface, tmp)[0].endpoint is None

        # Distance drives confidence, and the ceiling is enforced.
        far_source = '@app.route("/login")\n' + "pad\n" * 200 + "sink\n"
        (tmp / "far.py").write_text(far_source)
        far = StaticFinding("y", "m", "far.py", 202, "low")
        assert correlate([far], surface, tmp)[0].endpoint is None, "past the lookback ceiling"
        near = StaticFinding("z", "m", "far.py", 40, "low")
        near_lead = correlate([near], surface, tmp)[0]
        assert near_lead.endpoint is not None and near_lead.confidence == "medium"

        # A literal must be quoted and exact: "/login" must not match "/login/callback".
        (tmp / "sub.py").write_text('@app.route("/login/callback")\nsink\n')
        sub = StaticFinding("s", "m", "sub.py", 2, "low")
        assert correlate([sub], surface, tmp)[0].endpoint is None

        # Missing inputs are reported, not crashed on.
        assert correlate([sqli], None, tmp)[0].why.startswith("no discovered endpoints")
        assert "no --source" in correlate([sqli], surface, None)[0].why
        assert "could not read" in correlate(
            [StaticFinding("q", "m", "gone.py", 1)], surface, tmp)[0].why

        # All three map here (see the pinned limitation above); the lonely one does not.
        assert summarise(correlate([sqli, cmdi, orphan], surface, tmp)) == \
            "3 static candidate(s), 3 mapped to a discovered endpoint, 0 unmapped"
        assert summarise(correlate(
            [sqli, StaticFinding("l", "m", "lonely.py", 2)], surface, tmp)) == \
            "2 static candidate(s), 1 mapped to a discovered endpoint, 1 unmapped"
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print("static.correlate: ok")


if __name__ == "__main__":
    demo()
