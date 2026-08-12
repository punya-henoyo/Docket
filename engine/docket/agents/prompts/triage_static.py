"""Triage prompt: read the code around a static candidate and rule on it.

This is the job SAST leaves undone. Semgrep says line 34 concatenates input into SQL. It
cannot see the parameterisation on line 31, cannot follow the helper on line 28, and
cannot know the route is admin-only. Somebody reads the surrounding code and decides. That
somebody is the expensive part of every SAST programme, and it is what this replaces.

The verdict vocabulary is deliberately three-valued. A binary confirmed/false-positive
forces a guess, and a guessed FALSE POSITIVE is the one outcome that actually costs
someone a breach — so UNCERTAIN is a first-class answer and the prompt says to prefer it.

Kept alongside agents/prompts/triage.py, which is the wired one. Two triage agents
were built in parallel: static/triage.py rules on a correlated Semgrep candidate
using this prompt, core/triage.py decides reachability using the other. Only
core/triage.py is wired into the runner; this side stays for its three-valued
verdict wording and its bounded-candidate demo.
# ponytail: two triage prompts is one too many. Fold the UNCERTAIN-preference
# wording into prompts/triage.py and delete this once a real run shows which
# verdict language holds up.
"""
from __future__ import annotations

SYSTEM_PROMPT = """You are a security engineer triaging static-analysis findings by
reading source code. You do not attack anything and you have no network access: your only
tools read files.

For the one candidate you are given, decide whether it is real.

Rules:
- READ THE CODE FIRST. Use `read_around` on the flagged line, then widen with `read_source`,
  `list_source` and `grep_source` as needed. A verdict given without reading is worthless.
- Follow the data. Where does the value come from? Is it user-controlled at all? If it
  arrives from a config file or a constant, the finding is not exploitable however
  dangerous the pattern looks.
- Look for the guard. Escaping, parameterised queries, allow-lists, type coercion,
  framework auto-escaping, an authz check on the route. A guard three lines above the sink
  is the single most common reason a static hit is a false positive.
- QUOTE what you rely on. Every claim in your verdict must point at `file:line` and include
  the line. "It is escaped" is not a finding; "escaped at views.py:31 by `escape(q)`" is.
- Prefer UNCERTAIN over a guess. Three verdicts:
    CONFIRMED       user input reaches the sink and you found no adequate guard
    FALSE_POSITIVE  it cannot be reached, or a guard makes it safe. Quote the guard.
    UNCERTAIN       you could not follow it far enough, the framework's behaviour is not
                    visible here, or it depends on a caller you cannot see
  A wrong FALSE_POSITIVE is the only verdict that gets someone breached. When the evidence
  runs out, say UNCERTAIN and state exactly what you could not determine.
- Do not widen scope. One candidate. Do not audit the file, do not report other bugs you
  notice in passing, do not suggest refactors.
- Finish by calling `agent_finish` exactly once. Nothing else ends your turn.
"""


def build_task(candidate: dict, source_root: str = "") -> str:
    """`candidate` is a docket.static.models.StaticFinding rendered to a dict."""
    lines = [
        "Triage ONE static-analysis candidate.",
        f"  rule    : {candidate.get('rule_id', '?')}",
        f"  file    : {candidate.get('file', '?')}:{candidate.get('line', '?')}",
        f"  engine  : {candidate.get('engine', '?')}",
        f"  severity: {candidate.get('severity', '?')} (as the RULE rates it, not as you must)",
    ]
    if candidate.get("cwe"):
        lines.append(f"  cwe     : {candidate['cwe']}")
    if candidate.get("message"):
        lines.append(f"  message : {candidate['message'].strip()[:400]}")
    if candidate.get("snippet"):
        lines.append(f"  matched : {candidate['snippet'].strip()[:300]}")
    if candidate.get("endpoint"):
        lines.append(
            f"  endpoint: {candidate['endpoint']} — a HEURISTIC pairing (nearest route "
            "literal above the line, no dataflow). Verify it rather than trusting it."
        )
    if source_root:
        lines.append(f"The repository root is {source_root}. All paths are relative to it.")
    lines.append(
        "Start with `read_around` on that file and line. Then decide: CONFIRMED, "
        "FALSE_POSITIVE or UNCERTAIN, with every claim quoting file:line. Call "
        "`agent_finish` once with your verdict and reasoning."
    )
    return "\n".join(lines)


def demo() -> None:
    candidate = {
        "rule_id": "python.lang.security.audit.formatted-sql-query",
        "file": "app/views.py", "line": 34, "engine": "semgrep",
        "severity": "high", "cwe": "CWE-89",
        "message": "user input in a formatted SQL string",
        "snippet": 'query = f"SELECT ... {username}"',
        "endpoint": "POST /login",
    }
    task = build_task(candidate, "/work/source")
    assert "app/views.py:34" in task
    assert "CWE-89" in task and "POST /login" in task
    # The heuristic must be labelled as one, or the agent inherits its error.
    assert "HEURISTIC" in task
    # The rule's severity must not be presented as the answer.
    assert "not as you must" in task
    assert "/work/source" in task

    # Absent optional fields simply do not appear; nothing renders as "None".
    sparse = build_task({"rule_id": "r", "file": "a.py", "line": 1})
    assert "None" not in sparse, sparse
    assert "cwe" not in sparse and "endpoint" not in sparse

    # The three verdicts, and the instruction to prefer the safe one, are all stated.
    for token in ("CONFIRMED", "FALSE_POSITIVE", "UNCERTAIN", "Prefer UNCERTAIN"):
        assert token in SYSTEM_PROMPT, token
    assert "QUOTE" in SYSTEM_PROMPT
    print("agents.prompts.triage_static: ok")


if __name__ == "__main__":
    demo()
