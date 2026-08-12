"""Root agent prompts. Root delegates to specialist children instead of testing routes
itself: the test target's 3 known routes map directly to the 3 specialist roles, so root's
job is spawn + wait + aggregate.

Root does NO recon. `build_root_task` hands it a route list, and that list is hardcoded to
the fixture — see the comment there. README "Current limits" documents this as the tool's
largest gap; do not let the prompt imply otherwise.
"""
from __future__ import annotations

SYSTEM_PROMPT = """You are the root agent coordinating a pentest of a single target web
app. You do not test routes yourself — you delegate to specialist child agents, each
scoped to one vulnerability class and one route.

Rules:
- Use `create_agent` to spawn a specialist for each candidate vulnerability class you
  identify (role: "sqli", "cmdi", or "xss"), scoped to exactly one route each. Check
  `view_agent_graph` first so you don't spawn a duplicate for a route already covered.
- Use `wait_for_agents` to block until your children report back — issue one wait,
  react to what it returns, don't poll in a loop.
- A finding is only real once a specialist has reported it via the `finding` tool with
  real, reproduced evidence — you don't call `finding` yourself.
- When all specialists have finished (check `view_agent_graph`), call `finish_scan`
  exactly once with a summary and the combined list of finding IDs your children
  registered. Nothing else ends your turn — call it even if nothing was found.
"""


def build_root_task(
    target_url: str,
    instruction: str | None,
    surface: object | None = None,
    leads: list | None = None,
) -> str:
    """Renders root's opening task from a discovered attack surface.

    `surface` is a discovery.models.AttackSurface. When it is absent or empty, root is
    told so EXPLICITLY and asked to probe — never handed the fixture's routes as if they
    were facts about the target. That was the old behaviour and its failure mode was
    worse than an empty list: root confidently tested three paths that may not exist,
    found nothing, and reported success without ever signalling it was misinformed.
    """
    lines = [f"Target: {target_url}"]
    endpoints = list(getattr(surface, "endpoints", []) or [])

    if endpoints:
        lines.append(
            f"{len(endpoints)} endpoint(s) were discovered on this target "
            f"(from {', '.join(getattr(surface, 'sources_tried', []) or ['discovery'])}). "
            "These are observed, not guessed:"
        )
        lines += [f"- {e.describe()}" for e in endpoints[:_MAX_LISTED]]
        if len(endpoints) > _MAX_LISTED:
            lines.append(
                f"- ...and {len(endpoints) - _MAX_LISTED} more in surface.json. Prioritise "
                "what you listed; do not assume the rest are safe."
            )
        for note in getattr(surface, "notes", []) or []:
            lines.append(f"Note on discovery: {note}")
        lines.append(
            "Pick the endpoints worth testing and spawn ONE specialist per "
            "(vulnerability class, endpoint) pair. A parameter named in the list is a "
            "candidate injection point. Endpoints marked 'auth required' need credentials "
            "— use what the operator gave you, or say so and move on."
        )
    else:
        lines.append(
            "NO endpoints were discovered. Discovery found nothing: the target may need "
            "authentication, publish no spec, render its routes client-side, or simply be "
            "unreachable. You have NOT been given a route list, so do not invent one."
        )
        lines.append(
            "Use `http_request` yourself to probe a small number of likely paths before "
            "spawning anyone. If you still find nothing, call `finish_scan` and say "
            "plainly that the surface could not be determined. Reporting an honest "
            "nothing is correct; guessing is not."
        )
        for note in getattr(surface, "notes", []) or []:
            lines.append(f"Note on discovery: {note}")

    if leads:
        reachable = [lead for lead in leads if getattr(lead, "reachable", False)]
        lines.append("")
        lines.append(
            f"STATIC ANALYSIS produced {len(leads)} candidate(s), {len(reachable)} of "
            "which a discovered endpoint appears to reach. These are UNPROVEN leads from "
            "a pattern matcher, not findings. Each names a file and line where dangerous "
            "code was flagged, and the request that may reach it:"
        )
        for lead in reachable[:_MAX_LISTED]:
            lines.append(f"- {lead.describe()}")
        unmapped = len(leads) - len(reachable)
        if unmapped:
            lines.append(
                f"- ...and {unmapped} candidate(s) with no endpoint mapped. Ignore them "
                "unless you run out of leads: without a route you cannot reach the code."
            )
        lines.append(
            "Prioritise these over blind probing — a named sink with a route is the "
            "cheapest thing on this target to prove or rule out. The correlation is a "
            "HEURISTIC (nearest route literal above the line, no dataflow), so verify it "
            "rather than trusting it, and register a finding only if you actually exploit "
            "it. A lead you cannot exploit is a lead, not a finding: leave it alone and "
            "it stays in the report as unproven."
        )

    if instruction:
        lines.append(f"Extra context from the operator: {instruction}")
    lines.append(
        "Spawn specialists, wait for them with `wait_for_agents`, then aggregate what "
        "they PROVED with `finish_scan`."
    )
    return "\n".join(lines)


_MAX_LISTED = 40


def demo() -> None:
    from docket.discovery.models import AttackSurface, Endpoint, Param

    # With a surface, root is handed observations.
    s = AttackSurface(target="http://t.test", sources_tried=["well-known"])
    s.add(Endpoint("POST", "/api/login", params=(Param("email", "json", True),),
                    auth_required=True))
    task = build_root_task("http://t.test", None, s)
    assert "POST /api/login" in task and "email(json)" in task
    assert "auth required" in task
    assert "1 endpoint(s) were discovered" in task
    # The fixture's routes must NOT appear from nowhere.
    assert "/export" not in task and "/search" not in task

    # With nothing, root is told nothing was found and instructed not to invent.
    empty = build_root_task("http://t.test", None, AttackSurface(target="http://t.test"))
    assert "NO endpoints were discovered" in empty
    assert "do not invent one" in empty
    assert "/login" not in empty, "an empty surface must not leak example routes"

    # No surface argument at all behaves like an empty one, not like the old hardcoding.
    assert "NO endpoints were discovered" in build_root_task("http://t.test", None)

    # Operator instruction survives both branches.
    assert "creds a/b" in build_root_task("http://t.test", "creds a/b", s)
    assert "creds a/b" in build_root_task("http://t.test", "creds a/b")

    # --- static leads ----------------------------------------------------------------
    from docket.static.correlate import Lead
    from docket.static.models import StaticFinding

    sink = StaticFinding("sqli", "input in query", "app.py", 34, "high", "CWE-89")
    mapped = Lead(sink, Endpoint("POST", "/login"), "high", "'/login' appears 4 line(s) above")
    orphan = Lead(StaticFinding("x", "m", "helpers.py", 9), None, "none", "no route above")
    with_leads = build_root_task("http://t.test", None, s, [mapped, orphan])
    assert "STATIC ANALYSIS produced 2 candidate(s), 1 of which" in with_leads
    assert "app.py:34" in with_leads and "CWE-89" in with_leads
    assert "1 candidate(s) with no endpoint mapped" in with_leads
    # The heuristic must be flagged AS a heuristic, or the model trusts the pairing.
    assert "HEURISTIC" in with_leads
    # And a lead must never read as a finding.
    assert "UNPROVEN leads" in with_leads
    # No leads: the section is absent entirely rather than saying "0 candidates".
    assert "STATIC ANALYSIS" not in build_root_task("http://t.test", None, s)
    assert "STATIC ANALYSIS" not in build_root_task("http://t.test", None, s, [])

    # A long surface is truncated, and the truncation is stated rather than silent.
    big = AttackSurface(target="http://t.test")
    for i in range(_MAX_LISTED + 5):
        big.add(Endpoint("GET", f"/p{i}"))
    long_task = build_root_task("http://t.test", None, big)
    assert "and 5 more in surface.json" in long_task
    assert "/p0" in long_task and f"/p{_MAX_LISTED + 4}" not in long_task
    print("agents.prompts.root: ok")


if __name__ == "__main__":
    demo()
