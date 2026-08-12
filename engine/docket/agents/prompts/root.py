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


def build_root_task(target_url: str, instruction: str | None,
                    surface: dict | None = None) -> str:
    """Renders root's opening task, from the recon agent's map when there is one.

    This closes the gap this docstring used to describe: the route list was the test
    fixture's three routes, asserted as fact for ANY target. That is worse than an
    empty list — root was handed fiction confidently, went looking for routes that do
    not exist on the actual target, and reported nothing without ever signalling it
    had been misinformed.

    The AI recon agent now produces a real map by reading the repository, and
    render_attack_plan turns it into these lines. Each carries the parameters the
    handler reads, whether anything guards it, and the file it was read from — so a
    specialist knows where to aim and root can say where a route came from.

    When there is no map, the fixture list is used and LABELLED as a fixture, so a
    misinformed run is visible instead of silent. That fallback is the remaining half
    of the old problem, and it now announces itself.
    """
    from docket.core.surface_findings import render_attack_plan

    discovered = render_attack_plan(surface)
    if discovered:
        lines = [
            f"Target: {target_url}",
            "Attack surface mapped from source by the recon agent. Every route below "
            "was read out of a real file, named at the end of each line:",
            *discovered,
            "",
            "Routes marked with no auth, or an auth check its siblings have and it "
            "does not, are where to start. Spawn one specialist per route worth "
            "testing, wait for them, then aggregate their findings.",
        ]
        if instruction:
            lines.append(f"Extra context from the operator: {instruction}")
        return "\n".join(lines)

    lines = [
        f"Target: {target_url}",
        "NO ATTACK SURFACE WAS MAPPED for this target — the routes below are the test "
        "fixture's, not this application's. Treat them as a guess: confirm each one "
        "exists before spending a specialist on it, and say so if they do not.",
        "- POST /login (form fields: username, password) -> role \"sqli\": check for "
        "an injection-style auth bypass.",
        "- GET /export?file=... -> role \"cmdi\": check whether `file` can influence "
        "server-side command execution. This may be BLIND (the response body never "
        "changes regardless of what the command does) — a timing side-channel is a "
        "valid, real proof technique.",
        "- GET /search?q=... -> role \"xss\": check whether input is reflected "
        "unescaped in the response body.",
        "Spawn one specialist per route, wait for them, then aggregate their findings.",
    ]
    if instruction:
        lines.append(f"Extra context from the operator: {instruction}")
    return "\n".join(lines)
