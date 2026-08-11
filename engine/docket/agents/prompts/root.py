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


def build_root_task(target_url: str, instruction: str | None) -> str:
    """Renders root's opening task. The route list below is the fixture's, asserted as fact
    for ANY --target, which is wrong for every target but the fixture. It is stated rather
    than discovered because nothing in this tool discovers: no crawl, no spec parsing, no
    traffic-derived surface. Note the failure mode is worse than an empty list — root is
    handed fiction confidently, so it tests routes that may not exist and reports nothing
    without ever signalling that it was misinformed.
    # ponytail: hardcoded fixture routes, ceiling is "works on one app". Upgrade path is a
    # typed attack surface built by deterministic code (spec/HAR -> well-known paths ->
    # captured proxy flows -> bounded crawl) and rendered here, with an explicit "no routes
    # found" branch. Roadmap item 2. Land scope + rate controls first.
    """
    lines = [
        f"Target: {target_url}",
        "Known routes and the vulnerability class each is worth checking for:",
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
