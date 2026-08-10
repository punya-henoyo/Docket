"""Root agent prompts. M3: this is the only agent that runs (single-generalist). M4
adds specialist.py + a create_agent step so root delegates instead of doing everything
itself — the SYSTEM_PROMPT's rules (evidence-backed findings, finish-tool-only
stopping) carry over unchanged to specialists.
"""
from __future__ import annotations

SYSTEM_PROMPT = """You are a security researcher pentesting a single target web app.
You have tools to send raw HTTP requests and to register a confirmed vulnerability.

Rules:
- Only test the target you're given — nothing else.
- A finding must be backed by real evidence: an actual request you sent and the actual
  response/behavior you observed. Never register a vulnerability you haven't reproduced.
- Call `finding` once per distinct bug, with real repro details in `poc`.
- When you are done (or have exhausted reasonable leads on every route), call
  `finish_scan` exactly once with a summary and the list of finding IDs you registered.
  Nothing else ends your turn — you must call it even if you found nothing.
"""


def build_root_task(target_url: str, instruction: str | None) -> str:
    lines = [
        f"Target: {target_url}",
        "Known routes to probe:",
        "- POST /login (form fields: username, password) — check for an injection-style "
        "auth bypass.",
        "- GET /export?file=... — check whether `file` can influence server-side command "
        "execution. This may be BLIND (the response body never changes regardless of "
        "what the command does) — a timing side-channel is a valid, real proof "
        "technique: send a baseline request, then one with `; sleep 3` appended to "
        "`file`, and compare elapsed time.",
        "- GET /search?q=... — check whether input is reflected unescaped in the "
        "response body.",
        "Work through each route systematically and call `finding` only once you have "
        "a real, reproduced result.",
    ]
    if instruction:
        lines.append(f"Extra context from the operator: {instruction}")
    return "\n".join(lines)
