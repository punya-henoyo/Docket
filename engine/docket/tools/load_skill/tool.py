"""The `load_skill` tool: pull a markdown playbook into the agent's context on demand.

Skills are plain markdown under docket/skills/. The point of loading them on demand
rather than concatenating everything into the system prompt is context economy: an
agent working a blind command injection wants the blind-injection playbook, and paying
for the API-spec and cloud playbooks on every turn is pure waste.

Adding a skill is dropping a .md file in — no code change, which is what makes this a
system rather than a hardcoded list.
"""
from __future__ import annotations

from pathlib import Path

SKILLS_ROOT = Path(__file__).resolve().parents[2] / "skills"
MAX_SKILL_CHARS = 20_000


def _skill_files(root: Path | None = None) -> dict[str, Path]:
    base = root or SKILLS_ROOT
    if not base.exists():
        return {}
    found: dict[str, Path] = {}
    for path in sorted(base.rglob("*.md")):
        if path.name.upper() == "README.MD":
            continue
        # "coordination/root_agent" — namespaced by directory so two categories can
        # hold a same-named playbook.
        found[f"{path.parent.name}/{path.stem}"] = path
    return found


def list_skills(root: Path | None = None) -> dict:
    return {"skills": sorted(_skill_files(root))}


def load_skill(name: str, root: Path | None = None) -> dict:
    available = _skill_files(root)
    # Accept a bare name when it's unambiguous, so the model needn't remember the
    # category prefix.
    if name not in available:
        matches = [k for k in available if k.split("/", 1)[1] == name]
        if len(matches) == 1:
            name = matches[0]
    path = available.get(name)
    if path is None:
        return {
            "ok": False,
            "error": f"no such skill: {name!r}",
            "available": sorted(available),
        }
    return {"ok": True, "skill": name, "content": path.read_text()[:MAX_SKILL_CHARS]}


def demo() -> None:
    listed = list_skills()["skills"]
    assert "coordination/root_agent" in listed, listed
    assert "custom/blind_injection" in listed, listed

    loaded = load_skill("coordination/root_agent")
    assert loaded["ok"] and "wait_for_agents" in loaded["content"]

    # Bare, unambiguous name resolves to its namespaced skill.
    bare = load_skill("blind_injection")
    assert bare["ok"] and bare["skill"] == "custom/blind_injection"
    assert "side channel" in bare["content"]

    missing = load_skill("does-not-exist")
    assert missing["ok"] is False and missing["available"], missing

    # ── the recon/triage playbooks ──────────────────────────────────────────
    # These exist so recon and triage have reference material at all. Before they
    # were added, load_skill was reachable only by agents that need a live target,
    # so on every scan docket had actually run, nothing could open a playbook.
    recon = [s for s in listed if s.startswith("recon/")]
    triage = [s for s in listed if s.startswith("triage/")]
    assert len(recon) >= 20, f"recon playbooks missing: {len(recon)}"
    assert len(triage) >= 20, f"triage playbooks missing: {len(triage)}"

    # The classes recon demonstrably finds by reading source must all be covered.
    for cls in ("idor", "broken_function_level_authorization", "mass_assignment",
                "business_logic", "insecure_deserialization", "ssrf", "csrf"):
        assert f"recon/{cls}" in listed, cls
    # ...and the classes semgrep floods triage with.
    for cls in ("sql_injection", "xss", "idor", "path_traversal_lfi_rfi", "rce"):
        assert f"triage/{cls}" in listed, cls

    # A triage playbook's whole reason to exist is the rule-it-out list.
    for name in triage:
        body = load_skill(name)["content"]
        assert "## Not a bug when" in body, name

    # A recon playbook must frame itself for source reading. An agent handed
    # "replay the request" with no HTTP tool narrates attacks it never ran.
    for name in recon:
        body = load_skill(name)["content"]
        assert "READING SOURCE, not sending requests" in body, name
        for banned in ("## Testing Methodology", "## Bypass Techniques",
                       "## Validation"):
            assert banned not in body, f"{name} kept a live-target section: {banned}"

    # Apache-2.0 requires the notice to travel with the derived work.
    for name in recon + triage:
        assert "Apache-2.0" in load_skill(name)["content"], name

    # A bare name is now ambiguous — idor exists under both — and the loader must
    # refuse rather than silently pick one.
    ambiguous = load_skill("idor")
    assert ambiguous["ok"] is False, "a bare ambiguous name must not resolve"

    # A skills tree with no files degrades cleanly rather than raising.
    import tempfile
    assert list_skills(Path(tempfile.mkdtemp()))["skills"] == []
    print("tools.load_skill: ok")


if __name__ == "__main__":
    demo()
