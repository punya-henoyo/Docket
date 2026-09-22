"""Does the cache actually stop agents from running? That is the only claim that matters."""
import sys, tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent / "engine"))

from docket.core.triage import triage_findings
from docket.core.verdict_cache import VerdictCache

SPAWNED = []

def fake_finding(i, line):
    return {"id": f"f{i}", "dedupe_key": f"key{i}", "severity": "high",
            "rule_id": "sql-injection", "location": {"source_file": f"app.py:{i}"},
            "poc": {"request": line, "response": "msg"}}

def run(findings, cache, scope="acme/api", max_findings=10):
    """triage_findings with the agent layer stubbed: count what WOULD have been spawned."""
    import docket.core.triage as T
    real_build, real_loop = T.build_agent, T.run_agent_loop
    T.build_agent = lambda *a, **k: object()
    # ASYNC, because triage does `asyncio.run(run_agent_loop(...))`. A sync stub raises,
    # the handler turns that into a SYNTHESISED verdict, and the cache then correctly
    # refuses to store it — which is how the first version of this test "failed" while
    # the cache was working exactly as designed.
    async def loop(agent, ctx, task, max_turns=0):
        SPAWNED.append(ctx.agent_id)
        return {"verdict": "not_reachable", "reasoning": "only called from tests",
                "evidence": "tests/conftest.py:14"}
    T.run_agent_loop = loop
    try:
        return triage_findings(findings, run_dir=Path("/tmp"), config=CFG,
                               sandbox=object(), scope=scope, cache=cache,
                               max_findings=max_findings)
    finally:
        T.build_agent, T.run_agent_loop = real_build, real_loop

from docket.config.settings import Config
CFG = Config(llm="m", llm_api_key="k", max_cost_usd=5.0, max_child_cost_usd=2.0, max_agents=1)

with tempfile.TemporaryDirectory() as tmp:
    cache = VerdictCache(cwd=Path(tmp))
    findings = [fake_finding(i, f"db.execute(q{i})") for i in range(5)]

    SPAWNED.clear()
    v1 = run(findings, cache)
    assert len(SPAWNED) == 5, SPAWNED
    assert len(v1) == 5
    print(f"  first scan : {len(SPAWNED)} agents spawned, {len(v1)} verdicts")

    SPAWNED.clear()
    v2 = run(findings, cache)
    assert len(SPAWNED) == 0, f"rescan spawned {SPAWNED} — the cache did nothing"
    assert len(v2) == 5, v2
    assert all(x.get("cached") for x in v2.values())
    print(f"  rescan     : {len(SPAWNED)} agents spawned, {len(v2)} verdicts (all reused)")

    # One file edited in place: same key, different code. That one MUST be re-judged.
    findings[2] = fake_finding(2, "db.execute(f'... {user}')")
    SPAWNED.clear()
    v3 = run(findings, cache)
    assert len(SPAWNED) == 1, f"expected exactly the edited finding, got {SPAWNED}"
    print(f"  after edit : {len(SPAWNED)} agent spawned (only the changed line)")

    # A different repo must not inherit any of it.
    SPAWNED.clear()
    run(findings, cache, scope="other/repo")
    assert len(SPAWNED) == 5, SPAWNED
    print(f"  other repo : {len(SPAWNED)} agents spawned (no cross-repo reuse)")

    # THE POINT: the cap now applies to NEW work only. 5 findings, cap of 2, all cached
    # -> all 5 answered, 0 agents. Before, the cap would have hidden 3 of them.
    SPAWNED.clear()
    findings[2] = fake_finding(2, "db.execute(f'... {user}')")
    v5 = run(findings, cache, max_findings=2)
    assert len(v5) == 5, f"a cached verdict must not consume a cap slot: {len(v5)}"
    assert len(SPAWNED) == 0, SPAWNED
    print(f"  cap of 2   : {len(v5)} verdicts returned, {len(SPAWNED)} agents")
    cache.close()
print("test_verdict_cache: ok")
