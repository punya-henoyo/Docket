"""M9: the full 4-agent run against the test target, through the real Docker sandbox, with
every finding's evidence EXTRACTED FROM ACTUAL TOOL OUTPUT rather than hardcoded —
sqlmap's own verdict line for V1, a measured latency delta for V2, and the real
dialog_message a Chromium DOM raised for V3. Then checks report.json / report.sarif.

Only each agent's next-tool-call decision is scripted (no LLM_API_KEY here); every
tool call really executes.

Requires Docker running. The target is the self-contained fixture in tests/fixtures/.
Run: uv run python tests/test_full_run.py
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from fixtures.target_app import ensure_target
from mock_model import ScriptedModel
from docket.config.settings import Config, run_dir
from docket.core.runner import run_scan
from docket.report.dedupe import FindingStore
from docket.report.writer import build_report, format_summary, write_report
from docket.runtime.sandbox import rewrite_for_container

HOST_TARGET = ensure_target()
TARGET = rewrite_for_container(HOST_TARGET)  # agents run inside the container
XSS_PAYLOAD = "<script>alert(document.domain)</script>"
RUN_NAME = "m9-full-run"


# --- evidence extractors: pull real proof out of the conversation so far -------------

def _tool_results(outputs: dict) -> list[dict]:
    return [o for o in outputs.values() if isinstance(o, dict)]


def _sqlmap_verdict(outputs: dict) -> str:
    """The 'Parameter: ... Type: ... Payload: ...' block sqlmap prints on success."""
    for result in _tool_results(outputs):
        stdout = result.get("stdout") or ""
        if "Parameter:" in stdout and "Payload:" in stdout:
            start = stdout.index("Parameter:")
            return stdout[start : start + 400].strip()
    return ""


def _timing_evidence(outputs: dict) -> str:
    times = [r["elapsed_ms"] for r in _tool_results(outputs) if "elapsed_ms" in r]
    if len(times) < 2:
        return ""
    return (
        f"baseline={times[0]}ms vs injected={times[1]}ms "
        f"(delta {times[1] - times[0]}ms from an injected `sleep 3`); blind — os.system "
        f"stdout never reaches the HTTP response, so timing is the oracle"
    )


def _dialog_evidence(outputs: dict) -> str:
    for result in _tool_results(outputs):
        if result.get("dialog_message"):
            return (
                f"Chromium raised a real dialog: {result['dialog_message']!r} "
                f"(document.domain evaluated by the DOM — the script EXECUTED, "
                f"it was not merely reflected)"
            )
    return ""


def _ids(outputs: dict) -> list[str]:
    return [r["finding_id"] for r in _tool_results(outputs) if "finding_id" in r]


# --- scripts -------------------------------------------------------------------------

ROOT_SCRIPT = [
    ("create_agent", {"name": "sqli-login", "role": "sqli",
                       "task": "confirm SQLi with sqlmap", "target_route": "POST /login"}),
    ("create_agent", {"name": "cmdi-export", "role": "cmdi",
                       "task": "confirm blind command injection via timing", "target_route": "GET /export"}),
    ("create_agent", {"name": "xss-search", "role": "xss",
                       "task": "prove XSS executes in a real DOM", "target_route": "GET /search"}),
    ("wait_for_agents", {"timeout_seconds": 300}),
    ("finish_scan", lambda outputs: {
        "summary": "All three specialists confirmed their assigned vulnerability.",
        "findings": sorted({
            fid for r in _tool_results(outputs) for e in r.get("events", [])
            for fid in e.get("findings", [])
        }),
        "success": True,
    }),
]

SQLI_SCRIPT = [
    ("shell", {
        "command": (
            "python3 /opt/sqlmap/sqlmap.py "
            f"-u {TARGET}/login "
            '--data="username=admin&password=admin123" '
            "-p username --ignore-code=401 --string=Welcome --batch --flush-session "
            "--technique=B --level=1 --risk=1 --dbms=sqlite"
        ),
        "timeout_sec": 120,
    }),
    ("finding", lambda outputs: {
        "rule_type": "sqli", "severity": "high",
        "title": "SQL injection in POST /login",
        "description": "username is interpolated into the SQL query, confirmed by sqlmap.",
        "location": {"url": f"{TARGET}/login", "method": "POST", "parameter": "username",
                      "file": "app.py:34"},
        "poc": {
            "steps": ["ran sqlmap against POST /login with -p username"],
            "request": {"method": "POST", "url": f"{TARGET}/login",
                         "body": "username=admin&password=admin123"},
            "response_excerpt": _sqlmap_verdict(outputs),
        },
    }),
    ("agent_finish", lambda outputs: {
        "summary": "sqlmap confirmed boolean-based blind SQLi on username.",
        "findings": _ids(outputs), "success": True,
    }),
]

CMDI_SCRIPT = [
    ("http_request", {"method": "GET", "url": f"{TARGET}/export", "params": {"file": "report.csv"}}),
    ("http_request", {"method": "GET", "url": f"{TARGET}/export",
                       "params": {"file": "report.csv; sleep 3"}, "timeout_sec": 20}),
    ("finding", lambda outputs: {
        "rule_type": "command_injection", "severity": "critical",
        "title": "Command injection in GET /export",
        "description": "file is concatenated into os.system('cat exports/' + file).",
        "location": {"url": f"{TARGET}/export", "method": "GET", "parameter": "file",
                      "file": "app.py:47"},
        "poc": {
            "steps": ["baseline GET /export?file=report.csv",
                       "injected GET /export?file=report.csv; sleep 3",
                       "compared elapsed time"],
            "request": {"method": "GET", "url": f"{TARGET}/export?file=report.csv%3B+sleep+3"},
            "response_excerpt": _timing_evidence(outputs),
        },
    }),
    ("agent_finish", lambda outputs: {
        "summary": "Blind command injection confirmed by timing side-channel.",
        "findings": _ids(outputs), "success": True,
    }),
]

XSS_SCRIPT = [
    ("browser", {"action": "navigate",
                  "url": f"{TARGET}/search?q=" + urllib.parse.quote(XSS_PAYLOAD),
                  "timeout_sec": 30}),
    ("browser", {"action": "screenshot", "timeout_sec": 30}),
    ("finding", lambda outputs: {
        "rule_type": "xss_reflected", "severity": "medium",
        "title": "Reflected XSS in GET /search",
        "description": "q is concatenated into HTML and rendered unescaped.",
        "location": {"url": f"{TARGET}/search", "method": "GET", "parameter": "q",
                      "file": "app.py:57"},
        "poc": {
            "steps": [f"navigated a real browser to /search?q={XSS_PAYLOAD}",
                       "captured the dialog the DOM raised"],
            "request": {"method": "GET", "url": f"{TARGET}/search?q={XSS_PAYLOAD}"},
            "response_excerpt": _dialog_evidence(outputs),
        },
    }),
    ("agent_finish", lambda outputs: {
        "summary": "XSS proven to execute via a real DOM dialog.",
        "findings": _ids(outputs), "success": True,
    }),
]


def _model_override(role: str) -> ScriptedModel:
    return ScriptedModel({
        "root": ROOT_SCRIPT, "sqli": SQLI_SCRIPT,
        "cmdi": CMDI_SCRIPT, "xss": XSS_SCRIPT,
    }[role])


def test_full_run_produces_three_validated_findings_and_sarif() -> None:
    os.environ.setdefault("DOCKET_LLM", "anthropic/claude-sonnet-4-5-20250929")
    config = Config.from_env()
    store = FindingStore()
    directory = run_dir(RUN_NAME)

    result = run_scan(
        HOST_TARGET, on_finding=store.add, config=config, run_name=RUN_NAME,
        model_override=_model_override, use_sandbox=True, max_turns=25,
    )

    assert result.success is True, result
    assert result.agents_spawned == 4, result       # root + 3 specialists
    assert result.finding_count == 3, result        # root aggregated all three
    assert len(store) == 3, [f.rule_id for f in store.findings()]
    assert {f.rule_id for f in store.findings()} == {
        "sql-injection", "command-injection", "reflected-xss",
    }

    by_rule = {f.rule_id: f for f in store.findings()}

    # Each finding's evidence must be the REAL tool output, not a placeholder.
    sqli_evidence = by_rule["sql-injection"].poc.response
    assert "Parameter: username" in sqli_evidence, sqli_evidence
    assert "boolean-based blind" in sqli_evidence, sqli_evidence

    cmdi_evidence = by_rule["command-injection"].poc.response
    assert "delta" in cmdi_evidence and "injected=" in cmdi_evidence, cmdi_evidence
    delta = int(cmdi_evidence.split("delta ")[1].split("ms")[0])
    assert delta > 2500, f"injected sleep should add ~3s, got {delta}ms"

    xss_evidence = by_rule["reflected-xss"].poc.response
    assert "host.docker.internal" in xss_evidence, xss_evidence
    assert "EXECUTED" in xss_evidence, xss_evidence

    # --- artifacts ------------------------------------------------------------------
    paths = write_report(
        store, directory, run_name=RUN_NAME, target=HOST_TARGET, summary=result.summary,
        cost_usd=result.cost_usd, agents_spawned=result.agents_spawned, success=result.success,
    )
    report = json.loads(paths["json"].read_text())
    assert report["finding_count"] == 3
    assert report["severity_counts"] == {
        "critical": 1, "high": 1, "medium": 1, "low": 0, "info": 0,
    }, report["severity_counts"]
    assert [f["severity"] for f in report["findings"]] == ["critical", "high", "medium"]

    sarif = json.loads(paths["sarif"].read_text())
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "docket"
    assert len(run["tool"]["driver"]["rules"]) == 3
    assert len(run["results"]) == 3
    assert {r["level"] for r in run["results"]} == {"error", "warning"}
    # Agents mapped routes back to source, so results anchor to real files+lines.
    for res in run["results"]:
        loc = res["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"] == "app.py", loc
        assert loc["region"]["startLine"] > 0, loc
        assert res["partialFingerprints"]["docketDedupeKey/v1"]
    # Fingerprints are distinct, so a later run is diffable per-finding.
    assert len({r["partialFingerprints"]["docketDedupeKey/v1"] for r in run["results"]}) == 3

    text = format_summary(report, paths=paths)
    for expected in ("sql-injection", "command-injection", "reflected-xss", "3 finding(s)"):
        assert expected in text, text
    print(text)

    # Kept deliberately opt-in: this run directory is the only source of findings with
    # real, tool-derived PoC evidence that needs no API key, which makes it the demo
    # dataset for app/. Tests still clean up by default.
    if not os.environ.get("DOCKET_KEEP_RUN"):
        shutil.rmtree(directory, ignore_errors=True)
    else:
        print(f"\nkept {directory} (DOCKET_KEEP_RUN)")


if __name__ == "__main__":
    test_full_run_produces_three_validated_findings_and_sarif()
    print("\ntest_full_run: ok — 4 agents, 3 findings, real tool-derived evidence, valid SARIF")
