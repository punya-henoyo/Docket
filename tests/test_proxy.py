"""M7 check: the intercepting proxy — start, capture, inspect, and
replay-with-modification, all inside the sandbox.

Requires Docker running and vulnshop live on the host at 127.0.0.1:5000.
Run: uv run python tests/test_proxy.py
"""
from __future__ import annotations

import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from docket.config.settings import run_dir
from docket.runtime.sandbox import Sandbox, rewrite_for_container


def test_proxy_capture_inspect_and_replay_with_modification() -> None:
    target = rewrite_for_container("http://127.0.0.1:5000")
    directory = run_dir("m7-proxy-test")
    try:
        with Sandbox(directory / "sandbox") as sb:
            started = sb.call("proxy_start", rpc_timeout=60)
            assert started.get("ok") is True, started
            # Idempotent: a second start must not spawn a second mitmdump.
            assert sb.call("proxy_start", rpc_timeout=60).get("already_running") is True

            # 1. Traffic sent through the proxy gets captured.
            first = sb.call(
                "http_request", method="GET", url=f"{target}/search",
                params={"q": "benign"}, via_proxy=True,
            )
            assert first["status_code"] == 200, first

            listing = sb.call("proxy_list")
            assert listing["total"] >= 1, listing
            flow_id = listing["flows"][0]["id"]

            # 2. Full detail is retrievable for one flow.
            detail = sb.call("proxy_get", flow_id=flow_id)
            assert detail["method"] == "GET", detail
            assert "benign" in detail["url"], detail
            assert "Results for benign" in detail["resp_body"], detail
            assert sb.call("proxy_get", flow_id="nope")["error"]

            # 3. THE M7 GOAL: replay that captured request with a MODIFIED url, and
            #    see the modification reflected in the new response. This is the
            #    capability a pentester actually reaches for — mutate and re-fire.
            payload = "<script>alert(1)</script>"
            replay = sb.call(
                "proxy_replay", flow_id=flow_id,
                modifications={"url": f"{target}/search?q={payload}"},
            )
            assert replay["replayed_from"] == flow_id, replay
            assert replay["response"]["status_code"] == 200, replay
            # The payload came back unescaped — incidentally V3 (reflected XSS) showing
            # up in the response body, though M8's browser is what actually PROVES it
            # executes rather than merely echoes.
            assert payload in replay["response"]["body"], replay["response"]["body"]

            # 4. The replay itself went back through the proxy, so it was recorded as a
            #    new flow with no extra bookkeeping — the agent can diff the two.
            after = sb.call("proxy_list", limit=50)
            assert after["total"] == listing["total"] + 1, (listing["total"], after["total"])
            assert any("script" in f["url"] for f in after["flows"]), after["flows"]

            # 5. Flow log is on the HOST already via the bind mount.
            flows_file = directory / "sandbox" / "artifacts" / "proxy_flows.jsonl"
            assert flows_file.exists(), f"expected {flows_file}"
            assert len(flows_file.read_text().strip().splitlines()) == after["total"]

            assert sb.call("proxy_stop") == {"ok": True, "was_running": True}
            assert sb.call("proxy_stop")["was_running"] is False
    finally:
        shutil.rmtree(directory, ignore_errors=True)


if __name__ == "__main__":
    test_proxy_capture_inspect_and_replay_with_modification()
    print("test_proxy: ok — capture, inspect, replay-with-modification, and the replay re-captured")
