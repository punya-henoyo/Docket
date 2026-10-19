"""The Code Security console's read model, end to end on the seeded sample scenario.

No Docker and no API key: the seeder writes `docket_runs/*`, `docket_portfolio.json` and
`docket_policy.json` into a temp directory, and the api functions (plus the real HTTP
handler, over loopback) are asserted against the numbers in docs/ui/mockup/sample.js.

Run: uv run python tests/test_portfolio.py
"""
from __future__ import annotations

import json
import os
import tempfile
import threading
import urllib.error
import urllib.parse
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

from docket.compliance.models import Control, ControlPack
from docket.compliance.packs import save_uploaded
from docket.compliance.service import pack_detail, packs_index
from docket.core.runner import ScanResult
from docket.demo import console
from docket.demo.seed import seed
from docket.portfolio import api
from docket.portfolio.catalog import CATALOG

NOW = 1_800_000_000.0
HERO = "ibank/card-payments"


def walk(node, path=""):
    """Every (path, key, value) in a JSON tree."""
    if isinstance(node, dict):
        for k, v in node.items():
            yield path, k, v
            yield from walk(v, f"{path}/{k}")
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from walk(v, f"{path}[{i}]")


def by(rows, key, value):
    return next(r for r in rows if r[key] == value)


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        seed(root, NOW)
        payloads: list[dict] = []

        # --- /api/portfolio: levels --------------------------------------------------------
        status, port = api.portfolio_payload(root, NOW)
        payloads.append(port)
        assert status == 200 and port["sample"] is True
        assert port["counts"] == {"action": 2, "attention": 4, "clear": 5, "unknown": 1}, port["counts"]
        levels = {a["id"]: a["level"] for a in port["applications"]}
        assert levels == {
            "ibank/card-payments": "action", "ibank/disputes": "action",
            "ibank/kyc-gateway": "attention", "ibank/admin-ledger": "attention",
            "ibank/upi-adapter": "attention", "ibank/loan-origination": "attention",
            "ibank/netbanking-web": "clear", "ibank/account-statements": "clear",
            "ibank/notifications": "clear", "ibank/treasury-reports": "clear",
            "ibank/branch-locator": "clear", "ibank/legacy-partner-feed": "unknown"}, levels
        assert [a["level"] for a in port["applications"]] == sorted(
            (a["level"] for a in port["applications"]),
            key=["action", "attention", "clear", "unknown"].index), "ordered by urgency"
        assert port["organization"].startswith("iBank")
        hero = by(port["applications"], "id", HERO)
        assert hero["tier"] == "Tier 1" and hero["owner"] == "Meera Nair"
        assert [e["kind"] for e in hero["events"]] == ["scan"] * 3 + ["pr", "scan"], hero["events"]
        assert [e["coverage"] for e in hero["events"]] == ["full", "full", "full", "full", "partial"]
        assert hero["events"][-1]["proven"] == 2 and hero["events"][-1]["candidates"] == 17
        assert hero["events"][3]["label"] == "PR #479" and hero["last_scan_at"]
        legacy = by(port["applications"], "id", "ibank/legacy-partner-feed")
        assert legacy["events"] == [] and legacy["age_days"] is None and legacy["last_scan_at"] is None
        assert legacy["reason"] == "Never scanned"
        # The scanner-coverage block replaces "findings by tool": no counts of leads at all.
        assert "by_origin" not in port
        sc = {s["id"]: s for s in port["scanner_coverage"]}
        assert list(sc) == ["trivy", "semgrep", "apisec", "triage", "swarm"], list(sc)
        assert (sc["apisec"]["current"], sc["apisec"]["of"]) == (3, 6), sc["apisec"]
        assert sc["trivy"]["required"] is True and sc["trivy"]["origin"] == "third_party"
        assert len(port["trend"]["periods"]) == 8 and len(port["trend"]["series"]) == 3
        assert all(len(s["values"]) == 8 for s in port["trend"]["series"])
        assert len(port["severity_age"]["cells"]) == 16

        # --- /api/application/<id>: Card Payments health -------------------------------------
        status, app = api.application_payload(HERO, root, NOW)
        payloads.append(app)
        assert status == 200 and app["application"]["level"] == "action"
        health = app["health"]
        analytes = {a["key"]: a for a in health["analytes"]}
        assert list(analytes) == ["proven", "reach", "secrets", "cves", "age", "cov", "triage"], list(analytes)
        want = {"proven": (2, "bad", "0"), "reach": (5, "warn", "3 or fewer"),
                "secrets": (1, "bad", "0"), "cves": (2, "bad", "0"),
                "age": (9, "warn", "7 days or fewer"), "cov": (4, "warn", "5 of 5"),
                "triage": (3, "warn", "2 or fewer")}
        for key, (value, flag, ref) in want.items():
            a = analytes[key]
            assert (a["value"], a["flag"], a["ref"]) == (value, flag, ref), (key, a)
            assert len(a["trend"]) == 8, (key, a["trend"])
            assert a["trend"][-1] == value, (key, "the trend ends at the current value")
            assert a["bands"] and a["scaleMax"] >= value
        assert analytes["cov"]["display"] == "4 of 5" and analytes["cov"]["higherIsBetter"] is True
        assert analytes["age"]["display"] == "9 d" and analytes["proven"]["previous"] == "1"
        assert analytes["proven"]["flagWord"] == "Out of range" and analytes["reach"]["flagWord"] == "High"
        assert analytes["cov"]["flagWord"] == "Low"

        ann = {a["key"]: a for a in health["annunciators"]}
        assert list(ann) == ["proven", "secrets", "deps", "coverage", "fresh", "comp", "fix"], list(ann)
        # One fact, one colour: an annunciator's state IS its analyte's flag.
        for a_key, an_key in (("proven", "proven"), ("secrets", "secrets"), ("cves", "deps"),
                              ("cov", "coverage")):
            assert ann[an_key]["state"] == analytes[a_key]["flag"], (a_key, ann[an_key])
        assert ann["proven"]["value"] == "2" and ann["secrets"]["hint"] == "config/prod.py"
        assert ann["deps"]["hint"] == "none reachable yet"
        assert ann["coverage"]["value"] == "4 of 5" and "API Security" in ann["coverage"]["hint"]
        assert ann["fresh"]["value"] == "1 d" and ann["fresh"]["state"] == "ok"
        # Compliance is advisory: flagged so, never red, and it has no analyte.
        assert ann["comp"]["advisory"] is True and ann["comp"]["state"] == "off"
        assert ann["comp"]["value"] == "5 not met" and ann["comp"]["hint"] == "of 14 readable from code"
        assert "comp" not in analytes and all(not a["advisory"] for k, a in ann.items() if k != "comp")
        assert ann["fix"]["value"] == "1 open" and "482" in ann["fix"]["hint"]
        assert health["reasons"][0].endswith("was reproduced; the proof is attached.")
        assert any("API Security engine has not run for 9 days" in r for r in health["reasons"])
        assert app["banner"][0]["level"] == "danger" and app["banner"][0]["word"] == "Exploit proven"
        assert app["lifecycle"]["current"] == "fix_proposed" and app["lifecycle"]["owner"] == "Meera Nair"
        assert [c["pack_id"] for c in app["compliance"]] == ["rbi-csf"]
        assert (app["compliance"][0]["met"], app["compliance"][0]["not_met"],
                app["compliance"][0]["unknown"], app["compliance"][0]["not_observable"]) == (6, 5, 3, 26)
        assert len(app["fixes"]) == 2 and by(app["fixes"], "url", None)["status"] == "verified_fixed"
        assert app["scans"][0]["coverage"] == "partial" and len(app["scans"]) == 9

        # Unscanned: no analytes, onboarded, honest banner.
        status, legacy_app = api.application_payload("ibank/legacy-partner-feed", root, NOW)
        payloads.append(legacy_app)
        assert legacy_app["health"]["analytes"] == [] and legacy_app["health"]["level"] == "unknown"
        assert legacy_app["lifecycle"]["current"] == "onboarded" and legacy_app["pipeline"]["run"] is None
        # A clear application says so, and says why it is clear.
        status, nb = api.application_payload("ibank/netbanking-web", root, NOW)
        assert nb["health"]["level"] == "clear" and nb["banner"][0]["level"] == "success"
        assert nb["health"]["analytes"][0]["flag"] == "ok"

        # --- /api/pipeline/<run> ---------------------------------------------------------------
        run = app["pipeline"]["run"]
        status, pl = api.pipeline_payload(run, root, NOW)
        payloads.append(pl)
        assert status == 200 and pl["application"] == HERO
        assert pl["elapsed"] == 760.0 and pl["commit"] == "a91f3c2" and pl["cost_usd"] == 1.84
        assert pl["agents"] == 6 and pl["tokens"] == {"input": 41200, "output": 9800}
        assert pl["required"] == {"ran": 4, "of": 5} and pl["policy"] == "Tier 1 payments baseline"
        assert [g["key"] for g in pl["groups"]] == ["pre", "agents"]
        lanes = {ln["id"]: ln for ln in pl["lanes"]}
        for sid in ("trivy", "semgrep", "nuclei"):
            assert lanes[sid]["origin"] == "third_party" and lanes[sid]["state"] == "done"
        assert lanes["trivy"]["tool"] == "Trivy" and lanes["trivy"]["summary"] == "2 critical CVEs, 1 secret"
        assert (lanes["trivy"]["candidates"], lanes["semgrep"]["candidates"],
                lanes["nuclei"]["candidates"]) == (3, 12, 2)
        assert lanes["nuclei"]["required"] is False
        api_lane = lanes["apisec"]
        assert (api_lane["origin"], api_lane["state"], api_lane["required"]) == ("henoyo", "not_run", True)
        assert api_lane["start"] == lanes["nuclei"]["end"], "a not_run lane takes the slot after the previous one"
        assert any("OWASP" in r for r in api_lane["requiredBy"])
        assert lanes["triage"]["summary"] == "12 judged: 5 exploitable, 4 not reachable, 3 unsure"
        assert lanes["compliance"]["required"] is False and "advisory" in lanes["compliance"]["summary"]
        assert lanes["recon"]["summary"] == "38 routes mapped" and lanes["fix"]["summary"] == "2 patches, 1 pull request"
        swarm = lanes["swarm"]
        assert swarm["proven"] == 2 and swarm["summary"] == "3 specialists, 2 exploits proven"
        kids = [ln for ln in pl["lanes"] if ln.get("parentId") == "swarm"]
        assert [k["id"] for k in kids] == ["sw-sqli", "sw-idor", "sw-ssrf"], kids
        assert [k["proven"] for k in kids] == [1, 1, 0]
        assert any("VAPT" in r for r in swarm["requiredBy"]), swarm["requiredBy"]
        # Times: every lane's start <= end, the pre scanners run in order, specialists sit
        # inside the swarm, and the whole thing fits in the run's elapsed time.
        for ln in pl["lanes"]:
            if "start" in ln and "end" in ln:
                assert 0 <= ln["start"] <= ln["end"] <= pl["elapsed"], ln
        pre = [lanes[s] for s in ("trivy", "semgrep", "nuclei", "apisec")]
        assert [p["start"] for p in pre] == sorted(p["start"] for p in pre), "pre lanes are monotonic"
        for k in kids:
            assert swarm["start"] <= k["start"] <= k["end"] <= swarm["end"], (k, swarm)
        assert lanes["fix"]["start"] >= swarm["end"] and lanes["triage"]["start"] > lanes["semgrep"]["start"]
        assert lanes["swarm"]["cost"] == 0.71 and lanes["triage"]["cost"] == 0.41
        assert api.pipeline_payload(run, root, NOW)[1]["lanes"] == pl["lanes"], "stable across calls"

        # --- /api/findings: proof classification -------------------------------------------------
        status, fnd = api.findings_payload(root, NOW)
        payloads.append(fnd)
        rows = fnd["findings"]
        assert status == 200 and fnd["count"] == len(rows) > 40
        needed = {"id", "run", "application", "sev", "title", "sub", "proof", "reach", "by", "age_days",
                  "status", "rule_id", "cwe", "location", "poc", "triage", "fix", "evidence_ref"}
        assert all(set(r) == needed for r in rows)
        assert all(r["proof"] in ("reproduced", "deterministic", "candidate", "not_reachable") for r in rows)

        def f(title_part: str, app_id: str | None = None) -> dict:
            hits = [r for r in rows if title_part in r["title"] and (app_id is None or r["application"] == app_id)]
            assert len(hits) == 1, (title_part, [h["title"] for h in hits])
            return hits[0]

        sqli = f("SQL injection in POST /payments/refund")
        assert (sqli["proof"], sqli["sev"], sqli["by"]) == (
            "reproduced", "critical", {"origin": "henoyo", "name": "Docket SQLi specialist"})
        assert sqli["poc"]["request"].startswith("POST /payments/refund") and sqli["poc"]["response"]
        assert sqli["status"] == "Fix proposed" and sqli["fix"]["diff"].startswith("--- a/payments/refund.py")
        assert sqli["sub"] == "CWE-89 · parameter ref_id" and sqli["age_days"] == 9
        assert f("Broken object-level")["by"]["name"] == "Docket IDOR specialist"
        ssrf = f("Server-side request forgery")
        assert (ssrf["proof"], ssrf["application"]) == ("reproduced", "ibank/disputes")
        key = f("Hardcoded API key")
        assert (key["proof"], key["by"], key["poc"]) == (
            "deterministic", {"origin": "third_party", "name": "Trivy"}, None)
        cve = f("CVE-2020-14343")
        assert (cve["proof"], cve["reach"], cve["poc"]) == ("candidate", None, None), "a CVE is never proof"
        log4j = f("log4j-core")
        assert (log4j["proof"], log4j["reach"], log4j["application"]) == (
            "candidate", "Reachable", "ibank/kyc-gateway")
        sql = f("Formatted SQL query in reports/export.py")
        assert (sql["proof"], sql["reach"], sql["status"]) == ("candidate", "Reachable", "Triaged")
        assert sql["triage"]["verdict"] == "exploitable" and sql["poc"] is None
        cloud = f("Possible cloud key")
        assert (cloud["proof"], cloud["reach"], cloud["application"]) == ("candidate", "Uncertain", "ibank/upi-adapter")
        assert cloud["triage"]["verdict"] == "uncertain"
        debug = f("Debug mode enabled in config/settings.js")
        assert (debug["proof"], debug["reach"], debug["application"]) == (
            "not_reachable", "Not reachable", "ibank/admin-ledger")
        assert debug["status"] == "Triaged: not reachable"
        csp = f("Content-Security-Policy", "ibank/netbanking-web")
        assert (csp["proof"], csp["sev"], csp["by"]["name"]) == ("candidate", "low", "Nuclei")
        # Only agents reproduce. Every non-reproduced row has no PoC; every reproduced row has one.
        for r in rows:
            assert (r["poc"] is not None) == (r["proof"] == "reproduced"), r["title"]
            if r["proof"] == "reproduced":
                assert r["poc"]["request"].strip() and r["poc"]["response"].strip()
                assert r["by"]["origin"] == "henoyo"
        # Ordered: proof first.
        order = ["reproduced", "deterministic", "candidate", "not_reachable"]
        assert [r["proof"] for r in rows] == sorted((r["proof"] for r in rows), key=order.index)

        # --- /api/policy ---------------------------------------------------------------------------
        status, pol = api.policy_payload(None, root, NOW)
        payloads.append(pol)
        assert status == 200 and [p["id"] for p in pol["policies"]] == ["tier1-payments", "standard-baseline"]
        t1 = pol["policies"][0]
        assert (t1["applies_count"], t1["version"], t1["cadence_days"]) == (6, 3, 7)
        assert [s["id"] for s in t1["steps"]] == [s.id for s in CATALOG], "nine steps, pipeline order"
        assert [s["n"] for s in t1["steps"]] == list(range(1, 10))
        required = [s["id"] for s in t1["steps"] if s["required"]]
        assert required == ["trivy", "semgrep", "apisec", "triage", "swarm"], required
        steps = {s["id"]: s for s in t1["steps"]}
        assert steps["compliance"]["required"] is False, "the compliance reader is always optional"
        assert steps["trivy"]["phase"] == "Before the agents" and steps["swarm"]["phase"] == "Docket agents"
        vapt = [w for w in steps["swarm"]["why"] if w["kind"] == "regulatory"]
        assert len(vapt) == 1 and vapt[0]["obligation_ref"] == "rbi-csf:vapt" and vapt[0]["authority"] == "RBI"
        assert "VAPT" in vapt[0]["text"] and vapt[0]["clause"] is None and vapt[0]["source_url"].startswith("https://")
        assert not any(w.get("authority") == "SEBI" for w in steps["swarm"]["why"])
        assert "Secure configuration" in steps["trivy"]["why"][1]["text"]
        assert [r["authority"] for r in t1["regulatory"]] == ["RBI", "RBI", "SEBI", "OWASP"]
        assert all(r["clause"] is None for r in t1["regulatory"]), "no clause is ever invented"
        assert [g["effect"] for g in t1["gate"]] == ["blocks", "flags", "advises"]
        assert "CVE" not in t1["gate"][0]["text"] and "triage verdict of confirmed" in t1["gate"][0]["text"]
        cov = pol["coverage"]
        assert cov["policy"] == "tier1-payments" and cov["window_days"] == 7
        assert [s["id"] for s in cov["scanners"]] == required
        assert len(cov["rows"]) == 6
        rows_by_id = {r["id"]: r for r in cov["rows"]}
        card = rows_by_id[HERO]
        assert card["cells"]["apisec"] == {"state": "stale", "ago": "9 d"}
        assert card["cells"]["trivy"] == {"state": "ok", "ago": "1 d"}
        assert card["consequence"] == {"effect": "flags", "text": "API Security engine is 9 days stale"}
        assert all(c["state"] == "stale" and c["ago"] == "11 d" for c in rows_by_id["ibank/kyc-gateway"]["cells"].values())
        assert rows_by_id["ibank/kyc-gateway"]["consequence"]["text"] == "Nothing has run for 11 days"
        assert rows_by_id["ibank/admin-ledger"]["cells"]["apisec"] == {"state": "missing", "ago": "never"}
        assert rows_by_id["ibank/admin-ledger"]["consequence"]["effect"] == "flags"
        assert rows_by_id["ibank/disputes"]["consequence"]["effect"] == "blocks"
        assert rows_by_id["ibank/upi-adapter"]["consequence"] == {"effect": None, "text": None}
        assert rows_by_id["ibank/netbanking-web"]["consequence"]["effect"] is None
        std = api.policy_payload("standard-baseline", root, NOW)[1]["coverage"]
        assert std["policy"] == "standard-baseline" and len(std["rows"]) == 6
        assert [s["id"] for s in std["scanners"]] == ["trivy", "semgrep", "triage"]
        assert std["rows"][-1]["cells"]["trivy"]["state"] in ("ok", "stale", "missing")
        assert api.policy_payload("no-such-policy", root, NOW)[0] == 404

        # --- compliance citation structure -----------------------------------------------------------
        status, detail = pack_detail("rbi-csf")
        assert status == 200
        controls = detail["pack"]["controls"]
        assert all(set(c["citation_parts"]) == {"authority", "instrument", "section", "clause", "source_url"}
                   for c in controls)
        first = controls[0]["citation_parts"]
        assert first == {"authority": "RBI", "instrument": "RBI Cyber Security Framework, Annex 1",
                         "section": "Cryptographic and network controls", "clause": None,
                         "source_url": "https://www.rbi.org.in/Scripts/NotificationUser.aspx"}, first
        assert all(c["citation_parts"]["clause"] is None for c in controls), "shipped packs carry no clause"
        md = by(controls, "id", "rbi-csf:crypto-algorithms")["citation_parts"]
        assert md["instrument"] == "RBI Master Direction on IT Governance" and md["section"] == "Cryptographic controls"
        for pack in packs_index()[1]["packs"]:
            for c in pack_detail(pack["id"])[1]["pack"]["controls"]:
                assert c["citation_parts"]["authority"] == pack["authority"]
        # A pack that DOES supply a clause and an obligation_ref has them passed through.
        custom = ControlPack(id="acme-policy", title="ACME", authority="customer", origin="uploaded",
                             source_url="https://example.test/policy",
                             controls=[Control(id="acme-policy:c1", title="t", requirement="r",
                                               citation="ACME InfoSec Policy: Passwords", clause="4.2.1",
                                               obligation_ref="acme:pw")])
        save_uploaded(custom, cwd=root)
        got = pack_detail("acme-policy", cwd=root)[1]["pack"]["controls"][0]
        assert got["citation_parts"]["clause"] == "4.2.1" and got["obligation_ref"] == "acme:pw"
        assert got["citation_parts"]["instrument"] == "ACME InfoSec Policy"

        # --- the words and keys this product refuses to show ------------------------------------------
        text = json.dumps(payloads).lower()
        assert "compliant" not in text
        for path, key, _ in walk(payloads):
            assert not any(bad in key.lower() for bad in ("percent", "score")), (path, key)
        assert all(a["state"] != "bad" for a in health["annunciators"] if a["advisory"])
        assert "%" not in json.dumps([a["reason"] for a in port["applications"]])

        # --- untrusted input: nothing from a URL becomes a path -----------------------------------------
        for bad in ("..", "../x", "../../etc/passwd", ".docket", "a/b", "", "x" * 400, "a b"):
            assert api.pipeline_payload(bad, root, NOW)[0] == 400, bad
        assert api.pipeline_payload("not-a-run", root, NOW)[0] == 404
        outside = Path(tmp) / "outside"
        outside.mkdir()
        (outside / "report.json").write_text(json.dumps({"target": "github:evil/x"}))
        os.symlink(outside, root / "docket_runs" / "escape")
        assert api.pipeline_payload("escape", root, NOW)[0] == 404
        assert "evil/x" not in json.dumps(api.portfolio_payload(root, NOW)[1])
        for bad in ("../../etc/passwd", "ibank/../x", "nope", "", "x" * 5000):
            assert api.application_payload(bad, root, NOW)[0] == 404, bad
        # A corrupt report is skipped, not fatal.
        broken = root / "docket_runs" / "broken"
        broken.mkdir()
        (broken / "report.json").write_text("{not json")
        assert api.portfolio_payload(root, NOW)[1]["counts"]["action"] == 2

        # --- the real HTTP handler, over loopback ------------------------------------------------------------
        from docket.interface.connect import make_handler

        before = os.getcwd()
        os.chdir(root)
        server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler())
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{server.server_address[1]}"

        def get(path: str) -> tuple[int, dict]:
            try:
                with urllib.request.urlopen(base + path, timeout=20) as resp:
                    return resp.status, json.loads(resp.read())
            except urllib.error.HTTPError as exc:
                return exc.code, json.loads(exc.read() or b"{}")

        try:
            status, body = get("/api/portfolio")
            assert status == 200 and body["sample"] is True and body["counts"]["action"] == 2
            status, body = get("/api/application/" + urllib.parse.quote(HERO, safe=""))
            assert status == 200 and body["application"]["id"] == HERO
            assert get("/api/application/nope")[0] == 404
            status, body = get("/api/pipeline/" + run)
            assert status == 200 and body["run"] == run
            assert get("/api/pipeline/..%2f..%2fetc")[0] == 400
            assert get("/api/pipeline/missing-run")[0] == 404
            status, body = get("/api/findings")
            assert status == 200 and body["count"] == fnd["count"]
            status, body = get("/api/policy")
            assert status == 200 and len(body["policies"]) == 2
            assert get("/api/policy?policy=standard-baseline")[1]["coverage"]["policy"] == "standard-baseline"
            status, body = get("/api/compliance/packs/rbi-csf")
            assert status == 200 and "citation_parts" in body["pack"]["controls"][0]
            # Existing routes are undisturbed, including the two prefixes next to ours.
            assert get("/api/runs")[0] == 200 and len(get("/api/runs")[1]["runs"]) >= 40
            status, body = get("/api/run/" + run)
            assert status == 200 and body["id"] == run
            assert get("/api/scan/unknown-id") == (404, {"error": "unknown scan"})
            assert get("/api/does-not-exist") == (404, {"error": "no such endpoint"})
        finally:
            server.shutdown()
            server.server_close()
            os.chdir(before)

    # --- stage timings reach the report (runner.py -> ScanResult -> build_report) ---------------------
    result = ScanResult(success=True, summary="", finding_count=0)
    assert result.stage_timings == {} and result.run_timing == {}
    console.demo()
    print("test_portfolio: ok")


if __name__ == "__main__":
    main()
