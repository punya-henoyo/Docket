"""The Code Security console's read model, end to end on the seeded sample scenario.

No Docker and no API key: the seeder writes `docket_runs/*`, `docket_portfolio.json` and
`docket_policy.json` into a temp directory, and the api functions (plus the real HTTP
handler, over loopback) are asserted against the numbers in docs/ui/mockup/sample.js.

Run: uv run python tests/test_portfolio.py
"""
from __future__ import annotations

import http.client
import json
import os
import shutil
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
from docket.portfolio import api, policy_write
from docket.portfolio import posture
from docket.portfolio.catalog import CATALOG, catalog_payload
from docket.portfolio.model.derive import build_model
from docket.portfolio.policy import floor_warnings, find_ties, load_policies

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


def check_policy_features(root: Path) -> None:
    """Profile, assignment, catalog, floor, policy writes and the preview, on a copy of the
    seeded scenario so no write leaks into the HTTP checks that follow."""
    # --- the profile and the assignment ------------------------------------------------------------
    port = api.portfolio_payload(root, NOW)[1]
    prof = {a["id"]: (a["category"], a["exposure"], a["stack"], a["assignment"]["policy"],
                      a["assignment"]["via"]) for a in port["applications"]}
    assert all(v[0] and v[1] and v[2] for k, v in prof.items() if k.startswith("ibank/")), prof
    assert prof[HERO] == ("Banking", "Customer-facing", "API", "banking-customer", "matched")
    assert prof["ibank/notifications"][3:] == ("non-banking-web", "matched")
    assert prof["ibank/branch-locator"][3:] == ("non-banking-web", "matched")
    assert prof["ibank/legacy-partner-feed"][3:] == ("internal", "matched")
    assert prof["ibank/kyc-gateway"][3:] == ("banking-customer", "matched")       # partner-facing
    assert prof["ibank/account-statements"][3:] == ("banking-customer", "matched")
    app = api.application_payload("ibank/admin-ledger", root, NOW)[1]["application"]
    assert app["assignment"] == {"policy": "banking-customer", "via": "pinned", "incomplete": [],
                                 "overrides": "internal"}, app["assignment"]
    assert api.application_payload(HERO, root, NOW)[1]["application"]["assignment"] == {
        "policy": "banking-customer", "via": "matched", "incomplete": [], "overrides": None}
    pols, warns, _ = load_policies(root)
    assert [p.id for p in pols] == ["banking-customer", "internal", "non-banking-web"] and not warns, warns
    assert find_ties(pols) == [] and all(floor_warnings(p) == [] for p in pols)

    # An incomplete profile still gets the best policy, and the card says so (attention).
    base_counts = port["counts"]
    gap = Path(tempfile.mkdtemp(dir=root.parent))
    shutil.copytree(root, gap, dirs_exist_ok=True)
    cfg = json.loads((gap / "docket_portfolio.json").read_text())
    next(a for a in cfg["applications"] if a["repo"] == "ibank/netbanking-web").pop("category")
    (gap / "docket_portfolio.json").write_text(json.dumps(cfg))
    st, body = api.application_payload("ibank/netbanking-web", gap, NOW)
    assert st == 200 and body["application"]["assignment"] == {
        "policy": "default", "via": "default", "incomplete": ["category"], "overrides": None}
    want = "Profile incomplete: category is missing, so the default policy applies"
    assert body["application"]["level"] == "attention" and body["application"]["reason"] == want
    assert want + "." in body["health"]["reasons"] and body["health"]["level"] == "attention"
    assert any(b["word"] == "Profile incomplete" for b in body["banner"])
    counts = api.portfolio_payload(gap, NOW)[1]["counts"]
    assert counts == {**base_counts, "attention": base_counts["attention"] + 1,
                      "clear": base_counts["clear"] - 1}, (base_counts, counts)
    shutil.rmtree(gap)

    # --- the catalog --------------------------------------------------------------------------------
    st, cat = catalog_payload(root)
    assert st == 200 and [x["id"] for x in cat["slots"]] == [s.id for s in CATALOG]
    slot = {x["id"]: x for x in cat["slots"]}
    assert [t["id"] for t in slot["semgrep"]["tools"]][:3] == ["semgrep", "codeql", "sonarqube"]
    # SARIF imports are recorded as a stage (report stage_meta), so they read imports.
    assert {t["availability"] for t in slot["semgrep"]["tools"] if not t.get("default")} == {"imports"}
    assert slot["trivy"]["tools"][0]["availability"] == "runs" and slot["triage"]["tools"][0]["origin"] == "henoyo"
    assert all(x["what"] and x["produces"] and x["command"] for x in cat["slots"])
    assert "--metrics=off" in slot["semgrep"]["command"]
    assert {t["kind"]: t["availability"] for t in cat["starts"]} == {
        "manual": "works", "pull_request": "works", "schedule": "planned", "release": "planned"}
    assert cat["profile"]["category"] == ["Banking", "Non-banking"] and "Batch" in cat["profile"]["stack"]
    rbi = next(g for g in cat["guidelines"] if g["id"] == "rbi-csf")
    assert rbi["authority"] == "RBI" and 0 < rbi["observable"] < rbi["controls"], rbi

    # --- /api/policy additions ----------------------------------------------------------------------
    pol = api.policy_payload("internal", root, NOW)[1]
    bc = by(pol["policies"], "id", "banking-customer")
    assert bc["applies_when"] == {"category": ["Banking"], "exposure": ["Customer-facing", "Partner-facing"],
                                  "stack": [], "tier": []}
    assert bc["guidelines"] == ["rbi-csf", "sebi-cscrf", "owasp-api-2023"] and bc["warnings"] == []
    assert bc["conflicts"] == [] and pol["conflicts"] == [] and bc["status"] == "saved"
    assert 0 <= bc["meets_count"] <= bc["applies_count"] == 7
    assert [s["kind"] for s in bc["starts"]] == ["manual", "pull_request", "schedule", "release"]
    assert by(bc["starts"], "kind", "schedule")["label"] == "Every 7 days"
    assert by(bc["steps"], "id", "semgrep")["tool_id"] is None and by(bc["steps"], "id", "semgrep")["tool"] == "Semgrep"
    assert pol["coverage"]["policy"] == "internal"

    # --- writes: patch the raw file, keep everything else ------------------------------------------
    raw = json.loads((root / "docket_policy.json").read_text())
    raw["x_note"] = "kept"
    raw["policies"][1]["x_owner"] = "kept too"
    raw["policies"].append({"id": "hand-broken", "name": "Unparseable", "steps": [{"id": "nope"}]})
    (root / "docket_policy.json").write_text(json.dumps(raw))
    steps = [{"id": "trivy", "required": True}, {"id": "semgrep", "required": True},
             {"id": "triage", "required": True}]
    st, res = policy_write.put_policy("mobile", {"name": "Mobile apps", "steps": steps,
                                                 "applies_when": {"category": ["Non-banking"], "stack": ["Mobile"]},
                                                 "applies_count": 99, "label": "view-only"}, root)
    assert st == 200 and res["created"] and res["version"] == 1, (st, res)
    after = json.loads((root / "docket_policy.json").read_text())
    assert after["x_note"] == "kept" and after["policies"][:3] == raw["policies"][:3]
    assert after["policies"][3] == raw["policies"][3], "an unparseable entry is not deleted"
    new = after["policies"][4]
    assert new["id"] == "mobile" and "applies_count" not in new and "label" not in new, new
    st, res = policy_write.put_policy("mobile", {"cadence_days": 14}, root)     # patch: other keys stay
    assert st == 200 and res["version"] == 2
    new = json.loads((root / "docket_policy.json").read_text())["policies"][4]
    assert new["cadence_days"] == 14 and new["name"] == "Mobile apps" and len(new["steps"]) == 3
    # Refusals leave the file byte for byte as it was.
    frozen = (root / "docket_policy.json").read_bytes()
    st, res = policy_write.put_policy("tier-tie", {"name": "T", "steps": steps,
                                                   "applies_when": {"category": ["Non-banking"], "stack": ["Mobile", "Web"]}}, root)
    assert st == 400 and all("equally specific" in e for e in res["errors"]), res
    assert any("Mobile apps" in e for e in res["errors"]) and any("Non-banking web" in e for e in res["errors"])
    st, res = policy_write.put_policy("planned", {"name": "P", "steps": [
        {"id": "trivy", "required": True, "tool": "grype"}]}, root)
    assert st == 400 and "planned" in res["errors"][0], res
    st, res = policy_write.put_policy("imports-ok", {"name": "P", "steps": [
        {"id": "semgrep", "required": True, "tool": "codeql"}]}, root)
    assert st == 200, ("codeql imports SARIF, so a policy may choose it", res)
    policy_write.delete_policy("imports-ok", root)
    assert policy_write.put_policy("../evil", {"name": "x", "steps": steps}, root)[0] == 400
    assert policy_write.put_policy("UP", {"name": "x", "steps": steps}, root)[0] == 400
    assert policy_write.put_policy("a", {"id": "b", "name": "x", "steps": steps}, root)[0] == 400
    assert policy_write.put_policy("bad-when", {"name": "x", "steps": steps,
                                                "applies_when": {"exposures": ["Internal"]}}, root)[0] == 400
    assert (root / "docket_policy.json").read_bytes() == frozen
    assert not [f for f in root.iterdir() if f.name.startswith(".docket_policy.")], "no temp file left"
    # A thin policy saves, with the floor warning.
    st, res = policy_write.put_policy("thin", {"name": "Thin", "steps": [{"id": "trivy", "required": True}],
                                               "applies_when": {"category": ["Banking"],
                                                                "exposure": ["Customer-facing"],
                                                                "stack": ["Mobile"]}}, root)
    assert st == 200 and "Thinner than the baseline" in res["warnings"][0], res
    thin = by(api.policy_payload(None, root, NOW)[1]["policies"], "id", "thin")
    assert thin["warnings"] and "Exploit swarm" in thin["warnings"][0]
    assert policy_write.delete_policy("thin", root)[0] == 200 and policy_write.delete_policy("thin", root)[0] == 404
    assert policy_write.delete_policy("mobile", root)[0] == 200
    assert json.loads((root / "docket_policy.json").read_text()) == raw, "delete restores the file"

    # --- the preview: a plan and the people it affects, with no side effects ------------------------
    frozen = (root / "docket_policy.json").read_bytes()
    draft = {"id": "internal", "name": "Internal and back-office", "applies_when": {"exposure": ["Internal"]},
             "steps": [{"id": "swarm", "required": False}, {"id": "apisec", "required": True},
                       {"id": "trivy", "required": True}, {"id": "semgrep", "required": True},
                       {"id": "triage", "required": True}]}
    st, prev = policy_write.preview_payload(draft, root, NOW)
    assert st == 200, prev
    assert sorted(m["id"] for m in prev["matches"]) == [
        "ibank/legacy-partner-feed", "ibank/loan-origination", "ibank/treasury-reports"]
    assert set(prev["matches"][0]) == {"id", "label", "tier", "category", "exposure"}
    assert (prev["would_meet"], prev["would_breach"]) == (0, 3), prev
    # Treasury meets today and would not once API Security is required; the others breach either way.
    assert prev["changes"] == [{"id": "ibank/treasury-reports", "label": "Treasury Reports",
                                "before": "meets", "after": "breaches",
                                "why": "API Security engine has never run."}], prev["changes"]
    assert [p["id"] for p in prev["plan"]] == ["trivy", "semgrep", "apisec", "triage", "swarm"], "Docket's order"
    assert [p["n"] for p in prev["plan"]] == [1, 2, 3, 4, 5]
    sem = by(prev["plan"], "id", "semgrep")
    assert (sem["tool"], sem["origin"], sem["availability"], sem["required"]) == ("Semgrep", "third_party", "runs", True)
    assert sem["command"].startswith("semgrep scan") and sem["what"] and sem["produces"]
    assert by(prev["plan"], "id", "apisec")["availability"] == "planned"
    assert prev["warnings"] == [] and prev["conflicts"] == []
    # A draft that moves applications: every Non-banking web app now falls under it.
    st, prev = policy_write.preview_payload({"id": "nb-strict", "name": "NB strict", "steps": steps,
        "applies_when": {"category": ["Non-banking"], "stack": ["Web"], "exposure": ["Customer-facing"]}},
        root, NOW)
    assert [m["id"] for m in prev["matches"]] == ["ibank/branch-locator"], prev["matches"]
    ch = prev["changes"][0]
    assert ch["id"] == "ibank/branch-locator" and ch["before"] == "meets" and ch["after"] == "meets"
    assert "Moves from Non-banking web and API to NB strict" in ch["why"], ch
    # Ties and floor warnings surface in the preview rather than blocking it.
    st, prev = policy_write.preview_payload({"id": "twin", "name": "Twin", "steps": steps,
                                             "applies_when": {"exposure": ["Internal"]}}, root, NOW)
    assert st == 200 and "equally specific" in prev["conflicts"][0]
    st, prev = policy_write.preview_payload({"id": "thin", "name": "Thin", "steps": steps[:1],
                                             "applies_when": {"category": ["Banking"]}}, root, NOW)
    assert st == 200 and "Thinner than the baseline" in prev["warnings"][0]
    assert policy_write.preview_payload({"id": "x", "name": "x", "steps": [{"id": "nope"}]}, root, NOW)[0] == 400
    assert policy_write.preview_payload("nope", root, NOW)[0] == 400
    assert (root / "docket_policy.json").read_bytes() == frozen, "the preview wrote nothing"


def check_policy_http(base: str, root: Path) -> None:
    """The write routes over the real handler: method, content type, origin and size guards."""
    def call(method: str, path: str, body: object = None, headers: dict | None = None) -> tuple[int, dict]:
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(base + path, data=data, method=method,
                                     headers={"Content-Type": "application/json", **(headers or {})})
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read() or b"{}")

    frozen = (root / "docket_policy.json").read_bytes()
    steps = [{"id": "trivy", "required": True}, {"id": "semgrep", "required": True},
             {"id": "triage", "required": True}]
    status, cat = call("GET", "/api/catalog")
    assert status == 200 and cat["slots"][0]["id"] == "trivy" and cat["guidelines"]
    status, body = call("PUT", "/api/policy/mobile", {"name": "Mobile", "steps": steps,
                                                      "applies_when": {"category": ["Non-banking"], "stack": ["Mobile"]}})
    assert status == 200 and body["version"] == 1, body
    status, body = call("GET", "/api/policy")
    assert status == 200 and by(body["policies"], "id", "mobile")["applies_when"]["stack"] == ["Mobile"]
    status, body = call("POST", "/api/policy/preview", {"id": "mobile", "name": "Mobile", "steps": steps,
                                                        "applies_when": {"category": ["Non-banking"], "stack": ["Mobile"]}})
    assert status == 200 and body["matches"] == [] and len(body["plan"]) == 3
    assert call("PUT", "/api/policy/mobile", {"name": "x", "steps": [{"id": "nope"}]})[0] == 400
    assert call("PUT", "/api/policy/preview", {"name": "x"})[0] == 404
    assert call("PUT", "/api/other", {"name": "x"})[0] == 404
    # Guards: cross-origin, not JSON, oversized.
    assert call("PUT", "/api/policy/mobile", {"name": "Mobile", "steps": steps},
                {"Origin": "http://evil.example"})[0] == 403
    assert call("DELETE", "/api/policy/mobile", None, {"Origin": "http://evil.example"})[0] == 403
    assert call("PUT", "/api/policy/mobile", {"name": "Mobile", "steps": steps},
                {"Content-Type": "text/plain"})[0] == 415
    assert call("POST", "/api/policy/preview", {"id": "x"}, {"Content-Type": "text/plain"})[0] == 415
    host, port = base.removeprefix("http://").split(":")
    conn = http.client.HTTPConnection(host, int(port), timeout=20)
    conn.putrequest("PUT", "/api/policy/mobile")
    conn.putheader("Content-Type", "application/json")
    conn.putheader("Content-Length", str(10 * 1024 * 1024))
    conn.endheaders()                      # the body is never sent: the cap answers first
    resp = conn.getresponse()
    assert resp.status == 413, resp.status
    resp.read()
    conn.close()
    conn = http.client.HTTPConnection(host, int(port), timeout=20)
    conn.request("PUT", "/api/policy/mobile", body=b"{not json", headers={"Content-Type": "application/json"})
    resp = conn.getresponse()
    assert resp.status == 400, resp.status
    resp.read()
    conn.close()
    assert call("DELETE", "/api/policy/mobile")[0] == 200 and call("DELETE", "/api/policy/mobile")[0] == 404
    assert json.loads((root / "docket_policy.json").read_text()) == json.loads(frozen), "back to the seed"


DAY = 86400.0
QUIET = "ibank/netbanking-web"      # clear, right half, nothing open
STALE = "ibank/loan-origination"    # quiet but overdue: no scan for 12 days
PROVEN = "ibank/disputes"           # one reproduced exploit open


def add_run(root: Path, repo: str, name: str, days_ago: float, *, leads: int = 0,
            stages: dict | None = None, pr: int | None = None, meta: dict | None = None) -> None:
    """A static-only report (no agents) for `repo`, `days_ago` before NOW."""
    d = root / "docket_runs" / name
    d.mkdir(parents=True)
    at = NOW - days_ago * DAY
    report = {"target": f"github:{repo}@main",
              "run_timing": {"started": at - 5, "ended": at},
              "stages": stages or {"trivy": "done", "semgrep": "done", "triage": "done"},
              "findings": [],
              "flagged_not_proven": [
                  {"rule_id": f"py.rule-{i}", "engine": "semgrep", "severity": "high",
                   "cwe": "CWE-89", "file": f"app/f{i}.py", "line": 10 + i, "message": "Possible issue",
                   "reachable": True} for i in range(leads)]}
    if pr:
        report["provenance"] = {"repo": repo, "pr": pr}
    if meta:
        report["stage_meta"] = meta
    (d / "report.json").write_text(json.dumps(report))


def point_of(root: Path, repo: str) -> dict:
    return by(api.portfolio_payload(root, NOW)[1]["posture"]["points"], "id", repo)


def check_posture(root: Path) -> None:
    """The two-by-two's data (policy-and-posture.md section 4) on the seeded scenario.
    `root` is only read: scenarios that add runs do it in further scratch copies."""
    port = api.portfolio_payload(root, NOW)[1]
    post = port["posture"]
    model = build_model(root, NOW)
    apps = {a.id: a for a in model.apps}

    # --- the level counts are untouched by the posture work ----------------------------------------
    assert port["counts"] == {"action": 2, "attention": 4, "clear": 5, "unknown": 1}, port["counts"]
    level_of = {a["id"]: a["level"] for a in port["applications"]}
    assert {p["id"]: p["level"] for p in post["points"]} == {
        k: v for k, v in level_of.items() if v != "unknown" or k not in
        [u["id"] for u in post["unassessed"]]}

    # --- shape ---------------------------------------------------------------------------------------
    assert post["history_days"] == 28 and len(post["snapshots"]) == 5
    assert post["snapshots"][-1] == api.timeutil.date(NOW) and post["as_of"].startswith("2027-01-15")
    assert [q["key"] for q in post["quadrants"]] == ["tl", "tr", "bl", "br"]
    titles = {q["key"]: q["title"] for q in post["quadrants"]}
    assert titles == {"tr": "Checks current, nothing proven", "tl": "Checks overdue, nothing proven",
                      "br": "Checks current, problems proven", "bl": "Checks overdue, problems proven"}
    assert len(post["points"]) == 11 and [u["id"] for u in post["unassessed"]] == [
        "ibank/legacy-partner-feed"], "unassessed applications are never plotted"
    legacy = post["unassessed"][0]
    assert "assurance" not in legacy and "standing" not in legacy and legacy["reason"] == "Never scanned"
    for p in post["points"]:
        assert 0 <= p["assurance"] <= 100 and 0 <= p["standing"] <= 100, p
        assert p["cell"] in ("tl", "tr", "bl", "br") and 1 <= p["days_in_cell"] <= 28, p
        assert len(p["trail"]) == 5 and p["trail"][-1]["cell"] == p["cell"], p["id"]
        assert p["trail"][-1]["level"] == p["level"] and p["trail"][-1]["assurance"] == p["assurance"]
        assert p["moved"] == "new" or set(p["moved"]) == {"assurance", "standing"}, p["moved"]
        assert p["assignment"]["policy"] == p["policy"] and p["policy_name"]

    # --- the quadrant is decided by RULE -------------------------------------------------------------
    for p in post["points"]:
        app = apps[p["id"]]
        # right half iff every required step is current: the matrix's "meets the policy"
        assert (p["cell"][1] == "r") == api.meets(app, NOW), (p["id"], p["cell"])
        if p["cell"][1] == "l":
            assert p["assurance"] < 50 and "required scanners current" in p["assurance_note"]
        else:
            assert p["assurance"] > 50
        items, _ = app.standing_items(app.latest)
        proven = [i for i in items if i.proof in ("reproduced", "deterministic")]
        confirmed = [i for i in items if i.verdict == "exploitable"]
        if proven or confirmed:
            assert p["cell"][0] == "b" and p["standing"] < 50, (p["id"], p["standing"])
        else:
            assert p["cell"][0] == "t" and p["standing"] > 50, (p["id"], p["standing"])
        if proven:
            assert p["standing"] <= 26, "a reproduced exploit or a secret is the lowest band"
    cells = {p["id"]: p["cell"] for p in post["points"]}
    assert cells[STALE] == "tl" and point_of(root, STALE)["standing"] == 90, "quiet and stale is tl"
    assert cells["ibank/card-payments"] == "bl" and cells[PROVEN] == "br" and cells[QUIET] == "tr"
    unsure = by(post["points"], "id", "ibank/upi-adapter")
    assert unsure["level"] == "attention" and 52 <= unsure["standing"] <= 64 and unsure["cell"] == "tr"
    assert unsure["standing_note"].startswith("needs a person to judge"), unsure["standing_note"]
    # A confirmed-not-reproduced item is the second band (26..48), still the lower half.
    assert by(post["points"], "id", "ibank/kyc-gateway")["cell"] == "bl"

    # --- replay, snapshots, movement ------------------------------------------------------------------
    snaps = [NOW - (4 - k) * 7 * DAY for k in range(5)]
    for p in post["points"]:
        first = apps[p["id"]].runs[0].at
        assert [e is None for e in p["trail"]] == [first > t for t in snaps], p["id"]
        if p["trail"][2] is None:
            assert p["moved"] == "new" and p["moved_since"] is None
        else:
            assert p["moved_since"] == post["snapshots"][2]
    assert any(p["trail"][0] is None for p in post["points"]), "someone was not yet assessed"
    for k, row in enumerate(post["by_snapshot"]):
        assessed = sum(p["trail"][k] is not None for p in post["points"])
        assert row["tl"] + row["tr"] + row["bl"] + row["br"] == assessed, row
        assert row["unassessed"] == len(apps) - assessed and row["at"] == post["snapshots"][k]
        for cell in ("tl", "tr", "bl", "br"):
            assert row[cell] == sum((p["trail"][k] or {}).get("cell") == cell for p in post["points"])
    last = post["by_snapshot"][-1]
    assert last["unassessed"] == 1 and last["tl"] + last["tr"] + last["bl"] + last["br"] == 11
    # Freshness as of a past instant, one definition: before the first run nothing ran.
    hero = apps[HERO]
    assert hero.last_ran("semgrep", hero.runs[0].at - 1) is None
    assert hero.last_ran("semgrep", NOW) >= hero.last_ran("semgrep", NOW - 20 * DAY)

    # --- leaders, categories, assessments --------------------------------------------------------------
    worst, best = post["leaders"]["worst"], post["leaders"]["best"]
    assert [w["id"] for w in worst] == ["ibank/card-payments", "ibank/disputes", "ibank/kyc-gateway"]
    assert all(w["level"] in ("action", "attention") for w in worst)
    assert best and all(by(post["points"], "id", b["id"])["cell"] == "tr" and b["level"] == "clear"
                        for b in best)
    assert [b["assurance"] for b in best] == sorted((b["assurance"] for b in best), reverse=True)
    assert "ibank/legacy-partner-feed" not in [r["id"] for r in worst + best]
    cats = post["categories"]
    assert sum(c["apps"] for c in cats) == 12 and all("checks_current" in c for c in cats)
    assert sum(c["checks_current"] for c in cats) == sum(
        api.meets(a, NOW) for a in model.apps if a.runs)
    assert sum(sum(c["levels"].values()) for c in cats) == 12
    assert {k: sum(c["levels"][k] for c in cats) for k in port["counts"]} == port["counts"]
    asm = post["assessments"]
    in_window = sum(len(a["events"]) for a in port["applications"])
    assert asm["total"] == in_window == asm["scan"] + asm["pr"] and asm["pr"] >= 1, asm
    assert sum(asm["outcomes"].values()) == asm["total"]
    assert sum(sum(w[k] for k in asm["outcomes"]) for w in asm["weekly"]) == asm["total"]
    assert len(asm["weekly"]) == 4 and asm["weekly"][0]["label"] == "18 Dec"

    # --- no grade, no percentage, no verdict word ------------------------------------------------------
    text = json.dumps(post).lower()
    assert "compliant" not in text and "adherence" not in text
    for path, key, _ in walk(post):
        assert not any(bad in key.lower() for bad in ("score", "percent", "compliant")), (path, key)
    # --- deterministic ---------------------------------------------------------------------------------
    again = api.portfolio_payload(root, NOW)[1]["posture"]
    assert json.dumps(post, sort_keys=True) == json.dumps(again, sort_keys=True)

    # --- candidates never move a dot ---------------------------------------------------------------------
    pts = []
    for leads in (0, 40):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp) / "w"
            shutil.copytree(root, work)
            add_run(work, QUIET, "extra-scan", 0.2, leads=leads)
            p = point_of(work, QUIET)
            pts.append((p["assurance"], p["standing"], p["cell"], p["standing_note"]))
    assert pts[0] == pts[1] and pts[0][2] == "tr" and pts[0][1] == 90, pts

    # --- proven items persist: a later static-only scan cannot make an application look better ----------
    before = point_of(root, PROVEN)
    assert before["cell"] == "br" and before["proven_as_of"] is None
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp) / "w"
        shutil.copytree(root, work)
        add_run(work, PROVEN, "static-later", 0.1)
        after = point_of(work, PROVEN)
        assert after["standing"] <= before["standing"] and after["cell"][0] == "b", after
        assert after["proven_as_of"] and "exploit run" in after["standing_note"], after["standing_note"]
        assert api.portfolio_payload(work, NOW)[1]["counts"]["action"] == 2, "the card agrees"
        card = api.application_payload(PROVEN, work, NOW)[1]["health"]
        proven_analyte = by(card["analytes"], "key", "proven")
        assert proven_analyte["value"] == 1 and "exploit run" in proven_analyte["asOf"]["label"]
        assert "exploit run" in by(card["annunciators"], "key", "proven")["hint"]
        # ...and every screen still shows the exploit, from the run it came from, never duplicated.
        def exploits(rows):
            return [f for f in rows if f["proof"] == "reproduced" and f["application"] == PROVEN]

        for rows in (api.application_payload(PROVEN, work, NOW)[1]["findings"],
                     api.findings_payload(work, NOW)[1]["findings"]):
            got = exploits(rows)
            assert len(got) == 1 and got[0]["status"] != "Fixed", got
            assert got[0]["run"] != "static-later" and got[0]["poc"], "carried from the exploit run"
            assert len({f["id"] for f in rows}) == len(rows), "no duplicates"
        orig = api.application_payload(PROVEN, root, NOW)[1]["findings"]
        later = api.application_payload(PROVEN, work, NOW)[1]["findings"]
        assert {f["proof"] for f in later} == {"reproduced"}, "only exploits are carried, never a candidate"
        assert [f["proof"] for f in later].count("reproduced") == [f["proof"] for f in orig].count("reproduced")
        row = by(api.policy_payload(None, work, NOW)[1]["coverage"]["rows"], "id", PROVEN)
        assert row["consequence"]["effect"] == "blocks" and "Reproduced exploit" in row["consequence"]["text"]
        assert api.application_payload(PROVEN, work, NOW)[1]["lifecycle"]["current"] == "proven"

    # --- a pull-request check does not refresh a required step; an imported file keeps its own time ------
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp) / "w"
        shutil.copytree(root, work)
        add_run(work, STALE, "pr-fresh", 0.1, pr=900)
        m = build_model(work, NOW)
        assert m.app(STALE).last_ran("trivy") == apps[STALE].last_ran("trivy"), "PR must not refresh"
        assert point_of(work, STALE)["cell"] == "tl" and api.meets(m.app(STALE), NOW) is False
        sarif_at = api.timeutil.iso(NOW - 20 * DAY)
        add_run(work, QUIET, "imported-scan", 0.2, meta={"semgrep": {
            "tool": "CodeQL", "tool_version": "2.17.0", "sarif_at": sarif_at, "revision": "abc123"}})
        m = build_model(work, NOW)
        q = m.app(QUIET)
        assert q.last_ran("semgrep") == apps[QUIET].last_ran("semgrep"), "an old file is not fresh"
        assert q.last_ran("trivy") > NOW - DAY
        lane = by(api.pipeline_payload("imported-scan", work, NOW)[1]["lanes"], "id", "semgrep")
        assert (lane["tool"], lane["tool_version"], lane["revision"], lane["sarif_at"]) == (
            "CodeQL", "2.17.0", "abc123", sarif_at) and lane["state"] == "done", lane


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
        assert (sc["apisec"]["current"], sc["apisec"]["of"]) == (4, 7), sc["apisec"]
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
        assert pl["required"] == {"ran": 4, "of": 5} and pl["policy"] == "Banking, customer-facing"
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
        assert status == 200 and [p["id"] for p in pol["policies"]] == [
        "banking-customer", "internal", "non-banking-web"]
        t1 = pol["policies"][0]
        assert (t1["applies_count"], t1["version"], t1["cadence_days"]) == (7, 3, 7)
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
        # Generated from the guidelines first, then the policy's own, then the step reasons; one
        # row per obligation.
        assert [r["obligation_ref"] for r in t1["regulatory"]][:4] == [
            "rbi-csf", "sebi-cscrf", "owasp-api-2023", "rbi-csf:crypto-algorithms"], t1["regulatory"]
        assert len({r["obligation_ref"] for r in t1["regulatory"]}) == len(t1["regulatory"])
        assert all(r["clause"] is None for r in t1["regulatory"]), "no clause is ever invented"
        assert [g["effect"] for g in t1["gate"]] == ["blocks", "flags", "advises"]
        assert "CVE" not in t1["gate"][0]["text"] and "triage verdict of confirmed" in t1["gate"][0]["text"]
        cov = pol["coverage"]
        assert cov["policy"] == "banking-customer" and cov["window_days"] == 7
        assert [s["id"] for s in cov["scanners"]] == required
        assert len(cov["rows"]) == 7
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
        std = api.policy_payload("internal", root, NOW)[1]["coverage"]
        assert std["policy"] == "internal" and len(std["rows"]) == 3
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

        with tempfile.TemporaryDirectory() as tmp2:
            work = Path(tmp2) / "work"
            shutil.copytree(root, work)
            check_policy_features(work)
            check_posture(root)

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
            assert status == 200 and len(body["policies"]) == 3
            assert get("/api/policy?policy=internal")[1]["coverage"]["policy"] == "internal"
            check_policy_http(base, root)
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
