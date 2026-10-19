"""Deterministic SAMPLE data for the Code Security console.

`seed(root)` writes `docket_runs/*`, `docket_portfolio.json` and `docket_policy.json` under
`root`, reproducing the scenario in docs/ui/mockup/sample.js: twelve applications, a scan
history for each, the Card Payments pipeline, its health measures, and RBI control results.

EVERY FILE IS LABELLED. Each report.json carries `"sample": true`, the portfolio file does
too, and `GET /api/portfolio` echoes it so the console can show a persistent "Sample data"
badge. Nothing here is a real scan, a real company or a real credential, and the seeder
refuses to delete anything it did not itself write (a run directory is replaced only if its
report says `sample`).

DETERMINISM. Dates are relative to `now` (the same offsets every time), run names come from
the app and the offset, and every "random-looking" value is a hash of a stable string. Two
calls with the same `now` write the same bytes, which is what lets tests assert exact levels.

THE DATA GOES THROUGH THE REAL MODELS where one exists: findings are built as
`report.models.Finding` and dumped, control results as `compliance.models.PackResult`. So a
shape the real report would not have cannot be seeded by accident, and the PoC validator
still refuses a proven finding with no evidence.
"""
from __future__ import annotations

import hashlib
import json
import shutil
import time
from pathlib import Path
from typing import Any

from docket import __version__
from docket.compliance.models import Citation, ControlResult, ControlStatus, PackResult
from docket.compliance.packs import load_pack
from docket.portfolio.timeutil import DAY, iso
from docket.report.models import Cvss, Finding, Location, PoC, Severity, Triage
from docket.report.writer import parse_source_file
from docket.service.gate import floor_reason

HOUR = 3600.0
REPO_ROOT_NAME = "docket_runs"

# --- the twelve applications (docs/ui/mockup/sample.js) -----------------------------------
# (slug, label, repo, tier, owner, lang, events[(days_ago, proven, candidates, kind)])
APPS: list[tuple[str, str, str, str, str, str, list[tuple[float, int, int, str]]]] = [
    ("card-payments", "Card Payments API", "ibank/card-payments", "Tier 1", "Meera Nair",
     "Python · FastAPI",
     [(52, 0, 5, "scan"), (45, 0, 6, "scan"), (38, 0, 7, "scan"), (31, 0, 8, "scan"),
      (24, 0, 9, "scan"), (17, 0, 11, "scan"), (9, 1, 14, "scan"), (5, 0, 2, "pr"),
      (1, 2, 17, "scan")]),
    ("disputes", "Disputes Service", "ibank/disputes", "Tier 1", "Arjun Rao", "Java · Spring",
     [(22, 0, 7, "scan"), (15, 0, 8, "scan"), (8, 0, 9, "scan"), (2, 1, 10, "scan")]),
    ("kyc-gateway", "KYC Vendor Gateway", "ibank/kyc-gateway", "Tier 1", "Divya Menon",
     "Java · Spring", [(25, 0, 8, "scan"), (18, 0, 8, "scan"), (11, 0, 9, "scan")]),
    ("admin-ledger", "Admin Ledger", "ibank/admin-ledger", "Tier 1", "Karan Shah",
     "Node · Express", [(21, 0, 5, "scan"), (14, 0, 4, "scan"), (7, 0, 4, "scan"),
                        (2, 0, 6, "scan")]),
    ("upi-adapter", "UPI Switch Adapter", "ibank/upi-adapter", "Tier 1", "Sana Iqbal", "Go",
     [(23, 0, 4, "scan"), (16, 0, 4, "scan"), (9, 0, 5, "scan"), (3, 0, 6, "scan")]),
    ("loan-origination", "Loan Origination", "ibank/loan-origination", "Tier 2", "Rahul Verma",
     "Java · Spring", [(27, 0, 6, "scan"), (19, 0, 5, "scan"), (12, 0, 6, "scan")]),
    ("netbanking-web", "Net Banking Web", "ibank/netbanking-web", "Tier 1", "Isha Kapoor",
     "TypeScript · Next",
     [(26, 0, 3, "scan"), (19, 0, 3, "scan"), (12, 0, 2, "scan"), (5, 0, 2, "scan"),
      (2, 0, 1, "pr"), (1, 0, 2, "scan")]),
    ("acct-statements", "Account Statements", "ibank/account-statements", "Tier 2",
     "Vikram Joshi", "Python · Django",
     [(27, 0, 2, "scan"), (20, 0, 2, "scan"), (13, 0, 1, "scan"), (6, 0, 1, "scan"),
      (1, 0, 1, "scan")]),
    ("notifications", "Notification Service", "ibank/notifications", "Tier 3", "Asha Pillai",
     "Go", [(25, 0, 1, "scan"), (18, 0, 1, "scan"), (11, 0, 0, "scan"), (4, 0, 1, "scan")]),
    ("treasury-reports", "Treasury Reports", "ibank/treasury-reports", "Tier 3", "Nitin Desai",
     "Python", [(22, 0, 3, "scan"), (15, 0, 2, "scan"), (8, 0, 2, "scan"), (2, 0, 2, "scan")]),
    ("branch-locator", "Branch Locator", "ibank/branch-locator", "Tier 3", "Pooja Reddy",
     "TypeScript", [(24, 0, 0, "scan"), (17, 0, 1, "scan"), (10, 0, 0, "scan"),
                    (3, 0, 0, "scan")]),
    ("legacy-feed", "Legacy Partner Feed", "ibank/legacy-partner-feed", "Tier 2", "Unassigned",
     "Java 8", []),
]
HERO = "card-payments"

# The application profile the policy assignment reads (docs/ui/policy-and-posture.md, section 2):
# slug -> (category, exposure, stack). `tier` stays on APPS.
PROFILE: dict[str, tuple[str, str, str]] = {
    "card-payments": ("Banking", "Customer-facing", "API"),
    "disputes": ("Banking", "Customer-facing", "API"),
    "kyc-gateway": ("Banking", "Partner-facing", "API"),
    "admin-ledger": ("Banking", "Internal", "Web"),
    "upi-adapter": ("Banking", "Customer-facing", "API"),
    "loan-origination": ("Banking", "Internal", "Web"),
    "netbanking-web": ("Banking", "Customer-facing", "Web"),
    "acct-statements": ("Banking", "Customer-facing", "Web"),
    "notifications": ("Non-banking", "Customer-facing", "API"),
    "treasury-reports": ("Banking", "Internal", "Batch"),
    "branch-locator": ("Non-banking", "Customer-facing", "Web"),
    "legacy-feed": ("Banking", "Internal", "Batch"),
}
# Applications whose scans carry the deep pipeline (apisec and the exploit swarm). Every
# Tier 1 application does; Account Statements is Tier 2 but customer-facing banking, so the
# policy that now covers it requires both and its sample scans ran them.
DEEP_SLUGS = frozenset({"acct-statements"})
# Non-banking web and API applications run Nuclei, which their policy requires.
NUCLEI_SLUGS = frozenset({"notifications", "branch-locator"})
# Admin Ledger is back-office (so its profile matches `internal`) but Tier 1, and the
# security council pinned it to the stricter policy: the sample for an explicit override.
PINNED = {"admin-ledger": "banking-customer"}

# Stage layout in seconds from the start of a run, taken from the mockup's hero pipeline.
TIER1 = {"trivy": (6, 62), "semgrep": (62, 195), "apisec": (195, 280), "triage": (285, 450)}
SWARM = (365, 665)
SPECIALIST_TIMES = {"sqli": (370, 580), "idor": (372, 650), "ssrf": (375, 485)}
HERO_LATEST = {"trivy": (6, 62), "semgrep": (62, 195), "nuclei": (195, 280),
               "recon": (280, 365), "triage": (285, 450), "compliance": (365, 500),
               "fix": (665, 760)}
STANDARD = {"trivy": (6, 62), "semgrep": (62, 195), "triage": (200, 300)}
PR_LAYOUT = {"trivy": (3, 30), "semgrep": (30, 75), "triage": (75, 120)}


def _h(*parts: object, n: int = 8) -> int:
    return int(hashlib.sha1("|".join(map(str, parts)).encode()).hexdigest()[:n], 16)


def _sha(*parts: object) -> str:
    return hashlib.sha1("|".join(map(str, parts)).encode()).hexdigest()


# --- findings ------------------------------------------------------------------------------


def _finding(*, rule_id: str, title: str, sev: str, method: str, path: str, by: str,
             desc: str, req: str, resp: str, cwe: str | None = None, param: str | None = None,
             source: str | None = None, notes: str | None = None, status: str = "validated",
             triage: tuple[str, str, str] | None = None, cvss: float | None = None,
             at: float = 0.0) -> dict[str, Any]:
    f = Finding(
        # uuid4 by default; a seeded report must be byte-identical between calls.
        id=_sha(rule_id, method, path, param, source)[:32],
        rule_id=rule_id, cwe=cwe, title=title, severity=Severity(sev),
        location=Location(method=method, path=path, parameter=param, source_file=source),
        description=desc, poc=PoC(request=req, response=resp, notes=notes),
        discovered_by=by, status=status,   # type: ignore[arg-type]
        triage=Triage(verdict=triage[0], reasoning=triage[1], evidence=triage[2])  # type: ignore[arg-type]
        if triage else None,
        cvss=Cvss(score=cvss, source="nvd") if cvss is not None else None)
    out = f.model_dump(mode="json")
    out["discovered_at"] = iso(at)
    return out


# The mockup's proof for f1 (SQL injection), verbatim.
SQLI_REQUEST = ("POST /payments/refund HTTP/1.1\nHost: staging.card-payments.ibank.example\n"
                "Authorization: Bearer <redacted>\nContent-Type: application/json\n\n"
                "{\"ref_id\":\"1001' OR '1'='1\",\"amount\":1}")
SQLI_RESPONSE = ("HTTP/1.1 200 OK\nContent-Type: application/json\n\n"
                 "{\"refunds\":[{\"ref_id\":\"1001\",\"card_last4\":\"4417\",\"amount\":1250.00},\n"
                 " {\"ref_id\":\"1002\",\"card_last4\":\"9023\",\"amount\":88.10},\n"
                 " ... 1,846 more rows]}")
SQLI_NOTES = ("The refund lookup concatenates ref_id into the query. A tautology returned every "
              "refund in the table instead of one. A time-delay payload (pg_sleep(5)) reproduced "
              "a 5.02 s delay against a 0.18 s baseline.")
SQLI_DIFF = ("--- a/payments/refund.py\n+++ b/payments/refund.py\n@@ -61,3 +61,3 @@\n"
             "-    q = f\"SELECT * FROM refunds WHERE ref_id = '{ref_id}'\"\n"
             "-    rows = db.execute(q)\n"
             "+    rows = db.execute(text(\"SELECT * FROM refunds WHERE ref_id = :ref\"), {\"ref\": ref_id})")


def f_sqli(at: float) -> dict[str, Any]:
    return _finding(
        rule_id="sql-injection", cwe="CWE-89", title="SQL injection in POST /payments/refund",
        sev="critical", method="POST", path="/payments/refund", param="ref_id",
        by="sqli-agent", desc="parameter ref_id", req=SQLI_REQUEST, resp=SQLI_RESPONSE,
        notes=SQLI_NOTES, at=at)


def f_idor(at: float) -> dict[str, Any]:
    return _finding(
        rule_id="idor", cwe="CWE-639",
        title="Broken object-level authorisation on GET /cards/{id}", sev="high",
        method="GET", path="/cards/{id}", param="id", by="idor-agent",
        desc="any user reads any card",
        req=("GET /cards/2002 HTTP/1.1\nHost: staging.card-payments.ibank.example\n"
             "Authorization: Bearer <redacted: user 1001>"),
        resp=("HTTP/1.1 200 OK\nContent-Type: application/json\n\n"
              "{\"id\":2002,\"owner\":\"user-2002\",\"card_last4\":\"9023\"}"),
        notes="User 1001's token read a card owned by user 2002; the handler never checks ownership.",
        at=at)


def f_ssrf(at: float) -> dict[str, Any]:
    return _finding(
        rule_id="ssrf", cwe="CWE-918",
        title="Server-side request forgery in POST /disputes/evidence/fetch", sev="high",
        method="POST", path="/disputes/evidence/fetch", param="url", by="ssrf-agent",
        desc="url parameter reaches internal metadata service",
        req=("POST /disputes/evidence/fetch HTTP/1.1\nHost: staging.disputes.ibank.example\n"
             "Content-Type: application/json\n\n{\"url\":\"http://169.254.169.254/latest/meta-data/\"}"),
        resp=("HTTP/1.1 200 OK\n\nami-id\nhostname\niam/\ninstance-id\n..."),
        notes="The fetcher followed a link-local address and returned the instance metadata index.",
        at=at)


def f_secret_key(at: float) -> dict[str, Any]:
    return _finding(
        rule_id="trivy/secret/generic-api-key", cwe="CWE-798",
        title="Hardcoded API key in config/prod.py:14", sev="critical", method="STATIC",
        path="config/prod.py", source="config/prod.py:14", by="trivy",
        desc="key matches the payment processor format",
        req="generic-api-key at config/prod.py:14",
        resp='PROCESSOR_KEY = "pk_live_********"', at=at)


def f_cve(i: int, at: float) -> dict[str, Any]:
    pkg, ver, cve = (("pyyaml", "5.3.1", "CVE-2020-14343"),
                     ("pillow", "8.2.0", "CVE-2022-22817"))[i]
    return _finding(
        rule_id=f"trivy/{cve}", title=f"{cve} in {pkg}@{ver}", sev="critical",
        method="DEPENDENCY", path="requirements.txt", param=pkg, source="requirements.txt",
        by="trivy", desc="Dependency scan (trivy), not dynamically exploited.",
        req=f"{pkg}@{ver} pinned in requirements.txt",
        resp=f"Advisory {cve}: arbitrary code execution. Fixed in a later release.",
        cvss=9.8, at=at)


# Twelve semgrep findings for the hero, in the order they first appear. The triage verdicts
# are 5 exploitable (f6 among them), 4 not reachable, 3 unsure, and f6 is positioned so it
# first shows up in the scan nine days ago, as in the mockup.
_V = ["not_reachable", "uncertain", "not_reachable", "exploitable", "not_reachable",
      "exploitable", "uncertain", "not_reachable", "exploitable", "exploitable",
      "exploitable", "uncertain"]
_HERO_SEMGREP: list[tuple[str, str, str, str, int, str]] = [
    # (check id, title, severity, file, line, cwe)
    ("python.lang.security.audit.insecure-hash-algorithm-md5", "Weak hash in tokens/hash.py", "medium", "tokens/hash.py", 31, "CWE-327"),
    ("python.flask.security.audit.wildcard-cors", "Wildcard CORS in app/main.py", "low", "app/main.py", 18, "CWE-942"),
    ("python.lang.security.audit.insecure-transport.requests.request-session-verify-false", "TLS verification disabled in vendor/client.py", "medium", "vendor/client.py", 52, "CWE-295"),
    ("python.django.security.audit.csrf-exempt", "CSRF exemption on the webhook view", "medium", "webhooks/views.py", 12, "CWE-352"),
    ("python.lang.security.audit.insecure-cookie-flag", "Session cookie without Secure flag", "low", "auth/session.py", 40, "CWE-614"),
    ("python.lang.security.audit.open-redirect", "Open redirect in auth/redirect.py", "medium", "auth/redirect.py", 22, "CWE-601"),
    ("python.lang.security.audit.weak-random", "Predictable random in otp/gen.py", "medium", "otp/gen.py", 9, "CWE-338"),
    ("python.lang.security.audit.debug-enabled", "Debug mode enabled in config/dev.py", "low", "config/dev.py", 6, "CWE-489"),
    ("python.requests.security.no-auth-over-http", "Credentials sent over http in jobs/sync.py", "medium", "jobs/sync.py", 27, "CWE-319"),
    ("python.sqlalchemy.formatted-sql-query", "Formatted SQL query in reports/export.py:64", "medium", "reports/export.py", 64, "CWE-89"),
    ("python.jinja2.security.audit.autoescape-disabled", "Template autoescape disabled in mail/render.py", "medium", "mail/render.py", 15, "CWE-79"),
    ("python.lang.security.audit.insecure-file-permissions", "World-writable export file in reports/export.py", "low", "reports/export.py", 88, "CWE-732"),
]
_REASON = {
    "exploitable": ("The handler is reachable from an authenticated route and the value is not "
                    "sanitised before use."),
    "not_reachable": "Only called from the test harness; no route reaches it.",
    "uncertain": "The input source depends on configuration set outside the repository.",
}


def f_hero_semgrep(i: int, at: float) -> dict[str, Any]:
    rule, title, sev, file, line, cwe = _HERO_SEMGREP[i]
    verdict = _V[i]
    return _finding(
        rule_id=f"semgrep/{rule}", cwe=cwe, title=title, sev=sev, method="STATIC", path=file,
        source=f"{file}:{line}", by="semgrep",
        desc=("semgrep " + rule if i == 9 else "Static analysis (semgrep), not dynamically exploited."),
        req=f"{file}:{line}", resp=title,
        triage=(verdict, _REASON[verdict], f"{file}:{line}"), at=at)


def f_apisec(at: float) -> dict[str, Any]:
    return _finding(
        rule_id="apisec/API-RL-001", title="No rate limit on POST /login", sev="medium",
        method="POST", path="/login", by="apisec", desc="brute force is not throttled",
        req="POST /login x 200 in 10 s", resp="200 responses throughout; no 429 returned",
        cwe="CWE-307", at=at)


def f_nuclei(i: int, at: float) -> dict[str, Any]:
    title = ("Missing Content-Security-Policy header on GET /",
             "Missing X-Frame-Options header on GET /")[i]
    return _finding(
        rule_id=f"nuclei/http-missing-security-headers-{i}", title=title, sev="low",
        method="GET", path="/", by="nuclei", desc="nuclei http-missing-security-headers",
        req="GET / HTTP/1.1", resp="HTTP/1.1 200 OK (header absent)", at=at)


def f_possible_secret(i: int, at: float) -> dict[str, Any]:
    file, line, title, sev = (
        ("deploy/ci.yml", 22, "Possible cloud key in deploy/ci.yml:22", "high"),
        ("scripts/release.sh", 9, "Possible token in scripts/release.sh:9", "medium"))[i]
    return _finding(
        rule_id=f"trivy/secret/{('aws-secret-access-key', 'generic-token')[i]}", cwe="CWE-798",
        title=title, sev=sev, method="STATIC", path=file, source=f"{file}:{line}", by="trivy",
        desc="triage could not tell a live key from a placeholder",
        req=f"secret at {file}:{line}", resp="match withheld",
        triage=("uncertain", "Could be a real credential or a documentation placeholder; the "
                            "value's format fits both.", f"{file}:{line}"), at=at)


def f_cve_log4j(at: float) -> dict[str, Any]:
    return _finding(
        rule_id="trivy/CVE-2021-44228", title="log4j-core 2.14.1 is vulnerable (CVE-2021-44228, CVSS 10.0)",
        sev="critical", method="DEPENDENCY", path="pom.xml", param="log4j-core", source="pom.xml",
        by="trivy", desc="Reachable from the request logger in KycAuditFilter",
        req="log4j-core@2.14.1 pinned in pom.xml", resp="Advisory CVE-2021-44228: remote code execution.",
        cvss=10.0, triage=("exploitable", "KycAuditFilter logs request headers through log4j, so "
                                           "attacker-controlled text reaches the vulnerable lookup.",
                           "src/main/java/KycAuditFilter.java:41"), at=at)


# --- leads (flagged_not_proven) for the applications that were not triaged ------------------

_LEAD_POOLS: dict[str, list[tuple[str, str, str, str, int, str]]] = {
    "py": _HERO_SEMGREP,
    "java": [
        ("java.spring.security.audit.spring-csrf-disabled", "CSRF protection disabled", "medium", "src/main/java/SecurityConfig.java", 44, "CWE-352"),
        ("java.lang.security.audit.weak-md5", "MD5 used for a digest", "medium", "src/main/java/Digests.java", 17, "CWE-327"),
        ("java.spring.security.audit.cors-wildcard", "Wildcard CORS origin", "low", "src/main/java/WebConfig.java", 29, "CWE-942"),
        ("java.lang.security.audit.xxe-factory", "XML parser without secure processing", "medium", "src/main/java/XmlReader.java", 33, "CWE-611"),
        ("java.lang.security.audit.insecure-random", "java.util.Random used for a token", "low", "src/main/java/Tokens.java", 12, "CWE-338"),
        ("java.spring.security.audit.actuator-exposed", "Actuator endpoints exposed", "medium", "src/main/resources/application.yml", 8, "CWE-200"),
        ("java.lang.security.audit.crlf-injection-logs", "Unsanitised value written to a log", "low", "src/main/java/AuditLog.java", 51, "CWE-117"),
        ("java.lang.security.audit.http-url-connection", "Plain http URL in a client", "low", "src/main/java/Client.java", 20, "CWE-319"),
        ("java.lang.security.audit.permissive-trust-manager", "Permissive trust manager", "medium", "src/main/java/TlsUtil.java", 37, "CWE-295"),
        ("java.spring.security.audit.mass-assignment", "Mass assignment on a request model", "medium", "src/main/java/Dto.java", 14, "CWE-915"),
    ],
    "js": [
        ("javascript.express.security.audit.debug-enabled", "Debug mode enabled", "medium", "config/settings.js", 8, "CWE-489"),
        ("javascript.express.security.audit.cors-misconfig", "Permissive CORS", "low", "src/app.js", 21, "CWE-942"),
        ("javascript.lang.security.audit.weak-hash", "Weak hash algorithm", "medium", "src/crypto.js", 10, "CWE-327"),
        ("javascript.express.security.audit.missing-helmet", "No security-header middleware", "low", "src/app.js", 5, "CWE-693"),
        ("javascript.express.security.audit.open-redirect", "Open redirect", "medium", "src/routes/auth.js", 48, "CWE-601"),
        ("javascript.lang.security.audit.insecure-random", "Math.random used for an identifier", "low", "src/ids.js", 7, "CWE-338"),
        ("javascript.express.security.audit.cookie-no-secure", "Cookie without secure flag", "low", "src/session.js", 19, "CWE-614"),
        ("javascript.express.security.audit.regex-dos", "Regular expression with catastrophic backtracking", "low", "src/validate.js", 33, "CWE-1333"),
    ],
    "go": [
        ("go.lang.security.audit.insecure-tls-skip-verify", "TLS verification skipped", "medium", "internal/client/http.go", 24, "CWE-295"),
        ("go.lang.security.audit.weak-hash-md5", "MD5 used for a digest", "low", "internal/sign/sign.go", 40, "CWE-327"),
        ("go.lang.security.audit.math-rand", "math/rand used for a token", "low", "internal/token/token.go", 15, "CWE-338"),
        ("go.lang.security.audit.http-server-no-timeout", "HTTP server without timeouts", "low", "cmd/server/main.go", 31, "CWE-400"),
        ("go.lang.security.audit.bind-all-interfaces", "Listener bound to all interfaces", "low", "cmd/server/main.go", 52, "CWE-1327"),
        ("go.lang.security.audit.error-ignored", "Error from a security check ignored", "medium", "internal/auth/check.go", 66, "CWE-252"),
    ],
}


def _pool(lang: str) -> list[tuple[str, str, str, str, int, str]]:
    low = lang.lower()
    pool = _LEAD_POOLS["java" if "java" in low else "go" if low.startswith("go") else
                       "js" if ("node" in low or "type" in low) else "py"]
    # A filler lead must never sit on the gate's deterministic floor (the Python pool shares
    # the hero's formatted-SQL rule, which does): a floor hit blocks, and a filler that turned
    # a clear application into an action one would be seeding a different scenario.
    return [e for e in pool if not floor_reason({"rule_id": f"semgrep/{e[0]}"})]


def _lead(app_slug: str, lang: str, i: int) -> dict[str, Any]:
    pool = _pool(lang)
    rule, msg, sev, file, line, cwe = pool[(i + _h(app_slug, n=4)) % len(pool)]
    # Same pool entry at the same position is the SAME lead in every run, so it ages.
    line = line + (i // len(pool)) * 100
    return {"rule_id": f"semgrep/{rule}", "engine": "semgrep", "severity": sev, "cwe": cwe,
            "message": msg, "file": file, "line": line, "snippet": f"{file}:{line}",
            "status": "flagged_not_proven", "endpoint": None, "reachable": None,
            "correlation_confidence": None, "correlation_reason": None,
            "cwe_proven_dynamically": False}


# --- one run ----------------------------------------------------------------------------------


def _usage(name: str, layout: dict[str, tuple[float, float]], swarm: bool, hero_latest: bool) -> dict[str, Any]:
    if hero_latest:
        rows = [("root", "root", 0.11, 6000, 1200), ("sqli-1", "sqli", 0.22, 8200, 2100),
                ("idor-1", "idor", 0.25, 9100, 2300), ("ssrf-1", "ssrf", 0.13, 4300, 900),
                ("triage-1", "triage", 0.41, 5800, 1600), ("compliance-1", "compliance", 0.38, 4800, 1100),
                ("fix-1", "fix", 0.34, 3000, 600)]
    else:
        total = 0.2 + (_h(name, n=4) % 60) / 100
        tri = round(total * (0.35 if swarm else 1.0), 2)
        rows = [("triage-1", "triage", tri, int(tri * 22400), int(tri * 5300))]
        if swarm:
            rest = round(total - tri, 2)
            rows += [("root", "root", round(rest * 0.2, 2), int(rest * 4000), int(rest * 900))]
            for k, role in enumerate(("sqli", "idor", "ssrf")):
                c = round(rest * 0.8 / 3, 2)
                rows.append((f"{role}-1", role, c, int(c * 24000), int(c * 5400)))
    agents = [{"agent_id": a, "role": r, "model": "sample/model", "requests": 6,
               "input_tokens": i, "output_tokens": o, "total_tokens": i + o, "cost_usd": c}
              for a, r, c, i, o in rows]
    totals = {"requests": 6 * len(rows), "input_tokens": sum(r[3] for r in rows),
              "output_tokens": sum(r[4] for r in rows),
              "total_tokens": sum(r[3] + r[4] for r in rows),
              "cost_usd": round(sum(r[2] for r in rows), 2), "cost_available": True}
    return {"totals": totals, "agents": agents}


def _hero_content(d: float, kind: str, at: float) -> tuple[list[dict], list[dict], list[dict], list[dict], list[dict]]:
    """(findings, flagged, triaged, patches, extra stages) for a hero run `d` days ago."""
    findings: list[dict] = []
    if kind == "pr":
        count = 2
    else:
        count = dict(((52, 5), (45, 6), (38, 7), (31, 8), (24, 9), (17, 11), (9, 10), (1, 12)))[int(d)]
    # The scanner-raised items first, so a run's candidate count is easy to read off.
    if d <= 9 and kind == "scan":
        findings += [f_secret_key(at), f_cve(0, at), f_cve(1, at)]
    if d <= 9 and kind == "scan" and int(d) == 9:
        findings.append(f_apisec(at))
    if int(d) == 1 and kind == "scan":
        findings += [f_nuclei(0, at), f_nuclei(1, at)]
    findings += [f_hero_semgrep(i, at) for i in range(count)]
    if kind == "scan" and d <= 9:
        findings.insert(0, f_sqli(at))
    if kind == "scan" and int(d) == 1:
        findings.insert(1, f_idor(at))
    patches: list[dict] = []
    if int(d) == 1 and kind == "scan":
        sqli = next(f for f in findings if f["rule_id"] == "sql-injection")
        idor = next(f for f in findings if f["rule_id"] == "idor")
        patches = [
            {"key": sqli["dedupe_key"], "status": "verified_fixed", "outcome": "patched",
             "rule_id": "sql-injection", "path": "payments/refund.py", "line": 61,
             "title": "Parameterise the refund lookup",
             "summary": "Bind ref_id as a parameter instead of formatting it into the query.",
             "files": ["payments/refund.py"], "validation": {"reproduction_closed": True},
             "diff": SQLI_DIFF, "pr_url": "https://github.com/ibank/card-payments/pull/482",
             "pr_number": 482, "pr_state": "open"},
            {"key": idor["dedupe_key"], "status": "verified_fixed", "outcome": "patched",
             "rule_id": "idor", "path": "cards/routes.py", "line": 44,
             "title": "Check card ownership in the handler",
             "summary": "Reject the request unless the card's owner is the caller.",
             "files": ["cards/routes.py"], "validation": {"reproduction_closed": True}}]
    return findings, [], [], patches, []


def _generic_content(slug: str, lang: str, d: float, proven: int, cand: int, kind: str,
                     at: float) -> tuple[list[dict], list[dict], list[dict], list[dict]]:
    findings: list[dict] = []
    flagged: list[dict] = []
    triaged: list[dict] = []
    named = 0
    if slug == "disputes" and proven:
        findings.append(f_ssrf(at))
    if slug == "kyc-gateway" and int(d) == 11:
        findings.append(f_cve_log4j(at))
        named += 1
    if slug == "upi-adapter" and int(d) == 3:
        findings += [f_possible_secret(0, at), f_possible_secret(1, at)]
        named += 2
    if slug == "netbanking-web" and int(d) == 1:
        findings.append(f_nuclei(0, at))
        named += 1
    if slug == "admin-ledger" and int(d) <= 14:
        # Triaged away: a debug flag only loaded by the test harness. It sits in `triaged`
        # (the static path) rather than `findings`.
        triaged.append({
            "rule_id": "semgrep/javascript.express.security.audit.debug-enabled",
            "engine": "semgrep", "severity": "medium", "cwe": "CWE-489",
            "file": "config/settings.js", "line": 8, "message": "Debug mode enabled",
            "endpoint": None, "correlation_confidence": None, "verdict": "FALSE_POSITIVE",
            "reasoning": "only loaded in the test harness",
            "evidence": "config/settings.js:8", "triaged": True})
        named += 1
    taken = {(t["file"], t["line"], t["rule_id"]) for t in triaged}
    i = 0
    while len(flagged) < max(0, cand - named):
        lead = _lead(slug, lang, i)
        i += 1
        if (lead["file"], lead["line"], lead["rule_id"]) not in taken:   # a triaged lead leaves the list
            flagged.append(lead)
    return findings, flagged, triaged, []


def _agents_roster(swarm: bool, layout: dict[str, tuple[float, float]], extra: bool,
                   findings: list[dict]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if swarm:
        rows.append({"id": "root", "role": "root", "label": "Exploit swarm root", "status": "done"})
        for role in SPECIALIST_TIMES:
            proven = sum(1 for f in findings if role in f["discovered_by"])
            rows.append({"id": f"{role}-1", "role": role, "label": role, "status": "done",
                         "outcome": f"{proven} proven"})
    if "triage" in layout:
        rows.append({"id": "triage-1", "role": "triage", "label": "triage", "status": "done"})
    if extra:
        rows += [{"id": "recon-1", "role": "recon", "label": "recon", "status": "done"},
                 {"id": "compliance-1", "role": "compliance", "label": "compliance", "status": "done"},
                 {"id": "fix-1", "role": "fix", "label": "fix", "status": "done"}]
    return rows


def _compliance_hero(finding_keys: dict[str, str], at: float) -> list[dict[str, Any]]:
    pack = load_pack("rbi-csf")
    ids = {c.id for c in pack.controls}

    def cite(f: str, line: int, quote: str) -> list[Citation]:
        return [Citation(file=f, line=line, quote=quote)]

    spec: dict[str, dict[str, Any]] = {
        "crypto-transit": dict(status="pass", why="TLS 1.2 or higher is enforced on every listener; HSTS is set.", cites=cite("config/tls.py", 12, "ssl_min_version = TLSVersion.TLSv1_2")),
        "crypto-rest": dict(status="unknown", why="The ORM models do not say whether the column store is encrypted; that is set outside the repository.", looked="models/*.py, config/db.py"),
        "crypto-algorithms": dict(status="fail", why="MD5 is used to derive the card token hash.", cites=cite("tokens/hash.py", 31, "digest = hashlib.md5(pan.encode()).hexdigest()")),
        "secrets": dict(status="fail", why="A payment-processor API key is committed.", cites=cite("config/prod.py", 14, 'PROCESSOR_KEY = "pk_live_..."')),
        "auth-customer": dict(status="pass", why="Customer logins require a second factor before a session is issued.", cites=cite("auth/otp.py", 33, "require_second_factor(user)")),
        "password-storage": dict(status="pass", why="Passwords are hashed with Argon2 and a per-user salt.", cites=cite("auth/passwords.py", 18, "hasher = argon2.PasswordHasher()")),
        "access-control": dict(status="fail", why="GET /cards/{id} does not check ownership. This was reproduced.", cites=cite("cards/routes.py", 44, "card = Card.get(id)  # no owner check"), escalated=True, proven=["idor"]),
        "session": dict(status="pass", why="Sessions expire after 15 minutes idle and are revoked on logout.", cites=cite("auth/session.py", 27, "SESSION_IDLE_TIMEOUT = 900")),
        "input-validation": dict(status="fail", why="refund_lookup builds SQL from request input. This was reproduced.", cites=cite("payments/refund.py", 61, "q = f\"SELECT * FROM refunds WHERE ref_id = '{ref_id}'\""), escalated=True, proven=["sql-injection"]),
        "audit-log-events": dict(status="pass", why="Login, refund and card-view events write structured audit records.", cites=cite("audit/log.py", 9, "def audit(event, actor, **ctx):")),
        "audit-log-content": dict(status="pass", why="Audit records carry the actor and object ids and never the card number.", cites=cite("audit/log.py", 21, "ctx.pop('pan', None)")),
        "secure-configuration": dict(status="unknown", why="Production settings are injected at deploy time, outside the repository.", looked="config/, deploy/, Dockerfile"),
        "patch-dependencies": dict(status="fail", why="Pinned dependencies carry known critical advisories.", cites=cite("requirements.txt", 7, "pyyaml==5.3.1")),
        "transaction-integrity": dict(status="unknown", why="Transaction monitoring is a separate service; no hook for it is visible here.", looked="payments/, risk/"),
    }
    results: list[ControlResult] = []
    for control in pack.controls:
        short = control.id.split(":", 1)[1]
        s = spec.get(short)
        if s is None:
            results.append(ControlResult(
                control_id=control.id, status=ControlStatus.NOT_OBSERVABLE,
                rationale="Not answerable from source; an organisational or runtime fact.",
                judged_at=at))   # type: ignore[arg-type]
            continue
        results.append(ControlResult(
            control_id=control.id, status=ControlStatus(s["status"]), rationale=s["why"],
            citations=s.get("cites", []), looked_at=s.get("looked", ""), judged_by="compliance-1",
            judged_at=at, escalated=bool(s.get("escalated")),   # type: ignore[arg-type]
            proven_findings=[finding_keys[r] for r in s.get("proven", []) if r in finding_keys]))
    assert all(f"rbi-csf:{k}" in ids for k in spec), "sample refers to a control that does not exist"
    judged = len(spec)
    packr = PackResult(pack_id=pack.id, pack_title=pack.title, authority=pack.authority,
                       version=pack.version, origin="builtin", total_controls=len(pack.controls),
                       results=results, requested=judged, judged=judged, unjudged=0)
    return [packr.model_dump(mode="json")]


def _build_run(slug: str, label: str, repo: str, tier: str, lang: str, d: float, proven: int,
               cand: int, kind: str, now: float) -> tuple[str, dict[str, Any], list[dict[str, Any]]]:
    is_hero = slug == HERO
    at = now - d * DAY
    name = f"{slug}-{kind}-{int(round(d * 10)):03d}"
    latest_hero = is_hero and int(d) == 1 and kind == "scan"
    tier1 = tier == "Tier 1" or slug in DEEP_SLUGS
    # Which stages ran, and when (seconds from the start of the run).
    if kind == "pr":
        layout, swarm, end = dict(PR_LAYOUT), False, 130.0
    elif latest_hero:
        layout, swarm, end = dict(HERO_LATEST), True, 760.0
    elif tier1:
        layout, swarm, end = {k: v for k, v in TIER1.items()}, True, 700.0
        if slug == "admin-ledger":
            layout.pop("apisec")        # never wired in for this application
    else:
        layout, swarm, end = dict(STANDARD), False, 320.0
    if slug in NUCLEI_SLUGS and kind == "scan":
        layout["nuclei"] = (200, 255)
        layout["triage"] = (258, 330)
        end = 340.0
    if slug == "netbanking-web" and kind == "scan":
        layout["nuclei"] = (195, 280)       # a staging site exists here
        layout["apisec"] = (280, 365)
    stages = {k: "done" for k in layout}
    if slug == "admin-ledger" and kind == "scan":
        stages["nuclei"] = "skipped"      # no staging URL is configured
    started = at - end

    if is_hero:
        findings, flagged, triaged, patches, _ = _hero_content(d, kind, at)
    else:
        findings, flagged, triaged, patches = _generic_content(slug, lang, d, proven, cand, kind, at)

    # Triage verdicts become triaged[] rows (the static path), derived exactly like
    # report.writer._derive_triage does, so triage_counts agree with the findings.
    verdicts = {"exploitable": "CONFIRMED", "not_reachable": "FALSE_POSITIVE", "uncertain": "UNCERTAIN"}
    rows = list(triaged)
    counts = {"CONFIRMED": 0, "FALSE_POSITIVE": 0, "UNCERTAIN": 0}
    for f in findings:
        t = f.get("triage")
        if t:
            where = parse_source_file(f["location"].get("source_file"))
            rows.append({"rule_id": f["rule_id"], "engine": f["discovered_by"], "severity": f["severity"],
                         "cwe": f["cwe"], "file": where[0] if where else None,
                         "line": where[1] if where else None,
                         "message": f["title"], "endpoint": None, "correlation_confidence": None,
                         "verdict": verdicts[t["verdict"]], "reasoning": t["reasoning"],
                         "evidence": t["evidence"], "triaged": True})
            counts[verdicts[t["verdict"]]] += 1
    for r in triaged:
        counts[r["verdict"]] += 1

    swarm_findings = [f for f in findings if f["discovered_by"].endswith("-agent")]
    # events.jsonl: scan_started, the swarm's agents, findings, scan_finished.
    events: list[dict[str, Any]] = [{"type": "scan_started", "ts": started, "agent_id": "root",
                                     "role": "root", "data": {"target": f"github:{repo}", "run_name": name}}]
    if swarm:
        for role, (a, b) in SPECIALIST_TIMES.items():
            aid = f"{role}-1"
            events.append({"type": "agent_spawned", "ts": started + a, "agent_id": aid, "role": role,
                           "data": {"name": f"{role}-{slug}", "parent_id": "root"}})
            for f in swarm_findings:
                if role in f["discovered_by"]:
                    events.append({"type": "finding", "ts": started + (a + b) / 2, "agent_id": aid,
                                   "role": role, "data": {"title": f["title"], "severity": f["severity"],
                                                          "rule_id": f["rule_id"]}})
            events.append({"type": "agent_finished", "ts": started + b, "agent_id": aid, "role": role,
                           "data": {"status": "completed", "summary": ""}})
    events.append({"type": "scan_finished", "ts": at, "agent_id": "root", "role": "root",
                   "data": {"success": True, "summary": "Sample scan."}})
    events.sort(key=lambda e: e["ts"])

    sev_counts = {s: sum(1 for f in findings if f["severity"] == s) for s in ("critical", "high", "medium", "low", "info")}
    usage = _usage(name, layout, swarm, latest_hero)
    surface = {}
    if latest_hero:
        stems = ["cards", "payments", "refunds", "login", "statements", "limits", "disputes", "tokens", "webhooks", "health"]
        eps = [{"method": "GET" if i % 3 else "POST", "path": f"/{stems[i % len(stems)]}/{'{id}' if i % 2 else 'list'}{i // len(stems) or ''}"}
               for i in range(38)]
        surface = {"endpoints": eps}
    keys = {f["rule_id"]: f["dedupe_key"] for f in findings if f["discovered_by"].endswith("-agent")}
    head = "a91f3c2" + _sha(name)[7:40] if latest_hero else _sha(name, "head")
    prov = {"repo": repo, "head_sha": head}
    if kind == "pr":
        prov["pr"] = str(479 if is_hero else 311)
    report: dict[str, Any] = {
        "sample": True,
        "run_name": name, "docket_version": __version__,
        "target": f"github:{repo}@" + (f"pr-{prov['pr']}" if kind == "pr" else "main"),
        "generated_at": iso(at), "success": True, "status": "completed",
        "stages": stages,
        "stage_timings": {k: {"started": started + a, "ended": started + b} for k, (a, b) in layout.items()},
        "run_timing": {"started": started, "ended": at},
        "provenance": prov,
        "summary": "SAMPLE DATA: this scan was generated by docket.demo.seed, not run.",
        "cost_usd": usage["totals"]["cost_usd"],
        "agents_spawned": 6 if latest_hero else (4 if swarm else 0),
        "finding_count": len(findings), "coverage": {}, "surface": surface,
        "agents": _agents_roster(swarm, layout, latest_hero, findings),
        "severity_counts": sev_counts,
        "flagged_count": len(flagged), "flagged_not_proven": flagged,
        "triage_counts": counts, "triaged": rows,
        "triage_requested": len(rows), "triage_judged": len(rows), "triage_unjudged": 0,
        "compliance": _compliance_hero(keys, at) if latest_hero else [],
        "suppressed_outside_diff": 0, "scanned_paths": None, "patches": patches,
        "usage": usage, "findings": findings,
    }
    packs = report["compliance"]
    report["compliance_requested"] = sum(p["requested"] for p in packs)
    report["compliance_judged"] = sum(p["judged"] for p in packs)
    report["compliance_unjudged"] = 0
    return name, report, events


# --- policy and portfolio files ----------------------------------------------------------------


def _policies() -> dict[str, Any]:
    def step(id_: str, required: bool, cadence: str, on_fail: str, *why: dict[str, Any]) -> dict[str, Any]:
        return {"id": id_, "required": required, "cadence": cadence, "on_fail": on_fail, "why": list(why)}

    sec = lambda t: {"kind": "security", "text": t}          # noqa: E731
    reg = lambda ref: {"kind": "regulatory", "obligation_ref": ref}   # noqa: E731
    every = "At least every 7 days, and on every pull request"
    thin = lambda t, d: {"text": t, "detail": d}          # noqa: E731
    secret = thin("No credentials in source",
                  "A deterministic rule: a secret in code blocks the pull request.")
    proof = thin("Only proof blocks a release",
                 "A reproduced exploit, a triage verdict of confirmed, or a deterministic "
                 "rule such as a secret. A scanner hit alone does not.")
    return {"sample": True, "policies": [
        {"id": "banking-customer", "name": "Banking, customer-facing",
         "applies": "Customer- and partner-facing banking applications",
         "applies_when": {"category": ["Banking"], "exposure": ["Customer-facing", "Partner-facing"],
                          "stack": [], "tier": []},
         "version": 3,
         "approved": "Sample: approved by the security council, 12 Sep 2026", "cadence_days": 7,
         "guidelines": ["rbi-csf", "sebi-cscrf", "owasp-api-2023"],
         "steps": [
             step("trivy", True, every, "Blocks on a secret in source. A critical CVE goes to triage.",
                  sec("No credentials in source"), reg("rbi-csf:secrets")),
             step("semgrep", True, every, "Flags the application as out of policy; feeds triage",
                  sec("Injection and unsafe-deserialisation patterns checked"), reg("rbi-csf:input-validation")),
             step("nuclei", False, "When a staging URL is configured", "None. Optional.",
                  sec("Known-exposure checks against the running staging site")),
             step("apisec", True, "At least every 7 days, and on any API spec change",
                  "Flags the application as out of policy",
                  sec("Every exposed endpoint is tested for authentication, rate limits and CORS"),
                  reg("owasp-api-2023")),
             step("recon", False, "With every exploit run", "None. Optional.",
                  sec("Maps the routes the exploit agents will try")),
             step("triage", True, "After every scanner run",
                  "Flags the application as out of policy. An exhausted run stays uncertain.",
                  sec("Every scanner hit is read against the source and judged reachable, not "
                      "reachable, or uncertain")),
             step("compliance", False, "Weekly", "Advises only. Never blocks.",
                  reg("rbi-csf"), reg("sebi-cscrf")),
             step("swarm", True, "At least every 7 days, and on pull requests that change routes",
                  "Blocks on any reproduced exploit",
                  sec("A finding needs a reproduced proof before it counts as an exploit"),
                  reg("rbi-csf:vapt")),
             step("fix", False, "After a proven exploit", "None. Optional.",
                  sec("Each proven exploit gets a proposed patch and a pull request")),
         ],
         "regulatory": [{"obligation_ref": "rbi-csf:crypto-algorithms"}],
         "security": [
             secret,
             thin("Every exposed API endpoint is tested", "By the API Security engine, at least every 7 days."),
             proof,
             thin("Triage never guesses", "A scanner hit it cannot judge stays uncertain for a person. It is never marked a false positive by default.")]},
        {"id": "internal", "name": "Internal and back-office",
         "applies": "Applications that are not exposed to customers or partners",
         "applies_when": {"category": [], "exposure": ["Internal"], "stack": [], "tier": []},
         "version": 1, "approved": None, "cadence_days": 7,
         "guidelines": ["rbi-csf"],
         "steps": [
             step("trivy", True, every, "Blocks on a secret in source. A critical CVE goes to triage.",
                  sec("No credentials in source"), reg("rbi-csf:secrets")),
             step("semgrep", True, every, "Flags the application as out of policy; feeds triage",
                  sec("Injection and unsafe-deserialisation patterns checked")),
             step("nuclei", False, "When a staging URL is configured", "None. Optional."),
             step("apisec", False, "When the application exposes an API", "None. Optional."),
             step("recon", False, "With every exploit run", "None. Optional."),
             step("triage", True, "After every scanner run", "Flags the application as out of policy.",
                  sec("Every scanner hit is read against the source and judged")),
             step("compliance", False, "Weekly", "Advises only. Never blocks."),
             step("swarm", False, "On request", "Blocks on any reproduced exploit"),
             step("fix", False, "After a proven exploit", "None. Optional."),
         ],
         "security": [secret]},
        {"id": "non-banking-web", "name": "Non-banking web and API",
         "applies": "Web and API applications outside banking",
         "applies_when": {"category": ["Non-banking"], "exposure": [], "stack": ["Web", "API"],
                          "tier": []},
         "version": 1, "approved": None, "cadence_days": 7,
         "guidelines": ["owasp-api-2023"],
         "steps": [
             step("trivy", True, every, "Blocks on a secret in source. A critical CVE goes to triage.",
                  sec("No credentials in source")),
             step("semgrep", True, every, "Flags the application as out of policy; feeds triage",
                  sec("Injection and unsafe-deserialisation patterns checked")),
             step("nuclei", True, "At least every 7 days", "Flags the application as out of policy",
                  sec("Known-exposure checks against the running site")),
             step("apisec", False, "When the application exposes an API", "None. Optional."),
             step("recon", False, "With every exploit run", "None. Optional."),
             step("triage", True, "After every scanner run", "Flags the application as out of policy.",
                  sec("Every scanner hit is read against the source and judged")),
             step("compliance", False, "Weekly", "Advises only. Never blocks."),
             step("swarm", False, "On request", "Blocks on any reproduced exploit"),
             step("fix", False, "After a proven exploit", "None. Optional."),
         ],
         "security": [secret]},
    ]}


def _portfolio() -> dict[str, Any]:
    apps = []
    for slug, label, repo, tier, owner, lang, _ in APPS:
        category, exposure, stack = PROFILE[slug]
        row = {"repo": repo, "label": label, "tier": tier, "owner": owner, "lang": lang,
               "category": category, "exposure": exposure, "stack": stack}
        if slug in PINNED:
            row["policy"] = PINNED[slug]
        apps.append(row)
    return {"sample": True, "organization": "iBank (sample data)", "cadence_days": 7,
            "applications": apps}


def _clear_previous(runs: Path) -> None:
    """Remove runs a previous seed wrote, and ONLY those: a directory is deleted only when
    its report.json says `sample`. Anything else in there is somebody's, and stays."""
    if not runs.is_dir():
        return
    for child in runs.iterdir():
        report = child / "report.json"
        if child.is_dir() and not child.is_symlink() and report.is_file():
            try:
                if json.loads(report.read_text()).get("sample") is True:
                    shutil.rmtree(child)
            except (OSError, ValueError):
                continue


def seed(root: Path, now: float | None = None) -> dict[str, Any]:
    """Write the sample scenario under `root`. Returns {"runs": n, "applications": n}."""
    root = Path(root)
    now = float(now if now is not None else time.time())
    runs = root / REPO_ROOT_NAME
    runs.mkdir(parents=True, exist_ok=True)
    _clear_previous(runs)
    count = 0
    for slug, label, repo, tier, owner, lang, events in APPS:
        for d, proven, cand, kind in events:
            name, report, evs = _build_run(slug, label, repo, tier, lang, d, proven, cand, kind, now)
            directory = runs / name
            directory.mkdir(parents=True, exist_ok=True)
            (directory / "report.json").write_text(json.dumps(report, indent=1), encoding="utf-8")
            (directory / "events.jsonl").write_text(
                "".join(json.dumps(e) + "\n" for e in evs), encoding="utf-8")
            count += 1
    (root / "docket_portfolio.json").write_text(json.dumps(_portfolio(), indent=1), encoding="utf-8")
    (root / "docket_policy.json").write_text(json.dumps(_policies(), indent=1), encoding="utf-8")
    return {"runs": count, "applications": len(APPS)}


def demo() -> None:
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        now = 1_800_000_000.0
        out = seed(root, now)
        assert out == {"runs": sum(len(a[6]) for a in APPS), "applications": 12}, out
        names = sorted(p.name for p in (root / "docket_runs").iterdir())
        # Deterministic: the same `now` writes the same bytes.
        first = {n: (root / "docket_runs" / n / "report.json").read_bytes() for n in names}
        seed(root, now)
        assert first == {n: (root / "docket_runs" / n / "report.json").read_bytes() for n in names}
        report = json.loads((root / "docket_runs" / "card-payments-scan-010" / "report.json").read_text())
        assert report["sample"] is True and report["compliance"][0]["pack_id"] == "rbi-csf"
        assert report["stage_timings"]["trivy"]["ended"] - report["run_timing"]["started"] == 62
        assert report["finding_count"] == len(report["findings"]) == 19
        assert json.loads((root / "docket_portfolio.json").read_text())["sample"] is True
        # A directory the seeder did not write is never deleted.
        (root / "docket_runs" / "mine").mkdir()
        (root / "docket_runs" / "mine" / "report.json").write_text('{"run_name": "mine"}')
        seed(root, now)
        assert (root / "docket_runs" / "mine" / "report.json").is_file()
    print("demo.seed: ok")


if __name__ == "__main__":
    demo()
