"""SonarQube: static analysis against mounted source, via a SonarQube Community Build
server (docket/runtime/sonar_service.py).

Same shape as semgrep.py from the caller's side — `run_sonar(sandbox, run_dir)` returns
Findings or raises ScannerError — but the middle is not the same at all. semgrep runs a
binary that writes JSON; sonar-scanner uploads source to a server, which analyses it
asynchronously, and the findings are then fetched over the Web API. The three steps
below (analyse, wait for the Compute Engine task, pull results) are all one stage as far
as the radar is concerned.

Honesty note, same as semgrep.py and trivy.py: a Sonar issue is a pattern match, not an
exploited proof. The PoC is real — the literal offending source line plus Sonar's own
message — but it is static evidence. rule_id is prefixed `sonar/` so it never reads as
an agent-confirmed finding.

SECURITY ONLY, DELIBERATELY
---------------------------
Only issues with a SECURITY impact (legacy type VULNERABILITY) and Security Hotspots are
imported. SonarQube also reports reliability bugs and maintainability smells; a real
repository produces hundreds to thousands of those, they would dominate a findings list
that is supposed to be a security list, and every one of them is a candidate the AI
triage pass may pay to judge. Override with DOCKET_SONAR_IMPACTS if that is ever wanted.
"""
from __future__ import annotations

import json
import os
import re
import shlex
import time
import urllib.parse
from pathlib import Path
from typing import Any

from docket.report.models import Finding, Location, PoC, Severity
from docket.runtime import sonar_service
from docket.tools.scanners.semgrep import ScannerError

# SonarQube reports severity two ways depending on version: the modern `impacts` array
# (softwareQuality + severity) and the legacy top-level `severity`. Servers in the wild
# send both, and which one is authoritative moved between releases, so both vocabularies
# are mapped and impacts wins when present.
_SEVERITY_MAP = {
    "BLOCKER": Severity.CRITICAL,
    "CRITICAL": Severity.HIGH,
    "HIGH": Severity.HIGH,
    "MAJOR": Severity.MEDIUM,
    "MEDIUM": Severity.MEDIUM,
    "MINOR": Severity.LOW,
    "LOW": Severity.LOW,
    "INFO": Severity.INFO,
}

# A hotspot is "review this", not "this is broken", so its scale is a probability rather
# than a severity. Mapped one step down from the equivalent issue severity for that
# reason: an unreviewed hotspot is not the same claim as a confirmed vulnerability.
_HOTSPOT_MAP = {
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}

# Three spellings, because where SonarQube puts a CWE moved between versions:
#   securityStandards: ["cwe:295", ...]        older servers, and some editions
#   a MITRE link in the rule's "resources" prose   what 26.x Community actually ships
#   a bare "CWE-295" in that same prose
# Measured on 26.8: api/rules/show returns no securityStandards field at all and
# api/rules/search rejects it as a parameter, so the prose is the only source left. The
# rule still carries a bare "cwe" sysTag with no number, which is worse than useless.
_CWE_RE = re.compile(r"cwe:(\d+)|cwe\.mitre\.org/data/definitions/(\d+)|CWE-(\d+)",
                     re.IGNORECASE)

# Project keys are interpolated into API paths and become directory-ish identifiers on
# the server. Anything outside this set gets replaced rather than rejected, because the
# key is derived from a directory name docket did not choose.
_KEY_SAFE = re.compile(r"[^A-Za-z0-9_.:-]")

_MOUNT = "/work/source/"

# Analysis is server-side and asynchronous. A large repository takes minutes; this is the
# ceiling before the stage gives up and reports `error` rather than hanging a scan.
CE_TIMEOUT_SEC = 900
PAGE_SIZE = 500
# SonarQube's search endpoints refuse to paginate past 10k results. Hitting it means the
# repository is enormous, not that something is wrong.
MAX_PAGES = 20


def sonar_impacts() -> str:
    return os.environ.get("DOCKET_SONAR_IMPACTS", "").strip() or "SECURITY"


def project_key(source_dir: Path | None) -> str:
    """Stable per repository, so SonarQube's history means something across runs.

    ponytail: derived from the source directory's name, which for a GitHub scan is the
    extracted tarball dir (`owner-repo-<sha>`), so the sha makes it change per commit and
    history does not accumulate. Upgrade path when that matters: thread the GitHub
    full_name down from connect.run_repo_scan and pass it here.
    """
    supplied = os.environ.get("DOCKET_SONAR_PROJECT_KEY", "").strip()
    if supplied:
        return _KEY_SAFE.sub("_", supplied)
    name = source_dir.name if source_dir is not None else "docket"
    return "docket_" + (_KEY_SAFE.sub("_", name) or "source")


def _relative(component: str, key: str) -> str:
    """`myproject:app/views.py` -> `app/views.py`.

    The component key is a server-internal identifier; a report that printed it would be
    telling the reader about SonarQube's database rather than about their code.
    """
    path = component.removeprefix(f"{key}:")
    return path.removeprefix(_MOUNT).removeprefix("/work/source")


def _severity_of(issue: dict[str, Any]) -> Severity:
    for impact in issue.get("impacts") or []:
        mapped = _SEVERITY_MAP.get(str(impact.get("severity") or "").upper())
        if mapped is not None:
            return mapped
    return _SEVERITY_MAP.get(str(issue.get("severity") or "").upper(), Severity.MEDIUM)


def _first_cwe(text: str) -> str | None:
    match = _CWE_RE.search(text)
    if not match:
        return None
    return f"CWE-{next(g for g in match.groups() if g)}"


def cwe_of_rule(rule: dict[str, Any]) -> str | None:
    """The CWE for one rule, from whichever place this server keeps it.

    A rule that cites several (S2245 names 1241, 326, 330 and 338) yields the first in
    document order, matching how semgrep.py takes the first of its metadata list. One
    finding carries one CWE, and picking arbitrarily beats inventing a combined one.
    """
    for entry in rule.get("securityStandards") or []:
        found = _first_cwe(str(entry))
        if found:
            return found
    sections = rule.get("descriptionSections") or []
    # "resources" is where the standards references live. Searched first and alone,
    # because "root_cause" prose can name a CWE it is contrasting against rather than
    # the one this rule detects.
    for wanted in ("resources", None):
        for section in sections:
            if wanted is not None and section.get("key") != wanted:
                continue
            found = _first_cwe(str(section.get("content") or ""))
            if found:
                return found
    return None


def source_line(source_root: Path | None, path: str, line: int | None) -> str:
    """The offending line, read from the source docket already has on disk.

    Finding.poc rejects empty evidence, so every finding needs something real here.
    SonarQube can serve the snippet over api/sources/issue_snippets, but that is one
    extra round trip per issue for a file sitting in the mount the scanner just read.
    """
    if source_root is None or not line or line < 1:
        return ""
    candidate = (source_root / path).resolve()
    try:
        # The path comes from the server's component key, so it is joined onto a local
        # root and must be contained by it — the same check load_run does for run names.
        if not str(candidate).startswith(str(Path(source_root).resolve())):
            return ""
        with candidate.open("r", encoding="utf-8", errors="replace") as handle:
            for number, text in enumerate(handle, start=1):
                if number == line:
                    return text.strip()
    except OSError:
        return ""
    return ""


def parse_sonar(
    issues: list[dict[str, Any]],
    hotspots: list[dict[str, Any]],
    rule_cwe: dict[str, str | None],
    key: str,
    source_root: Path | None = None,
) -> list[Finding]:
    """Pure: everything network- and disk-shaped is already resolved by the caller."""
    findings: list[Finding] = []

    for issue in issues:
        message = str(issue.get("message") or "").strip()
        if not message:
            continue
        path = _relative(str(issue.get("component") or ""), key)
        line = issue.get("line")
        rule = str(issue.get("rule") or "unknown")
        snippet = source_line(source_root, path, line)
        findings.append(Finding(
            rule_id=f"sonar/{rule}",
            cwe=rule_cwe.get(rule),
            title=f"{rule.rsplit(':', 1)[-1]} in {path}",
            severity=_severity_of(issue),
            location=Location(
                method="STATIC", path=path,
                source_file=f"{path}:{line}" if line else path,
            ),
            description=f"Static analysis (SonarQube) — not dynamically exploited. {message}",
            # Falls back to the message when the line could not be read, because a PoC
            # with an empty request is rejected outright and losing the finding would be
            # worse than repeating its message.
            poc=PoC(request=snippet or message, response=message),
            discovered_by="sonar",
        ))

    for hotspot in hotspots:
        message = str(hotspot.get("message") or "").strip()
        if not message:
            continue
        path = _relative(str(hotspot.get("component") or ""), key)
        line = hotspot.get("line")
        rule = str(hotspot.get("ruleKey") or "unknown")
        snippet = source_line(source_root, path, line)
        category = str(hotspot.get("securityCategory") or "").strip()
        findings.append(Finding(
            rule_id=f"sonar/{rule}",
            cwe=rule_cwe.get(rule),
            title=f"{rule.rsplit(':', 1)[-1]} in {path}",
            severity=_HOTSPOT_MAP.get(
                str(hotspot.get("vulnerabilityProbability") or "").upper(), Severity.LOW,
            ),
            location=Location(
                method="STATIC", path=path,
                source_file=f"{path}:{line}" if line else path,
            ),
            # Named as a hotspot, not a vulnerability. SonarQube's own model is that this
            # is code a human should review, and flattening that into "vulnerability"
            # would overstate every one of them.
            description=(
                f"Security hotspot (SonarQube{', ' + category if category else ''}) — "
                f"needs review, not dynamically exploited. {message}"
            ),
            poc=PoC(request=snippet or message, response=message),
            discovered_by="sonar",
        ))

    return findings


def _fetch_all(path: str, token: str, params: dict[str, str], field: str) -> list[dict]:
    """Every page of a paginated search endpoint."""
    out: list[dict] = []
    for page in range(1, MAX_PAGES + 1):
        query = "&".join(
            f"{k}={urllib.parse.quote(str(v))}"
            for k, v in {**params, "ps": PAGE_SIZE, "p": page}.items()
        )
        doc = sonar_service.api(f"{path}?{query}", token=token) or {}
        batch = doc.get(field) or []
        out.extend(batch)
        if len(batch) < PAGE_SIZE:
            break
    return out


def _rule_cwes(rules: set[str], token: str) -> dict[str, str | None]:
    """CWE per rule, because the issue objects carry none.

    Without this every Sonar finding lands untagged in the CWE breakdown, which is the
    view that turns 20 hard-coded-credential hits into one habit to fix rather than 20
    tickets.
    """
    out: dict[str, str | None] = {}
    for rule in sorted(rules):
        try:
            doc = sonar_service.api(
                f"/api/rules/show?key={urllib.parse.quote(rule)}", token=token,
            ) or {}
        except (OSError, json.JSONDecodeError):
            # A rule whose metadata cannot be fetched loses its CWE tag, which is a
            # degraded finding — not a reason to fail a completed analysis.
            out[rule] = None
            continue
        out[rule] = cwe_of_rule(doc.get("rule") or {})
    return out


def analysed_files(key: str, token: str) -> int:
    """How many files the server actually indexed.

    A SonarQube analysis that indexes ZERO files uploads fine, completes fine, and
    reports a clean project — which is indistinguishable from "your code has no issues"
    and is the single most dangerous way this scanner can fail. It is not hypothetical:
    a missing sonar.projectBaseDir did exactly that, on a fixture with four known
    vulnerabilities. Same rule as semgrep.py — "0 findings" and "nothing analysed" must
    never look the same.
    """
    try:
        doc = sonar_service.api(
            f"/api/measures/component?component={urllib.parse.quote(key)}"
            "&metricKeys=files", token=token,
        ) or {}
    except (OSError, json.JSONDecodeError):
        return -1  # unknown, not zero — do not fail a good analysis over a flaky read
    for measure in (doc.get("component") or {}).get("measures") or []:
        if measure.get("metric") == "files":
            try:
                return int(measure.get("value", 0))
            except (TypeError, ValueError):
                return -1
    return 0


def scanner_error(output: str) -> str:
    """The line that says what went wrong, out of a few hundred lines of scanner log.

    Tailing the output does not work: sonar-scanner ends on a Java stack trace, so the
    last 300 characters are "... 25 common frames omitted" while the actual cause —
    'Error when running: node -v. Is Node.js available during analysis?' — sits fifty
    lines earlier. That truncation cost a real debugging cycle, so the ERROR lines are
    picked out by hand.
    """
    errors = [
        line.strip() for line in output.splitlines()
        # Stack frames repeat the word ERROR without adding anything.
        if "ERROR" in line and not line.lstrip().startswith("at ")
    ]
    if errors:
        return " | ".join(dict.fromkeys(errors))[:500]
    return output.strip()[-300:] or "no diagnostics"


def _await_ce_task(task_id: str, token: str, cancel: Any, timeout: float) -> None:
    """Block until the server finishes analysing, or explain why it never will."""
    from docket.core.cancel import ScanCancelled

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if cancel is not None and getattr(cancel, "cancelled", False):
            # Unlike the other scanners, which are one blocking subprocess call, this
            # can sit here for minutes. A stop button that cannot stop it is not a stop
            # button.
            raise ScanCancelled()
        doc = sonar_service.api(
            f"/api/ce/task?id={urllib.parse.quote(task_id)}", token=token,
        ) or {}
        status = str((doc.get("task") or {}).get("status") or "").upper()
        if status == "SUCCESS":
            return
        if status in ("FAILED", "CANCELED"):
            detail = (doc.get("task") or {}).get("errorMessage") or status
            raise ScannerError(f"SonarQube analysis {status.lower()}: {detail}")
        time.sleep(2.0)
    raise ScannerError(f"SonarQube analysis did not finish within {int(timeout)}s")


def _ce_task_id(report_task: Path) -> str:
    """sonar-scanner writes report-task.txt; ceTaskId in it is the only handle on the
    server-side analysis it just queued."""
    try:
        for raw in report_task.read_text().splitlines():
            name, _, value = raw.partition("=")
            if name.strip() == "ceTaskId" and value.strip():
                return value.strip()
    except OSError:
        pass
    raise ScannerError("sonar-scanner produced no ceTaskId — the upload did not happen")


def run_sonar(
    sandbox: Any, run_dir: Path, *, cancel: Any = None, timeout_sec: int = 1800,
) -> list[Finding]:
    """Requires the sandbox to have been started with a source_dir mounted at
    /work/source — the caller gates on that, exactly as it does for trivy/semgrep.

    Raises ScannerError whenever analysis did not happen, so `drain()` marks the stage
    `error`. "0 findings" and "never analysed" must never look the same.
    """
    from docket.runtime.sonar_service import SonarError

    try:
        token = sonar_service.ensure()
    except SonarError as exc:
        raise ScannerError(str(exc)) from exc

    key = project_key(sandbox.source_dir)
    work_rel = "artifacts/scanners/sonar-work"
    report_task = run_dir / work_rel / "report-task.txt"

    command = (
        "mkdir -p /work/run/artifacts/scanners && "
        "sonar-scanner "
        f"-Dsonar.projectKey={shlex.quote(key)} "
        f"-Dsonar.projectName={shlex.quote(key)} "
        # projectBaseDir is REQUIRED, and its absence fails silently in the worst way.
        # sonar-scanner defaults the base dir to its working directory — /app in this
        # image — and then ignores every file outside it, so an analysis of /work/source
        # indexed 0 files, uploaded successfully, and reported a clean project. Measured:
        # "File '/work/source/target_app.py' is ignored. It is not located in project
        # basedir '/app'" on a fixture semgrep found four vulnerabilities in.
        "-Dsonar.projectBaseDir=/work/source "
        "-Dsonar.sources=. "
        f"-Dsonar.host.url={shlex.quote(sonar_service.container_url())} "
        f"-Dsonar.token={shlex.quote(token)} "
        # The repo arrives as a tarball with no .git, and asking Sonar to blame files
        # that have no history is a slow no-op that logs errors.
        "-Dsonar.scm.disabled=true "
        f"-Dsonar.working.directory=/work/run/{work_rel}"
    )
    try:
        result = sandbox.call("shell", command=command, timeout_sec=timeout_sec)
    except Exception as exc:
        raise ScannerError(f"sonar-scanner could not be started: {exc}") from exc
    if "error" in result:
        raise ScannerError(f"sonar-scanner failed: {result['error']}")
    if not report_task.exists():
        output = f"{result.get('stdout') or ''}\n{result.get('stderr') or ''}"
        raise ScannerError(
            f"sonar-scanner wrote no report-task.txt: {scanner_error(output)}"
        )

    _await_ce_task(_ce_task_id(report_task), token, cancel, CE_TIMEOUT_SEC)

    files = analysed_files(key, token)
    if files == 0:
        raise ScannerError(
            f"SonarQube analysed 0 files in {key} — the upload succeeded but nothing was "
            "indexed, so a clean result here would be a lie. Check sonar.projectBaseDir "
            "and that /work/source holds a language SonarQube supports."
        )

    issues = _fetch_all("/api/issues/search", token, {
        "componentKeys": key,
        "resolved": "false",
        "impactSoftwareQualities": sonar_impacts(),
    }, "issues")
    hotspots = _fetch_all("/api/hotspots/search", token, {
        "projectKey": key,
        "status": "TO_REVIEW",
    }, "hotspots")

    rules = {str(i.get("rule")) for i in issues if i.get("rule")}
    rules |= {str(h.get("ruleKey")) for h in hotspots if h.get("ruleKey")}
    rule_cwe = _rule_cwes(rules, token)

    # Kept for read_coverage(), which is what lets a report distinguish a clean repo
    # from one where analysis never looked at anything.
    artifact = run_dir / "artifacts" / "scanners" / "sonar.json"
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_text(json.dumps({
        "projectKey": key,
        # The count that lets a reader tell a clean repository from an empty analysis.
        "files_analysed": files,
        "issues": len(issues),
        "hotspots": len(hotspots),
        "rules": sorted(rules),
        "impacts": sonar_impacts(),
    }, indent=2))

    return parse_sonar(issues, hotspots, rule_cwe, key, sandbox.source_dir)


def demo() -> None:
    key = "docket_myrepo"
    issues = [{
        "rule": "python:S3649",
        "component": f"{key}:app/views.py",
        "line": 42,
        "message": "Change this code to not construct SQL queries directly from user input.",
        "severity": "BLOCKER",
        "impacts": [{"softwareQuality": "SECURITY", "severity": "HIGH"}],
    }]
    hotspots = [{
        "ruleKey": "python:S4830",
        "component": f"{key}:app/net.py",
        "line": 7,
        "message": "Enable server certificate validation on this SSL/TLS connection.",
        "vulnerabilityProbability": "HIGH",
        "securityCategory": "weak-cryptography",
    }]
    rule_cwe = {"python:S3649": "CWE-89", "python:S4830": "CWE-295"}

    findings = parse_sonar(issues, hotspots, rule_cwe, key)
    assert len(findings) == 2, findings

    issue, hotspot = findings
    assert issue.rule_id == "sonar/python:S3649"
    assert issue.cwe == "CWE-89"
    # impacts wins over the legacy field: BLOCKER would have meant CRITICAL, the
    # modern HIGH impact means HIGH, and picking the wrong one misreports every issue.
    assert issue.severity == Severity.HIGH, issue.severity
    assert issue.location.source_file == "app/views.py:42"
    assert issue.discovered_by == "sonar"
    assert "not dynamically exploited" in issue.description
    # The server's component key is an internal identifier and must never reach a report.
    assert key not in issue.location.path, issue.location.path
    assert issue.location.path == "app/views.py"

    # A hotspot is a review request, not a proven vulnerability, and the text has to say so.
    assert hotspot.severity == Severity.HIGH
    assert hotspot.cwe == "CWE-295"
    assert "hotspot" in hotspot.description.lower()
    assert "weak-cryptography" in hotspot.description
    assert "needs review" in hotspot.description

    # Legacy-only servers send no impacts at all.
    legacy = parse_sonar(
        [{**issues[0], "impacts": []}], [], rule_cwe, key,
    )
    assert legacy[0].severity == Severity.CRITICAL, legacy[0].severity

    # An unmapped rule is untagged, never guessed: a wrong CWE on a security finding is
    # worse than no CWE.
    untagged = parse_sonar(issues, [], {}, key)
    assert untagged[0].cwe is None

    # CWE extraction, against the three shapes SonarQube has used. The prose case is not
    # hypothetical: 26.8 Community returns no securityStandards field at all, which is
    # how every imported finding first arrived untagged.
    assert cwe_of_rule({"securityStandards": ["cwe:295", "owaspTop10:a3"]}) == "CWE-295"
    assert cwe_of_rule({"descriptionSections": [
        {"key": "root_cause", "content": "<p>unrelated prose</p>"},
        {"key": "resources", "content": "<a href='https://cwe.mitre.org/data/definitions/295'>x</a>"},
    ]}) == "CWE-295"
    assert cwe_of_rule({"descriptionSections": [
        {"key": "resources", "content": "See CWE-1240 for detail"},
    ]}) == "CWE-1240"
    # "resources" wins over other sections, which may name a CWE only to contrast it.
    assert cwe_of_rule({"descriptionSections": [
        {"key": "root_cause", "content": "unlike CWE-79, this is..."},
        {"key": "resources", "content": "CWE-295"},
    ]}) == "CWE-295"
    # No CWE anywhere stays None rather than becoming a guess.
    assert cwe_of_rule({}) is None
    assert cwe_of_rule({"descriptionSections": [{"key": "resources", "content": "none"}]}) is None

    # The sandbox mount prefix must not survive into a report either.
    mounted = parse_sonar(
        [{**issues[0], "component": f"{key}:/work/source/app/views.py"}], [], rule_cwe, key,
    )
    assert mounted[0].location.path == "app/views.py", mounted[0].location.path

    # Finding.poc rejects empty evidence, so a message-only issue must still produce one.
    assert parse_sonar(issues, [], rule_cwe, key)[0].poc.request
    # An issue with no message carries no evidence at all and is dropped rather than
    # given an invented PoC.
    assert parse_sonar([{**issues[0], "message": ""}], [], rule_cwe, key) == []

    # Project keys reach an API path; anything path-shaped in one is neutralised.
    saved = os.environ.pop("DOCKET_SONAR_PROJECT_KEY", None)
    try:
        os.environ["DOCKET_SONAR_PROJECT_KEY"] = "../../etc/passwd"
        # Dots are legal in a SonarQube key, so ".." survives and that is fine — the key
        # is a query-parameter value and a shell-quoted scanner property, never a path.
        # What must not survive is a separator: every character has to be in the safe
        # set, which is exactly what makes the prefix strip in _relative() unambiguous.
        assert _KEY_SAFE.search(project_key(None)) is None, project_key(None)
        assert "/" not in project_key(None), project_key(None)
        os.environ.pop("DOCKET_SONAR_PROJECT_KEY")
        assert project_key(Path("/tmp/owner-repo-abc123")) == "docket_owner-repo-abc123"
        assert project_key(None) == "docket_docket"
    finally:
        if saved is not None:
            os.environ["DOCKET_SONAR_PROJECT_KEY"] = saved

    # Only security by default. Importing bugs and smells would bury a security list in
    # maintainability noise and multiply what triage pays to judge.
    assert sonar_impacts() == "SECURITY"

    # The diagnostic must survive a Java stack trace. Verbatim shape of the failure that
    # a tail-the-output message reduced to "... 25 common frames omitted".
    log = """
19:55:02.064 INFO  Using Node.js executable: 'node'.
19:55:02.079 ERROR Error when running: 'node -v'. Is Node.js available during analysis?
org.sonar.plugins.javascript.nodejs.NodeCommandException: Error when running: 'node -v'.
\tat org.sonar.plugins.javascript.nodejs.NodeCommand.start(NodeCommand.java:85)
Caused by: java.io.IOException: Cannot run program "node"
\t... 25 common frames omitted
"""
    picked = scanner_error(log)
    assert "Node.js available" in picked, picked
    assert "common frames omitted" not in picked, picked
    assert "at org.sonar" not in picked, picked
    # Nothing marked ERROR still yields something rather than an empty message.
    assert scanner_error("plain failure text") == "plain failure text"
    assert scanner_error("") == "no diagnostics"

    # An analysis that indexed nothing must be distinguishable from a clean one. This
    # parses the shape /api/measures/component returns; run_sonar treats 0 as fatal and
    # -1 ("could not tell") as fine, because failing a good analysis over a flaky read
    # would be its own kind of lie.
    class _FakeApi:
        def __init__(self, payload):
            self.payload = payload

        def __call__(self, path, token=None, **_):
            if isinstance(self.payload, Exception):
                raise self.payload
            return self.payload

    real_api = sonar_service.api
    try:
        sonar_service.api = _FakeApi({"component": {"measures": [
            {"metric": "files", "value": "12"},
        ]}})
        assert analysed_files("k", "t") == 12
        sonar_service.api = _FakeApi({"component": {"measures": []}})
        assert analysed_files("k", "t") == 0, "no measure at all means nothing indexed"
        sonar_service.api = _FakeApi({"component": {"measures": [
            {"metric": "files", "value": "0"},
        ]}})
        assert analysed_files("k", "t") == 0
        sonar_service.api = _FakeApi(OSError("connection reset"))
        assert analysed_files("k", "t") == -1, "unknown must not read as zero"
    finally:
        sonar_service.api = real_api

    # report-task.txt is the only handle on the queued analysis; a missing ceTaskId is a
    # failed upload, not an empty result.
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        good = Path(tmp) / "report-task.txt"
        good.write_text("projectKey=x\nceTaskId=AXbc123\nserverUrl=http://s\n")
        assert _ce_task_id(good) == "AXbc123"
        bad = Path(tmp) / "empty.txt"
        bad.write_text("projectKey=x\n")
        try:
            _ce_task_id(bad)
            raise AssertionError("expected ScannerError")
        except ScannerError:
            pass

        # source_line reads real evidence off disk, and refuses to escape the mount.
        root = Path(tmp) / "src"
        (root / "app").mkdir(parents=True)
        (root / "app" / "views.py").write_text("one\ntwo\nthree\n")
        assert source_line(root, "app/views.py", 2) == "two"
        assert source_line(root, "app/views.py", 99) == ""
        assert source_line(root, "../../../etc/passwd", 1) == ""
        assert source_line(None, "app/views.py", 1) == ""

    print("scanners.sonar: ok")


if __name__ == "__main__":
    demo()
