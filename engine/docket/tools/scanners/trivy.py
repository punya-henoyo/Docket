"""Trivy: deterministic dependency (SCA) scanning against mounted source.

Same shape as nuclei.py — a pre-scan, not an agent tool, parsing trivy's own JSON
straight into a Finding. Requires `--source <path>` (docket/interface/cli_args.py),
which docket mounts read-only into the sandbox at /work/source
(docket/runtime/sandbox.py); with no source path this scanner does not run.

Honesty note: unlike a dynamic finding, this is NOT an exploited proof — it is "this
advisory applies to this pinned version." rule_id is prefixed `trivy/` and the
description says so explicitly, so a report reader can't mistake it for something an
agent reproduced.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from docket.report.models import Cvss, Finding, Location, PoC, Severity

_SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW, "UNKNOWN": Severity.INFO,
}


def _cwe(vuln: dict[str, Any]) -> str | None:
    ids = vuln.get("CweIDs") or []
    return ids[0].upper() if ids else None


# Scoring bodies disagree, often materially: CVE-2024-56201 is 8.8 from NVD and 7.3
# from Red Hat, with different vectors (AV:L vs AV:N). Taking the max across sources
# would be defensible but anonymous — you could not tell afterwards who said what.
# A fixed precedence plus the recorded source name stays auditable.
_CVSS_SOURCES = ("nvd", "ghsa", "redhat")


def _cvss(vuln: dict[str, Any]) -> Cvss | None:
    """The published CVSS for this CVE, or None. Never computed here."""
    scores = vuln.get("CVSS") or {}
    if not isinstance(scores, dict):
        return None
    ordered = [s for s in _CVSS_SOURCES if s in scores] + [
        s for s in scores if s not in _CVSS_SOURCES
    ]
    for name in ordered:
        entry = scores.get(name) or {}
        if not isinstance(entry, dict):
            continue
        # v3 first: it is populated far more widely and its 0-10 band boundaries are
        # what every downstream consumer assumes. v4 is taken only when v3 is absent,
        # and the version is recorded so the two are never silently compared.
        for key, vec_key, version in (("V3Score", "V3Vector", "3.1"),
                                      ("V40Score", "V40Vector", "4.0"),
                                      ("V2Score", "V2Vector", "2.0")):
            raw = entry.get(key)
            if isinstance(raw, (int, float)) and 0.0 <= float(raw) <= 10.0:
                vector = entry.get(vec_key)
                # The vector string names its own version; trust it over our guess.
                if isinstance(vector, str) and vector.startswith("CVSS:"):
                    version = vector.split("/")[0].removeprefix("CVSS:") or version
                return Cvss(score=float(raw), vector=vector if isinstance(vector, str) else None,
                            version=version, source=name)
    return None


def parse_trivy_json(text: str) -> list[Finding]:
    try:
        doc = json.loads(text)
    except json.JSONDecodeError:
        return []

    findings: list[Finding] = []
    for result in doc.get("Results") or []:
        target = result.get("Target", "unknown")
        for vuln in result.get("Vulnerabilities") or []:
            vuln_id = vuln.get("VulnerabilityID", "unknown")
            package = vuln.get("PkgName", "unknown")
            installed = vuln.get("InstalledVersion", "?")
            fixed = vuln.get("FixedVersion")
            findings.append(Finding(
                rule_id=f"trivy/{vuln_id}",
                cwe=_cwe(vuln),
                title=f"{vuln_id} in {package}@{installed}",
                severity=_SEVERITY_MAP.get((vuln.get("Severity") or "UNKNOWN").upper(), Severity.INFO),
                location=Location(method="DEPENDENCY", path=target, parameter=package, source_file=target),
                description=(
                    f"Dependency scan (trivy) — not dynamically exploited. "
                    f"{(vuln.get('Title') or vuln.get('Description') or '').strip()}"
                ).strip(),
                poc=PoC(
                    request=f"{package}@{installed} pinned in {target}",
                    response=(
                        f"Advisory {vuln_id}: {(vuln.get('Title') or 'no title').strip()}. "
                        f"Fixed in {fixed or 'no fix available yet'}."
                    ),
                ),
                discovered_by="trivy",
                cvss=_cvss(vuln),
            ))
        findings.extend(_secrets(result, target))
    return findings


# A leaked credential is not a dependency advisory and does not get one's shape: there is
# no package, no version, no CVSS and nothing to upgrade. It is a line in a file.
_SECRET_SEVERITY = {
    "CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH, "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW, "UNKNOWN": Severity.INFO,
}


def _secrets(result: dict, target: str) -> list[Finding]:
    """Hardcoded credentials trivy matched.

    WHY THIS IS WORTH A SEPARATE SCANNER when semgrep already has secret rules: measured
    on a file holding an AWS key pair, a GitHub PAT, a Slack bot token and an RSA private
    key, semgrep p/default found TWO (the AWS pair) and trivy found FOUR — it caught the
    GitHub PAT and the Slack token semgrep has no rule for. A leaked GitHub token in a
    repository is close to the worst single finding there is, and docket was not looking
    for one. `p/secrets` was measured too and added nothing p/default did not already
    have, which is why the rule packs were left alone and this was enabled instead.

    The REDACTION matters. trivy returns the matched text, and copying that into a
    Finding would write the live credential into report.json, report.sarif and a pull
    request comment — docket would publish the secret it is reporting. Only trivy's own
    starred form is used, and never the raw match.
    """
    out: list[Finding] = []
    for secret in result.get("Secrets") or []:
        rule = str(secret.get("RuleID") or "secret")
        line = secret.get("StartLine")
        where = f"{target}:{line}" if line else target
        title = str(secret.get("Title") or rule).strip()
        out.append(Finding(
            rule_id=f"trivy/secret/{rule}",
            cwe="CWE-798",
            title=f"Hardcoded credential: {title}",
            severity=_SECRET_SEVERITY.get(
                str(secret.get("Severity") or "UNKNOWN").upper(), Severity.INFO),
            location=Location(method="STATIC", path=target, source_file=where),
            description=(
                "Secret scan (trivy) — a credential committed to the repository. Rotate "
                "it first: removing the line does not un-leak a value that is in the git "
                "history and may already have been cloned."
            ),
            poc=PoC(
                # `Match` is trivy's redacted rendering, with the secret starred out.
                # `Code` holds the surrounding lines and is NOT used: it contains the
                # literal value.
                request=f"{rule} at {where}",
                response=str(secret.get("Match") or "match withheld").strip()[:400],
            ),
            discovered_by="trivy",
        ))
    return out


def run_trivy(sandbox: Any, run_dir: Path, *, timeout_sec: int = 120) -> list[Finding]:
    """Requires the sandbox to have been started with a source_dir (mounted read-only
    at /work/source) — callers gate on that before invoking this. Never raises."""
    out_path = run_dir / "artifacts" / "scanners" / "trivy.json"
    command = (
        "mkdir -p /work/run/artifacts/scanners && "
        # vuln,secret — not vuln alone. The secret scanner is already in this binary and
        # costs one pass over the same tree; it catches GitHub PATs and Slack tokens that
        # semgrep has no rule for. See _secrets.
        "trivy fs --scanners vuln,secret --format json --quiet "
        # docket's own output directory. --fix writes patched COPIES of the source under
        # docket_runs/<run>/fix/<name>/tree/, each with its own requirements.txt, so a
        # repo scanned before reports the same dependency CVE once per historical run.
        "--skip-dirs docket_runs "
        "--output /work/run/artifacts/scanners/trivy.json /work/source"
    )
    try:
        result = sandbox.call("shell", command=command, timeout_sec=timeout_sec)
    except Exception:
        return []
    if "error" in result:
        return []
    if not out_path.exists():
        return []
    return parse_trivy_json(out_path.read_text())


def demo() -> None:
    # The command must skip docket's own run directory, or a repo that has been scanned
    # before reports every previous run's patched copies as fresh dependency findings.
    import inspect

    assert "--skip-dirs docket_runs" in inspect.getsource(run_trivy)

    sample = json.dumps({
        "Results": [{
            "Target": "package-lock.json",
            "Vulnerabilities": [{
                "VulnerabilityID": "CVE-2021-23337",
                "PkgName": "lodash",
                "InstalledVersion": "4.17.15",
                "FixedVersion": "4.17.21",
                "Severity": "HIGH",
                "Title": "lodash: command injection",
                "CweIDs": ["CWE-78"],
            }],
        }],
    })
    findings = parse_trivy_json(sample)
    assert len(findings) == 1, findings
    f = findings[0]
    assert f.rule_id == "trivy/CVE-2021-23337"
    assert f.cwe == "CWE-78"
    assert f.severity == Severity.HIGH
    assert f.location.parameter == "lodash" and f.location.path == "package-lock.json"
    assert "not dynamically exploited" in f.description
    assert "4.17.21" in f.poc.response
    assert parse_trivy_json("not json") == []
    # ── CVSS: taken from the advisory, never computed ──────────────────────
    # Real shape from disk. NVD and Red Hat disagree on both score and vector for this
    # CVE, which is exactly why the source is recorded rather than a bare number.
    disputed = json.dumps({"Results": [{"Target": "requirements.txt", "Vulnerabilities": [{
        "VulnerabilityID": "CVE-2024-56201", "PkgName": "jinja2",
        "InstalledVersion": "3.1.4", "Severity": "MEDIUM", "Title": "template injection",
        "CVSS": {
            "ghsa": {"V3Score": 8.8, "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                     "V40Score": 5.4},
            "nvd": {"V3Score": 8.8, "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H"},
            "redhat": {"V3Score": 7.3, "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H"},
        }}]}]})
    got = parse_trivy_json(disputed)[0]
    assert got.cvss.source == "nvd", got.cvss.source  # precedence, not max
    assert got.cvss.score == 8.8 and got.cvss.version == "3.1"
    assert got.cvss.vector.startswith("CVSS:3.1/AV:L"), got.cvss.vector
    assert got.cvss.rating == "high"  # 8.8 sits in the 7.0-8.9 band, not critical

    # v4-only advisory: taken, but labelled v4 so it is never compared against a v3.
    v4 = json.dumps({"Results": [{"Target": "req.txt", "Vulnerabilities": [{
        "VulnerabilityID": "CVE-2026-1", "PkgName": "x", "InstalledVersion": "1",
        "Severity": "LOW", "CVSS": {"ghsa": {"V40Score": 2.3}}}]}]})
    assert parse_trivy_json(v4)[0].cvss.version == "4.0"
    assert parse_trivy_json(v4)[0].cvss.score == 2.3

    # No CVSS block, or a nonsense score, means None — never a 0.0, which in CVSS is
    # an affirmative claim that the vulnerability has no impact.
    none_case = json.dumps({"Results": [{"Target": "r.txt", "Vulnerabilities": [{
        "VulnerabilityID": "CVE-X", "PkgName": "p", "InstalledVersion": "1",
        "Severity": "HIGH"}]}]})
    assert parse_trivy_json(none_case)[0].cvss is None
    junk = json.dumps({"Results": [{"Target": "r.txt", "Vulnerabilities": [{
        "VulnerabilityID": "CVE-Y", "PkgName": "p", "InstalledVersion": "1",
        "Severity": "HIGH", "CVSS": {"nvd": {"V3Score": 99.0}}}]}]})
    assert parse_trivy_json(junk)[0].cvss is None, "out-of-range score must be refused"

    # --- secrets --------------------------------------------------------------------
    # The shape trivy actually returns, taken from a real run against a file holding an
    # AWS key pair, a GitHub PAT and a Slack token.
    secret_doc = json.dumps({"Results": [{
        "Target": "settings.py",
        "Secrets": [
            {"RuleID": "github-pat", "Severity": "CRITICAL", "StartLine": 3,
             "Title": "GitHub Personal Access Token",
             "Match": 'GITHUB_TOKEN = "ghp_****************************"',
             # trivy also returns the surrounding source, WITH the live value in it.
             "Code": {"Lines": [{"Content": 'GITHUB_TOKEN = "ghp_REALSECRETVALUE123"'}]}},
            {"RuleID": "slack-access-token", "Severity": "HIGH", "StartLine": 4,
             "Match": "xoxb-****"},
        ]}]})
    found = parse_trivy_json(secret_doc)
    assert len(found) == 2, found
    pat = found[0]
    assert pat.rule_id == "trivy/secret/github-pat", pat.rule_id
    assert pat.cwe == "CWE-798" and pat.severity is Severity.CRITICAL
    assert pat.location.source_file == "settings.py:3", pat.location
    # A credential is not a dependency advisory: no package, no version to upgrade.
    assert pat.location.method == "STATIC", pat.location
    assert pat.cvss is None, "a leaked secret has no CVSS and must not be given one"
    # Rotation first. Deleting the line does not un-leak a value already in git history.
    assert "Rotate it first" in pat.description, pat.description

    # THE ONE THAT MATTERS. report.json, report.sarif and the pull-request comment are all
    # built from these fields. Writing trivy's `Code` into a Finding would mean docket
    # PUBLISHES the credential it is reporting — to a GitHub comment, on a public repo.
    serialised = pat.model_dump_json()
    assert "REALSECRETVALUE123" not in serialised, "docket just leaked the secret it found"
    assert "ghp_****" in pat.poc.response, pat.poc.response

    # A result carrying both kinds yields both, and neither shape contaminates the other.
    both = parse_trivy_json(json.dumps({"Results": [{
        "Target": "requirements.txt",
        "Vulnerabilities": [{"VulnerabilityID": "CVE-1", "PkgName": "flask",
                             "InstalledVersion": "1.0", "Severity": "HIGH"}],
        "Secrets": [{"RuleID": "aws-secret-access-key", "Severity": "CRITICAL",
                     "StartLine": 9, "Match": "aws_secret = ****"}]}]}))
    assert len(both) == 2, both
    assert {f.location.method for f in both} == {"DEPENDENCY", "STATIC"}, both
    # Malformed secret rows must not sink a scan that already cost money.
    assert parse_trivy_json(json.dumps({"Results": [{"Target": "x", "Secrets": [{}]}]}))

    print("scanners.trivy: ok")


if __name__ == "__main__":
    demo()
