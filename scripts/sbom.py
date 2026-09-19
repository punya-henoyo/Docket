#!/usr/bin/env python3
"""Generate docket's own SBOM: CycloneDX JSON plus a readable summary.

    uv run python scripts/sbom.py            # -> sbom/docket.cdx.json + sbom/SBOM.md
    uv run python scripts/sbom.py --check    # non-zero if the committed SBOM is stale

WHY A SCRIPT AND NOT A COMMITTED FILE. An SBOM that is written once is wrong by the next
`uv sync`. This regenerates from the lockfiles that are already the source of truth, so a
stale SBOM is a diff rather than a surprise. `--check` is the same idea as
scripts/build_skills.py's: the committed bytes must match what regenerating produces.

HOW IT IS BUILT, AND THE ONE PLACE TRIVY IS NOT ENOUGH.

trivy is already in docket's sandbox image — it is what `docket scan` uses for dependency
findings — so the component list and the purls come from the tool this project already
trusts, rather than from a hand-rolled lockfile parser that would get CycloneDX subtly
wrong. But trivy reads LOCKFILES, and a lockfile carries no licence. Measured on this
repo: 3 of 85 components came back with one.

A licence-less SBOM is half an SBOM — licence compliance is usually the whole reason
somebody asks for one. So the pypi components are enriched from `importlib.metadata`,
which reads the licence out of the actually-installed distributions: 76 of 78 here. Where
even that is silent the component keeps NO licence rather than a guessed one, and the
summary counts those separately. An invented licence is worse than a blank.

NPM coverage is production-only by design: react, react-dom and scheduler are what ship
in the browser bundle. vite and typescript build it and are not in it, so they are not
components of the delivered artifact.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from collections import Counter
from pathlib import Path

def _today() -> str:
    """Date only. A timestamp would guarantee a diff on every run and make --check
    permanently red, which is how a check gets ignored."""
    from datetime import date

    return date.today().isoformat()


REPO = Path(__file__).resolve().parent.parent
OUT_DIR = REPO / "sbom"
CDX = OUT_DIR / "docket.cdx.json"
SUMMARY = OUT_DIR / "SBOM.md"
IMAGE = "docket-sandbox:latest"
# docket's own run artifacts and the virtualenv. Neither is part of what ships, and
# docket_runs holds patched COPIES of other people's source (see tools/scanners/trivy.py).
SKIP = ("docket_runs", ".venv", "node_modules", "graphify-out")


def run_trivy(out: Path) -> None:
    """Component list + purls, from the tool docket already ships."""
    skips = [arg for d in SKIP for arg in ("--skip-dirs", d)]
    command = [
        "docker", "run", "--rm",
        "-v", f"{REPO}:/src:ro",
        "-v", f"{out.parent}:/out",
        IMAGE, "trivy", "fs", "--format", "cyclonedx", "--quiet",
        *skips, "--output", f"/out/{out.name}", "/src",
    ]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=300)
    except FileNotFoundError:
        sys.exit("error: docker is not on PATH. The SBOM is generated with the trivy in "
                 "docket's sandbox image.")
    except subprocess.TimeoutExpired:
        sys.exit("error: trivy timed out after 300s")
    if result.returncode != 0:
        sys.exit(f"error: trivy failed ({result.returncode}): {result.stderr.strip()[:500]}\n"
                 f"Is the docker daemon running, and has `make image` been run?")


# Spelling variants of the SAME licence, normalised to their SPDX id so a reader counting
# licence families is not defeated by "MIT" and "MIT License" appearing as two rows.
#
# ONLY unambiguous renames belong here. "BSD License" is deliberately absent: it does not
# say 2-clause or 3-clause, and picking one would be inventing a term of the licence
# rather than tidying its spelling. Ambiguous values are left exactly as the package
# declared them, and show up in the summary as their own row — which is the signal that
# somebody should go and read that package's LICENSE file.
_LICENCE_ALIASES = {
    "MIT License": "MIT",
    "The MIT License (MIT)": "MIT",
    "Apache 2.0": "Apache-2.0",
    "Apache License 2.0": "Apache-2.0",
    "Apache Software License": "Apache-2.0",
    "Apache License, Version 2.0": "Apache-2.0",
    "BSD-3-Clause License": "BSD-3-Clause",
    "Mozilla Public License 2.0 (MPL 2.0)": "MPL-2.0",
    "Python Software Foundation License": "PSF-2.0",
    "ISC License (ISCL)": "ISC",
}


def normalise_licence(value: str) -> str:
    return _LICENCE_ALIASES.get(value.strip(), value.strip())


def vulnerability_status(cdx: Path) -> dict:
    """Scan the SBOM we just produced and record the result, with its date.

    Written to a file rather than into the document, because the DOCX generator must run
    with no Docker: a reader who cannot rebuild the SBOM should still be able to rebuild
    the document from the committed JSON.

    The result is deliberately recorded as "as of this date, against this database" and
    never as "is secure". A vulnerability scan is a point-in-time statement about what was
    PUBLISHED by then; an SBOM that says "0 vulnerabilities" with no date is a claim that
    silently rots.
    """
    command = [
        "docker", "run", "--rm", "-v", f"{cdx.parent}:/s:ro", IMAGE,
        "trivy", "sbom", "--quiet", "--format", "json", f"/s/{cdx.name}",
    ]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=300)
        if result.returncode != 0:
            return {"assessed": False, "reason": result.stderr.strip()[:200]}
        report = json.loads(result.stdout or "{}")
    except Exception as exc:  # noqa: BLE001 — a missing scan must not lose the SBOM
        return {"assessed": False, "reason": f"{type(exc).__name__}: {exc}"}

    by_severity: Counter[str] = Counter()
    for target in report.get("Results") or []:
        for vuln in target.get("Vulnerabilities") or []:
            by_severity[str(vuln.get("Severity", "UNKNOWN")).upper()] += 1
    return {
        "assessed": True,
        "scanner": "trivy",
        "total": sum(by_severity.values()),
        "by_severity": dict(by_severity),
    }


def installed_licenses() -> dict[str, str]:
    """name -> licence, from the distributions actually installed.

    Three sources in order of trust: the PEP 639 `License-Expression`, the legacy
    `License` field, then the `License ::` trove classifier. A `License` field longer than
    a line is the full licence TEXT pasted into metadata, which is not an identifier and
    must not be written into the SBOM as one.
    """
    from importlib import metadata

    out: dict[str, str] = {}
    for dist in metadata.distributions():
        try:
            md = dist.metadata
            name = (md["Name"] or "").strip().lower().replace("_", "-")
            if not name:
                continue
            licence = (md.get("License-Expression") or md.get("License") or "").strip()
            if not licence or len(licence) > 60 or "\n" in licence:
                # Some packages paste the FULL licence text into the `License` field —
                # tiktoken ships the entire MIT licence there, with no classifier, so it
                # fell through to blank. Its first line is literally "MIT License", which
                # IS an identifier. Accept that first line ONLY when it maps through the
                # alias table; a file that opens with "Copyright (c) 2022 ..." maps to
                # nothing and correctly stays blank rather than being guessed at.
                head = licence.splitlines()[0].strip() if licence else ""
                if head and head in _LICENCE_ALIASES:
                    licence = head
                else:
                    trove = [c for c in (md.get_all("Classifier") or [])
                             if c.startswith("License ::")]
                    licence = trove[0].split(" :: ")[-1].strip() if trove else ""
            if licence and licence.lower() not in ("unknown", "none"):
                out[name] = normalise_licence(licence)
        except Exception:  # noqa: BLE001 — one unreadable dist must not lose the rest
            continue
    return out


def enrich(document: dict, licences: dict[str, str]) -> tuple[int, int]:
    """Fill in missing licences on pypi components. Returns (filled, still_missing)."""
    filled = missing = 0
    for component in document.get("components") or []:
        if component.get("licenses"):
            continue
        purl = component.get("purl") or ""
        if not purl.startswith("pkg:pypi"):
            missing += 1
            continue
        key = str(component.get("name", "")).strip().lower().replace("_", "-")
        licence = licences.get(key)
        if not licence:
            # Left blank on purpose. A guessed licence in an SBOM is worse than a gap,
            # because a gap gets looked at and a guess gets relied on.
            missing += 1
            continue
        component["licenses"] = [{"license": {"name": licence}}]
        filled += 1
    return filled, missing


def stabilise(document: dict) -> None:
    """Make the document byte-reproducible, in place.

    trivy mints a fresh UUID `bom-ref` per component on every run and emits the lockfiles
    in filesystem order, so two generations of an UNCHANGED tree differ on ~30 lines.
    `--check` would then be permanently red, and a check that is always red is a check
    everyone learns to ignore.

    The refs are cross-referenced by the `dependencies` graph, so they are rewritten
    through a map rather than in place: a stable ref derived from the purl (or
    name@version) replaces the UUID everywhere it appears, and components and their
    dependency lists are then sorted.
    """
    components = document.get("components") or []

    def stable_ref(component: dict) -> str:
        purl = component.get("purl")
        if purl:
            return str(purl)
        name = str(component.get("name", "?"))
        version = str(component.get("version", "")).strip()
        return f"{name}@{version}" if version else name

    mapping: dict[str, str] = {}
    for component in components:
        old_ref = component.get("bom-ref")
        new_ref = stable_ref(component)
        if old_ref:
            mapping[str(old_ref)] = new_ref
        component["bom-ref"] = new_ref

    meta_component = (document.get("metadata") or {}).get("component") or {}
    if meta_component.get("bom-ref"):
        stable = stable_ref(meta_component)
        mapping[str(meta_component["bom-ref"])] = stable
        meta_component["bom-ref"] = stable

    for entry in document.get("dependencies") or []:
        if entry.get("ref") in mapping:
            entry["ref"] = mapping[entry["ref"]]
        if entry.get("dependsOn"):
            entry["dependsOn"] = sorted(mapping.get(r, r) for r in entry["dependsOn"])

    components.sort(key=lambda c: (str(c.get("bom-ref")), str(c.get("name"))))
    if document.get("dependencies"):
        document["dependencies"] = sorted(document["dependencies"],
                                          key=lambda e: str(e.get("ref")))


def summarise(document: dict) -> str:
    components = document.get("components") or []
    ecosystems: Counter[str] = Counter()
    licences: Counter[str] = Counter()
    unlicensed: list[str] = []
    lockfiles: list[str] = []
    for component in components:
        purl = component.get("purl") or ""
        ecosystems[purl.split("/")[0] if purl.startswith("pkg:") else "other"] += 1
        names = [
            (entry.get("license") or {}).get("name")
            or (entry.get("license") or {}).get("id")
            or entry.get("expression")
            for entry in component.get("licenses") or []
        ]
        names = [normalise_licence(n) for n in names if n]
        if names:
            for name in names:
                licences[name] += 1
        elif component.get("type") == "application" or not purl:
            # trivy emits one `application` component per LOCKFILE it parsed. Those are
            # not packages and have no licence to carry; counting them as gaps sends a
            # reader looking for a licence on `uv.lock`.
            lockfiles.append(str(component.get("name")))
        else:
            unlicensed.append(f"{component.get('name')} {component.get('version', '')}".strip())

    lines = [
        "# Docket — Software Bill of Materials",
        "",
        f"`{CDX.relative_to(REPO)}` · CycloneDX "
        f"{document.get('specVersion', '?')} · {len(components)} components",
        "",
        "Regenerate with `make sbom`. Do not hand-edit: `make sbom-check` fails if the",
        "committed file and a fresh generation disagree.",
        "",
        "## What is counted",
        "",
        "Everything that ships. Excluded, with reasons:",
        "",
        "- `docket_runs/` — docket's own scan output, including patched copies of other",
        "  repositories' source. Not part of this product.",
        "- `.venv/` — a local install of the same packages already listed from the lockfile.",
        "- npm **dev** dependencies (vite, typescript, @vitejs/plugin-react) — they build",
        "  the console bundle and are not in it. Only react, react-dom and scheduler are",
        "  delivered to a browser.",
        "",
        "## Components by ecosystem",
        "",
        "| Ecosystem | Count |",
        "|---|---|",
    ]
    for eco, count in ecosystems.most_common():
        lines.append(f"| `{eco}` | {count} |")

    lines += [
        "",
        "## Licences",
        "",
        f"{len(components) - len(unlicensed) - len(lockfiles)} of "
        f"{len(components) - len(lockfiles)} packages carry one. "
        f"({len(lockfiles)} further entries are the lockfiles trivy parsed, not packages: "
        f"{', '.join(f'`{name}`' for name in sorted(lockfiles))}.)",
        "",
        "| Licence | Count |",
        "|---|---|",
    ]
    for name, count in licences.most_common():
        lines.append(f"| {name} | {count} |")

    if unlicensed:
        lines += [
            "",
            f"### {len(unlicensed)} package(s) with no licence recorded",
            "",
            "Left blank rather than guessed. A guessed licence gets relied on; a gap gets",
            "looked at. Resolve these by hand before shipping to anyone who audits them.",
            "",
            "Usually because the package is platform-specific or optional, so the lockfile",
            "resolves it but it is NOT installed on the machine that generated this SBOM",
            "and there was no local metadata to read. Generating on the target platform,",
            "or installing every extra first, fills most of them in.",
            "",
            *(f"- `{name}`" for name in sorted(unlicensed)),
        ]

    lines += [
        "",
        "## Declared direct dependencies",
        "",
        "From `pyproject.toml`. Everything else in the list above is transitive.",
        "",
        "| Package | Constraint | Why |",
        "|---|---|---|",
        "| `openai-agents[litellm]` | `>=0.19,<0.20` | the agent runtime; litellm routes every model |",
        "| `pydantic` | `>=2` | every model that crosses a trust boundary |",
        "| `python-dotenv` | `>=1` | `.env` loading |",
        "| `textual` | `>=8.2.8` | the `--tui` live view |",
        "| `fastapi` (extra `app`) | `>=0.115` | the console API |",
        "| `uvicorn[standard]` (extra `app`) | `>=0.32` | serves it |",
        "| `pypdf` (extra `app`) | `>=5` | reading an uploaded compliance policy as PDF |",
        "| `tokenizers` (extra `tokenizer`) | `>=0.20` | real token counting; a char fallback works without it |",
        "",
        "Four runtime packages, three optional. `CONTRIBUTING.md`: every dependency earns",
        "its place — `web_search` talks to five providers over plain `urllib` rather than",
        "pulling in five SDKs.",
        "",
        "## Tools invoked, not linked",
        "",
        "These run as subprocesses inside the sandbox container and are not Python or npm",
        "components of docket. They carry their own licences and are listed so an auditor",
        "is not surprised by them.",
        "",
        "| Tool | Role |",
        "|---|---|",
        "| `semgrep` | static analysis over mounted source |",
        "| `trivy` | dependency and CVE scanning — and the generator of this SBOM |",
        "| `nuclei` | live-target templates, when a target is given |",
        "| `docker` | the sandbox itself |",
        "",
    ]
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate docket's SBOM.")
    parser.add_argument("--check", action="store_true",
                        help="Exit non-zero if the committed SBOM is stale.")
    args = parser.parse_args()

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    scratch = OUT_DIR / ".docket.cdx.json.tmp"
    run_trivy(scratch)
    document = json.loads(scratch.read_text())
    scratch.unlink(missing_ok=True)

    filled, missing = enrich(document, installed_licenses())
    # The timestamp and a fresh serial number change on every run, so --check would fail
    # on an unchanged tree. Dropped: an SBOM's value is its component list, and a field
    # that guarantees a spurious diff guarantees the check gets ignored.
    document.get("metadata", {}).pop("timestamp", None)
    document.pop("serialNumber", None)
    stabilise(document)

    body = json.dumps(document, indent=2, sort_keys=True) + "\n"
    summary = summarise(document)

    if args.check:
        stale = [
            str(path.relative_to(REPO))
            for path, want in ((CDX, body), (SUMMARY, summary))
            if not path.exists() or path.read_text() != want
        ]
        if stale:
            print("SBOM is stale — run `make sbom`:", file=sys.stderr)
            for path in stale:
                print(f"  {path}", file=sys.stderr)
            return 1
        print(f"sbom: up to date ({len(document.get('components') or [])} components)")
        return 0

    CDX.write_text(body)
    SUMMARY.write_text(summary)
    # Written AFTER the SBOM, because it scans the file we just wrote. Carries a date, so
    # a document built from it can say "as of" rather than making a timeless claim.
    status = vulnerability_status(CDX)
    status["scanned_on"] = _today()
    (OUT_DIR / "scan-status.json").write_text(json.dumps(status, indent=2) + "\n")
    total = len(document.get("components") or [])
    print(f"wrote {CDX.relative_to(REPO)} ({total} components)")
    print(f"wrote {SUMMARY.relative_to(REPO)}")
    print(f"licences: {filled} filled from installed metadata, {missing} still missing")
    return 0


if __name__ == "__main__":
    sys.exit(main())
