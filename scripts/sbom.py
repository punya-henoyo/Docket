#!/usr/bin/env python3
"""Generate docket's SBOM: CycloneDX JSON, a readable summary, and a dated scan status.

    uv run python scripts/sbom.py                 # -> sbom/docket.cdx.json + SBOM.md
    uv run python scripts/sbom.py --check         # non-zero if the committed copy is stale
    uv run python scripts/sbom.py --verify-image  # re-read sandbox licences from the image

WHY THIS IS NOT JUST `trivy fs`.

trivy reads lockfiles and emits a flat list. That is a start, and it is kept below as an
INDEPENDENT CROSS-CHECK, but three kinds of component never appear in it and a fourth
appears without the fact that matters:

  1. What the sandbox container ships. Every `docket scan` executes semgrep, nuclei,
     trivy, mitmproxy and Chromium INSIDE the container built by containers/Dockerfile.
     They are as much a part of the delivered system as anything in uv.lock, and a
     filesystem scan of this repository cannot see them. One of them — semgrep — is
     LGPL-2.1, which is precisely the fact a licence review exists to surface.

  2. Third-party CONTENT. 50 agent playbooks under engine/docket/skills/ are DERIVED
     from the strix project under Apache-2.0 (see NOTICE). No lockfile records prose. It
     carries a real attribution obligation and belongs in the inventory.

  3. The base image underneath those tools.

  4. WHY each Python package is present. trivy lists 80 packages flat. uv.lock holds the
     resolution graph, so every transitive package here carries the shortest path back to
     something a human actually declared: `h11` is not a mystery, it is `uvicorn -> h11`.
     Each is also attributed to the extra that pulls it in, so a core runtime package is
     distinguishable from one only needed by `--extra app`.

The output is byte-reproducible; `--check` fails if the committed copy drifts.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tomllib
from collections import Counter, deque
from datetime import date
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
OUT_DIR = REPO / "sbom"
CDX = OUT_DIR / "docket.cdx.json"
SUMMARY = OUT_DIR / "SBOM.md"
STATUS = OUT_DIR / "scan-status.json"
IMAGE = "docket-sandbox:latest"

# Licences for what the sandbox container installs. HAND-LISTED on purpose, in the same
# spirit as service/gate.py's FLOOR_RULES: each was read out of the built image on
# 2026-09-19, not recalled. `--verify-image` re-reads them and fails on drift, so this
# cannot rot silently.
#
# VERSIONS are deliberately NOT here — they are parsed from containers/Dockerfile, so
# they cannot disagree with what is actually built.
SANDBOX_LICENCES = {
    # The one a licence review cares about. LGPL-2.1 is weak copyleft; docket INVOKES
    # semgrep as a subprocess inside a container, does not link against it and does not
    # modify it, which is the distinction that governs the obligation.
    "semgrep": "LGPL-2.1-only",
    "nuclei": "MIT",
    "trivy": "Apache-2.0",
    "mitmproxy": "MIT",
    "playwright": "Apache-2.0",
}
_ARG_VERSION = re.compile(r"^ARG\s+([A-Z_]+)_VERSION=(\S+)", re.M)
_PIP_PIN = re.compile(r"pip install\s+([a-z0-9_-]+)==(\S+)", re.M)


def today() -> str:
    """Date only. A timestamp would diff on every run and make --check permanently red,
    which is how a check gets ignored."""
    return date.today().isoformat()


# ── Python: the graph, not just the list ────────────────────────────────────────────

def python_components() -> list[dict]:
    """Every resolved Python package, each carrying why it is here.

    Breadth-first from docket's own declared dependencies gives each package the SHORTEST
    path back to something a human chose — which is the question a reviewer actually has
    about an 80-package list. Origins are walked separately and in order, so a package
    reachable from both `core` and an extra is attributed to `core`, the stronger claim.
    """
    lock = tomllib.loads((REPO / "uv.lock").read_text())
    packages = {p["name"]: p for p in lock["package"]}
    root = packages["docket"]

    def requirements(entry: dict) -> list[dict]:
        """A dependency entry resolved to the requirement list it actually pulls in.

        THE BUG THIS CLOSES: docket declares `openai-agents[litellm]` and
        `uvicorn[standard]`, and an entry records that as `{"name": ..., "extra": [...]}`.
        Walking only `dependencies` therefore never reaches litellm — or aiohttp, jinja2,
        tiktoken, uvloop and eighteen more underneath it — and 23 of 80 packages came out
        labelled "unreachable". litellm is the entire reason that extra is requested, so
        that label was not a cosmetic error; it was the SBOM answering "why is this here"
        with "no idea".
        """
        package = packages.get(entry["name"])
        if package is None:
            return []
        out = list(package.get("dependencies", []))
        optional = package.get("optional-dependencies") or {}
        for extra in entry.get("extra", []):
            out += list(optional.get(extra, []))
        return out

    def label_of(entry: dict) -> str:
        extra = entry.get("extra")
        return f"{entry['name']}[{','.join(extra)}]" if extra else entry["name"]

    direct = {d["name"] for d in root.get("dependencies", [])}
    extras: dict[str, list[dict]] = {
        name: list(deps) for name, deps in (root.get("optional-dependencies") or {}).items()
    }
    declared = direct | {d["name"] for deps in extras.values() for d in deps}

    origins: list[tuple[str, list[dict]]] = [("core", list(root.get("dependencies", [])))]
    origins += [(f"extra:{name}", deps) for name, deps in sorted(extras.items())]

    # TWO different "seen" sets, and conflating them was a bug.
    #
    # `why` is keyed by NAME: the first origin to reach a package owns its attribution,
    # which is what makes `core` beat `extra:app` for a package both need.
    #
    # `expanded` is keyed by (name, extras): `mcp` pulls in plain `uvicorn` during the
    # core walk, which marked the name seen — so when `extra:app` later arrived at
    # `uvicorn[standard]`, the walk skipped it and never expanded the `standard` extra.
    # httptools, uvloop and watchfiles came out "unreachable" as a result. A package
    # requested with extras not yet expanded must still be expanded, even when its name
    # already has an attribution.
    why: dict[str, tuple[str, list[str]]] = {}
    expanded: set[tuple[str, frozenset[str]]] = set()
    for label, seeds in origins:
        queue = deque((entry, [label_of(entry)])
                      for entry in sorted(seeds, key=lambda e: e["name"]))
        while queue:
            entry, path = queue.popleft()
            name = entry["name"]
            if name not in packages:
                continue
            key = (name, frozenset(entry.get("extra", [])))
            if key in expanded:
                continue
            expanded.add(key)
            why.setdefault(name, (label, path))
            for dep in requirements(entry):
                if (dep["name"], frozenset(dep.get("extra", []))) not in expanded:
                    queue.append((dep, [*path, label_of(dep)]))

    out: list[dict] = []
    for name, package in sorted(packages.items()):
        if name == "docket":
            continue
        label, path = why.get(name, ("unreachable", []))
        version = package.get("version", "")
        properties = [
            {"name": "docket:origin", "value": label},
            {"name": "docket:directness",
             "value": "direct" if name in declared else "transitive"},
        ]
        if len(path) > 1:
            properties.append({"name": "docket:required-by", "value": " -> ".join(path)})
        out.append({
            "type": "library",
            "bom-ref": f"pkg:pypi/{name}@{version}",
            "name": name,
            "version": version,
            "purl": f"pkg:pypi/{name}@{version}",
            "properties": properties,
        })
    return out


# ── npm: only what reaches a browser ────────────────────────────────────────────────

def npm_components() -> list[dict]:
    """Production dependencies of the console bundle.

    Dev dependencies (vite, typescript) BUILD the bundle and are not in it, so they are
    not components of the delivered software. package-lock.json marks them `dev: true`.
    """
    lock = json.loads((REPO / "app" / "frontend" / "package-lock.json").read_text())
    entries = {
        path.split("node_modules/")[-1]: entry
        for path, entry in (lock.get("packages") or {}).items()
        if path.startswith("node_modules/") and not entry.get("dev")
    }
    declared = set((lock.get("packages", {}).get("", {}).get("dependencies") or {}))

    # Same "why is this here" walk as the Python side. react-dom pulling in scheduler is
    # not obvious from a flat list, and a reviewer asking why an unfamiliar package
    # reaches a browser deserves the chain rather than a shrug.
    chains: dict[str, list[str]] = {}
    queue = deque((name, [name]) for name in sorted(declared))
    while queue:
        name, path = queue.popleft()
        if name in chains or name not in entries:
            continue
        chains[name] = path
        for dep in sorted((entries[name].get("dependencies") or {})):
            if dep not in chains:
                queue.append((dep, [*path, dep]))

    out: list[dict] = []
    for name, entry in sorted(entries.items()):
        version = entry.get("version", "")
        properties = [
            {"name": "docket:origin", "value": "console-bundle"},
            {"name": "docket:directness",
             "value": "direct" if name in declared else "transitive"},
        ]
        chain = chains.get(name, [])
        if len(chain) > 1:
            properties.append({"name": "docket:required-by", "value": " -> ".join(chain)})
        out.append({
            "type": "library",
            "bom-ref": f"pkg:npm/{name}@{version}",
            "name": name,
            "version": version,
            "purl": f"pkg:npm/{name}@{version}",
            "licenses": ([{"license": {"name": entry["license"]}}]
                         if entry.get("license") else []),
            "properties": properties,
        })
    return out


# ── the sandbox: what a repository scan cannot see ──────────────────────────────────

def sandbox_versions() -> dict[str, str]:
    """Tool versions parsed from containers/Dockerfile, so they cannot drift from it."""
    text = (REPO / "containers" / "Dockerfile").read_text()
    versions = {key.lower(): value for key, value in _ARG_VERSION.findall(text)}
    versions.update(dict(_PIP_PIN.findall(text)))
    return versions


def sandbox_components() -> list[dict]:
    """The container's base image and the tools docket executes inside it."""
    versions = sandbox_versions()
    out: list[dict] = [{
        "type": "operating-system",
        "bom-ref": "container:base",
        "name": "python:3.13-slim-bookworm",
        "version": "debian-12-bookworm",
        "licenses": [{"license": {"name": "multiple (Debian main)"}}],
        "properties": [
            {"name": "docket:origin", "value": "sandbox-image"},
            {"name": "docket:role",
             "value": "base image of containers/Dockerfile; every scanner runs in a "
                      "container built from it"},
        ],
    }]
    roles = {
        "semgrep": "static analysis over mounted source",
        "nuclei": "live-target vulnerability templates, when a target is given",
        "trivy": "dependency and CVE scanning; also the cross-check for this SBOM",
        "mitmproxy": "intercepting proxy for agent HTTP traffic",
        "playwright": "browser automation; installs Chromium",
    }
    for tool, role in roles.items():
        pinned = versions.get(tool)
        # `pip install mitmproxy` with no `==` resolves to whatever is current the day
        # the image is built, so two builds of the same Dockerfile can ship different
        # code. Stated rather than smoothed over: it is the same thing docket's own
        # python-baseline:pinned-deps control looks for in a customer's repository, and
        # an SBOM that quietly prints a version implies a guarantee the build does not
        # make.
        version = pinned or "unpinned"
        out.append({
            "type": "application",
            "bom-ref": f"container:{tool}@{version}",
            "name": tool,
            "version": version,
            "licenses": [{"license": {"name": SANDBOX_LICENCES[tool]}}],
            "properties": [
                {"name": "docket:origin", "value": "sandbox-image"},
                {"name": "docket:role", "value": role},
                {"name": "docket:pinned",
                 "value": "yes, in containers/Dockerfile" if pinned else
                          "NO — containers/Dockerfile installs it unversioned, so the "
                          "version shipped depends on when the image was built"},
                # The distinction that governs a copyleft obligation, recorded where the
                # licence is rather than left for a reviewer to establish.
                {"name": "docket:linkage",
                 "value": "invoked as a subprocess in the container; not linked against, "
                          "not modified, not redistributed"},
            ],
        })
    return out


# ── third-party content: no lockfile records prose ──────────────────────────────────

def vendored_components() -> list[dict]:
    """Material derived from another project, per NOTICE.

    The attribution is ASSERTED here, not assumed: build_skills.py prepends it to every
    generated file and load_skill.demo() checks it. If that ever stops being true the
    SBOM must not quietly claim otherwise.
    """
    skills = sorted([*(REPO / "engine/docket/skills/recon").glob("*.md"),
                     *(REPO / "engine/docket/skills/triage").glob("*.md")])
    if not skills:
        return []
    unattributed = [p.name for p in skills if "Apache-2.0" not in p.read_text()]
    return [{
        "type": "data",
        "bom-ref": "vendored:strix-skills",
        "name": "strix vulnerability playbooks (derived)",
        "version": "derived",
        "licenses": [{"license": {"name": "Apache-2.0"}}],
        "properties": [
            {"name": "docket:origin", "value": "vendored-content"},
            {"name": "docket:source", "value": "https://github.com/usestrix/strix"},
            {"name": "docket:files", "value": str(len(skills))},
            {"name": "docket:location", "value": "engine/docket/skills/{recon,triage}/"},
            {"name": "docket:attribution",
             "value": ("every file carries the licence and the changes made"
                       if not unattributed
                       else f"MISSING on {len(unattributed)}: {', '.join(unattributed[:5])}")},
            {"name": "docket:derivation",
             "value": "scripts/build_skills.py --check verifies it"},
        ],
    }]


# ── licences, which lockfiles do not carry ──────────────────────────────────────────

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
    "GNU Lesser General Public License v2 (LGPLv2)": "LGPL-2.1-only",
}


def normalise_licence(value: str) -> str:
    """Unambiguous spelling variants only. "BSD License" is deliberately absent: it does
    not say 2-clause or 3-clause, and choosing would invent a term of the licence."""
    return _LICENCE_ALIASES.get(value.strip(), value.strip())


def installed_licences() -> dict[str, str]:
    """name -> licence, read from the distributions actually installed.

    Some packages paste the full licence TEXT into the `License` field (tiktoken ships
    the whole MIT licence there, with no classifier). Its first line is accepted only
    when it maps through the alias table, so "MIT License" resolves and
    "Copyright (c) 2022 ..." correctly stays blank.
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


def apply_licences(components: list[dict], licences: dict[str, str]) -> None:
    for component in components:
        if component.get("licenses"):
            continue
        if not str(component.get("purl", "")).startswith("pkg:pypi"):
            component.setdefault("licenses", [])
            continue
        key = str(component["name"]).strip().lower().replace("_", "-")
        licence = licences.get(key)
        # Blank when unknown. A guessed licence gets relied on; a gap gets looked at.
        component["licenses"] = [{"license": {"name": licence}}] if licence else []


# ── trivy, demoted to a cross-check ─────────────────────────────────────────────────

def trivy_crosscheck(components: list[dict]) -> dict:
    """Does an independent tool agree about the packages both can see?

    If trivy finds a package this generator missed, the bug is HERE. Components trivy
    cannot see (the sandbox tools, the vendored playbooks) carry no purl and are excluded
    from the comparison rather than counted as a disagreement.
    """
    command = [
        "docker", "run", "--rm", "-v", f"{REPO}:/src:ro", IMAGE,
        "trivy", "fs", "--format", "cyclonedx", "--quiet",
        "--skip-dirs", "docket_runs", "--skip-dirs", ".venv",
        "--skip-dirs", "node_modules", "--skip-dirs", "graphify-out", "/src",
    ]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=300)
        if result.returncode != 0:
            return {"ran": False, "reason": result.stderr.strip()[:200]}
        theirs = {c["purl"] for c in (json.loads(result.stdout).get("components") or [])
                  if c.get("purl")}
    except Exception as exc:  # noqa: BLE001
        return {"ran": False, "reason": f"{type(exc).__name__}: {exc}"}
    mine = {c["purl"] for c in components if c.get("purl")}
    # docket itself is the SUBJECT of this SBOM, not a component of it: it lives in
    # metadata.component per the CycloneDX spec. trivy emits it as a component, so
    # excluding it here stops a spec-correct choice reading as a missed package.
    theirs.discard("pkg:pypi/docket@0.1.0")
    return {"ran": True, "agreed": len(mine & theirs),
            "missed_by_generator": sorted(theirs - mine),
            "not_seen_by_trivy": sorted(mine - theirs)}


def vulnerability_status(cdx: Path) -> dict:
    """A DATED result. Never "is secure": a scan states what had been published by then."""
    command = ["docker", "run", "--rm", "-v", f"{cdx.parent}:/s:ro", IMAGE,
               "trivy", "sbom", "--quiet", "--format", "json", f"/s/{cdx.name}"]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=300)
        if result.returncode != 0:
            return {"assessed": False, "reason": result.stderr.strip()[:200]}
        report = json.loads(result.stdout or "{}")
    except Exception as exc:  # noqa: BLE001
        return {"assessed": False, "reason": f"{type(exc).__name__}: {exc}"}
    by_severity: Counter[str] = Counter()
    for target in report.get("Results") or []:
        for vuln in target.get("Vulnerabilities") or []:
            by_severity[str(vuln.get("Severity", "UNKNOWN")).upper()] += 1
    return {"assessed": True, "scanner": "trivy", "total": sum(by_severity.values()),
            "by_severity": dict(by_severity)}


def verify_image() -> int:
    """Re-read the sandbox tools' licences from the built image and fail on drift."""
    script = (
        "python - <<'PY'\n"
        "from importlib import metadata\n"
        "for n in ('semgrep','mitmproxy','playwright'):\n"
        "    md = metadata.metadata(n)\n"
        "    lic = md.get('License-Expression') or md.get('License') or ''\n"
        "    if not lic or len(lic)>60 or '\\n' in lic:\n"
        "        tr=[c for c in (md.get_all('Classifier') or []) "
        "if c.startswith('License ::')]\n"
        "        lic = tr[0].split(' :: ')[-1] if tr else ''\n"
        "    print(n+'|'+lic)\n"
        "PY"
    )
    try:
        result = subprocess.run(
            ["docker", "run", "--rm", "--entrypoint", "sh", IMAGE, "-c", script],
            capture_output=True, text=True, timeout=200)
    except Exception as exc:  # noqa: BLE001
        print(f"could not run the image: {exc}", file=sys.stderr)
        return 1
    if result.returncode != 0:
        print(f"could not read the image: {result.stderr.strip()[:200]}", file=sys.stderr)
        return 1
    drift = []
    for line in result.stdout.splitlines():
        if "|" not in line:
            continue
        name, _, licence = line.partition("|")
        want, got = SANDBOX_LICENCES.get(name), normalise_licence(licence)
        if want and got and want != got:
            drift.append(f"  {name}: recorded {want!r}, image says {got!r}")
    if drift:
        print("sandbox licence drift — update SANDBOX_LICENCES:", file=sys.stderr)
        print("\n".join(drift), file=sys.stderr)
        return 1
    print("sandbox licences: match the built image")
    return 0


# ── assembly ────────────────────────────────────────────────────────────────────────

def prop(component: dict, name: str) -> str:
    for entry in component.get("properties") or []:
        if entry["name"] == name:
            return entry["value"]
    return ""


def origin_of(component: dict) -> str:
    return prop(component, "docket:origin") or "unknown"


def licence_of(component: dict) -> str:
    for entry in component.get("licenses") or []:
        licence = entry.get("license") or {}
        return str(licence.get("name") or licence.get("id") or "")
    return ""


def build_document() -> dict:
    components = (python_components() + npm_components()
                  + sandbox_components() + vendored_components())
    apply_licences(components, installed_licences())
    components.sort(key=lambda c: (origin_of(c), str(c["name"]).lower()))
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "bom-ref": "pkg:pypi/docket@0.1.0",
                "name": "docket",
                "version": "0.1.0",
                "licenses": [{"license": {"id": "Apache-2.0"}}],
                "purl": "pkg:pypi/docket@0.1.0",
            },
            "tools": [{"vendor": "docket", "name": "scripts/sbom.py", "version": "2"}],
        },
        "components": components,
    }


ORIGIN_NOTES = {
    "core": "required by docket's four declared runtime dependencies",
    "extra:app": "only installed with `--extra app` (the console)",
    "extra:tokenizer": "only installed with `--extra tokenizer`",
    "console-bundle": "delivered to a browser; build tooling excluded",
    "sandbox-image": "executed inside the scan container",
    "vendored-content": "third-party material under an attribution obligation",
    "unreachable": "resolved but not reachable from any declared dependency",
}


def summarise(document: dict, status: dict, crosscheck: dict) -> str:
    components = document["components"]
    groups: dict[str, list[dict]] = {}
    for component in components:
        groups.setdefault(origin_of(component), []).append(component)
    licences: Counter[str] = Counter()
    unlicensed: list[dict] = []
    for component in components:
        name = licence_of(component)
        licences[name] += 1 if name else 0
        if not name:
            unlicensed.append(component)

    lines = [
        "# Docket — Software Bill of Materials",
        "",
        f"`sbom/docket.cdx.json` · CycloneDX {document['specVersion']} · "
        f"{len(components)} components · generated {status.get('scanned_on', today())}",
        "",
        "Regenerate with `make sbom`. `make sbom-check` fails if the committed copy and a",
        "fresh generation disagree, so this can be checked rather than trusted.",
        "",
        "## Why this is not just a dependency scan",
        "",
        "A scanner reading this repository's lockfiles sees the Python and npm packages",
        "and stops. Three further kinds of component are part of what docket delivers:",
        "",
        "- **What the sandbox ships.** Every scan executes semgrep, nuclei, trivy,",
        "  mitmproxy and Chromium inside the container built by `containers/Dockerfile`.",
        "  Versions are parsed from that file, so they cannot drift from what is built.",
        "- **Third-party content.** 50 agent playbooks are derived from the strix project",
        "  under Apache-2.0 (`NOTICE`). No lockfile records prose.",
        "- **Why each package is here.** Every transitive package below carries the",
        "  shortest path back to a dependency docket declared, from `uv.lock`'s graph.",
        "",
        "## Components by origin",
        "",
        "| Origin | Count | What it is |",
        "|---|---|---|",
    ]
    for origin in sorted(groups, key=lambda o: (-len(groups[o]), o)):
        lines.append(f"| `{origin}` | {len(groups[origin])} | {ORIGIN_NOTES.get(origin, '')} |")

    lines += [
        "",
        "## Licences",
        "",
        f"{len(components) - len(unlicensed)} of {len(components)} components declare one.",
        "",
        "| Licence | Components |",
        "|---|---|",
        *(f"| {name} | {count} |"
          for name, count in licences.most_common() if name),
        "",
        "Identifiers come from each package's own published metadata. Unambiguous",
        "spelling variants normalise to SPDX ids; ambiguous ones are left exactly as",
        "declared — `BSD License` does not say 2-clause or 3-clause, and docket does not",
        "choose on the publisher's behalf.",
        "",
        "### Copyleft, called out",
        "",
        "**semgrep is LGPL-2.1-only** — the one component here under a copyleft licence.",
        "A dependency scan of this repository would not surface it, because it is",
        "installed into the sandbox container and not into `uv.lock`. docket invokes it",
        "as a subprocess inside that container: not linked against, not modified, not",
        "redistributed. That distinction governs the obligation, so it is stated here",
        "rather than left for a reviewer to establish.",
        "",
    ]
    if unlicensed:
        lines += [
            f"### {len(unlicensed)} component(s) with no licence recorded",
            "",
            "Left blank rather than guessed. Usually a platform-specific or optional",
            "package that the lockfile resolves but that is not installed on the machine",
            "generating this, so there was no local metadata to read.",
            "",
            *(f"- `{c['name']} {c.get('version', '')}` ({origin_of(c)})"
              for c in sorted(unlicensed, key=lambda c: str(c["name"]))),
            "",
        ]

    unpinned = [c for c in components
                if prop(c, "docket:pinned").startswith("NO")]
    if unpinned:
        lines += [
            "## Build reproducibility gap",
            "",
            f"{len(unpinned)} component(s) are installed into the sandbox container "
            "WITHOUT a pinned version, so two builds of the same Dockerfile on different "
            "days can ship different code and this inventory cannot state what a given "
            "image actually contains:",
            "",
            *(f"- `{c['name']}` — `containers/Dockerfile` installs it unversioned"
              for c in unpinned),
            "",
            "This is the same condition docket's own `python-baseline:pinned-deps` and",
            "`twelve-factor:II` controls look for in a customer's repository. Recorded",
            "here rather than smoothed over with whatever version happens to be installed",
            "today, because printing a version would imply a guarantee the build does not",
            "make. Fix by pinning them the way nuclei, trivy and semgrep already are.",
            "",
        ]

    lines += ["## Known vulnerabilities", ""]
    if status.get("assessed"):
        total = status.get("total", 0)
        lines.append(
            f"**No known vulnerabilities** were reported against the Python and npm "
            f"components as of {status.get('scanned_on', today())} by "
            f"{status.get('scanner', 'the scanner')}."
            if total == 0 else
            f"**{total} known vulnerabilities** as of "
            f"{status.get('scanned_on', today())}: {status.get('by_severity')}."
        )
        lines += [
            "",
            "A point-in-time statement about what had been published by that date. It is",
            "not a claim that the software is free of defects, it does not stay true, and",
            "it does not cover the sandbox tools above — those are container images and",
            "are scanned separately.",
            "",
        ]
    else:
        lines += [f"Not assessed: {status.get('reason', 'not recorded')}.", ""]

    lines += ["## Independent cross-check", ""]
    if crosscheck.get("ran"):
        missed = crosscheck.get("missed_by_generator") or []
        lines.append(f"trivy, reading the same lockfiles independently, agreed on "
                     f"{crosscheck['agreed']} packages.")
        lines += (["", "**It found packages this generator missed — that is a bug here, "
                       "not in trivy:**", "", *(f"- `{p}`" for p in missed[:20]), ""]
                  if missed else ["", "It found nothing this generator missed.", ""])
    else:
        lines += [f"Not run: {crosscheck.get('reason', 'unavailable')}.", ""]

    lines += [
        "## Declared dependencies",
        "",
        "Everything else in the inventory is transitive or shipped in the container.",
        "",
        "| Package | Version | Origin | Licence |",
        "|---|---|---|---|",
        *(f"| `{c['name']}` | {c.get('version', '')} | {origin_of(c)} | "
          f"{licence_of(c) or '—'} |"
          for c in components if prop(c, "docket:directness") == "direct"),
        "",
        "## Full inventory",
        "",
        "| Component | Version | Origin | Licence | Required by / role |",
        "|---|---|---|---|---|",
        *(f"| `{c['name']}` | {c.get('version', '')} | {origin_of(c)} | "
          f"{licence_of(c) or '—'} | "
          f"{(prop(c, 'docket:required-by') or prop(c, 'docket:role'))[:88]} |"
          for c in components),
        "",
    ]
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate docket's SBOM.")
    parser.add_argument("--check", action="store_true",
                        help="Exit non-zero if the committed SBOM is stale.")
    parser.add_argument("--verify-image", action="store_true",
                        help="Re-read sandbox licences from the built image.")
    args = parser.parse_args()
    if args.verify_image:
        return verify_image()

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    document = build_document()
    body = json.dumps(document, indent=2, sort_keys=True) + "\n"

    if args.check:
        if not CDX.exists() or CDX.read_text() != body:
            print("SBOM is stale — run `make sbom`", file=sys.stderr)
            return 1
        print(f"sbom: up to date ({len(document['components'])} components)")
        return 0

    CDX.write_text(body)
    status = vulnerability_status(CDX)
    status["scanned_on"] = today()
    STATUS.write_text(json.dumps(status, indent=2, sort_keys=True) + "\n")
    crosscheck = trivy_crosscheck(document["components"])
    SUMMARY.write_text(summarise(document, status, crosscheck))

    counts = Counter(origin_of(c) for c in document["components"])
    print(f"wrote {CDX.relative_to(REPO)} ({len(document['components'])} components)")
    for origin, count in sorted(counts.items()):
        print(f"    {origin:18} {count}")
    if crosscheck.get("ran"):
        missed = crosscheck.get("missed_by_generator") or []
        print(f"cross-check: trivy agreed on {crosscheck['agreed']}, "
              f"{len(missed)} missed by this generator")
        for purl in missed[:10]:
            print(f"    MISSED {purl}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
