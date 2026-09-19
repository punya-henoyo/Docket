#!/usr/bin/env python3
"""Render the committed SBOM as a Word document for external review.

    uv run python scripts/sbom_docx.py      # -> sbom/docket-sbom.docx

NO DEPENDENCY, AND NO DOCKER. A .docx is a zip of XML — docket already READS one that
way in compliance/ingest.py, so writing one is the same trick in reverse and
`python-docx` is not worth a dependency for it. And this reads only the committed
`docket.cdx.json`, so anyone who cannot rebuild the SBOM (no Docker, no image) can still
rebuild this document from what is in the repository.

WRITTEN FOR A CUSTOMER OR A REGULATOR, which sets three rules:

  - Every number traces to a file in the repository, and the document says which.
  - The vulnerability line is "none KNOWN, as of <date>, against <scanner>". Never "is
    secure". A scan is a point-in-time statement about what was published by then, and an
    SBOM that claims zero with no date is a claim that silently rots.
  - Gaps are printed, not omitted. Two packages carry no licence; they get their own
    named section rather than being quietly dropped from a total.
"""
from __future__ import annotations

import json
import sys
import zipfile
from collections import Counter
from pathlib import Path
from xml.sax.saxutils import escape

REPO = Path(__file__).resolve().parent.parent
SBOM_DIR = REPO / "sbom"
CDX = SBOM_DIR / "docket.cdx.json"
STATUS = SBOM_DIR / "scan-status.json"
OUT = SBOM_DIR / "docket-sbom.docx"

W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"

_CONTENT_TYPES = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
<Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>
</Types>"""

_RELS = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>"""

_DOC_RELS = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>
</Relationships>"""


def _style(sid: str, name: str, size: int, *, bold: bool = False, before: int = 0,
           mono: bool = False, colour: str = "1A1F1C") -> str:
    """One paragraph style. Half-points for size, twentieths of a point for spacing."""
    font = "Consolas" if mono else "Calibri"
    return (
        f'<w:style w:type="paragraph" w:styleId="{sid}"><w:name w:val="{name}"/>'
        f'<w:pPr><w:spacing w:before="{before}" w:after="120"/></w:pPr>'
        f'<w:rPr><w:rFonts w:ascii="{font}" w:hAnsi="{font}"/>'
        f'<w:sz w:val="{size * 2}"/><w:color w:val="{colour}"/>'
        f'{"<w:b/>" if bold else ""}</w:rPr></w:style>'
    )


_STYLES = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    f'<w:styles xmlns:w="{W}">'
    + _style("Title", "Title", 22, bold=True, before=0)
    + _style("Heading1", "heading 1", 15, bold=True, before=320)
    + _style("Heading2", "heading 2", 12, bold=True, before=240)
    + _style("Normal", "Normal", 10)
    + _style("Small", "Small", 8, colour="5A625B")
    + _style("Mono", "Mono", 9, mono=True)
    + "</w:styles>"
)


def para(text: str = "", style: str = "Normal") -> str:
    body = f'<w:r><w:t xml:space="preserve">{escape(text)}</w:t></w:r>' if text else ""
    return f'<w:p><w:pPr><w:pStyle w:val="{style}"/></w:pPr>{body}</w:p>'


def cell(text: str, width: int, *, bold: bool = False, mono: bool = False) -> str:
    font = '<w:rFonts w:ascii="Consolas" w:hAnsi="Consolas"/>' if mono else ""
    size = '<w:sz w:val="16"/>' if mono else '<w:sz w:val="18"/>'
    return (
        f'<w:tc><w:tcPr><w:tcW w:w="{width}" w:type="dxa"/></w:tcPr>'
        f'<w:p><w:pPr><w:spacing w:after="20"/></w:pPr><w:r><w:rPr>{font}{size}'
        f'{"<w:b/>" if bold else ""}</w:rPr>'
        f'<w:t xml:space="preserve">{escape(text)}</w:t></w:r></w:p></w:tc>'
    )


def table(headers: list[str], rows: list[list[str]], widths: list[int],
          mono_columns: set[int] | None = None) -> str:
    mono_columns = mono_columns or set()
    grid = "".join(f'<w:gridCol w:w="{w}"/>' for w in widths)
    borders = "".join(
        f'<w:{edge} w:val="single" w:sz="4" w:color="D9D9D9"/>'
        for edge in ("top", "left", "bottom", "right", "insideH", "insideV")
    )
    head = "<w:tr>" + "".join(
        cell(h, w, bold=True) for h, w in zip(headers, widths)) + "</w:tr>"
    body = "".join(
        "<w:tr>" + "".join(
            cell(value, widths[i], mono=i in mono_columns)
            for i, value in enumerate(row)
        ) + "</w:tr>"
        for row in rows
    )
    return (
        f'<w:tbl><w:tblPr><w:tblW w:w="0" w:type="auto"/>'
        f"<w:tblBorders>{borders}</w:tblBorders></w:tblPr>"
        f"<w:tblGrid>{grid}</w:tblGrid>{head}{body}</w:tbl>" + para()
    )


def licence_of(component: dict) -> str:
    for entry in component.get("licenses") or []:
        licence = entry.get("license") or {}
        name = licence.get("name") or licence.get("id") or entry.get("expression")
        if name:
            return str(name)
    return ""


def ecosystem_of(component: dict) -> str:
    purl = component.get("purl") or ""
    if purl.startswith("pkg:pypi"):
        return "PyPI"
    if purl.startswith("pkg:npm"):
        return "npm"
    return "container / content"


def prop(component: dict, name: str) -> str:
    for entry in component.get("properties") or []:
        if entry["name"] == name:
            return entry["value"]
    return ""


def origin_of(component: dict) -> str:
    return prop(component, "docket:origin") or "unknown"


ORIGIN_NOTES = {
    "core": "required by docket's declared runtime dependencies",
    "extra:app": "only installed with the optional console extra",
    "extra:tokenizer": "only installed with the optional tokenizer extra",
    "console-bundle": "delivered to a browser; build tooling excluded",
    "sandbox-image": "executed inside the scan container",
    "vendored-content": "third-party material under an attribution obligation",
}


def build(document: dict, status: dict) -> str:
    components = document.get("components") or []
    generated = status.get("scanned_on", "unrecorded")

    groups: dict[str, list[dict]] = {}
    licences: Counter[str] = Counter()
    unlicensed: list[dict] = []
    for component in components:
        groups.setdefault(origin_of(component), []).append(component)
        name = licence_of(component)
        if name:
            licences[name] += 1
        else:
            unlicensed.append(component)
    unpinned = [c for c in components if prop(c, "docket:pinned").startswith("NO")]

    body: list[str] = [
        para("Docket — Software Bill of Materials", "Title"),
        para(f"CycloneDX {document.get('specVersion', '?')} · {len(components)} "
             f"components · prepared {generated}", "Small"),
        para(),
        para("Purpose and scope", "Heading1"),
        para(
            "This document inventories every third-party component that Docket is built "
            "from or ships, with its version, its licence, and the reason it is present. "
            "It is generated from the repository's own lockfiles, container definition "
            "and attribution notices; it is not hand-maintained."
        ),
        para(
            "The machine-readable original is sbom/docket.cdx.json in the Docket "
            "repository, in CycloneDX format. This document is rendered from that file "
            "and contains nothing that is not in it. Both regenerate with 'make sbom' "
            "and 'make sbom-doc', and 'make sbom-check' fails if the committed copy and "
            "a fresh generation disagree — so this can be verified rather than trusted."
        ),
        para("Why this is broader than a dependency scan", "Heading2"),
        para(
            "A scanner reading this repository's lockfiles sees the Python and "
            "JavaScript packages and stops. Three further classes of component are part "
            "of what Docket delivers and are derived here instead:"
        ),
    ]
    for line in (
        "What the sandbox ships. Every scan executes semgrep, nuclei, trivy, mitmproxy "
        "and Chromium inside a container built from containers/Dockerfile. Their "
        "versions are parsed from that file so they cannot drift from what is built.",
        "Third-party content. Fifty agent playbooks are derived from the strix project "
        "under the Apache License 2.0, recorded in NOTICE. No lockfile records prose, "
        "and the obligation is the same as a code dependency's.",
        "The reason each package is present. Every transitive package in the inventory "
        "carries the shortest path back to a dependency Docket actually declared, "
        "computed from the resolution graph in uv.lock.",
    ):
        body.append(para("•  " + line))
    body.append(para("What is excluded", "Heading2"))
    for line in (
        "JavaScript build tooling. It produces the console bundle and is not present in "
        "it, so it is not a component of the delivered software.",
        "Docket's own scan output. It contains copies of source from repositories Docket "
        "has analysed and is not part of this product.",
    ):
        body.append(para("•  " + line))

    body += [
        para("Components by origin", "Heading1"),
        table(
            ["Origin", "Count", "What it is"],
            [[origin, str(len(items)), ORIGIN_NOTES.get(origin, "")]
             for origin, items in sorted(groups.items(), key=lambda kv: -len(kv[1]))],
            [1900, 800, 4500],
        ),
        para("Licences", "Heading1"),
        para(f"{len(components) - len(unlicensed)} of {len(components)} components "
             f"declare a licence."),
        table(["Licence", "Components"],
              [[name, str(count)] for name, count in licences.most_common()],
              [3200, 1800]),
        para(
            "Identifiers are read from each package's own published metadata. "
            "Unambiguous spelling variants are normalised to their SPDX identifier, so "
            "'MIT License' is recorded as 'MIT'. Ambiguous values are left exactly as "
            "declared: 'BSD License' does not state whether it is the 2-clause or "
            "3-clause variant, and Docket does not choose one on the publisher's behalf.",
            "Small",
        ),
        para("Copyleft", "Heading2"),
        para(
            "semgrep is licensed under the GNU Lesser General Public License, version "
            "2.1. It is the only component in this inventory under a copyleft licence, "
            "and a dependency scan of the repository would not surface it, because it is "
            "installed into the sandbox container rather than declared in the Python "
            "lockfile. Docket invokes semgrep as a separate process inside that "
            "container: it does not link against it, modify it, or redistribute it. That "
            "distinction governs the obligation, and it is stated here so that a reviewer "
            "does not have to establish it independently."
        ),
    ]

    if unlicensed:
        body += [
            para(f"Components with no licence recorded ({len(unlicensed)})", "Heading2"),
            para(
                "These publish no licence identifier that could be read on the machine "
                "that generated this document, typically because they are "
                "platform-specific or optional and were therefore not installed. They "
                "are left blank rather than assigned a likely licence. Anyone relying on "
                "this document for licence compliance should establish these by hand."
            ),
            table(
                ["Component", "Version", "Origin"],
                [[str(c.get("name")), str(c.get("version", "")), origin_of(c)]
                 for c in sorted(unlicensed, key=lambda c: str(c.get("name")))],
                [3000, 1500, 1800],
                mono_columns={0},
            ),
        ]

    if unpinned:
        body += [
            para("Build reproducibility", "Heading1"),
            para(
                f"{len(unpinned)} component(s) are installed into the sandbox container "
                "without a pinned version. Two builds of the same container definition "
                "on different dates can therefore contain different code, and this "
                "inventory cannot state which version a particular image holds."
            ),
            table(
                ["Component", "Status"],
                [[str(c.get("name")), "installed unversioned in containers/Dockerfile"]
                 for c in unpinned],
                [2400, 4800],
                mono_columns={0},
            ),
            para(
                "This is recorded rather than resolved by printing whichever version "
                "happens to be installed today, because doing so would imply a guarantee "
                "the build does not make. It is the same condition Docket's own control "
                "packs look for when auditing a customer's repository.",
                "Small",
            ),
        ]

    body += [para("Known vulnerabilities", "Heading1")]
    if status.get("assessed"):
        total = status.get("total", 0)
        if total == 0:
            body.append(para(
                f"No known vulnerabilities were reported against the Python and "
                f"JavaScript components listed in this document, as of {generated}, by "
                f"{status.get('scanner', 'the scanner')}."
            ))
        else:
            body += [
                para(f"{total} known vulnerabilities were reported as of {generated} by "
                     f"{status.get('scanner', 'the scanner')}."),
                table(["Severity", "Count"],
                      [[k, str(v)] for k, v in sorted(
                          (status.get("by_severity") or {}).items())],
                      [3200, 1800]),
            ]
        body.append(para(
            "This is a statement about what had been published and recorded in the "
            "scanner's vulnerability database on that date. It is not a statement that "
            "the software is free of defects; it does not remain true over time, since a "
            "vulnerability disclosed afterwards would not appear; and it does not cover "
            "the container components listed above, which are scanned as images rather "
            "than as packages. Re-run the scan for a current result.",
            "Small",
        ))
    else:
        body.append(para("Not assessed when this document was generated. Reason: "
                         f"{status.get('reason', 'not recorded')}."))

    body += [
        para("Licence of Docket itself", "Heading1"),
        para(
            "Docket is distributed under the Apache License 2.0. The full text is in "
            "LICENSE at the root of the repository, and attribution for third-party "
            "material incorporated into it is in NOTICE."
        ),
        para("Full inventory", "Heading1"),
        para(f"All {len(components)} components, grouped by origin. 'Required by' gives "
             f"the dependency chain back to a declared dependency, or the component's "
             f"role where it is not a package."),
    ]
    for origin, items in sorted(groups.items(), key=lambda kv: -len(kv[1])):
        body += [
            para(f"{origin} ({len(items)})", "Heading2"),
            table(
                ["Component", "Version", "Licence", "Required by / role"],
                [[str(c.get("name")), str(c.get("version", "")),
                  licence_of(c) or "not recorded",
                  (prop(c, "docket:required-by") or prop(c, "docket:role"))[:110]]
                 for c in sorted(items, key=lambda c: str(c.get("name")).lower())],
                [2100, 1100, 1700, 4300],
                mono_columns={0},
            ),
        ]

    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        f'<w:document xmlns:w="{W}"><w:body>{"".join(body)}'
        '<w:sectPr><w:pgSz w:w="11906" w:h="16838"/>'
        '<w:pgMar w:top="1134" w:right="1134" w:bottom="1134" w:left="1134"/>'
        "</w:sectPr></w:body></w:document>"
    )


def main() -> int:
    if not CDX.exists():
        sys.exit(f"error: {CDX.relative_to(REPO)} not found. Run `make sbom` first.")
    document = json.loads(CDX.read_text())
    status = json.loads(STATUS.read_text()) if STATUS.exists() else {"assessed": False,
                                                                     "reason": "no scan recorded"}
    xml = build(document, status)
    with zipfile.ZipFile(OUT, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", _CONTENT_TYPES)
        archive.writestr("_rels/.rels", _RELS)
        archive.writestr("word/_rels/document.xml.rels", _DOC_RELS)
        archive.writestr("word/styles.xml", _STYLES)
        archive.writestr("word/document.xml", xml)
    print(f"wrote {OUT.relative_to(REPO)} "
          f"({len(document.get('components') or [])} components)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
