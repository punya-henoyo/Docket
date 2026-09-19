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
    return "—"


def build(document: dict, status: dict) -> str:
    components = document.get("components") or []
    packages = [c for c in components if c.get("purl")]
    lockfiles = [c for c in components if not c.get("purl")]
    generated = status.get("scanned_on", "unrecorded")

    licences: Counter[str] = Counter()
    unlicensed: list[dict] = []
    ecosystems: Counter[str] = Counter()
    for component in packages:
        ecosystems[ecosystem_of(component)] += 1
        name = licence_of(component)
        if name:
            licences[name] += 1
        else:
            unlicensed.append(component)

    body: list[str] = [
        para("Docket — Software Bill of Materials", "Title"),
        para(f"CycloneDX {document.get('specVersion', '?')} · "
             f"{len(packages)} packages · prepared {generated}", "Small"),
        para(),
        para("Purpose and scope", "Heading1"),
        para(
            "This document lists every third-party software component that Docket is "
            "built from, with its version and licence, and records the result of a "
            "vulnerability scan of that component list. It is generated from the "
            "repository's own lockfiles; it is not a hand-maintained list."
        ),
        para(
            "The machine-readable original is sbom/docket.cdx.json in the Docket "
            "repository, in CycloneDX format. This document is rendered from that file "
            "and contains no information that is not in it. Both regenerate with "
            "'make sbom' and 'make sbom-doc'."
        ),
        para("What is included", "Heading2"),
        para(
            "Everything that ships as part of the product: Python packages resolved by "
            "uv.lock, and the JavaScript packages that are delivered to a browser in the "
            "console bundle."
        ),
        para("What is excluded, and why", "Heading2"),
    ]
    for line in (
        "JavaScript build tooling (vite, typescript and their dependencies). These "
        "produce the console bundle and are not present in it, so they are not "
        "components of the delivered software.",
        "docket_runs/ — Docket's own scan output. It contains copies of source from "
        "repositories Docket has analysed and is not part of the product.",
        ".venv/ — a local installation of the same packages already listed from the "
        "lockfile. Including it would double-count every entry.",
    ):
        body.append(para("•  " + line))

    body += [
        para("Components", "Heading1"),
        table(
            ["Ecosystem", "Packages"],
            [[eco, str(count)] for eco, count in ecosystems.most_common()],
            [3200, 1800],
        ),
    ]
    if lockfiles:
        body.append(para(
            f"The source document additionally contains {len(lockfiles)} entries "
            f"describing the lockfiles that were parsed "
            f"({', '.join(str(c.get('name')) for c in lockfiles)}). These are not "
            f"software components and are excluded from every count in this document.",
            "Small",
        ))

    body += [
        para("Licences", "Heading1"),
        para(f"{len(packages) - len(unlicensed)} of {len(packages)} packages declare a "
             f"licence."),
        table(
            ["Licence", "Packages"],
            [[name, str(count)] for name, count in licences.most_common()],
            [3200, 1800],
        ),
        para(
            "Licence identifiers are read from each package's own published metadata. "
            "Unambiguous spelling variants are normalised to their SPDX identifier — for "
            "example 'MIT License' is recorded as 'MIT'. Ambiguous values are left "
            "exactly as the package declared them: 'BSD License' does not state whether "
            "it is the 2-clause or 3-clause variant, and Docket does not choose one on "
            "the publisher's behalf.",
            "Small",
        ),
    ]

    if unlicensed:
        body += [
            para(f"Packages with no licence recorded ({len(unlicensed)})", "Heading2"),
            para(
                "These packages publish no licence identifier that could be read on the "
                "machine that generated this document, typically because they are "
                "platform-specific or optional and were therefore not installed. They "
                "are left blank rather than assigned a likely licence. Anyone relying on "
                "this document for licence compliance should establish these by hand."
            ),
            table(
                ["Package", "Version", "Ecosystem"],
                [[str(c.get("name")), str(c.get("version", "")), ecosystem_of(c)]
                 for c in sorted(unlicensed, key=lambda c: str(c.get("name")))],
                [3000, 1500, 1500],
                mono_columns={0},
            ),
        ]

    body += [para("Known vulnerabilities", "Heading1")]
    if status.get("assessed"):
        total = status.get("total", 0)
        if total == 0:
            body.append(para(
                f"No known vulnerabilities were reported against the components listed "
                f"in this document, as of {generated}, by "
                f"{status.get('scanner', 'the scanner')}."
            ))
        else:
            by_sev = status.get("by_severity") or {}
            body += [
                para(f"{total} known vulnerabilities were reported as of {generated} by "
                     f"{status.get('scanner', 'the scanner')}."),
                table(["Severity", "Count"],
                      [[k, str(v)] for k, v in sorted(by_sev.items())], [3200, 1800]),
            ]
        body.append(para(
            "This is a statement about what had been published and recorded in the "
            "scanner's vulnerability database on that date. It is not a statement that "
            "the software is free of defects, and it does not remain true over time: a "
            "vulnerability disclosed after that date would not appear. Re-run the scan "
            "to obtain a current result.",
            "Small",
        ))
    else:
        body.append(para(
            "Not assessed when this document was generated. "
            f"Reason: {status.get('reason', 'not recorded')}."
        ))

    body += [
        para("Licence of Docket itself", "Heading1"),
        para(
            "Docket is distributed under the Apache License 2.0. The full text is in "
            "LICENSE at the root of the repository, and attribution for third-party "
            "material incorporated into it is in NOTICE."
        ),
        para("How this document was produced", "Heading1"),
        para(
            "The component list is produced by Trivy reading the repository's lockfiles, "
            "and is emitted as CycloneDX. Licence identifiers are then read from the "
            "installed Python distributions, because a lockfile records versions but not "
            "licences. The vulnerability result is produced by scanning the resulting "
            "CycloneDX document."
        ),
        para(
            "The output is byte-reproducible: regenerating it on an unchanged repository "
            "produces an identical file, and 'make sbom-check' fails if the committed "
            "copy does not match a fresh generation. This is what allows the document to "
            "be checked rather than trusted.",
            "Small",
        ),
        para("Full inventory", "Heading1"),
        para(f"All {len(packages)} packages, alphabetically."),
        table(
            ["Package", "Version", "Ecosystem", "Licence"],
            [[str(c.get("name")), str(c.get("version", "")), ecosystem_of(c),
              licence_of(c) or "not recorded"]
             for c in sorted(packages, key=lambda c: str(c.get("name")).lower())],
            [2900, 1300, 1200, 2600],
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
          f"({len([c for c in document.get('components') or [] if c.get('purl')])} packages)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
