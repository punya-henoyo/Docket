"""Turn an uploaded policy document into plain text a compile agent can read.

Four formats, and the dependency budget is the interesting part. CONTRIBUTING.md's rule
is that every dependency earns its place, and docket ships four runtime packages total.
So:

  .txt/.md   bytes.decode. Stdlib.
  .docx      a .docx IS a zip holding word/document.xml. `zipfile` + `ElementTree`, both
             stdlib, read it in about fifteen lines. `python-docx` would be a dependency
             to avoid writing those fifteen lines.
  .pdf       `pypdf` — pure Python, no compiled extensions, in the OPTIONAL `app` extra.
             This is the one new package in the whole compliance feature. There is no
             stdlib PDF parser and writing one is not a fifteen-line job.

A format we cannot read returns an explicit error naming the fix. It never returns empty
text: "don't silently degrade" (CONTRIBUTING.md), and an empty policy compiles to an
empty pack, which would tell a customer their document contained no controls.

Upload transport is deliberately NOT multipart. The browser sends the file bytes as the
raw request body with `?filename=`, so the identical handler works on the FastAPI server
and on connect.py's stdlib one, and `python-multipart` is not needed either.
"""
from __future__ import annotations

import io
import re
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

# Beyond this the compile agent is being handed more than it can read in one context, and
# the tail would be silently ignored. Truncate and SAY SO, so a 400-page framework does
# not quietly become its first 60 pages.
MAX_CHARS = 200_000
# A policy document is text. Anything larger than this is not one, and reading it into
# memory to find that out is the attack.
MAX_BYTES = 10 * 1024 * 1024

SUPPORTED = (".md", ".markdown", ".txt", ".text", ".docx", ".pdf")
# WordprocessingML. `w:t` holds the text runs; `w:p` is a paragraph boundary.
_W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"


class IngestError(Exception):
    """The document could not be read. The message names what to do about it."""


def extract_text(data: bytes, filename: str) -> tuple[str, bool]:
    """(text, truncated). Raises IngestError with an actionable message."""
    if not data:
        raise IngestError("the uploaded file is empty")
    if len(data) > MAX_BYTES:
        raise IngestError(
            f"the file is {len(data) // 1024 // 1024} MB; the limit is "
            f"{MAX_BYTES // 1024 // 1024} MB. A policy document should be well under it."
        )
    suffix = Path(filename or "").suffix.lower()
    if suffix in (".md", ".markdown", ".txt", ".text"):
        text = data.decode("utf-8", errors="replace")
    elif suffix == ".docx":
        text = _from_docx(data)
    elif suffix == ".pdf":
        text = _from_pdf(data)
    else:
        raise IngestError(
            f"cannot read {suffix or 'a file with no extension'}. Supported: "
            f"{', '.join(SUPPORTED)}. For anything else, export or paste it as text."
        )

    text = _tidy(text)
    if not text.strip():
        # A PDF of scanned pages is the common case here, and it is the one where a
        # cheerful empty result would be worst: an empty pack reads as "your policy has
        # no controls", which is a statement about their document rather than about ours.
        raise IngestError(
            "no text could be extracted. If this is a scanned or image-only document, it "
            "needs OCR first — docket will not guess at controls it cannot read."
        )
    if len(text) > MAX_CHARS:
        return text[:MAX_CHARS], True
    return text, False


def _from_docx(data: bytes) -> str:
    """A .docx is a zip of XML. Stdlib reads it; python-docx is not worth a dependency."""
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            document = archive.read("word/document.xml")
    except KeyError as exc:
        raise IngestError(
            "this .docx has no word/document.xml — it may be a .doc renamed, or corrupt"
        ) from exc
    except (zipfile.BadZipFile, OSError) as exc:
        raise IngestError(f"this .docx could not be opened ({exc})") from exc
    try:
        root = ET.fromstring(document)
    except ET.ParseError as exc:
        raise IngestError(f"this .docx has unreadable XML ({exc})") from exc

    lines: list[str] = []
    for paragraph in root.iter(f"{_W}p"):
        # Join the runs, THEN append. Word splits a sentence across runs at every
        # formatting change, so joining per-run with newlines shreds it into fragments and
        # the compile agent loses the clause boundaries it needs.
        parts = [node.text or "" for node in paragraph.iter(f"{_W}t")]
        lines.append("".join(parts))
    return "\n".join(lines)


def _from_pdf(data: bytes) -> str:
    try:
        from pypdf import PdfReader
    except ImportError as exc:
        raise IngestError(
            "PDF support needs pypdf, which is in the optional `app` extra. Install it "
            "with `uv sync --extra app`, or export the policy as .docx, .md or .txt."
        ) from exc
    try:
        reader = PdfReader(io.BytesIO(data))
        if reader.is_encrypted:
            # decrypt("") succeeds on the common "owner password only" case.
            try:
                reader.decrypt("")
            except Exception as exc:  # noqa: BLE001 — pypdf raises several types here
                raise IngestError("this PDF is password protected") from exc
        pages = [page.extract_text() or "" for page in reader.pages]
    except IngestError:
        raise
    except Exception as exc:  # noqa: BLE001 — pypdf raises broadly on malformed files
        raise IngestError(f"this PDF could not be read ({type(exc).__name__}: {exc})") from exc
    # Page markers survive into the compile prompt on purpose: they are what makes a
    # control's `citation` ("uploaded:policy.pdf p12") point at something a human can open.
    return "\n".join(f"\n[page {n}]\n{text}" for n, text in enumerate(pages, 1) if text.strip())


def _tidy(text: str) -> str:
    """Collapse the whitespace damage every extractor does, without losing structure."""
    text = text.replace("\r\n", "\n").replace("\r", "\n").replace("\x00", "")
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return "\n".join(line.rstrip() for line in text.split("\n")).strip()


def demo() -> None:
    # --- markdown and text: the path with no dependency at all ------------------------
    text, truncated = extract_text(b"# Policy\n\n3.2.1 Passwords shall be hashed.\n", "p.md")
    assert "3.2.1 Passwords shall be hashed." in text, text
    assert truncated is False

    long_text, truncated = extract_text(b"x" * (MAX_CHARS + 500), "p.txt")
    # Truncation is REPORTED, never silent: a 400-page framework must not quietly become
    # its first 60 pages while the report says the whole thing was compiled.
    assert truncated is True and len(long_text) == MAX_CHARS

    # --- .docx via stdlib zipfile + ElementTree ---------------------------------------
    def docx(paragraphs: list[list[str]]) -> bytes:
        body = "".join(
            "<w:p>" + "".join(f"<w:r><w:t>{run}</w:t></w:r>" for run in runs) + "</w:p>"
            for runs in paragraphs
        )
        xml = (f'<?xml version="1.0"?><w:document xmlns:w="{_W[1:-1]}">'
               f"<w:body>{body}</w:body></w:document>")
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("word/document.xml", xml)
        return buffer.getvalue()

    # Word splits a sentence at every formatting change. Runs must be joined WITHIN a
    # paragraph, or the clause the compile agent needs arrives as three fragments.
    got, _ = extract_text(docx([["Clause 3.2: passwords ", "shall", " be hashed."],
                                ["Clause 3.3: logs shall be retained."]]), "policy.docx")
    assert "Clause 3.2: passwords shall be hashed." in got, got
    assert "Clause 3.3: logs shall be retained." in got, got

    try:
        extract_text(b"not a zip", "policy.docx")
        raise AssertionError("accepted a .docx that is not a zip")
    except IngestError as exc:
        assert "could not be opened" in str(exc), exc

    # A zip with no document.xml is a .doc renamed, which is a real user mistake.
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("other.xml", "<a/>")
    try:
        extract_text(buffer.getvalue(), "policy.docx")
        raise AssertionError("accepted a zip with no document.xml")
    except IngestError as exc:
        assert "word/document.xml" in str(exc), exc

    # --- refusals, each naming the fix ------------------------------------------------
    for data, name, needle in (
        (b"", "p.md", "empty"),
        (b"x" * (MAX_BYTES + 1), "p.md", "MB"),
        (b"data", "policy.rtf", "Supported"),
        (b"data", "policy", "no extension"),
        # An image-only PDF extracts nothing. An empty pack would say "your policy has no
        # controls", which is a claim about THEIR document, not about our reader.
        (b"   \n  \n ", "p.txt", "no text could be extracted"),
    ):
        try:
            extract_text(data, name)
            raise AssertionError(f"accepted {name} / {needle}")
        except IngestError as exc:
            assert needle in str(exc), (name, exc)

    # --- PDF: the one optional dependency, and it must fail LOUDLY when absent --------
    try:
        import pypdf  # noqa: F401
        has_pypdf = True
    except ImportError:
        has_pypdf = False
    if not has_pypdf:
        try:
            extract_text(b"%PDF-1.4\n", "p.pdf")
            raise AssertionError("a missing pypdf must not silently produce nothing")
        except IngestError as exc:
            assert "uv sync --extra app" in str(exc), exc
    else:
        try:
            extract_text(b"%PDF-1.4\nnot really a pdf\n", "p.pdf")
        except IngestError:
            pass  # a malformed PDF is refused, which is the point

    assert _tidy("a  \t b\n\n\n\nc  \n") == "a b\n\nc"
    print("compliance.ingest: ok")


if __name__ == "__main__":
    demo()
