"""Bounds tool output so a big response/dump doesn't blow the LLM's context, while
keeping the full text pageable on disk.

Head+tail, not head-only: tools like sqlmap put their actual verdict at the *end* of
noisy output, so pure head-truncation would hide the useful part.
"""
from __future__ import annotations

import uuid
from pathlib import Path

MAX_INLINE_CHARS = 4000
_HEAD = 2000
_TAIL = 2000


def bound(text: str, run_dir: Path) -> dict:
    if len(text) <= MAX_INLINE_CHARS:
        return {"text": text, "truncated": False, "ref": None, "total_chars": len(text)}

    ref = uuid.uuid4().hex
    out_dir = run_dir / "artifacts" / "output"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / f"{ref}.txt").write_text(text)

    omitted = len(text) - _HEAD - _TAIL
    preview = f"{text[:_HEAD]}\n...[{omitted} chars omitted, ref={ref}]...\n{text[-_TAIL:]}"
    return {"text": preview, "truncated": True, "ref": ref, "total_chars": len(text)}


def get(ref: str, run_dir: Path, offset: int = 0, limit: int = MAX_INLINE_CHARS) -> dict:
    path = run_dir / "artifacts" / "output" / f"{ref}.txt"
    full = path.read_text()
    chunk = full[offset : offset + limit]
    return {"text": chunk, "has_more": offset + limit < len(full), "next_offset": offset + limit}


def demo() -> None:
    import shutil
    import tempfile

    tmp = Path(tempfile.mkdtemp())
    try:
        short = bound("hello", tmp)
        assert short == {"text": "hello", "truncated": False, "ref": None, "total_chars": 5}

        long_text = ("A" * 3000) + "MIDDLE_MARKER" + ("Z" * 3000)
        result = bound(long_text, tmp)
        assert result["truncated"] is True
        assert result["text"].startswith("A" * 100)
        assert result["text"].endswith("Z" * 100)
        assert "MIDDLE_MARKER" not in result["text"]  # correctly omitted from the preview

        full = get(result["ref"], tmp, limit=len(long_text))
        assert full["text"] == long_text
        assert full["has_more"] is False

        paged = get(result["ref"], tmp, offset=0, limit=10)
        assert paged["text"] == long_text[:10]
        assert paged["has_more"] is True
    finally:
        shutil.rmtree(tmp)
    print("output_store: ok")


if __name__ == "__main__":
    demo()
