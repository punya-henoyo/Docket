"""Run preparation: names, directories, target normalisation.

Split out of main.py so the same preparation is shared by the CLI, the interactive
mode, and the TUI, instead of each inventing its own run-name and directory logic.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from docket.core.paths import run_path, runs_root

_SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")


def default_run_name(now: datetime | None = None) -> str:
    stamp = (now or datetime.now(timezone.utc)).strftime("%Y%m%dT%H%M%SZ")
    return f"run-{stamp}"


def sanitize_run_name(name: str) -> str:
    """A run name becomes a directory name, so path separators and spaces in it are a
    traversal/breakage risk rather than a cosmetic issue."""
    cleaned = _SAFE_NAME.sub("-", name.strip()).strip("-._")
    return cleaned or default_run_name()


def normalize_target(target: str) -> str:
    """Accept "localhost:5000" and "example.com/app" the way a human types them."""
    target = target.strip()
    if not target:
        raise ValueError("target must not be empty")
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", target):
        target = "http://" + target
    return target.rstrip("/")


@dataclass(slots=True)
class ScanSetup:
    run_name: str
    target: str
    run_dir: Path
    instruction: str | None = None
    use_sandbox: bool = True


def prepare_scan(
    target: str,
    *,
    run_name: str | None = None,
    instruction: str | None = None,
    out_dir: str | None = None,
    use_sandbox: bool = True,
) -> ScanSetup:
    name = sanitize_run_name(run_name) if run_name else default_run_name()
    base = Path(out_dir) if out_dir else None
    directory = (base / name) if base else run_path(name)
    directory.mkdir(parents=True, exist_ok=True)
    return ScanSetup(
        run_name=name, target=normalize_target(target), run_dir=directory,
        instruction=instruction, use_sandbox=use_sandbox,
    )


def list_runs(base: Path | None = None) -> list[Path]:
    root = base or runs_root()
    if not root.exists():
        return []
    runs = [d for d in root.iterdir() if d.is_dir() and (d / "report.json").exists()]
    return sorted(runs, key=lambda d: (d / "report.json").stat().st_mtime, reverse=True)


def latest_run(base: Path | None = None) -> Path | None:
    runs = list_runs(base)
    return runs[0] if runs else None


def demo() -> None:
    import shutil
    import tempfile

    assert normalize_target("localhost:5000") == "http://localhost:5000"
    assert normalize_target("https://x.test/app/") == "https://x.test/app"
    assert normalize_target(" 127.0.0.1:5000 ") == "http://127.0.0.1:5000"
    try:
        normalize_target("")
        raise AssertionError("empty target must raise")
    except ValueError:
        pass

    # A run name becomes a directory: separators must not survive.
    assert sanitize_run_name("../../etc/passwd") == "etc-passwd"
    assert sanitize_run_name("my scan #1") == "my-scan-1"
    assert sanitize_run_name("   ").startswith("run-")
    assert default_run_name(datetime(2026, 8, 11, 9, 30, tzinfo=timezone.utc)) == "run-20260811T093000Z"

    tmp = Path(tempfile.mkdtemp())
    try:
        setup = prepare_scan("localhost:5000", run_name="demo run", out_dir=str(tmp))
        assert setup.run_name == "demo-run" and setup.run_dir.exists()
        assert setup.target == "http://localhost:5000"
        assert list_runs(tmp) == []            # no report.json yet
        (setup.run_dir / "report.json").write_text("{}")
        assert list_runs(tmp) == [setup.run_dir]
        assert latest_run(tmp) == setup.run_dir
        assert latest_run(tmp / "nope") is None
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print("interface.scan_setup: ok")


if __name__ == "__main__":
    demo()
