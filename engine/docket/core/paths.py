"""Run directory path helpers.

Kept dependency-free on purpose so every other module can import it without pulling
in config, the SDK, or the report layer.
"""
from __future__ import annotations

from pathlib import Path

RUNS_DIR_NAME = "docket_runs"
STATE_DIR_NAME = ".state"
RUN_MANIFEST_FILENAME = "run-manifest.json"
ARTIFACTS_DIR_NAME = "artifacts"
FINDINGS_DIR_NAME = "findings"


def runs_root(*, cwd: Path | None = None) -> Path:
    return (cwd or Path.cwd()) / RUNS_DIR_NAME


def run_path(run_name: str, *, cwd: Path | None = None) -> Path:
    return runs_root(cwd=cwd) / run_name


def state_path(run_dir: Path) -> Path:
    """Where non-report run state lives (session DBs, resume markers)."""
    return run_dir / STATE_DIR_NAME


def manifest_path(run_dir: Path) -> Path:
    return run_dir / RUN_MANIFEST_FILENAME


def artifacts_dir(run_dir: Path) -> Path:
    return run_dir / ARTIFACTS_DIR_NAME


def findings_dir(run_dir: Path) -> Path:
    return run_dir / FINDINGS_DIR_NAME


def demo() -> None:
    base = Path("/tmp/docket-paths-demo")
    run = run_path("abc", cwd=base)
    assert run == base / "docket_runs" / "abc", run
    assert state_path(run).name == ".state"
    assert manifest_path(run).name == "run-manifest.json"
    assert artifacts_dir(run).name == "artifacts"
    assert findings_dir(run).name == "findings"
    assert runs_root(cwd=base) == base / "docket_runs"
    print("core.paths: ok")


if __name__ == "__main__":
    demo()
