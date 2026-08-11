"""Run directory path helpers. Mirrors docket/core/paths.py.

Kept dependency-free on purpose so every other module can import it without pulling
in config, the SDK, or the report layer.
"""
from __future__ import annotations

from pathlib import Path

RUNS_DIR_NAME = "docket_runs"
RUNTIME_STATE_DIR_NAME = ".state"
RUN_RECORD_FILENAME = "run.json"
ARTIFACTS_DIR_NAME = "artifacts"
FINDINGS_DIR_NAME = "findings"


def runs_base_dir(*, cwd: Path | None = None) -> Path:
    return (cwd or Path.cwd()) / RUNS_DIR_NAME


def run_dir_for(run_name: str, *, cwd: Path | None = None) -> Path:
    return runs_base_dir(cwd=cwd) / run_name


def runtime_state_dir(run_dir: Path) -> Path:
    """Where non-report run state lives (session DBs, resume markers)."""
    return run_dir / RUNTIME_STATE_DIR_NAME


def run_record_path(run_dir: Path) -> Path:
    return run_dir / RUN_RECORD_FILENAME


def artifacts_dir(run_dir: Path) -> Path:
    return run_dir / ARTIFACTS_DIR_NAME


def findings_dir(run_dir: Path) -> Path:
    return run_dir / FINDINGS_DIR_NAME


def demo() -> None:
    base = Path("/tmp/docket-paths-demo")
    run = run_dir_for("abc", cwd=base)
    assert run == base / "docket_runs" / "abc", run
    assert runtime_state_dir(run).name == ".state"
    assert run_record_path(run).name == "run.json"
    assert artifacts_dir(run).name == "artifacts"
    assert findings_dir(run).name == "findings"
    assert runs_base_dir(cwd=base) == base / "docket_runs"
    print("core.paths: ok")


if __name__ == "__main__":
    demo()
