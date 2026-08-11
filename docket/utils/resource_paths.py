"""Locating packaged resources. Mirrors docket/utils/resource_paths.py.

Paths are resolved relative to the package rather than the working directory, so they
keep working when docket is installed as a wheel and run from anywhere.
"""
from __future__ import annotations

from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parents[1]


def package_path(*parts: str) -> Path:
    return PACKAGE_ROOT.joinpath(*parts)


def skills_dir() -> Path:
    return package_path("skills")


def dashboard_html() -> Path:
    return package_path("interface", "viewer", "dashboard.html")


def containers_dir() -> Path:
    """The Dockerfile lives beside the package, not inside it — it is build input,
    not a runtime resource."""
    return PACKAGE_ROOT.parent / "containers"


def demo() -> None:
    assert PACKAGE_ROOT.name == "docket"
    assert skills_dir().is_dir(), skills_dir()
    assert (skills_dir() / "coordination" / "root_agent.md").exists()
    assert dashboard_html().is_file(), dashboard_html()
    assert package_path("core", "runner.py").exists()
    assert containers_dir().name == "containers"
    print("utils.resource_paths: ok")


if __name__ == "__main__":
    demo()
