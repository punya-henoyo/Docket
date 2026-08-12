"""Locating packaged resources.

Paths are resolved relative to the package rather than the working directory, so they
keep working when docket is installed as a wheel and run from anywhere.
"""
from __future__ import annotations

from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parents[1]

# Repo root is derived HERE and nowhere else. It used to be counted independently in
# runtime/sandbox.py too, and moving the package under engine/ silently broke both
# counters at once — one depth constant is the whole point of this module.
REPO_ROOT = PACKAGE_ROOT.parents[1]


def package_path(*parts: str) -> Path:
    return PACKAGE_ROOT.joinpath(*parts)


def skills_dir() -> Path:
    return package_path("skills")


def dashboard_html() -> Path:
    return package_path("interface", "viewer", "dashboard.html")


def frontend_dir() -> Path:
    """The console's React source (interface/connect.py serves its build output from
    frontend/dist). Lives at the repo root rather than inside the package: it is the
    product surface for a hosted deployment and build input, not a runtime resource
    the CLI needs, so it is absent from an installed wheel."""
    return REPO_ROOT / "frontend"


def containers_dir() -> Path:
    """The Dockerfile lives at the repo root, not inside the package — it is build
    input, not a runtime resource, so it is absent from an installed wheel."""
    return REPO_ROOT / "containers"


def demo() -> None:
    assert PACKAGE_ROOT.name == "docket"
    assert skills_dir().is_dir(), skills_dir()
    assert (skills_dir() / "coordination" / "root_agent.md").exists()
    assert dashboard_html().is_file(), dashboard_html()
    assert package_path("core", "runner.py").exists()
    # is_dir(), not just .name — a wrong depth still yields a path ending in
    # "containers", so only existence actually catches a moved package.
    assert containers_dir().is_dir(), containers_dir()
    assert (containers_dir() / "Dockerfile").is_file()
    assert (frontend_dir() / 'package.json').is_file(), frontend_dir()
    print("utils.resource_paths: ok")


if __name__ == "__main__":
    demo()
