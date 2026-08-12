"""The attack surface: what discovery produces and the agents consume.

A typed artifact rather than prose in a prompt, for four reasons that prose cannot
manage: it is reviewable before you spend a dollar on a scan, diffable between runs so a
new endpoint on the target is visible, testable without a model, and it turns "did we
cover the surface?" into a set comparison.

Plain dataclasses, not pydantic. Everything here is produced by our own parsers from
sources we fetched; the model never writes to it. `report/models.py` is pydantic because
that IS the boundary where model free-text becomes a record — this is not.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path

SURFACE_FILENAME = "surface.json"

# Where a parameter lives. Kept explicit because it decides how a specialist injects:
# a query param goes on the URL, a form field in a urlencoded body, a json field in a
# JSON body. Collapsing them loses the distinction the exploit depends on.
ParamIn = str  # "query" | "form" | "json" | "path" | "header" | "cookie"


@dataclass(frozen=True, slots=True)
class Param:
    name: str
    location: ParamIn = "query"
    required: bool = False
    example: str | None = None

    def __str__(self) -> str:
        return f"{self.name}({self.location})"


@dataclass(frozen=True, slots=True)
class Endpoint:
    method: str
    path: str
    params: tuple[Param, ...] = ()
    content_type: str | None = None
    auth_required: bool | None = None      # None = unknown, never guessed
    source: str = "unknown"                # which rung found it, for auditability
    note: str | None = None

    @property
    def key(self) -> tuple[str, str]:
        """Identity for dedupe. Method plus path — two sources describing the same
        endpoint must collapse, and the richer description should win (see
        AttackSurface.add)."""
        return (self.method.upper(), self.path)

    def describe(self) -> str:
        """One line for the root agent's task. This is what the model actually reads."""
        bits = [f"{self.method.upper()} {self.path}"]
        if self.params:
            bits.append("params: " + ", ".join(str(p) for p in self.params))
        if self.content_type:
            bits.append(self.content_type)
        if self.auth_required:
            bits.append("auth required")
        if self.note:
            bits.append(self.note)
        return " | ".join(bits)


@dataclass(slots=True)
class AttackSurface:
    target: str
    endpoints: list[Endpoint] = field(default_factory=list)
    sources_tried: list[str] = field(default_factory=list)
    requests_made: int = 0
    notes: list[str] = field(default_factory=list)

    def add(self, endpoint: Endpoint) -> bool:
        """Merge on (method, path). Returns True if this changed the surface.

        A later source with MORE parameters replaces an earlier sparse entry — a crawl
        finding "GET /search" should not shadow a spec that documented its `q` param.
        Equal or poorer descriptions are dropped.
        """
        for i, existing in enumerate(self.endpoints):
            if existing.key == endpoint.key:
                if len(endpoint.params) > len(existing.params):
                    self.endpoints[i] = endpoint
                    return True
                return False
        self.endpoints.append(endpoint)
        return True

    def __len__(self) -> int:
        return len(self.endpoints)

    def __bool__(self) -> bool:
        return bool(self.endpoints)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "endpoint_count": len(self.endpoints),
            "sources_tried": self.sources_tried,
            "requests_made": self.requests_made,
            "notes": self.notes,
            "endpoints": [asdict(e) for e in self.endpoints],
        }

    def save(self, run_dir: Path) -> Path:
        path = Path(run_dir) / SURFACE_FILENAME
        path.write_text(json.dumps(self.to_dict(), indent=2))
        return path

    @classmethod
    def load(cls, run_dir: Path) -> "AttackSurface | None":
        path = Path(run_dir) / SURFACE_FILENAME
        if not path.is_file():
            return None
        try:
            raw = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError):
            return None
        surface = cls(target=raw.get("target", ""),
                      sources_tried=raw.get("sources_tried", []),
                      requests_made=raw.get("requests_made", 0),
                      notes=raw.get("notes", []))
        for e in raw.get("endpoints", []):
            surface.endpoints.append(Endpoint(
                method=e["method"], path=e["path"],
                params=tuple(Param(**p) for p in e.get("params", [])),
                content_type=e.get("content_type"), auth_required=e.get("auth_required"),
                source=e.get("source", "unknown"), note=e.get("note"),
            ))
        return surface


def demo() -> None:
    import shutil
    import tempfile

    s = AttackSurface(target="http://x.test")
    assert not s and len(s) == 0

    sparse = Endpoint("GET", "/search", source="crawl")
    rich = Endpoint("GET", "/search", params=(Param("q", "query", True),), source="openapi")
    assert s.add(sparse) is True
    # A richer description of the SAME endpoint replaces the sparse one rather than
    # appending a duplicate — the whole point of merging on (method, path).
    assert s.add(rich) is True and len(s) == 1
    assert s.endpoints[0].source == "openapi"
    # ...and the reverse does not undo it.
    assert s.add(sparse) is False and s.endpoints[0].source == "openapi"

    # Method is part of identity: GET and POST on one path are two endpoints.
    assert s.add(Endpoint("POST", "/search")) is True and len(s) == 2

    line = rich.describe()
    assert "GET /search" in line and "q(query)" in line

    tmp = Path(tempfile.mkdtemp())
    try:
        s.notes.append("crawl capped at 200 requests")
        path = s.save(tmp)
        assert path.name == SURFACE_FILENAME
        back = AttackSurface.load(tmp)
        assert back is not None and len(back) == 2 and back.target == "http://x.test"
        assert back.endpoints[0].params[0].name == "q"
        assert back.notes == ["crawl capped at 200 requests"]
        # A corrupt or absent file degrades to None rather than raising into a scan.
        (tmp / SURFACE_FILENAME).write_text("{not json")
        assert AttackSurface.load(tmp) is None
        assert AttackSurface.load(tmp / "nope") is None
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print("discovery.models: ok")


if __name__ == "__main__":
    demo()
