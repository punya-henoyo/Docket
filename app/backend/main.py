"""FastAPI backend for the docket demo app.

Thin on purpose. docket already writes everything a UI needs to the run directory,
and `docket.interface.viewer.transcript.build_payload` already assembles it into JSON
that renders both a live run (events only) and a finished one (validated report). This
server adds the three things the built-in viewer cannot do: start a scan, stream it,
and switch between runs.

Binds to loopback. Nothing here is hardened for exposure — it can launch a process
that fires exploit payloads, so it must never be reachable from anything but this
machine.
"""
from __future__ import annotations

import asyncio
import json
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from docket.core.paths import runs_root
from docket.interface.environment import check_environment
from docket.interface.scan_setup import sanitize_run_name
from docket.interface.tui.backend.protocol import read_events
from docket.interface.viewer.transcript import build_payload

from app.backend.scans import ALLOW_ANY_TARGET, ScanManager, TargetRefused

POLL_SECONDS = 0.5
FRONTEND_DIST = Path(__file__).resolve().parent.parent / "frontend" / "dist"

manager = ScanManager()


@asynccontextmanager
async def lifespan(_: FastAPI):
    yield
    # A scan outliving the server would keep a container up and keep writing to a run
    # directory nothing is watching.
    manager.stop_all()


api = FastAPI(title="docket demo", lifespan=lifespan)


# --- helpers ------------------------------------------------------------------------

def run_dir_for(run_name: str) -> Path:
    """Resolve a run name to its directory, refusing anything that escapes runs_root.

    The name arrives from an HTTP client, and it is used to build a filesystem path.
    sanitize_run_name strips separators; the containment check is the belt to that
    braces, and uses parent traversal rather than string prefixes so a sibling
    directory sharing a name prefix cannot be reached.
    """
    root = runs_root().resolve()
    candidate = (root / sanitize_run_name(run_name)).resolve()
    if candidate != root and root not in candidate.parents:
        raise HTTPException(400, "invalid run name")
    if not candidate.is_dir():
        raise HTTPException(404, f"no run named {run_name!r}")
    return candidate


def list_all_runs() -> list[dict]:
    """Every run directory, including ones still in progress.

    interface.scan_setup.list_runs only returns runs that already have a report.json,
    which is exactly the set a live demo needs to NOT filter out.
    """
    root = runs_root()
    if not root.exists():
        return []
    rows = []
    for directory in root.iterdir():
        if not directory.is_dir():
            continue
        report = directory / "report.json"
        events = directory / "events.jsonl"
        log = directory / "scan.log"
        # scan.log counts: a scan that died before writing its first event (no API key,
        # Docker down) has only a log, and dropping it from the list makes a failed
        # start look like nothing happened at all.
        if not any(p.exists() for p in (report, events, log)):
            continue
        newest = max((p.stat().st_mtime for p in (report, events, log) if p.exists()), default=0.0)
        summary = {}
        if report.exists():
            try:
                data = json.loads(report.read_text())
                summary = {
                    "target": data.get("target"),
                    "finding_count": data.get("finding_count"),
                    "severity_counts": data.get("severity_counts", {}),
                    "cost_usd": data.get("cost_usd"),
                }
            except (OSError, json.JSONDecodeError):
                pass
        scan = manager.active.get(directory.name)
        rows.append({
            "run_name": directory.name,
            "modified": newest,
            "finished": report.exists(),
            "running": bool(scan and scan.running),
            "failed": bool(scan and not scan.running and scan.exit_code not in (0, 2, None)),
            **summary,
        })
    return sorted(rows, key=lambda r: r["modified"], reverse=True)


# --- models -------------------------------------------------------------------------

class ScanRequest(BaseModel):
    target: str
    run_name: str | None = None
    instruction: str | None = None
    max_steps: int = Field(default=20, ge=1, le=200)
    use_sandbox: bool = True


# --- routes -------------------------------------------------------------------------

@api.get("/api/health")
def health() -> dict:
    report = check_environment(require_sandbox=False)
    scan = manager.current()
    return {
        "ok": report.ok,
        "llm": report.llm_model,
        "docker": report.docker_available,
        "docker_error": report.docker_error,
        "search": report.search_provider,
        "warnings": list(report.warnings),
        "loopback_only": not ALLOW_ANY_TARGET,
        "active_scan": scan.run_name if scan else None,
    }


@api.get("/api/runs")
def get_runs() -> dict:
    return {"runs": list_all_runs()}


@api.get("/api/runs/{run_name}")
def get_run(run_name: str) -> dict:
    payload = build_payload(run_dir_for(run_name))
    scan = manager.active.get(run_name)
    payload["running"] = bool(scan and scan.running)
    payload["exit_code"] = scan.exit_code if scan else None
    return payload


@api.get("/api/runs/{run_name}/sarif")
def get_sarif(run_name: str) -> FileResponse:
    path = run_dir_for(run_name) / "report.sarif"
    if not path.is_file():
        raise HTTPException(404, "no report.sarif for this run")
    return FileResponse(path, media_type="application/json", filename=f"{run_name}.sarif")


@api.get("/api/runs/{run_name}/log")
def get_log(run_name: str) -> PlainTextResponse:
    path = run_dir_for(run_name) / "scan.log"
    return PlainTextResponse(path.read_text() if path.is_file() else "")


@api.get("/api/runs/{run_name}/artifacts/{path:path}")
def get_artifact(run_name: str, path: str) -> FileResponse:
    directory = run_dir_for(run_name)
    target = (directory / "artifacts" / path).resolve()
    # Containment via parent traversal, not a string prefix: "<run>-other/x" shares a
    # prefix with "<run>" but is a different directory.
    if directory.resolve() not in target.parents or not target.is_file():
        raise HTTPException(404, "not found")
    kind = "image/png" if target.suffix == ".png" else "text/plain; charset=utf-8"
    return FileResponse(target, media_type=kind)


@api.post("/api/scans", status_code=201)
def start_scan(request: ScanRequest) -> dict:
    try:
        scan = manager.start(
            request.target, run_name=request.run_name, instruction=request.instruction,
            max_steps=request.max_steps, use_sandbox=request.use_sandbox,
        )
    except TargetRefused as exc:
        raise HTTPException(403, str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(409, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return scan.to_dict()


@api.delete("/api/scans/{run_name}")
def stop_scan(run_name: str) -> JSONResponse:
    stopped = manager.stop(run_name)
    return JSONResponse({"stopped": stopped}, status_code=200 if stopped else 404)


@api.websocket("/ws/runs/{run_name}")
async def stream_run(socket: WebSocket, run_name: str) -> None:
    """Push a fresh payload whenever the run's event log grows.

    Polls the event file's line offset rather than pushing on a timer: read_events()
    already returns (events, next_offset) for exactly this, and an idle run then costs
    one stat-and-read per tick instead of a full payload rebuild plus a socket write.
    """
    await socket.accept()
    try:
        directory = run_dir_for(run_name)
    except HTTPException as exc:
        await socket.send_json({"error": exc.detail})
        await socket.close()
        return

    offset = 0
    last_finished = None
    try:
        while True:
            _, next_offset = await asyncio.to_thread(read_events, directory, offset)
            scan = manager.active.get(run_name)
            running = bool(scan and scan.running)
            # Send on new events, and once more when the run stops, so the client sees
            # the final report.json without needing a refresh.
            if next_offset != offset or last_finished != running:
                offset = next_offset
                last_finished = running
                payload = await asyncio.to_thread(build_payload, directory)
                payload["running"] = running
                payload["exit_code"] = scan.exit_code if scan else None
                await socket.send_json(json.loads(json.dumps(payload, default=str)))
            await asyncio.sleep(POLL_SECONDS)
    except (WebSocketDisconnect, RuntimeError):
        return


# Mount last: a catch-all static mount at "/" would otherwise shadow every /api route.
if FRONTEND_DIST.is_dir():
    api.mount("/", StaticFiles(directory=FRONTEND_DIST, html=True), name="frontend")


def demo() -> None:
    from fastapi.testclient import TestClient

    with TestClient(api) as client:
        health_body = client.get("/api/health").json()
        assert "docker" in health_body and health_body["loopback_only"] in (True, False)
        assert isinstance(client.get("/api/runs").json()["runs"], list)

        # A target the guard refuses must 403, not start a process.
        refused = client.post("/api/scans", json={"target": "example.com"})
        assert refused.status_code == 403, refused.status_code
        assert manager.current() is None

        # Run-name traversal must not escape the runs root.
        for bad in ("../../etc", "..%2f..%2fetc"):
            assert client.get(f"/api/runs/{bad}").status_code in (400, 404)
    print("app.backend.main: ok")


if __name__ == "__main__":
    demo()
