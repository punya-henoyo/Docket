"""The console as CONTROL PLANE: switch repos on, set policy, watch PR scans.

The other two routers serve things the operator STARTS. This one serves the thing that
runs on its own: a poller notices a pull request, docket scans the diff, triage judges,
the gate decides, and where a fix is proven a fix PR is opened. None of that lives in the
customer's repository — no workflow file, no YAML — so this console is the only place any
of it can be turned on, tuned, or looked at.

WHY THE SERVICE HALF IS IMPORTED LAZILY
---------------------------------------
State lives in a SQLite file owned by `docket.service.store`, and the poll pass lives in
`docket.service.poll`. Both are younger than the console, and a console that cannot start
because the service half is unbuilt is worse than one that says so. Every route here
degrades to a 503 naming the missing piece, and this module's demo() runs with the store
absent as well as present. Same reason /api/repos answers 401 rather than exploding when
GitHub is not connected.

WHO OWNS THE LOOP
-----------------
poll.py deliberately owns no thread and no scheduler — "tick() is a single pass the
console calls when it feels like it". So the loop is here, and so is the wiring: tick
needs a Store and an authenticated GitHub App client, and the console is the half that has
credentials. The loop records `last_tick` because it is the thing that ticks; asking the
poller to report its own liveness would be a second source of truth for a fact this
process already knows.

WHY POLLING NEEDS THE APP, NOT THE OAUTH SESSION
------------------------------------------------
tick() reads pull requests as the GitHub App. A connected OAuth console is NOT enough, and
the failure otherwise is a poller that starts, ticks, and finds zero pull requests forever
with nothing on screen to say why.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field

from docket.interface.connect import _FULL_NAME

router = APIRouter()

# store.py's state machine, mirrored here only to validate the ?state= filter — so a typo
# comes back as a 422 rather than as an empty list that reads like "no scans".
SCAN_STATES = ("queued", "scanning", "delivered", "failed", "abandoned")
# delivery.py's word for a patch it proved. Anything else is a suggestion.
VERIFIED_STATUS = "verified_fixed"
# A patch renders into a <pre>. A multi-megabyte diff would be sent, parsed and laid out
# by the browser for no benefit; the operator reviews the real thing on GitHub.
MAX_DIFF_CHARS = 40_000
MAX_PATCHES = 20
DEFAULT_SCAN_LIMIT = 50


# --- lazy imports of the service half ------------------------------------------------
# Three one-line seams rather than inline imports: demo() swaps them to exercise the
# store-missing and poller paths deterministically, the same way main.py's demo swaps
# scans.allow_any_target instead of arranging the real condition.

def _import_store():
    from docket.service import store

    return store


def _import_poll():
    from docket.service import poll

    return poll


def _import_scm():
    from docket.interface import scm

    return scm


def _store():
    try:
        return _import_store()
    except Exception as exc:
        raise HTTPException(
            503,
            "the service store is not built yet — engine/docket/service/store.py could "
            f"not be imported ({exc}). Watched repos and PR scans live there.",
        ) from exc


def _poll_module():
    try:
        return _import_poll()
    except Exception as exc:
        raise HTTPException(
            503,
            "the poller is not built yet — engine/docket/service/poll.py could not be "
            f"imported ({exc}).",
        ) from exc


def _open() -> Any:
    """An open store.Store. Its constructor creates the directory and the schema.

    THIS ROUTER NEVER WRITES A `CREATE TABLE`. Two modules racing to define the same table
    is how the console's idea of it wins and the poller's INSERTs then fail on a column
    that was never made. Owning the schema is store.py's job alone.
    """
    store = _store()
    factory = getattr(store, "Store", None)
    if factory is None:
        raise HTTPException(
            503, "docket.service.store exposes no Store class, so there is nothing to open",
        )
    try:
        return factory()
    except Exception as exc:
        raise HTTPException(503, f"the service store could not be opened: {exc}") from exc


def _rows(store_obj: Any, sql: str, args: tuple = ()) -> list[dict]:
    try:
        return [dict(row) for row in store_obj.db.execute(sql, args)]
    except sqlite3.OperationalError as exc:
        # "no such table"/"no such column" is the store existing without the schema this
        # router expects — a 503, not a 500: the request was fine, the dependency is not.
        raise HTTPException(503, f"the service store schema is not ready: {exc}") from exc


def _iso_now() -> str:
    """store.py's exact timestamp format: fixed-width UTC ISO with a Z suffix.

    It MUST match, character for character. store.py relies on "string comparison IS time
    order", and a `+00:00` suffix sorts before every `Z` one — so a rescanned row would
    silently drop to the bottom of a newest-first list instead of the top.
    """
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z")


# --- models ---------------------------------------------------------------------------
# extra="forbid" on every request model, deliberately. Pydantic IGNORES unknown fields by
# default, and that default is what made the console's AI toggles do nothing for a day:
# the frontend sent triage_max, the model did not declare it, pydantic dropped it in
# silence and the handler used its default. A field name that does not exist here is now a
# 422 naming the field instead of a setting that appears to save and does nothing.

AutofixMode = Literal["off", "suggest", "open_pr"]


class Policy(BaseModel):
    """Per-repo policy. TRI-STATE: every member may be None, meaning "inherit the org
    default" — which is a different answer from "off". `autofix_mode=None` inherits;
    `autofix_mode="off"` is an operator saying no.

    Constraints are Field constraints, not hand-rolled ifs in the handler, so a bad value
    is a 422 naming the field before any of this reaches the database.
    """

    model_config = ConfigDict(extra="forbid")

    autofix_mode: AutofixMode | None = None
    # A fix PR that rewrites 40 files is not a fix, it is a refactor nobody asked for.
    max_files_changed: int | None = Field(default=None, ge=1, le=200)
    # Whether a patch must be PROVEN before it may be opened as a PR. delivery.py already
    # refuses to branch for anything but status == verified_fixed; this is the per-repo
    # switch for the softer modes.
    require_verified_validation: bool | None = None
    # Finding classes this repo gates on. None inherits; [] is an operator saying none.
    enabled_classes: list[str] | None = None
    # ge=0 because 0 is a real, meaningful setting: judge nothing.
    triage_max: int | None = Field(default=None, ge=0)
    # gt=0 because 0 means UNSET, not "spend nothing" — a 0 ceiling would make every agent
    # trip its budget check before its first turn and record `uncertain`, which is a
    # fail-open dressed as a clean scan (see service/gate.py's opening comment).
    budget_usd: float | None = Field(default=None, gt=0)
    label: str | None = Field(default=None, max_length=50)


class RepoUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    policy: Policy = Field(default_factory=Policy)


class PollStart(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # ge=1: a sub-second poll loop is a way to get rate-limited by GitHub, not a feature.
    interval_sec: float = Field(default=30.0, ge=1.0, le=3600.0)


# --- the poller ----------------------------------------------------------------------
# Shared state behind a lock, copied before serialising — the house pattern from
# connect.SESSION. The loop mutates this dict from its own thread.

LOCK = threading.Lock()
POLL: dict[str, Any] = {
    "thread": None,
    "stop": None,
    "store": None,
    "last_tick": None,
    "ticks": 0,
    "error": None,
    "interval_sec": None,
    "last_summary": None,
}
# ponytail: one poller per console process, because there is one service store per
# machine. A second loop would double-lease the same pr_scans rows.


def _bind_tick() -> tuple[Any, Any]:
    """(store, a zero-argument tick). Raises a 503 naming whatever is not ready.

    poll.tick(store, scm) takes its dependencies as arguments on purpose — it owns no
    state — so binding them is the caller's job, and the caller is this console.
    """
    poll = _poll_module()
    tick = getattr(poll, "tick", None)
    if not callable(tick):
        raise HTTPException(
            503,
            "engine/docket/service/poll.py exposes no tick(), so there is nothing to drive",
        )
    try:
        scm = _import_scm()
    except Exception as exc:
        raise HTTPException(503, f"the SCM client is not available ({exc})") from exc
    # Prefer the App when one is configured — it is the only identity that can put a
    # CHECK RUN on a pull request, which is the richer signal because it carries per-line
    # annotations. Fall back to the console's OAuth token, which can do everything else the
    # service needs: list pull requests, read changed files, post review comments with
    # `suggestion` blocks, create the fix branch and open the fix PR. Its pass/fail signal
    # is a COMMIT STATUS instead of a check run (see scm.create_commit_status) — same place
    # on the PR, same branch-protection behaviour, no annotations.
    #
    # Requiring the App outright was wrong: it made the whole service unreachable for an
    # operator who had already connected over OAuth and could have had everything but the
    # annotations.
    from docket.interface import connect

    app_configured = getattr(scm, "app_config", lambda: None)() is not None
    oauth_token = (connect.SESSION.token or "") if not app_configured else ""
    if not app_configured and not oauth_token:
        raise HTTPException(
            503,
            "no GitHub credential. Either connect the console over OAuth on the "
            "Integrations tab — which is enough for everything except per-line "
            "annotations — or configure a GitHub App with DOCKET_GITHUB_APP_ID, "
            "DOCKET_GITHUB_APP_INSTALLATION_ID and DOCKET_GITHUB_APP_PRIVATE_KEY "
            "(or _PRIVATE_KEY_PATH) for the full check-run experience.",
        )
    store_obj = _open()
    client = scm.GitHubApp() if app_configured else scm.GitHubApp(oauth_token=oauth_token)
    return store_obj, lambda: tick(store_obj, client)


def _loop(stop: threading.Event, tick, interval: float) -> None:
    while not stop.is_set():
        try:
            summary = tick()
            summary = summary if isinstance(summary, dict) else None
            with LOCK:
                POLL["last_tick"] = time.time()
                POLL["ticks"] += 1
                POLL["last_summary"] = summary
                # tick() SWALLOWS per-repo failures by design — one uninstalled App must
                # not stop the other twenty repos being polled — so a pass "succeeds"
                # while a repo is silently not watched at all. Lifting the first one out
                # of the summary is the only way that ever reaches a screen.
                errors = (summary or {}).get("errors") or []
                if errors:
                    first = errors[0] if isinstance(errors[0], dict) else {}
                    more = f" (+{len(errors) - 1} more)" if len(errors) > 1 else ""
                    POLL["error"] = (f"{first.get('repo', 'a repo')}: "
                                     f"{first.get('error', 'failed')}{more}")
                else:
                    POLL["error"] = None
        except Exception as exc:
            # One bad tick must not end the loop: an expired token or a GitHub 502 is
            # transient, and a poller that dies silently on the first one is how a repo
            # stops being watched with nobody told. Recorded so the console shows it
            # rather than showing a healthy poller doing nothing.
            with LOCK:
                POLL["error"] = f"{type(exc).__name__}: {exc}"
        # wait(), not sleep(): a stop is honoured immediately rather than after a full
        # interval.
        stop.wait(interval)


def _poll_status() -> dict:
    with LOCK:
        state = dict(POLL)          # copied inside the lock, then serialised outside it
    thread: threading.Thread | None = state.pop("thread", None)
    state.pop("stop", None)
    state.pop("store", None)
    state["running"] = bool(thread and thread.is_alive())
    return state


def _shutdown_poller() -> None:
    """Stop the loop and close the store it held. Safe to call when nothing is running."""
    with LOCK:
        stop: threading.Event | None = POLL["stop"]
        thread: threading.Thread | None = POLL["thread"]
        store_obj = POLL["store"]
    if stop is not None:
        stop.set()
    if thread is not None:
        # Joined briefly, not forever: a tick mid-request would otherwise hold the stop
        # route open for as long as GitHub takes.
        thread.join(timeout=2.0)
    if store_obj is not None:
        try:
            store_obj.close()
        except Exception:
            pass
    with LOCK:
        POLL.update({"thread": None, "stop": None, "store": None})


# --- reading the store ----------------------------------------------------------------

def _json_policy(raw: object) -> dict:
    """The stored policy blob as a full tri-state dict.

    Every key is ALWAYS present, defaulted to None. runs.py:87 is the scar: an omitted
    field arrives as `undefined`, the console maps over it, and one missing key blanks the
    whole page. One endpoint, one shape.
    """
    parsed: object = raw
    if isinstance(raw, (str, bytes)):
        try:
            parsed = json.loads(raw or "{}")
        except (json.JSONDecodeError, UnicodeDecodeError):
            parsed = {}
    if not isinstance(parsed, dict):
        parsed = {}
    empty = Policy().model_dump()
    return {key: parsed.get(key, empty[key]) for key in empty}


def _repo_row(row: dict) -> dict:
    return {
        "full_name": row.get("full_name") or "",
        "enabled": bool(row.get("enabled")),
        "policy": _json_policy(row.get("policy")),
        "added_at": row.get("added_at"),
    }


def _scan_row(row: dict) -> dict:
    """One pr_scans row, every field present.

    Fed from `SELECT *`, so a column store.py adds later arrives under `extra` instead of
    raising, and one it never had reads as None instead of raising.
    """
    known = {
        "id": row.get("id"),
        "repo": row.get("repo") or "",
        "pr": row.get("pr"),
        # The PR title is not in store.py's schema. Read defensively so it appears for
        # free if the column is ever added; until then the console shows repo#pr.
        "title": row.get("title") or row.get("pr_title"),
        "head_sha": row.get("head_sha") or "",
        "base_sha": row.get("base_sha") or "",
        "state": row.get("state") or "queued",
        "run_name": row.get("run_name"),
        "conclusion": row.get("conclusion"),
        "created_at": row.get("created_at"),
        "updated_at": row.get("updated_at"),
        "lease_owner": row.get("lease_owner"),
        "lease_expires_at": row.get("lease_expires_at"),
    }
    known["extra"] = {k: v for k, v in row.items()
                      if k not in known and k not in ("title", "pr_title")}
    return known


def _run_dir(run_name: object) -> Path | None:
    if not run_name or not isinstance(run_name, str):
        return None
    try:
        # Reuses the runs router's traversal guard rather than repeating it: the run name
        # comes out of a database a poller feeds, and it is used to build a path.
        from app.backend.routers.runs import run_dir_for

        return run_dir_for(run_name)
    except HTTPException:
        return None


def _report(run_dir: Path | None) -> dict | None:
    if run_dir is None:
        return None
    path = run_dir / "report.json"
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def _patch_field(patch: Any, name: str, default: Any = None) -> Any:
    """One field off a dict or an object, mirroring delivery.py's `_field`.

    The patch producer is a different phase and has not settled on a shape, so nothing
    here may care which one it picked.
    """
    if isinstance(patch, dict):
        return patch.get(name, default)
    return getattr(patch, name, default)


def _patch(name: str, diff: str, verified: bool, source: str, **extra: Any) -> dict:
    return {
        "name": name,
        "diff": diff[:MAX_DIFF_CHARS],
        "truncated": len(diff) > MAX_DIFF_CHARS,
        # delivery.py's rule, restated for display: only `verified_fixed` is a fix.
        # "proof failed" and "nobody tried" collapse into the same False on purpose, so
        # this can only ever err towards calling a patch unproven.
        "verified": verified,
        "source": source,
        **extra,
    }


def _patches(run_dir: Path | None, report: dict | None) -> list[dict]:
    """Proposed fixes for this scan.

    ponytail: the patch producer persists nowhere agreed yet, so both plausible places are
    read — `report["patches"]` and loose *.patch/*.diff files in the run directory. Narrow
    this to the one real location once that phase lands.
    """
    out: list[dict] = []
    for item in (report or {}).get("patches") or []:
        status = str(_patch_field(item, "status") or "")
        # A patch may be a unified diff, or delivery.py's file-content shape. Render
        # whichever it is rather than picking one and showing nothing for the other.
        diff = _patch_field(item, "diff") or _patch_field(item, "patch") or ""
        files = _patch_field(item, "files") or []
        files = files if isinstance(files, list) else []
        if not isinstance(diff, str) or not diff.strip():
            blocks = []
            for entry in files:
                path = _patch_field(entry, "path") or "?"
                content = _patch_field(entry, "content")
                blocks.append(f"--- {path}\n{content}" if content is not None
                              else f"--- {path}\n(content read from the workspace)")
            diff = "\n\n".join(blocks)
        name = str(_patch_field(item, "key") or _patch_field(item, "rule_id")
                   or _patch_field(item, "title") or "patch")
        out.append(_patch(
            name, diff, status == VERIFIED_STATUS, "report",
            status=status or None,
            title=_patch_field(item, "title"),
            summary=_patch_field(item, "summary") or _patch_field(item, "body"),
            files=[str(_patch_field(e, "path") or "?") for e in files],
        ))
    if run_dir is not None:
        seen = {p["name"] for p in out}
        found = sorted({*run_dir.glob("*.patch"), *run_dir.glob("*.diff"),
                        *run_dir.glob("artifacts/*.patch"),
                        *run_dir.glob("artifacts/*.diff")})
        for path in found:
            if len(out) >= MAX_PATCHES or path.name in seen:
                continue
            try:
                text = path.read_text(errors="replace")
            except OSError:
                continue
            # A loose file on disk carries no proof with it, so it is unverified by
            # definition — False here, never a guess in the other direction.
            out.append(_patch(path.name, text, False, f"file:{path.name}",
                              status=None, title=None, summary=None, files=[]))
    return out[:MAX_PATCHES]


# --- routes ---------------------------------------------------------------------------

@router.get("/api/service/status")
def status() -> dict:
    """Is the service half alive, and how much is waiting for it."""
    with closing(_open()) as store_obj:
        watched = store_obj.watched(enabled_only=False)
        counts = _rows(store_obj,
                       "SELECT state, COUNT(*) AS n FROM pr_scans GROUP BY state")
    by_state = {str(r.get("state")): int(r.get("n") or 0) for r in counts}
    return {
        **_poll_status(),
        "watched": len(watched),
        "enabled": sum(1 for r in watched if r.get("enabled")),
        # Depth is what is WAITING. A scanning row is already someone's work in progress.
        "queue_depth": by_state.get("queued", 0),
        "scanning": by_state.get("scanning", 0),
        "states": by_state,
    }


@router.post("/api/service/poll/start", status_code=202)
def poll_start(request: PollStart) -> dict:
    """202, not 200: the loop has been asked to start. Its first tick has not happened."""
    with LOCK:
        thread: threading.Thread | None = POLL["thread"]
    if thread is not None and thread.is_alive():
        raise HTTPException(409, "the poller is already running")
    # Everything the loop needs is resolved BEFORE the thread exists, so a missing App or
    # an unbuilt store is a 503 an operator reads rather than a failure only visible as a
    # poller that ticks and finds nothing.
    store_obj, tick = _bind_tick()
    stop = threading.Event()
    thread = threading.Thread(
        target=_loop, args=(stop, tick, request.interval_sec),
        name="service-poller", daemon=True,
    )
    with LOCK:
        # update(), not |=: an augmented assignment on a module global makes it local for
        # the whole function and UnboundLocalErrors the read above.
        POLL.update({"thread": thread, "stop": stop, "store": store_obj, "error": None,
                     "interval_sec": request.interval_sec})
    thread.start()
    return _poll_status()


@router.post("/api/service/poll/stop", status_code=202)
def poll_stop() -> dict:
    """202: asked to stop. The loop halts after the tick it is inside finishes."""
    with LOCK:
        thread: threading.Thread | None = POLL["thread"]
    if thread is None or not thread.is_alive():
        raise HTTPException(409, "the poller is not running")
    _shutdown_poller()
    return _poll_status()


@router.get("/api/service/repos")
def watched_repos() -> dict:
    with closing(_open()) as store_obj:
        # enabled_only=False: the console must still show a repo an operator switched OFF,
        # or turning one off looks like a delete and it gets switched on somewhere else.
        rows = store_obj.watched(enabled_only=False)
    return {"repos": [_repo_row(r) for r in rows]}


@router.put("/api/service/repos/{owner}/{name}")
def set_watched_repo(owner: str, name: str, request: RepoUpdate) -> dict:
    """Enable or disable a repo and set its policy. Creates the row if it is new."""
    full_name = f"{owner}/{name}"
    if not _FULL_NAME.match(full_name):
        # Checked before it reaches SQL or a GitHub URL, not after.
        raise HTTPException(400, f"invalid repository name: {full_name!r}")
    # model_dump() keeps the Nones. Dropping them would lose the difference between
    # "inherit the org default" and a member that was never set.
    policy = request.policy.model_dump()
    with closing(_open()) as store_obj:
        try:
            store_obj.watch(full_name, policy, enabled=request.enabled)
        except sqlite3.OperationalError as exc:
            raise HTTPException(503,
                                f"the service store schema is not ready: {exc}") from exc
        row = next((r for r in store_obj.watched(enabled_only=False)
                    if r.get("full_name") == full_name), None)
    if row is None:
        raise HTTPException(500, f"{full_name} was written but cannot be read back")
    return _repo_row(row)


@router.get("/api/service/scans")
def list_scans(
    repo: str | None = None,
    state: str | None = None,
    limit: int = Query(default=DEFAULT_SCAN_LIMIT, ge=1, le=500),
) -> dict:
    """PR scans, NEWEST first. Optional repo and state filters.

    Its own query rather than store.scans(), which orders by id ASC — with a LIMIT that
    returns the OLDEST rows, which is the opposite of an inbox.
    """
    if state is not None and state not in SCAN_STATES:
        # A typo'd state must not come back as an empty list, which reads as "no scans".
        raise HTTPException(422, f"state must be one of {', '.join(SCAN_STATES)}")
    where, args = [], []
    if repo:
        where.append("repo = ?")
        args.append(repo)
    if state:
        where.append("state = ?")
        args.append(state)
    sql = "SELECT * FROM pr_scans"
    if where:
        sql += " WHERE " + " AND ".join(where)
    # store.py's timestamps are fixed-width UTC, so string order IS time order. COALESCE
    # for a row written before updated_at was populated; id DESC to make ties stable.
    sql += " ORDER BY COALESCE(updated_at, created_at) DESC, id DESC LIMIT ?"
    args.append(limit)
    with closing(_open()) as store_obj:
        rows = _rows(store_obj, sql, tuple(args))
    out = []
    for row in rows:
        scan = _scan_row(row)
        report = _report(_run_dir(scan["run_name"]))
        # Always present, always a number. The inbox sums and charts these, and one
        # undefined in that array is what blanked this console's page twice.
        scan["finding_count"] = int((report or {}).get("finding_count") or 0)
        scan["cost_usd"] = float((report or {}).get("cost_usd") or 0.0)
        scan["severity_counts"] = (report or {}).get("severity_counts") or {}
        out.append(scan)
    return {"scans": out}


@router.get("/api/service/scans/{scan_id}")
def get_scan(scan_id: str) -> dict:
    """One scan in full: findings with their triage verdicts, the gate's reasons, patches.

    The gate is RE-EVALUATED from report.json rather than read from the stored conclusion.
    evaluate() is pure, so this cannot disagree with what was posted to GitHub, and it is
    the only way to get the REASONS — the row keeps the verdict, not the argument for it.
    """
    with closing(_open()) as store_obj:
        # CAST, because id is an INTEGER column and a path parameter is text: '5' != 5
        # without it. One comparison that is right either way.
        rows = _rows(store_obj, "SELECT * FROM pr_scans WHERE CAST(id AS TEXT) = ?",
                     (scan_id,))
    if not rows:
        raise HTTPException(404, f"no PR scan {scan_id!r}")
    scan = _scan_row(rows[0])
    run_dir = _run_dir(scan["run_name"])
    report = _report(run_dir)

    findings = [f for f in (report or {}).get("findings") or [] if isinstance(f, dict)]
    gate: dict | None = None
    if report is not None:
        from docket.service.gate import evaluate

        result = evaluate(report)
        gate = {
            "conclusion": result.conclusion,
            "exit_code": result.exit_code,
            "reasons": list(result.reasons),
            "annotation_count": len(result.annotations),
        }
    return {
        **scan,
        # Says WHY the panels below are empty. "No findings" and "the report was never
        # written" look identical otherwise, and only one of them is good news.
        "report_found": report is not None,
        "findings": findings,
        "finding_count": int((report or {}).get("finding_count") or len(findings)),
        "severity_counts": (report or {}).get("severity_counts") or {},
        "triaged": (report or {}).get("triaged") or [],
        "cost_usd": float((report or {}).get("cost_usd") or 0.0),
        "summary": (report or {}).get("summary"),
        "gate": gate,
        "patches": _patches(run_dir, report),
    }


def _requeued(scan: dict) -> dict:
    return {"id": scan["id"], "repo": scan["repo"], "pr": scan["pr"],
            "head_sha": scan["head_sha"]}


@router.post("/api/service/scans/{scan_id}/rescan", status_code=202)
def rescan(scan_id: str, force: bool = False) -> dict:
    """Re-queue this scan at the SAME head_sha. 202: queued, not scanned.

    Goes through store.set_state FIRST, so the state machine gets to refuse. `delivered`
    and `abandoned` are terminal there, and `scanning` holds a live lease — for those,
    ?force=true does the requeue directly, which is what "force" has to mean for a row
    whose worker died holding its lease. Without the escape hatch such a row could never
    be re-scanned by anybody.
    """
    with closing(_open()) as store_obj:
        rows = _rows(store_obj, "SELECT * FROM pr_scans WHERE CAST(id AS TEXT) = ?",
                     (scan_id,))
        if not rows:
            raise HTTPException(404, f"no PR scan {scan_id!r}")
        scan = _scan_row(rows[0])
        if scan["state"] == "queued":
            # Already waiting. A no-op, not an error: the operator asked for it to be
            # queued and it is queued.
            return {**_requeued(scan), "state": "queued", "was": "queued",
                    "forced": bool(force), "refused_by_state_machine": None}
        refused: str | None = None
        try:
            store_obj.set_state(scan["id"], "queued")
        except Exception as exc:
            refused = str(exc)
        if refused is not None:
            if not force:
                lease = (f" A lease is held by {scan['lease_owner']}."
                         if scan["lease_owner"] else "")
                raise HTTPException(
                    409,
                    f"scan {scan_id} cannot be re-queued from {scan['state']}: "
                    f"{refused}.{lease} Retry with ?force=true to override.",
                )
            try:
                store_obj.db.execute(
                    "UPDATE pr_scans SET state = 'queued', conclusion = NULL, "
                    "lease_owner = NULL, lease_expires_at = NULL, updated_at = ? "
                    "WHERE CAST(id AS TEXT) = ?",
                    (_iso_now(), scan_id),
                )
            except sqlite3.OperationalError as exc:
                raise HTTPException(
                    503, f"the service store schema is not ready: {exc}") from exc
    return {**_requeued(scan), "state": "queued", "was": scan["state"],
            "forced": bool(force), "refused_by_state_machine": refused}


# --- self-check -----------------------------------------------------------------------

def demo() -> None:
    """Runs with no network, no Docker, no credentials, and no GitHub App.

    The service half is swapped at the `_import_*` seams rather than by arranging the real
    conditions on disk, for the same reason main.py's demo swaps allow_any_target: a
    self-check must produce each failure state deterministically, whether or not the
    service modules happen to be built on this machine.
    """
    import tempfile
    import types

    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    global _import_store, _import_poll, _import_scm
    originals = (_import_store, _import_poll, _import_scm)

    app = FastAPI()
    app.include_router(router)

    def missing_store():
        raise ImportError("No module named 'docket.service.store'")

    def missing_poll():
        raise ImportError("No module named 'docket.service.poll'")

    try:
        with TestClient(app) as client, tempfile.TemporaryDirectory() as tmp:
            # --- 1. the store-missing path. A clean 503 with a reason, never a traceback.
            _import_store, _import_poll = missing_store, missing_poll
            for path in ("/api/service/status", "/api/service/repos",
                         "/api/service/scans", "/api/service/scans/1"):
                response = client.get(path)
                assert response.status_code == 503, (path, response.status_code)
                assert "not built yet" in response.json()["detail"], response.text
            assert client.post("/api/service/scans/1/rescan").status_code == 503
            assert client.put("/api/service/repos/a/b",
                              json={"enabled": True}).status_code == 503
            # The poller reports ITS missing half, not the store's.
            no_poll = client.post("/api/service/poll/start", json={})
            assert no_poll.status_code == 503, no_poll.text
            assert "poll.py" in no_poll.json()["detail"], no_poll.text

            # --- 2. a bad policy is a 422 BEFORE the store is consulted. This is the state
            # a first-time operator is in, and a validation error that only appears once
            # the service half exists is one nobody ever sees.
            for bad in ({"policy": {"triage_max": -1}},
                        {"policy": {"budget_usd": 0}},        # 0 means unset, not free
                        {"policy": {"autofix_mode": "yolo"}},
                        {"policy": {"max_files_changed": 0}},
                        # The silent-drop bug, now loud: an unknown field is a 422 naming
                        # it rather than a setting that appears to save and does nothing.
                        {"policy": {"autofix_mod": "off"}},
                        {"enabled": True, "autofix_mode": "off"}):
                response = client.put("/api/service/repos/acme/api", json=bad)
                assert response.status_code == 422, (bad, response.status_code)
            assert client.get("/api/service/scans?state=nonsense").status_code == 422

            # --- 3. against a REAL store, in a temp runs root. store.Store creates its own
            # schema, so nothing here writes a CREATE TABLE.
            from docket.service.store import Store, db_path

            path = db_path(cwd=Path(tmp))
            _import_store = lambda: types.SimpleNamespace(  # noqa: E731
                Store=lambda: Store(path))
            seed = Store(path)
            try:
                seed.watch("acme/api")
                seed.watch("acme/web")
                done = seed.enqueue("acme/api", 7, "a" * 40, "b" * 40)
                seed.claim(done, "worker-1")
                seed.set_state(done, "delivered", conclusion="failure", run_name="pr-7")
                held = seed.enqueue("acme/api", 8, "c" * 40, "b" * 40)
                seed.claim(held, "worker-2")
                queued = seed.enqueue("acme/web", 9, "d" * 40, "b" * 40)
            finally:
                seed.close()

            live = client.get("/api/service/status")
            assert live.status_code == 200, live.text
            body = live.json()
            assert body["running"] is False and body["last_tick"] is None, body
            assert (body["watched"], body["queue_depth"], body["scanning"]) == (2, 1, 1), body

            # A valid policy round-trips, and every tri-state member survives: one left out
            # must read back as None (inherit), not vanish.
            saved = client.put("/api/service/repos/acme/api", json={
                "enabled": True,
                "policy": {"autofix_mode": "open_pr", "triage_max": 0,
                            "require_verified_validation": True, "budget_usd": 2.5,
                            "enabled_classes": []},
            })
            assert saved.status_code == 200, saved.text
            policy = saved.json()["policy"]
            assert set(policy) == set(Policy().model_dump()), policy
            assert policy["autofix_mode"] == "open_pr" and policy["triage_max"] == 0
            assert policy["enabled_classes"] == [], "[] is 'none', not 'inherit'"
            assert policy["max_files_changed"] is None, "an unset member must inherit"
            # A disabled repo must still be LISTED, or switching one off looks like a
            # delete and the operator switches it on again somewhere else.
            assert client.put("/api/service/repos/acme/api",
                              json={"enabled": False}).json()["enabled"] is False
            listed = client.get("/api/service/repos").json()["repos"]
            assert [r["full_name"] for r in listed] == ["acme/api", "acme/web"], listed
            assert client.put("/api/service/repos/acme/../etc",
                              json={"enabled": True}).status_code in (400, 404)

            # Newest first — the opposite of store.scans()'s id-ascending order — and
            # filters narrow rather than empty.
            scans = client.get("/api/service/scans").json()["scans"]
            assert [s["id"] for s in scans] == [queued, held, done], scans
            assert all({"finding_count", "cost_usd", "conclusion"} <= set(s)
                       for s in scans), "every row needs every field the inbox reads"
            assert len(client.get("/api/service/scans?repo=acme/web").json()["scans"]) == 1
            assert len(client.get("/api/service/scans?state=queued").json()["scans"]) == 1

            # One scan. No run directory on this machine, so report_found is False and the
            # lists are empty rather than the route 404ing on a scan that exists.
            one = client.get(f"/api/service/scans/{done}")
            assert one.status_code == 200, one.text
            detail = one.json()
            assert detail["report_found"] is False and detail["findings"] == []
            assert detail["gate"] is None and detail["patches"] == []
            assert detail["conclusion"] == "failure", detail
            assert client.get("/api/service/scans/999").status_code == 404

            # Rescan. A live lease and a terminal state both refuse; force overrides both;
            # a row that is already queued is a no-op rather than an error.
            assert client.post(f"/api/service/scans/{held}/rescan").status_code == 409
            assert client.post(f"/api/service/scans/{done}/rescan").status_code == 409
            forced = client.post(f"/api/service/scans/{held}/rescan?force=true")
            assert forced.status_code == 202, forced.text
            assert forced.json()["was"] == "scanning", forced.text
            after = client.get(f"/api/service/scans/{held}").json()
            assert (after["state"], after["lease_owner"]) == ("queued", None), after
            assert client.post(f"/api/service/scans/{queued}/rescan").status_code == 202
            assert client.post("/api/service/scans/999/rescan").status_code == 404
            # The forced requeue must keep store.py's timestamp format, or the row sorts to
            # the BOTTOM of a newest-first list instead of the top.
            assert str(after["updated_at"]).endswith("Z"), after["updated_at"]
            # And the list is still genuinely time-ordered afterwards, which is the thing
            # the format actually protects.
            order = [s["updated_at"] for s in
                     client.get("/api/service/scans").json()["scans"]]
            assert order == sorted(order, reverse=True), order

            # --- 4. the poller. NO credential of either kind -> a 503 naming both routes
            # out, not a thread that ticks and quietly finds nothing.
            #
            # This used to demand the App specifically. It no longer does: an OAuth token
            # can list pull requests, read changed files, post review comments with
            # `suggestion` blocks, cut the fix branch and open the fix PR. The only thing
            # it cannot write is a CHECK RUN, so OAuth mode signals pass/fail with a commit
            # status instead. Requiring the App made the service unreachable for an
            # operator who was already connected and could have had all of that.
            _import_poll = lambda: types.SimpleNamespace(  # noqa: E731
                tick=lambda store, scm: {"repos": 0})
            _import_scm = lambda: types.SimpleNamespace(  # noqa: E731
                app_config=lambda: None,
                GitHubApp=lambda **kw: types.SimpleNamespace(**kw))
            from docket.interface import connect as _connect

            _saved_token = _connect.SESSION.token
            try:
                _connect.SESSION.token = None          # neither App nor OAuth
                unconfigured = client.post("/api/service/poll/start", json={})
                assert unconfigured.status_code == 503, unconfigured.text
                detail = unconfigured.json()["detail"]
                assert "OAuth" in detail and "GitHub App" in detail, detail

                # With an OAuth token and no App, the poller must START, on the fallback.
                _connect.SESSION.token = "gho_pretend"
                started = client.post("/api/service/poll/start", json={})
                assert started.status_code == 202, started.text
                client.post("/api/service/poll/stop", json={})
            finally:
                _connect.SESSION.token = _saved_token

            # Configured. tick(store, scm) is called with BOTH arguments — the whole point
            # of binding it here — and the store it gets is a real one.
            seen: list[tuple] = []

            def fake_tick(store_arg, scm_arg) -> dict:
                seen.append((store_arg, scm_arg))
                return {"repos": 2, "pull_requests": 3, "enqueued": [], "errors": []}

            _import_poll = lambda: types.SimpleNamespace(tick=fake_tick)  # noqa: E731
            _import_scm = lambda: types.SimpleNamespace(  # noqa: E731
                app_config=lambda: object(), GitHubApp=lambda: "app-client")
            started = client.post("/api/service/poll/start", json={"interval_sec": 60})
            assert started.status_code == 202, started.text
            assert client.post("/api/service/poll/start", json={}).status_code == 409
            for _ in range(200):
                if client.get("/api/service/status").json()["last_tick"]:
                    break
                time.sleep(0.02)
            running = client.get("/api/service/status").json()
            assert running["running"] is True and running["ticks"] >= 1, running
            assert running["error"] is None, running
            assert running["last_summary"] == {"repos": 2, "pull_requests": 3,
                                                "enqueued": [], "errors": []}, running
            assert seen and seen[0][1] == "app-client", seen
            assert hasattr(seen[0][0], "watched"), "tick must get a real store"
            assert client.post("/api/service/poll/stop").status_code == 202
            assert client.get("/api/service/status").json()["running"] is False
            assert client.post("/api/service/poll/stop").status_code == 409

            # tick() swallows per-repo failures by design, so a pass can "succeed" while a
            # repo is not being watched at all. That has to reach the screen.
            _import_poll = lambda: types.SimpleNamespace(  # noqa: E731
                tick=lambda store, scm: {"repos": 1, "errors": [
                    {"repo": "acme/api", "error": "HTTP 404: Not Found"},
                    {"repo": "acme/web", "error": "rate limited"}]})
            assert client.post("/api/service/poll/start",
                                json={"interval_sec": 60}).status_code == 202
            for _ in range(200):
                if client.get("/api/service/status").json()["error"]:
                    break
                time.sleep(0.02)
            swallowed = client.get("/api/service/status").json()
            assert "acme/api" in (swallowed["error"] or ""), swallowed
            assert "+1 more" in (swallowed["error"] or ""), swallowed
            client.post("/api/service/poll/stop")

            # A tick that RAISES records it and keeps the loop alive: a transient GitHub
            # failure must not silently stop every repo being watched.
            def angry(store_arg, scm_arg) -> None:
                raise RuntimeError("GitHub said 502")

            _import_poll = lambda: types.SimpleNamespace(tick=angry)  # noqa: E731
            assert client.post("/api/service/poll/start",
                                json={"interval_sec": 60}).status_code == 202
            for _ in range(200):
                if client.get("/api/service/status").json()["error"]:
                    break
                time.sleep(0.02)
            raised = client.get("/api/service/status").json()
            assert "502" in (raised["error"] or ""), raised
            assert raised["running"] is True, "one bad tick must not end the loop"
            client.post("/api/service/poll/stop")
    finally:
        # No self-check may leave a thread running or a database handle open.
        _shutdown_poller()
        with LOCK:
            POLL.update({"last_tick": None, "ticks": 0, "error": None,
                         "interval_sec": None, "last_summary": None})
        _import_store, _import_poll, _import_scm = originals
    assert POLL["thread"] is None and POLL["store"] is None
    print("app.backend.routers.service: ok")


if __name__ == "__main__":
    demo()
