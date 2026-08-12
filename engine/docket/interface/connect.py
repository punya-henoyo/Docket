"""GitHub connect: authorize -> pick a repo -> fetch source read-only -> scan it.

This is the hosted-product surface, not the CLI. A customer opens the console, clicks
Connect GitHub, authorizes, and picks repositories; docket pulls each one read-only and
runs the deterministic scanners (trivy + semgrep) against it.

AN OAUTH APP, AND WHAT THAT COSTS
---------------------------------
Register an OAuth App (Developer settings -> OAuth Apps), callback
http://127.0.0.1:8765/auth/callback.

The user authorizes once and docket can scan every repository they can reach,
INCLUDING ones they only collaborate on, with no repository owner installing
anything. That reach is the product requirement, and only an OAuth App delivers it.

The price is real: GitHub has NO read-only scope for private code. `repo` grants read
AND WRITE; there is no `repo:read`. Docket only ever reads — it clones nothing, pushes
nothing, opens no branches, and fetch_source() below pulls a tarball precisely so
there is no remote to push to — but the token it holds could write. A leaked token is
therefore worse than the access actually used, which raises the bar on the token
storage this module does not yet have.

A GitHub App would have been read-only (`contents: read`), at the cost of every
repository OWNER having to install it first; a collaborator cannot grant access to a
repo they do not own. That path was removed deliberately: it made onboarding depend on
someone other than the person connecting.

WHAT THIS IS NOT
----------------
Single-tenant and in-memory: one operator, on their own machine, holding one token.
There is no user table, no encryption at rest, no tenant isolation. Do not point this
at real customers as-is.
# ponytail: in-memory single-tenant session, ceiling is "one operator on localhost".
# Multi-tenant needs a real session store, per-tenant token encryption, and a job queue
# (a scan takes minutes and needs Docker, so it cannot run inside a request handler).
"""
from __future__ import annotations

import json
import logging
import os
import re
import secrets
import shutil
import tarfile
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

from docket.tools.scanners import read_coverage
from docket.utils.resource_paths import frontend_dir

logger = logging.getLogger(__name__)

GITHUB_AUTHORIZE = "https://github.com/login/oauth/authorize"
GITHUB_TOKEN = "https://github.com/login/oauth/access_token"
GITHUB_API = "https://api.github.com"

# "owner/repo" exactly. Anything else never reaches a URL or the filesystem: this value
# arrives from the browser and is interpolated into an api.github.com path, so a stray
# "../" or scheme here would be a path-traversal / SSRF primitive.
_FULL_NAME = re.compile(r"^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$")

# A git ref: branch, tag or commit SHA. Slashes are legal and common ("feat/x"), which
# is exactly why this needs its own check rather than reusing _FULL_NAME — it is
# interpolated into the same API path, so "..", a leading "-" (which a shell or CLI
# could read as a flag) and empty segments are all rejected explicitly.
_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]*$")


# A run name is a directory name under docket_runs/ and arrives from the browser.
# sanitize_run_name() already restricts what gets written; this restricts what can be
# read back.
_RUN_NAME = re.compile(r"^[A-Za-z0-9._-]+$")


def valid_ref(ref: str) -> bool:
    return bool(_REF.match(ref)) and ".." not in ref and not ref.endswith("/") and "//" not in ref

# GitHub caps a tarball at a few hundred MB; refuse anything absurd rather than filling
# the disk of whoever runs this.
MAX_TARBALL_BYTES = 512 * 1024 * 1024

# No ceiling on triage count, deliberately. The operator chooses how many findings to
# triage; capping by COUNT here would only be a proxy for the thing actually worth
# bounding, which is money. DOCKET_MAX_COST_USD is the real stop, checked before every
# model turn (core/hooks.py) — and it stops mid-run rather than pre-emptively refusing
# a number that might have been affordable.
#
# That gate only became real once DOCKET_PRICE_*_PER_1M was set: LiteLLM cannot price
# an Azure deployment name, so an unpriced model reports $0.00 and the budget silently
# enforces nothing. Unpriced + unbounded count is genuinely unbounded spend.


# A scan in one of these has not finished. Used both to decide whether to refresh
# usage on read and to answer "is anything running", so the two can never disagree.
LIVE_STATUSES = ("queued", "fetching", "scanning")


def active_scans() -> list[dict[str, Any]]:
    """Scans still running, newest first.

    Exists so the console can find a live scan it has lost track of. The browser held
    the only reference to a running scan in React state, so opening a historical run
    replaced it and the scan became unreachable — still running, still spending, with
    no way back to it. A reload or a second tab had the same problem.
    """
    with SESSION.lock:
        return [
            {"id": scan_id, "repo": state.get("repo"), "ref": state.get("ref"),
             "status": state.get("status"), "started_at": state.get("started_at")}
            for scan_id, state in SESSION.scans.items()
            if state.get("status") in LIVE_STATUSES
        ]


def _merge_live_usage(state: dict[str, Any]) -> dict[str, Any]:
    """Refresh a scan state's per-agent turns and cost from the usage ledger.

    Called on every READ, not only when something happens to call snapshot(). During
    recon nothing calls snapshot() for minutes at a time — the runner's on_progress
    fires only after recon finishes — so the console sat on "Model turns 0, Spend
    $0.0000" for the entire run while the agent was demonstrably burning turns.
    Joining at read time means a poll can never show a stale number, whatever the
    callbacks do or do not do.
    """
    from docket.report.state import get_global_report_state

    ledger = get_global_report_state().usage
    totals = ledger.totals()
    state["cost_usd"] = round(totals.get("cost_usd", 0.0), 4)
    state["input_tokens"] = totals.get("input_tokens", 0)
    state["output_tokens"] = totals.get("output_tokens", 0)

    rows = {row["agent_id"]: row for row in ledger.per_agent()}
    for agent in state.get("agents", []):
        row = rows.get(agent["id"])
        if row:
            agent["turns"] = row["requests"]
            agent["cost_usd"] = round(row["cost_usd"], 4)
    return state


@dataclass
class Session:
    """One operator's connection. Module-level singleton — see the module docstring."""
    token: str | None = None
    login: str | None = None
    oauth_state: str | None = None
    scans: dict[str, dict[str, Any]] = field(default_factory=dict)
    # Kept out of `scans` deliberately: that dict is serialised straight to the
    # browser and a threading.Event is not JSON.
    cancels: dict[str, Any] = field(default_factory=dict)
    lock: threading.Lock = field(default_factory=threading.Lock)


SESSION = Session()


def oauth_config() -> tuple[str, str, str] | None:
    """(client_id, client_secret, redirect_uri) or None when unconfigured.

    Reads .env on every call, for the same reason app/backend/scans.py and runs.py do.
    Nothing in this module's import chain loads it: `docket connect` got it for free
    because interface/main.py imports docket.config.settings (which calls load_dotenv at
    import), but the app console imports only this module — so credentials sat in .env
    while /api/session answered `configured: false` and /auth/start answered 503. The
    Connect GitHub button did nothing, with no error anywhere to explain why.
    """
    load_dotenv(override=True)
    client_id = os.environ.get("DOCKET_GITHUB_CLIENT_ID", "").strip()
    client_secret = os.environ.get("DOCKET_GITHUB_CLIENT_SECRET", "").strip()
    if not client_id or not client_secret:
        return None
    redirect = os.environ.get("DOCKET_GITHUB_REDIRECT_URI", "").strip()
    return client_id, client_secret, redirect


def oauth_scope() -> str:
    """OAuth scope to request. `repo` unless DOCKET_GITHUB_SCOPE overrides it.

    `repo` covers every repository the user can reach, including ones they only
    collaborate on. That reach is the point: anyone with access to a repo can connect
    it and scan it, with no repository owner having to install anything.

    The cost is unavoidable, not a choice made here: GitHub has NO read-only scope for
    private code. `repo` grants read AND WRITE; there is no `repo:read`. Docket only
    ever reads — it clones nothing, pushes nothing, opens no branches — but the token
    it holds could write, which makes a leaked token worse than the access we use.

    `public_repo` narrows this to public repositories (still write on those) and is
    the only meaningful alternative worth setting.
    """
    return os.environ.get("DOCKET_GITHUB_SCOPE", "").strip() or "repo"


def _api(path: str, token: str, *, timeout: float = 20.0) -> Any:
    request = urllib.request.Request(
        f"{GITHUB_API}{path}",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "docket",
        },
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read() or b"null")


def exchange_code(code: str) -> tuple[str | None, str | None]:
    """Trade the callback's ?code for a user token. Returns (token, error)."""
    config = oauth_config()
    if config is None:
        return None, "DOCKET_GITHUB_CLIENT_ID / _SECRET are not set"
    client_id, client_secret, redirect = config
    form = {"client_id": client_id, "client_secret": client_secret, "code": code}
    if redirect:
        form["redirect_uri"] = redirect
    request = urllib.request.Request(
        GITHUB_TOKEN,
        data=urllib.parse.urlencode(form).encode(),
        headers={"Accept": "application/json", "User-Agent": "docket"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            payload = json.loads(response.read() or b"{}")
    except urllib.error.URLError as exc:
        return None, f"token exchange failed: {exc}"
    token = payload.get("access_token")
    if not token:
        # GitHub returns 200 with an error body on a bad/expired code.
        return None, payload.get("error_description") or payload.get("error") or "no access_token returned"
    return token, None


def list_repos(token: str) -> list[dict[str, Any]]:
    """Every repository this user can reach, newest first.

    affiliation is spelled out rather than left to GitHub's default: repos the user
    only COLLABORATES on are the entire reason this product uses OAuth, so a change
    in that default is the one thing that would quietly break it.
    """
    return _api(
        "/user/repos?per_page=100&sort=updated"
        "&affiliation=owner,collaborator,organization_member", token,
    ) or []


def fetch_source(full_name: str, token: str, dest: Path, ref: str | None = None) -> Path:
    """Download a tarball of `full_name` at `ref` and extract it under `dest`.

    `ref` is a branch, tag or commit SHA; None means the repository's default branch,
    which is what GitHub returns when the path omits a ref. A PR branch is the point:
    scanning only ever the default branch cannot gate a change before it merges.

    Deliberately NOT `git clone`: a clone puts the token in the command line (visible
    to `ps`) or persists it in .git/config. The REST tarball carries the token in an
    Authorization header only, so it never touches the disk or the process table. It
    is also read-only by construction — there is no remote to push back to.
    """
    if not _FULL_NAME.match(full_name):
        raise ValueError(f"refusing suspicious repository name: {full_name!r}")
    if ref is not None and not valid_ref(ref):
        raise ValueError(f"refusing suspicious ref: {ref!r}")

    path = f"/repos/{full_name}/tarball" + (f"/{ref}" if ref else "")
    request = urllib.request.Request(
        f"{GITHUB_API}{path}",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "User-Agent": "docket",
        },
    )
    dest.mkdir(parents=True, exist_ok=True)
    archive = dest / "source.tar.gz"
    try:
        response_cm = urllib.request.urlopen(request, timeout=120)
    except urllib.error.HTTPError as exc:
        # "HTTP Error 404: Not Found" tells the operator nothing, and GitHub returns
        # 404 for three quite different situations — a missing ref, a repo the token
        # cannot see, and a repo that does not exist. It deliberately will not confirm
        # a private repo exists, so the status alone can never distinguish them. Say
        # what was requested and list the causes; the operator can tell which is which
        # instantly, and the raw status alone has them guessing.
        if exc.code == 404:
            where = f"{full_name}@{ref}" if ref else f"{full_name} (default branch)"
            raise RuntimeError(
                f"GitHub has no source at {where}. That 404 means one of three things, "
                f"and GitHub will not say which: the branch or tag '{ref}' does not "
                "exist; your token cannot see this repository (a private repo you lack "
                "access to returns 404, not 403); or the repository name is wrong. "
                "Leave the branch blank to use the default."
                if ref else
                f"GitHub has no source for {full_name}. That 404 means either your "
                "token cannot see this repository — a private repo you lack access to "
                "returns 404, not 403 — or the name is wrong."
            ) from exc
        if exc.code in (401, 403):
            raise RuntimeError(
                f"GitHub refused the request for {full_name} ({exc.code}). The token "
                "is expired, revoked, or lacks the `repo` scope. Reconnect GitHub."
            ) from exc
        raise
    with response_cm as response:
        size = 0
        with archive.open("wb") as out:
            while chunk := response.read(1 << 16):
                size += len(chunk)
                if size > MAX_TARBALL_BYTES:
                    raise ValueError(f"tarball exceeds {MAX_TARBALL_BYTES} bytes; refusing")
                out.write(chunk)

    extracted = dest / "src"
    extracted.mkdir(exist_ok=True)
    with tarfile.open(archive, "r:gz") as tar:
        # filter="data" (3.12+) blocks absolute paths, "..", symlinks and device files.
        # This archive is third-party content, so extractall without it is exactly the
        # traversal bug semgrep flags in this very repo.
        tar.extractall(extracted, filter="data")
    archive.unlink(missing_ok=True)

    # GitHub wraps everything in one "owner-repo-<sha>" directory; hand back the real root.
    entries = [p for p in extracted.iterdir() if p.is_dir()]
    return entries[0] if len(entries) == 1 else extracted


def run_repo_scan(full_name: str, token: str, scan_id: str, ref: str | None = None,
                  triage_max: int = 0, recon: bool = False, cancel: Any = None,
                  budget_usd: float | None = None) -> None:
    """Fetch + scan, updating SESSION.scans[scan_id] as it goes. Never raises: the
    status dict is how the browser learns something failed.

    Findings are published as each scanner finishes rather than in one lump at the
    end, so the console's radar fills in during the run instead of staying empty and
    then jumping. Sequential scanners make that ordering exact.
    """
    from docket.core.cancel import NEVER, ScanCancelled
    from docket.report.dedupe import FindingStore

    cancel = cancel if cancel is not None else NEVER

    def set_state(**fields: Any) -> None:
        with SESSION.lock:
            SESSION.scans[scan_id].update(fields)

    def stage(scanner: str, state: str) -> None:
        with SESSION.lock:
            SESSION.scans[scan_id]["stages"][scanner] = state

    store = FindingStore()
    try:
        from docket.config.settings import Config

        cfg_budget = budget_usd if budget_usd else Config.from_env().max_cost_usd
    except Exception:
        # static-only scans need no DOCKET_LLM; a missing budget just means nothing to
        # draw a meter against, not a failure.
        cfg_budget = 0.0

    def snapshot() -> None:
        """Push the store's CURRENT state, including any triage verdicts already
        attached. Called both as scanners produce findings and as triage judges them,
        so the console reflects work while it happens rather than only after."""
        from docket.report.state import get_global_report_state

        current = [f.model_dump(mode="json") for f in store.findings()]
        totals = get_global_report_state().usage.totals()
        with SESSION.lock:
            _merge_live_usage(SESSION.scans[scan_id])
        set_state(
            findings=current, finding_count=len(current),
            cost_usd=round(totals.get("cost_usd", 0.0), 4),
            input_tokens=totals.get("input_tokens", 0),
            output_tokens=totals.get("output_tokens", 0),
            budget_usd=cfg_budget,
        )

    def note_agent(record: dict[str, Any]) -> None:
        """Merge one agent's lifecycle update into the scan state.

        Merged rather than appended: an agent reports twice, once on start and once
        on finish, and the second must update the row the browser is already showing
        rather than adding a duplicate beneath it.
        """
        with SESSION.lock:
            agents = SESSION.scans[scan_id].setdefault("agents", [])
            for existing in agents:
                if existing["id"] == record["id"]:
                    existing.update({k: v for k, v in record.items() if v is not None})
                    break
            else:
                agents.append(dict(record))
        snapshot()

    def publish(finding: Any) -> None:
        store.add(finding)
        snapshot()

    workdir = Path(tempfile.mkdtemp(prefix="docket-connect-"))
    started = time.time()
    run_name = f"connect-{scan_id}"
    try:
        set_state(status="fetching")
        stage("fetch", "running")
        source = fetch_source(full_name, token, workdir, ref)
        stage("fetch", "done")
        cancel.check()

        set_state(status="scanning")
        from docket.core.runner import run_scan

        result = run_scan(
            target_url=None,
            whitebox_path=str(source),
            on_finding=publish,
            run_name=run_name,
            use_sandbox=True,
            store=store,
            static_only=True,
            on_stage=stage,
            triage_max=triage_max,
            on_progress=snapshot,
            recon=recon,
            on_surface=lambda surface: set_state(surface=surface),
            cancel=cancel,
            on_agent=note_agent,
            budget_usd=budget_usd,
        )
        # Persist the same artifacts `docket scan` writes, so a console scan is
        # visible to `docket view`, to the run-history panel, and to anything reading
        # report.sarif — rather than existing only in this process's memory.
        from docket.core.paths import run_path
        from docket.report.writer import write_report

        write_report(
            store, run_path(run_name), run_name=run_name,
            target=f"github:{full_name}" + (f"@{ref}" if ref else ""),
            coverage=read_coverage(run_path(run_name) / "sandbox"),
            surface=SESSION.scans[scan_id].get("surface"),
            agents=SESSION.scans[scan_id].get("agents"),
            summary=result.summary, cost_usd=result.cost_usd,
            agents_spawned=result.agents_spawned, success=result.success,
        )
        from docket.report.state import get_global_report_state

        totals = get_global_report_state().usage.totals()
        # Re-dump: `publish` snapshots each finding as it arrives, but the triage pass
        # mutates those same Finding objects AFTERWARDS. Without this the verdicts sit
        # in the store and in report.json while the console shows the pre-triage
        # snapshot — which is exactly how "triage ran, judged 0" looked.
        snapshot()
        # Coverage read from the scanners' own artifacts, which live under the
        # sandbox's bind mount, not the run dir the report goes to.
        set_state(coverage=read_coverage(run_path(run_name) / "sandbox"))
        set_state(
            status="done", summary=result.summary,
            elapsed_sec=round(time.time() - started, 1),
            cost_usd=round(totals.get("cost_usd", 0.0), 4),
            input_tokens=totals.get("input_tokens", 0),
            output_tokens=totals.get("output_tokens", 0),
            budget_usd=cfg_budget,
        )
    except ScanCancelled as exc:
        # A deliberate stop is not a failure, and the findings already produced are
        # real. Write them out and mark the stage that was interrupted "skipped"
        # rather than "error" — calling an operator's own stop an error trains people
        # to ignore errors.
        with SESSION.lock:
            stages = SESSION.scans[scan_id]["stages"]
            for name, value in stages.items():
                if value in ("running", "pending", ""):
                    stages[name] = "skipped"
        try:
            from docket.core.paths import run_path
            from docket.report.writer import write_report

            write_report(
                store, run_path(run_name), run_name=run_name,
                target=f"github:{full_name}" + (f"@{ref}" if ref else ""),
                coverage=read_coverage(run_path(run_name) / "sandbox"),
                surface=SESSION.scans[scan_id].get("surface"),
                summary=f"Stopped by the operator after {len(store)} finding(s). "
                        "This run is incomplete: what is here was measured, what is "
                        "missing was never looked at.",
                cost_usd=0.0, agents_spawned=0, success=False,
            )
        except Exception:  # noqa: BLE001 — a failed save must not mask the cancel
            logger.warning("could not write the partial report for %s", run_name)
        snapshot()
        set_state(status="cancelled", error=str(exc),
                  elapsed_sec=round(time.time() - started, 1))
    except Exception as exc:
        # Mark whichever stage was actually in flight. Blaming "fetch" unconditionally
        # reported a post-scan crash as a download failure, next to two scanners that
        # had plainly finished.
        with SESSION.lock:
            stages = SESSION.scans[scan_id]["stages"]
            in_flight = next((k for k, v in stages.items() if v == "running"), None)
            if in_flight:
                stages[in_flight] = "error"
        set_state(status="error", error=f"{type(exc).__name__}: {exc}",
                  elapsed_sec=round(time.time() - started, 1))
    finally:
        # The customer's source never outlives the scan.
        shutil.rmtree(workdir, ignore_errors=True)
        with SESSION.lock:
            SESSION.cancels.pop(scan_id, None)


def new_scan_state(scan_id: str, full_name: str, ref: str | None = None,
                   triage_max: int = 0, recon: bool = False,
                   budget_usd: float | None = None) -> dict[str, Any]:
    return {
        "id": scan_id,
        "repo": full_name,
        # None renders as "default branch" in the console; a real value is echoed back
        # so a finished scan says which code it actually looked at.
        "ref": ref,
        "status": "queued",
        "triage_max": triage_max,
        "recon": recon,
        # The attack surface an agent mapped: entry points, auth model, and candidates
        # no scanner rule encodes. None until recon runs, which is off by default.
        "surface": None,
        "coverage": {},
        "agents": [],
        "cost_usd": 0.0,
        # Shown as the denominator on the spend meter. 0 means "whatever
        # DOCKET_MAX_COST_USD says", resolved once the scan thread starts.
        "requested_budget_usd": budget_usd or 0.0,
        "input_tokens": 0,
        "output_tokens": 0,
        "budget_usd": 0.0,
        # Radar rings, outermost last. "skipped" is a real outcome, not a failure:
        # nuclei needs a live URL and a source-only scan has none, and triage is off
        # unless asked for because it costs LLM money per finding.
        "stages": {"fetch": "pending", "trivy": "pending", "semgrep": "pending",
                   "nuclei": "pending", "recon": "pending", "triage": "pending"},
        "findings": [],
        "finding_count": 0,
        "error": None,
    }


_MIME = {
    ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8", ".svg": "image/svg+xml",
    ".json": "application/json", ".woff2": "font/woff2", ".ico": "image/x-icon",
    ".png": "image/png", ".map": "application/json",
}

_NOT_BUILT = b"""<!doctype html><meta charset=utf-8>
<title>docket - not built</title>
<body style="background:#0b0b0b;color:#e8e6e1;font:15px/1.7 ui-monospace,monospace;padding:44px">
<h1 style="font-size:19px">Console not built</h1>
<p>The React app has not been compiled yet. From the repo root:</p>
<pre style="background:#1b1b1b;border:1px solid #333;border-radius:6px;padding:14px">cd frontend
npm install
npm run build</pre>
<p style="color:#8a8781">Then reload. For hot-reload development run <b>npm run dev</b> instead and use
the Vite URL it prints, which proxies /api and /auth back to this server.</p>"""


def frontend_dist() -> Path:
    return frontend_dir() / "dist"


def list_runs() -> list[dict[str, Any]]:
    """Past runs on disk, newest first. Read straight from the run directories the CLI
    already writes, so the console and `docket view` never disagree."""
    from docket.core.paths import runs_root

    root = runs_root()
    if not root.exists():
        return []
    runs: list[dict[str, Any]] = []
    for directory in root.iterdir():
        report = directory / "report.json"
        if not report.is_file():
            continue
        try:
            data = json.loads(report.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        runs.append({
            "run_name": data.get("run_name", directory.name),
            "target": data.get("target"),
            "generated_at": data.get("generated_at"),
            "finding_count": data.get("finding_count", 0),
            "severity_counts": data.get("severity_counts", {}),
            # usage.totals is where the writer records spend. The top-level cost_usd
            # key exists but is always 0.0, so reading it made every historical run
            # look free and the cost trend a flat line at zero.
            "cost_usd": round(
                ((data.get("usage") or {}).get("totals") or {}).get(
                    "cost_usd", data.get("cost_usd", 0.0)),
                4),
            "mtime": report.stat().st_mtime,
        })
    runs.sort(key=lambda r: r["mtime"], reverse=True)
    return runs


DOWNLOAD_FORMATS = {
    "json": ("report.json", "application/json"),
    "sarif": ("report.sarif", "application/json"),
    "md": (None, "text/markdown; charset=utf-8"),  # rendered, not stored
    # Written by a model, so CACHED on disk after the first request: a download button
    # must not bill the operator every time someone clicks it.
    "brief": ("brief.html", "text/html; charset=utf-8"),
}


def _download_brief(run_name: str) -> tuple[int, bytes, str, str]:
    """The LLM-written executive brief. Generated once, then served from disk.

    A failure here returns the reason as plain text rather than a broken download: the
    brief is a convenience over report.json, and the deterministic report.md is always
    available and always correct. Never silently substitute one for the other — a
    reader who asked for the brief must know they did not get it.
    """
    from docket.core.paths import runs_root

    if not _RUN_NAME.match(run_name):
        return 400, b"bad run name", "text/plain; charset=utf-8", "error.txt"
    root = runs_root().resolve()
    run_dir = (root / run_name).resolve()
    if not str(run_dir).startswith(str(root)) or not (run_dir / "report.json").is_file():
        return 404, b"no such run", "text/plain; charset=utf-8", "error.txt"

    cached = run_dir / "brief.html"
    if cached.is_file():
        return 200, cached.read_bytes(), "text/html; charset=utf-8", f"{run_name}-brief.html"

    try:
        report = json.loads((run_dir / "report.json").read_text())
    except (OSError, json.JSONDecodeError) as exc:
        return 500, f"unreadable report: {exc}".encode(), "text/plain; charset=utf-8", "error.txt"

    try:
        from docket.config.settings import Config

        config = Config.from_env()
    except Exception as exc:  # noqa: BLE001
        return 400, (f"An executive brief needs a model configured: {exc}\n"
                     "The .md and .json reports need no model and are ready now."
                     ).encode(), "text/plain; charset=utf-8", "error.txt"

    from docket.report.narrative import generate

    html, note = generate(report, config)
    if html is None:
        return 502, (f"No brief was produced: {note}\n"
                     "Nothing was written rather than something unverified."
                     ).encode(), "text/plain; charset=utf-8", "error.txt"
    try:
        cached.write_text(html)
    except OSError:
        logger.warning("could not cache the brief for %s", run_name)
    return 200, html.encode(), "text/html; charset=utf-8", f"{run_name}-brief.html"


def download_run(run_name: str, fmt: str) -> tuple[int, bytes, str, str]:
    """(status, body, content_type, filename) for one run in one format.

    json and sarif are served straight off disk — they are already written by the
    report writer, and re-generating them here would let the download drift from what
    the scan actually produced. Markdown is rendered on demand because nothing needs
    it until someone asks.
    """
    from docket.core.paths import runs_root
    from docket.report.markdown import render_markdown

    if fmt == "brief":
        return _download_brief(run_name)
    if fmt not in DOWNLOAD_FORMATS:
        return 400, b'{"error":"format must be json, sarif or md"}', "application/json", ""
    if not run_name or not _RUN_NAME.match(run_name):
        return 400, b'{"error":"bad run name"}', "application/json", ""

    root = runs_root().resolve()
    directory = (root / run_name).resolve()
    # Same containment check as load_run: the name comes from the browser and is
    # joined onto a filesystem path.
    # `in .parents`, NOT a string prefix: "<root>-other/x" shares a prefix with
    # "<root>" and is a different directory. Proven against the viewer already.
    if root not in directory.parents or not directory.is_dir():
        return 404, b'{"error":"no such run"}', "application/json", ""

    filename, content_type = DOWNLOAD_FORMATS[fmt]
    if filename:
        path = directory / filename
        if not path.is_file():
            return 404, b'{"error":"not written for this run"}', "application/json", ""
        return 200, path.read_bytes(), content_type, f"{run_name}-{filename}"

    report = directory / "report.json"
    if not report.is_file():
        return 404, b'{"error":"no report.json"}', "application/json", ""
    try:
        rendered = render_markdown(json.loads(report.read_text()))
    except (OSError, json.JSONDecodeError) as exc:
        return 500, f'{{"error":"unreadable report: {exc}"}}'.encode(), "application/json", ""
    return 200, rendered.encode(), content_type, f"{run_name}.md"


def load_run(run_name: str) -> tuple[int, dict[str, Any]]:
    """(status, payload) for one finished run, shaped like a ScanState so the console
    can render a reloaded run through exactly the same components as a live one."""
    from docket.core.paths import runs_root

    if not run_name or not _RUN_NAME.match(run_name):
        return 400, {"error": "bad run name"}
    # Resolved and containment-checked: run_name comes from the browser and is joined
    # onto a filesystem path, so a traversal here would read arbitrary files.
    root = runs_root().resolve()
    report = (root / run_name / "report.json").resolve()
    if root not in report.parents or not report.is_file():
        return 404, {"error": f"no run named {run_name}"}
    try:
        data = json.loads(report.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        return 500, {"error": f"unreadable report: {exc}"}

    target = str(data.get("target") or "")
    repo, _, ref = target.removeprefix("github:").partition("@")
    totals = (data.get("usage") or {}).get("totals") or {}
    return 200, {
        "id": run_name,
        "repo": repo or target or run_name,
        "ref": ref or None,
        "status": "done",
        # A finished run says nothing about which scanners were skipped, and inventing
        # stages would put lit rings on the radar that never ran. "done" everywhere is
        # the honest rendering of "this is history, not a live scan".
        "stages": {},
        "findings": data.get("findings", []),
        "finding_count": data.get("finding_count", 0),
        "error": None,
        "summary": data.get("summary", ""),
        "surface": data.get("surface") or None,
        # Coverage and spend are in the report and must survive a reload. Without them
        # the console showed "not recorded" and "$0.0000" for a run that recorded both,
        # which reads as "nothing was analysed and nothing was spent" — the two claims
        # a security report can least afford to get wrong.
        "coverage": data.get("coverage") or None,
        "agents": data.get("agents") or [],
        "cost_usd": round(totals.get("cost_usd", 0.0), 4),
        "input_tokens": totals.get("input_tokens", 0),
        "output_tokens": totals.get("output_tokens", 0),
        "budget_usd": 0.0,  # the live cap; a finished run was not bounded by today's
        "historical": True,
    }


def make_handler() -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _send(self, status: int, body: bytes, content_type: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _json(self, status: int, payload: Any) -> None:
            self._send(status, json.dumps(payload, default=str).encode(), "application/json")

        def _redirect(self, location: str) -> None:
            self.send_response(302)
            self.send_header("Location", location)
            self.send_header("Content-Length", "0")
            self.end_headers()

        # -- routes ----------------------------------------------------------------

        def do_GET(self) -> None:  # noqa: N802 — stdlib naming
            parsed = urllib.parse.urlparse(self.path)
            path, query = parsed.path, urllib.parse.parse_qs(parsed.query)

            if path.startswith("/assets/") or path in ("/favicon.ico", "/favicon.svg"):
                self._static(path)
            elif path == "/api/runs":
                self._json(200, {"runs": list_runs()})
            elif path.startswith("/api/download/"):
                rest = path[len("/api/download/"):]
                name, _, fmt = rest.rpartition(".")
                status, body, ctype, filename = download_run(name, fmt)
                self.send_response(status)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                if status == 200 and filename:
                    # Machine formats download; the brief opens in the tab. It is a
                    # document meant to be READ, and print-to-PDF from the browser is
                    # how it becomes something you send on — forcing a save first just
                    # adds a step before every one of those.
                    disposition = "inline" if fmt == "brief" else "attachment"
                    self.send_header("Content-Disposition",
                                     f'{disposition}; filename="{filename}"')
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(body)
            elif path.startswith("/api/run/"):
                # A finished run, rehydrated from disk. The console keeps its live scan
                # in memory only, so without this a reload loses everything — even
                # though report.json has been sitting there the whole time.
                self._json(*load_run(path[len("/api/run/"):]))
            elif path == "/api/session":
                self._json(200, {
                    "connected": SESSION.token is not None,
                    "login": SESSION.login,
                    "configured": oauth_config() is not None,
                    # Shown in the console so the granted scope is visible on screen
                    # rather than buried in a config file nobody rereads.
                    "scope": oauth_scope(),
                })
            elif path == "/auth/start":
                self._auth_start()
            elif path == "/auth/callback":
                self._auth_callback(query)
            elif path == "/api/repos":
                self._repos()
            elif path == "/api/scans/active":
                self._json(200, {"scans": active_scans()})
            elif path.startswith("/api/scan/"):
                scan_id = path.rsplit("/", 1)[-1]
                with SESSION.lock:
                    state = SESSION.scans.get(scan_id)
                    # Refreshed inside the lock: a live scan mutates this dict from
                    # its own thread while the handler serialises it.
                    if state is not None and state.get("status") in LIVE_STATUSES:
                        _merge_live_usage(state)
                    payload = dict(state) if state else None
                self._json(200 if payload else 404, payload or {"error": "unknown scan"})
            elif path.startswith("/api/") or path.startswith("/auth/"):
                self._json(404, {"error": "no such endpoint"})
            else:
                # Everything else is a client-side route: serve the SPA shell and let
                # the router decide, so a deep link or a refresh does not 404.
                self._static("/index.html")

        def do_POST(self) -> None:  # noqa: N802 — stdlib naming
            post_path = urllib.parse.urlparse(self.path).path
            if post_path == "/api/scan/cancel":
                self._cancel_scan()
                return
            if post_path != "/api/scan":
                self._send(404, b"not found", "text/plain")
                return
            if SESSION.token is None:
                self._json(401, {"error": "not connected to GitHub"})
                return
            length = int(self.headers.get("Content-Length", "0"))
            try:
                body = json.loads(self.rfile.read(length) or b"{}")
            except json.JSONDecodeError:
                self._json(400, {"error": "body must be JSON"})
                return
            full_name = str(body.get("repo", "")).strip()
            if not _FULL_NAME.match(full_name):
                self._json(400, {"error": "repo must look like owner/name"})
                return
            ref = str(body.get("ref", "")).strip() or None
            if ref is not None and not valid_ref(ref):
                self._json(400, {"error": f"not a usable branch/tag/sha: {ref}"})
                return
            # Validated, not capped: a non-number or a negative would break the loop
            # rather than cost money, so it is refused. How MANY is the operator's call.
            try:
                triage_max = int(body.get("triage_max") or 0)
            except (TypeError, ValueError):
                self._json(400, {"error": "triage_max must be a whole number"})
                return
            if triage_max < 0:
                self._json(400, {"error": "triage_max cannot be negative"})
                return
            # Triage spawns real LLM agents, so refuse early with a clear reason
            # rather than starting a scan that dies partway. Config.from_env() is what
            # loads .env, so asking it beats reading os.environ directly — an earlier
            # version did the latter and refused on a correctly-configured machine.
            # A ceiling in dollars, not a count. This is the only control that bounds
            # an AI phase by the thing actually worth bounding — triage_max caps how
            # many findings are judged, but says nothing about what each one costs.
            budget_usd: float | None = None
            if body.get("budget_usd") not in (None, ""):
                try:
                    budget_usd = float(body["budget_usd"])
                except (TypeError, ValueError):
                    self._json(400, {"error": "budget_usd must be a number"})
                    return
                if budget_usd <= 0:
                    self._json(400, {"error": "budget_usd must be greater than zero"})
                    return

            recon = bool(body.get("recon"))
            if triage_max or recon:
                try:
                    from docket.config.settings import Config

                    Config.from_env()
                except Exception as exc:
                    self._json(400, {"error": f"AI agents need a model configured: {exc}"})
                    return

            from docket.core.cancel import CancelToken

            scan_id = secrets.token_hex(8)
            token = CancelToken()
            with SESSION.lock:
                SESSION.scans[scan_id] = new_scan_state(scan_id, full_name, ref,
                                                        triage_max, recon, budget_usd)
                SESSION.cancels[scan_id] = token
            threading.Thread(
                target=run_repo_scan,
                args=(full_name, SESSION.token, scan_id, ref, triage_max, recon, token,
                      budget_usd),
                name=f"docket-scan-{scan_id}", daemon=True,
            ).start()
            self._json(202, {"id": scan_id, "status": "queued"})

        def _cancel_scan(self) -> None:
            """Ask the running scan to stop at its next checkpoint.

            202, not 200: the scan has not stopped when this returns, it has been
            asked to. Reporting a stop that has not happened yet is how a UI ends up
            showing "stopped" over a scanner that is still burning CPU.
            """
            length = int(self.headers.get("Content-Length", "0"))
            try:
                body = json.loads(self.rfile.read(length) or b"{}")
            except json.JSONDecodeError:
                body = {}
            scan_id = str(body.get("id", "")).strip()
            with SESSION.lock:
                # No id means "whatever is running", which is what the Stop button
                # sends: the console only ever shows one live scan.
                if not scan_id:
                    scan_id = next(
                        (k for k, v in SESSION.scans.items()
                         if v.get("status") in ("queued", "fetching", "scanning")),
                        "",
                    )
                token = SESSION.cancels.get(scan_id)
                state = SESSION.scans.get(scan_id)
            if token is None or state is None:
                self._json(404, {"error": "no scan is running"})
                return
            if state.get("status") in ("done", "error", "cancelled"):
                self._json(409, {"error": f"scan already {state['status']}"})
                return
            token.cancel("stopped by the operator")
            self._json(202, {"id": scan_id, "status": "cancelling"})

        # -- handlers --------------------------------------------------------------

        def _static(self, path: str) -> None:
            """Serve the Vite build. Resolved and containment-checked: this reads from
            a directory path derived from the URL, so a traversal here would hand out
            arbitrary files from the operator's machine."""
            dist = frontend_dist()
            index = dist / "index.html"
            if not index.is_file():
                self._send(200, _NOT_BUILT, "text/html; charset=utf-8")
                return
            target = (dist / path.lstrip("/")).resolve()
            if not str(target).startswith(str(dist.resolve())) or not target.is_file():
                if path == "/index.html":
                    self._send(200, _NOT_BUILT, "text/html; charset=utf-8")
                else:
                    self._send(404, b"not found", "text/plain")
                return
            self._send(200, target.read_bytes(),
                       _MIME.get(target.suffix, "application/octet-stream"))

        def _auth_start(self) -> None:
            config = oauth_config()
            if config is None:
                self._json(503, {
                    "error": "GitHub is not configured",
                    "detail": "Set DOCKET_GITHUB_CLIENT_ID and DOCKET_GITHUB_CLIENT_SECRET.",
                })
                return
            client_id, _, redirect = config
            # CSRF: an attacker who can make the browser hit /auth/callback with their
            # own code would otherwise bind THEIR GitHub account to this session.
            state = secrets.token_urlsafe(24)
            SESSION.oauth_state = state
            params = {"client_id": client_id, "state": state, "scope": oauth_scope()}
            if redirect:
                params["redirect_uri"] = redirect
            self._redirect(f"{GITHUB_AUTHORIZE}?{urllib.parse.urlencode(params)}")

        def _auth_callback(self, query: dict[str, list[str]]) -> None:
            expected, SESSION.oauth_state = SESSION.oauth_state, None
            state = (query.get("state") or [""])[0]
            if not expected or not secrets.compare_digest(state, expected):
                self._json(400, {"error": "state mismatch — restart the connection"})
                return
            code = (query.get("code") or [""])[0]
            if not code:
                self._json(400, {"error": "no code in callback"})
                return
            token, error = exchange_code(code)
            if error:
                self._json(502, {"error": error})
                return
            SESSION.token = token
            try:
                SESSION.login = (_api("/user", token) or {}).get("login")
            except urllib.error.URLError:
                SESSION.login = None
            self._redirect("/?connected=1")

        def _repos(self) -> None:
            if SESSION.token is None:
                self._json(401, {"error": "not connected to GitHub"})
                return
            try:
                repos = list_repos(SESSION.token)
            except urllib.error.HTTPError as exc:
                self._json(502, {"error": f"GitHub API {exc.code}"})
                return
            self._json(200, {"repos": [
                {
                    "full_name": r.get("full_name"),
                    "private": r.get("private"),
                    "language": r.get("language"),
                    "updated_at": r.get("updated_at"),
                }
                for r in repos
            ]})

        def log_message(self, fmt: str, *args) -> None:
            pass

    return Handler


def start_server(port: int = 8765) -> ThreadingHTTPServer:
    # Must happen on the main thread: signal.signal() refuses anywhere else, and a
    # console killed mid-scan is exactly when the sandbox needs reaping.
    try:
        from docket.runtime.sandbox import install_cleanup

        install_cleanup()
    except Exception:  # noqa: BLE001 — no docker is not a reason to refuse to serve
        logger.debug("sandbox cleanup hook not installed", exc_info=True)
    """Loopback only. The OAuth client secret lives in this process; binding it to a
    public interface would expose an unauthenticated scan trigger to the network."""
    return ThreadingHTTPServer(("127.0.0.1", port), make_handler())


def serve(port: int = 8765) -> int:
    from docket.interface.cli_args import EXIT_CLEAN

    server = start_server(port)
    actual = server.server_address[1]
    print(f"docket console: http://127.0.0.1:{actual}")
    if oauth_config() is None:
        print("warning: DOCKET_GITHUB_CLIENT_ID / DOCKET_GITHUB_CLIENT_SECRET are unset —")
        print("         the console loads but Connect GitHub will refuse. Register a GitHub App")
        print("         with 'Contents: read' + 'Metadata: read', callback")
        print(f"         http://127.0.0.1:{actual}/auth/callback, then export both values.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print()
    finally:
        server.shutdown()
    return EXIT_CLEAN


def demo() -> None:
    import threading as _threading

    # 1. Repo-name validation is the guard in front of every URL and path built below.
    for bad in ("../../etc/passwd", "owner/repo/../..", "https://evil.test/x",
                "owner", "", "owner/repo extra", "-flag/repo\nx"):
        assert not _FULL_NAME.match(bad), bad
    for good in ("punya-henoyo/Docket", "a/b", "org.name/repo_1.2-3"):
        assert _FULL_NAME.match(good), good

    state = new_scan_state("abc", "o/r")
    assert state["status"] == "queued" and state["finding_count"] == 0
    assert state["ref"] is None  # None means "whatever GitHub calls the default"
    assert set(state["stages"]) == {"fetch", "trivy", "semgrep", "nuclei", "recon", "triage"}
    # Both AI phases cost real money per run, so both are opt-in and neither can be
    # switched on by a caller that simply forgot to pass a flag.
    assert state["triage_max"] == 0, "triage costs money, so it must be opt-in"
    assert state["recon"] is False, "recon costs money, so it must be opt-in"
    assert state["surface"] is None, "no surface until an agent actually maps one"
    assert new_scan_state("abc", "o/r", None, 0, True)["recon"] is True
    assert new_scan_state("abc", "o/r", "feat/x")["ref"] == "feat/x"
    assert new_scan_state("abc", "o/r", None, 5)["triage_max"] == 5

    # Refs are interpolated into the same API path as the repo name, so they get the
    # same scrutiny. Slashes ARE legal here, which is why this is a separate check.
    for good in ("main", "feat/new-ui", "v1.2.3", "release/2026.08", "a1b2c3d4"):
        assert valid_ref(good), good
    for bad in ("../../etc/passwd", "-rf", "feat//x", "feat/", "", "a b",
                "main;rm -rf /", "..", "/abs"):
        assert not valid_ref(bad), bad

    # A reloaded run must carry coverage and spend. Dropping them showed "not recorded"
    # and "$0.0000" for a run that recorded both — silently, because a missing key
    # renders as a plausible zero rather than as an error.
    import tempfile as _tempfile
    with _tempfile.TemporaryDirectory() as tmp:
        from docket.core import paths as _paths
        _orig = _paths.runs_root
        _root = Path(tmp)
        _paths.runs_root = lambda: _root  # type: ignore[assignment]
        try:
            (_root / "connect-1").mkdir()
            (_root / "connect-1" / "report.json").write_text(json.dumps({
                "run_name": "connect-1", "target": "github:o/r@main", "finding_count": 1,
                "findings": [{"id": "f1"}],
                "coverage": {"semgrep": {"files_scanned": 3}},
                "usage": {"totals": {"input_tokens": 35773, "output_tokens": 2368,
                                     "cost_usd": 0.077928}},
            }))
            listed = list_runs()
            assert len(listed) == 1 and listed[0]["cost_usd"] == 0.0779, listed
            code, run = load_run("connect-1")
            assert code == 200, (code, run)
            assert run["repo"] == "o/r" and run["ref"] == "main", run
            assert run["coverage"]["semgrep"]["files_scanned"] == 3, run["coverage"]
            assert run["input_tokens"] == 35773 and run["output_tokens"] == 2368, run
            assert run["cost_usd"] == 0.0779, run["cost_usd"]
            # Traversal is rejected before any read.
            assert load_run("../../etc")[0] == 400
            assert load_run("connect-missing")[0] == 404
        finally:
            _paths.runs_root = _orig  # type: ignore[assignment]

    saved = {k: os.environ.pop(k, None)
             for k in ("DOCKET_GITHUB_CLIENT_ID", "DOCKET_GITHUB_CLIENT_SECRET")}
    # oauth_config() now reads .env on every call, so popping the keys is not enough: a
    # real developer .env puts them straight back and BOTH branches below would assert
    # against whatever happens to be on this machine. Stub the loader for the duration —
    # what is under test here is how the two variables are read, not where they came from.
    # Without this the self-check passed only on a machine with no GitHub App configured,
    # which is the one machine where it proves the least.
    real_load_dotenv = globals()["load_dotenv"]
    globals()["load_dotenv"] = lambda *a, **k: None
    try:
        assert oauth_config() is None
        token, error = exchange_code("irrelevant")
        assert token is None and "CLIENT_ID" in error, (token, error)

        os.environ["DOCKET_GITHUB_CLIENT_ID"] = "iv1.test"
        os.environ["DOCKET_GITHUB_CLIENT_SECRET"] = "shh"
        assert oauth_config()[:2] == ("iv1.test", "shh")

        server = start_server(port=0)
        base = f"http://127.0.0.1:{server.server_address[1]}"
        _threading.Thread(target=server.serve_forever, daemon=True).start()

        # "/" serves the built SPA, or a build-me page when dist/ is absent. Either
        # way it is HTML and mentions docket — never a 404.
        page = urllib.request.urlopen(base + "/", timeout=5).read().decode()
        assert "docket" in page.lower(), page[:200]
        # An unknown non-API path is a client-side route, not a 404.
        deep = urllib.request.urlopen(base + "/findings", timeout=5).read().decode()
        assert "docket" in deep.lower(), deep[:200]
        # ...but an unknown API path still 404s rather than returning HTML.
        try:
            urllib.request.urlopen(base + "/api/nonsense", timeout=5)
            raise AssertionError("unknown API path must 404")
        except urllib.error.HTTPError as exc:
            assert exc.code == 404, exc.code

        # ── live usage is joined on READ, not only on write ───────────────────
        # The bug this guards: during recon nothing calls snapshot() for minutes, so
        # a state written once at agent-start kept reporting 0 turns and $0.0000 for
        # the whole run while the agent was plainly spending money.
        from docket.report.state import get_global_report_state

        ledger = get_global_report_state().usage

        from agents.usage import Usage

        ledger.record(
            "recon",
            Usage(requests=4, input_tokens=900, output_tokens=60, total_tokens=960),
            cost_usd=0.05, role="recon", model="m",
        )
        live = {"status": "scanning", "agents": [{"id": "recon", "role": "recon"}]}
        merged = _merge_live_usage(live)
        assert merged["agents"][0]["turns"] == 4, merged
        assert merged["agents"][0]["cost_usd"] == 0.05, merged
        assert merged["cost_usd"] >= 0.05 and merged["input_tokens"] >= 900, merged
        # An agent the ledger has never seen keeps whatever it had rather than being
        # zeroed — absence of a row means "no turn charged yet", not "0 turns".
        untouched = _merge_live_usage({"agents": [{"id": "triage-9", "turns": 3}]})
        assert untouched["agents"][0]["turns"] == 3, untouched

        # ── cancel ────────────────────────────────────────────────────────────
        def post(path: str, payload: dict) -> tuple[int, dict]:
            request = urllib.request.Request(
                base + path, data=json.dumps(payload).encode(),
                headers={"Content-Type": "application/json"}, method="POST")
            try:
                with urllib.request.urlopen(request, timeout=5) as response:
                    return response.status, json.loads(response.read() or b"{}")
            except urllib.error.HTTPError as exc:
                return exc.code, json.loads(exc.read() or b"{}")

        # Nothing running: a 404, never a cheerful 202 for a stop that stopped nothing.
        code, payload = post("/api/scan/cancel", {})
        assert code == 404, (code, payload)

        from docket.core.cancel import CancelToken

        SESSION.scans["fake"] = new_scan_state("fake", "o/r")
        SESSION.scans["fake"]["status"] = "scanning"
        SESSION.cancels["fake"] = CancelToken()
        try:
            # No id means "whatever is running", which is what the Stop button sends.
            code, payload = post("/api/scan/cancel", {})
            assert code == 202 and payload["id"] == "fake", (code, payload)
            assert SESSION.cancels["fake"].cancelled
            # 202 is "asked to stop", not "stopped" — the status must NOT have been
            # flipped by the handler, only by the scan thread reaching a checkpoint.
            assert SESSION.scans["fake"]["status"] == "scanning", "handler must not lie"

            SESSION.scans["fake"]["status"] = "done"
            code, _ = post("/api/scan/cancel", {"id": "fake"})
            assert code == 409, code  # cannot stop what already finished
        finally:
            SESSION.scans.pop("fake", None)
            SESSION.cancels.pop("fake", None)

        # ── a 404 from GitHub must say WHICH 404 ──────────────────────────────
        # GitHub returns 404 for a missing ref, a repo the token cannot see, and a
        # repo that does not exist, and deliberately will not distinguish them. The
        # raw "HTTP Error 404: Not Found" left the operator with no idea which.
        import urllib.error as _ue

        def _fetch_404(ref_value):
            def _raise(*_a, **_k):
                raise _ue.HTTPError("u", 404, "Not Found", {}, None)
            saved = urllib.request.urlopen
            urllib.request.urlopen = _raise
            try:
                fetch_source("o/r", "tok", Path(_tempfile.mkdtemp()), ref_value)
            except RuntimeError as exc:
                return str(exc)
            finally:
                urllib.request.urlopen = saved
            raise AssertionError("a 404 must not pass silently")

        with_ref = _fetch_404("nope")
        assert "o/r@nope" in with_ref and "does not exist" in with_ref, with_ref
        assert "not 403" in with_ref, "the private-repo case must be named"
        no_ref = _fetch_404(None)
        assert "default branch" not in no_ref, "no ref means no ref to blame"
        assert "the name is wrong" in no_ref, no_ref

        # ── per-scan budget ───────────────────────────────────────────────────
        # Validated, not clamped: the operator chooses the ceiling. Refusing a
        # nonsense value beats silently substituting one, because a budget the caller
        # did not set is a budget nobody is watching.
        assert new_scan_state("s", "o/r", None, 0, False, 0.5)["requested_budget_usd"] == 0.5
        assert new_scan_state("s", "o/r")["requested_budget_usd"] == 0.0

        # /api/scan refuses an unconnected session before it validates anything, so
        # a token has to exist for the validation path to be reachable at all.
        SESSION.token = "test-token"
        try:
            for bad in ("abc", -1, 0):
                code, payload = post("/api/scan", {"repo": "o/r", "budget_usd": bad})
                assert code == 400, (bad, code, payload)
                assert "budget_usd" in payload.get("error", ""), payload
        finally:
            SESSION.token = None

        # A per-scan ceiling must reach the config the pre-turn gate reads, or it is
        # a label on a dashboard rather than a control.
        from dataclasses import replace as _replace

        from docket.config.settings import Config as _Config

        _base = _Config(llm="m", llm_api_key=None, max_cost_usd=2.0,
                        max_child_cost_usd=0.75, max_agents=6)
        _capped = _replace(_base, max_cost_usd=0.25,
                           max_child_cost_usd=min(_base.max_child_cost_usd, 0.25))
        assert _capped.max_cost_usd == 0.25
        # A child reserve larger than the whole scan budget would let one agent
        # consume more than the operator allowed for everything.
        assert _capped.max_child_cost_usd <= _capped.max_cost_usd

        # ── a running scan must always be findable ────────────────────────────
        # The console held the only reference to a live scan in browser state, so
        # opening a historical run replaced it and the scan became unreachable while
        # still running and still spending.
        assert active_scans() == []
        SESSION.scans["live1"] = new_scan_state("live1", "o/r")
        SESSION.scans["live1"]["status"] = "scanning"
        SESSION.scans["old1"] = new_scan_state("old1", "o/r")
        SESSION.scans["old1"]["status"] = "done"
        try:
            listed = json.loads(
                urllib.request.urlopen(base + "/api/scans/active", timeout=5).read()
            )["scans"]
            assert [s["id"] for s in listed] == ["live1"], listed
            assert listed[0]["repo"] == "o/r"
            # Every non-terminal status counts, or a scan stuck in "queued" would be
            # just as unreachable as before.
            for status in LIVE_STATUSES:
                SESSION.scans["live1"]["status"] = status
                assert len(active_scans()) == 1, status
            for status in ("done", "error", "cancelled"):
                SESSION.scans["live1"]["status"] = status
                assert active_scans() == [], status
        finally:
            SESSION.scans.pop("live1", None)
            SESSION.scans.pop("old1", None)

        runs = json.loads(urllib.request.urlopen(base + "/api/runs", timeout=5).read())
        assert isinstance(runs.get("runs"), list), runs

        session = json.loads(urllib.request.urlopen(base + "/api/session", timeout=5).read())
        assert session["configured"] is True and session["connected"] is False, session
        assert session["scope"] == "repo", session

        # The scope MUST reach the authorize URL. Without it GitHub issues a token that
        # can read nothing private, and the failure looks identical to "this user has
        # no repositories" — which is exactly the dead end that killed the App path.
        opener = urllib.request.build_opener(_NoRedirect())
        try:
            opener.open(base + "/auth/start", timeout=5)
            raise AssertionError("expected a redirect")
        except urllib.error.HTTPError as exc:
            assert "scope=repo" in exc.headers["Location"], exc.headers["Location"]

        os.environ["DOCKET_GITHUB_SCOPE"] = "public_repo"
        try:
            assert oauth_scope() == "public_repo"
        finally:
            os.environ.pop("DOCKET_GITHUB_SCOPE", None)
        assert oauth_scope() == "repo", "unset must default to repo, not empty"

        # 2. /auth/start redirects to GitHub and plants a CSRF state.
        opener = urllib.request.build_opener(_NoRedirect())
        try:
            opener.open(base + "/auth/start", timeout=5)
            raise AssertionError("expected a redirect")
        except urllib.error.HTTPError as exc:
            assert exc.code == 302, exc.code
            location = exc.headers["Location"]
        assert location.startswith(GITHUB_AUTHORIZE), location
        assert SESSION.oauth_state and SESSION.oauth_state in location

        # 3. A callback whose state does not match is refused (CSRF).
        for bad_state in ("", "not-the-state"):
            try:
                urllib.request.urlopen(f"{base}/auth/callback?code=x&state={bad_state}", timeout=5)
                raise AssertionError("bad state must be refused")
            except urllib.error.HTTPError as exc:
                assert exc.code == 400, exc.code
        assert SESSION.oauth_state is None, "state must be single-use"

        # 4. Scanning without a connection is refused rather than half-attempted.
        for path, method in (("/api/repos", "GET"), ("/api/scan", "POST")):
            request = urllib.request.Request(
                base + path, method=method,
                data=b'{"repo":"a/b"}' if method == "POST" else None,
            )
            try:
                urllib.request.urlopen(request, timeout=5)
                raise AssertionError(f"{path} must require a connection")
            except urllib.error.HTTPError as exc:
                assert exc.code == 401, (path, exc.code)

        # 5. With a token present, a malformed repo name or ref never reaches the network.
        SESSION.token = "fake"
        try:
            urllib.request.urlopen(urllib.request.Request(
                base + "/api/scan", data=b'{"repo":"a/b","ref":"../../etc/passwd"}',
                method="POST"), timeout=5)
            raise AssertionError("bad ref must be rejected")
        except urllib.error.HTTPError as exc:
            assert exc.code == 400, exc.code
        try:
            urllib.request.urlopen(urllib.request.Request(
                base + "/api/scan", data=b'{"repo":"../../etc/passwd"}', method="POST"), timeout=5)
            raise AssertionError("bad repo name must be rejected")
        except urllib.error.HTTPError as exc:
            assert exc.code == 400, exc.code
        SESSION.token = None

        # 6. Polling an unknown scan id is a 404, not an empty "still running".
        try:
            urllib.request.urlopen(base + "/api/scan/nope", timeout=5)
            raise AssertionError("unknown scan id must 404")
        except urllib.error.HTTPError as exc:
            assert exc.code == 404, exc.code

        server.shutdown()
    finally:
        globals()["load_dotenv"] = real_load_dotenv
        for key, value in saved.items():
            if value is not None:
                os.environ[key] = value
            else:
                os.environ.pop(key, None)
        SESSION.token = SESSION.login = SESSION.oauth_state = None
    print("interface.connect: ok")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # noqa: ANN002, ANN003
        return None


if __name__ == "__main__":
    demo()
