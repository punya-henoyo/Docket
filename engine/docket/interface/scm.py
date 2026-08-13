"""GitHub App client: the only place docket WRITES to a repository.

WHY AN APP AND NOT THE OAUTH APP
--------------------------------
interface/connect.py is an OAuth App on purpose (read its docstring: a collaborator can
connect a repo nobody has to install anything into). It stays exactly as it is, for human
login. It cannot do this job: GitHub states plainly that "to create a check run, you must
use a GitHub App. OAuth apps and authenticated users are not able to create a check
suite." A service that puts a check on a pull request therefore needs App credentials,
and `connect._api()` is GET-only by construction anyway — no `data=`, no `method=`, no
argument a caller could pass. This module is the write half, and nothing else writes.

CAPABILITY BY OMISSION — READ THIS BEFORE ADDING A METHOD
--------------------------------------------------------
There is deliberately NO `force` parameter anywhere, NO merge method, NO review-approve
method and NO delete-ref method. Not "disabled by default", not "behind a flag": absent.
The same reasoning as agents/factory.py, which gives the triage role no network tools
instead of trusting it not to probe — a capability that does not exist cannot be reached
by a bug, a prompt injection in a diff, or a caller in a hurry. Docket's whole claim is
that it proposes changes and never lands them; a `force=True` on an update-ref, or one
merge call, silently converts it into a tool that can destroy someone's branch. If you
believe you need one of those, you need a design review, not this file. tests/test_scm.py
asserts the absence structurally, so adding one fails the suite rather than the review.

WRITES ARE GUARDED HERE, NOT AT THE CALL SITES
----------------------------------------------
1. every write first checks repo_permissions()["push"] — connect.list_repos() asks for
   `affiliation=owner,collaborator,organization_member`, which routinely returns repos
   the user only has `pull` on, so an ungated write 403s halfway through a flow
2. create_branch refuses the default branch and any protected branch
3. create_branch treats "ref already exists" as adoption when the SHA matches and as a
   distinguishable stale error when it does not — a re-run must find its own branch
4. commit_files takes FileChange objects only, refuses CI/secret-shaped paths, and
   refuses any git mode other than a plain file (no symlinks, no submodules)
"""
from __future__ import annotations

import base64
import fnmatch
import json
import logging
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any

from dotenv import load_dotenv

from docket.tools.source_read.tools import SourceAccessError, resolve_in_root

logger = logging.getLogger(__name__)

GITHUB_API = "https://api.github.com"

# Duplicated from connect.py rather than imported: connect pulls in the scanners and the
# frontend path helper, and this module is imported by the service loop. Same regexes,
# same reason — both values are interpolated into an api.github.com path, so a stray
# "../" or a scheme here would be a path-traversal / SSRF primitive.
_FULL_NAME = re.compile(r"^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$")
_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]*$")

# GitHub rejects more than 50 annotations in one check-run request. Batching lives in
# create_check_run/update_check_run so no caller can silently truncate a finding list.
ANNOTATION_LIMIT = 50

# GitHub's closed set. Sending anything else is a 422 after the work is done.
CONCLUSIONS = ("success", "failure", "neutral", "cancelled", "timed_out",
               "action_required", "skipped")

# Paths a fix commit must never touch, matched per path component with fnmatch. CI
# config is remote code execution on someone else's runner; the rest are credentials.
DENIED_PATH_PARTS = (".github", ".git", ".circleci", "Jenkinsfile", ".gitlab-ci.yml",
                     ".env*", "*.pem", "*.key", "id_rsa*", "*.p12")

# Plain file and executable file. NOT 120000 (symlink) or 160000 (gitlink/submodule):
# either would let a "text file" commit point at /etc/passwd or an arbitrary repo.
_MODES = ("100644", "100755")

_JWT_TTL_SECONDS = 540  # GitHub's ceiling is 600
_TOKEN_SKEW_SECONDS = 60


class ScmError(RuntimeError):
    """A refusal or a failed call. `code` is stable and meant to be branched on.

    Codes used: bad_repo · bad_ref · bad_change · refused_path · repo_read_only ·
    default_branch · branch_protected · branch_stale · base_commit_stale · app_auth ·
    missing_dependency · not_configured · http · network.
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class AppConfig:
    app_id: str
    private_key: str = field(repr=False)  # repr=False so no traceback ever prints a key
    installation_id: str


@dataclass(frozen=True, slots=True)
class FileChange:
    """One file in a fix commit. `content=None` means read it from a filesystem root."""

    path: str
    content: str | None = None
    mode: str = "100644"


def app_config() -> AppConfig | None:
    """App credentials from the environment, or None when unconfigured.

    Reads .env on every call, like connect.oauth_config() does and for the same reason:
    a long-lived server that loaded .env once at import reports its boot-time state
    forever, so configuring credentials and restarting nothing looks like a silent
    failure with no error anywhere to explain it.
    """
    load_dotenv(override=True)
    app_id = os.environ.get("DOCKET_GITHUB_APP_ID", "").strip()
    installation_id = os.environ.get("DOCKET_GITHUB_APP_INSTALLATION_ID", "").strip()
    key = os.environ.get("DOCKET_GITHUB_APP_PRIVATE_KEY", "").strip()
    if not key:
        key_path = os.environ.get("DOCKET_GITHUB_APP_PRIVATE_KEY_PATH", "").strip()
        if key_path:
            try:
                key = Path(key_path).expanduser().read_text()
            except OSError as exc:
                raise ScmError("not_configured",
                               f"DOCKET_GITHUB_APP_PRIVATE_KEY_PATH is set but unreadable: {exc}")
    # A PEM pasted into .env arrives with literal backslash-n.
    key = key.replace("\\n", "\n").strip()
    if not (app_id and installation_id and key):
        return None
    return AppConfig(app_id, key, installation_id)


def _checked_repo(repo: str) -> str:
    if not _FULL_NAME.match(repo or ""):
        raise ScmError("bad_repo", f"not an owner/repo name: {repo!r}")
    return repo


def _checked_ref(ref: str) -> str:
    ok = bool(_REF.match(ref or "")) and ".." not in ref and not ref.endswith("/") and "//" not in ref
    if not ok:
        raise ScmError("bad_ref", f"not a usable git ref: {ref!r}")
    return ref


def _checked_path(path: str) -> str:
    """A repo-relative path a fix commit is allowed to write, or ScmError."""
    raw = str(path or "").strip()
    if not raw or raw.startswith(("/", "\\")):
        raise ScmError("refused_path", f"path must be relative to the repo root: {path!r}")
    parts = PurePosixPath(raw).parts
    if not parts or ".." in parts:
        raise ScmError("refused_path", f"path escapes the repo root: {path!r}")
    for part in parts:
        for pattern in DENIED_PATH_PARTS:
            if fnmatch.fnmatch(part, pattern):
                raise ScmError(
                    "refused_path",
                    f"refused: {raw!r} touches {part!r}, which is CI config or a "
                    "credential file. Docket does not write those, ever.",
                )
    return "/".join(parts)


def _epoch(value: object) -> float:
    """GitHub's ISO-8601 Z timestamp as a unix float, or 0.0."""
    try:
        return datetime.fromisoformat(str(value)).timestamp()
    except (TypeError, ValueError):
        return 0.0


def _app_jwt(config: AppConfig, now: float) -> str:
    """RS256 JWT for /app endpoints. PyJWT does the signing.

    PyJWT ships transitively via `mcp` (a hard dependency of openai-agents), which pins
    `pyjwt[crypto]`, so `cryptography` is present too. Nothing is added to pyproject.
    If either ever disappears this raises missing_dependency by name instead of failing
    somewhere further in with an opaque error.
    """
    try:
        import jwt  # PyJWT
    except ModuleNotFoundError as exc:
        raise ScmError(
            "missing_dependency",
            "GitHub App auth needs RS256 JWT signing. PyJWT is missing — it normally "
            "arrives via mcp -> pyjwt[crypto]. Install \"pyjwt[crypto]\" (which pulls "
            "cryptography) to use the service.",
        ) from exc
    payload = {"iat": int(now) - _TOKEN_SKEW_SECONDS,
               "exp": int(now) + _JWT_TTL_SECONDS,
               "iss": config.app_id}
    try:
        return jwt.encode(payload, config.private_key, algorithm="RS256")
    except Exception as exc:  # bad PEM, or PyJWT without the crypto extra
        # Deliberately only the exception TYPE: some key-loading errors echo input.
        raise ScmError(
            "app_auth",
            f"could not sign the App JWT ({type(exc).__name__}). Check "
            "DOCKET_GITHUB_APP_PRIVATE_KEY holds the full PEM and that cryptography "
            "is installed (pyjwt[crypto]).",
        ) from exc


def _https_transport(method: str, url: str, body: bytes | None,
                     headers: dict[str, str]) -> tuple[int, Any]:
    request = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.status, json.loads(response.read() or b"null")
    except urllib.error.HTTPError as exc:
        raw = exc.read() or b"{}"
        try:
            payload = json.loads(raw)
        except ValueError:
            payload = {"message": raw.decode(errors="replace")[:500]}
        return exc.code, payload
    except urllib.error.URLError as exc:
        raise ScmError("network", f"{method} {urllib.parse.urlsplit(url).path} failed: {exc}") from exc


Transport = Callable[[str, str, "bytes | None", dict], tuple[int, Any]]


class GitHubApp:
    """Authenticated GitHub App client. Every write goes through one of its methods."""

    def __init__(self, *, config: AppConfig | None = None,
                 oauth_token: str | None = None,
                 transport: Transport | None = None) -> None:
        """`oauth_token` runs the whole client on the console's existing OAuth token
        instead of a GitHub App.

        Everything this client does works on a user-to-server token with the `repo`
        scope EXCEPT one thing: check runs. GitHub is explicit — "To create a check run,
        you must use a GitHub App. OAuth apps and authenticated users are not able to
        create a check suite." So in OAuth mode the pass/fail signal is a COMMIT STATUS
        (`create_commit_status`), which an OAuth token may write and which appears in the
        same place on the pull request and can block merge through branch protection.

        What OAuth costs you: per-line ANNOTATIONS, which only a check run carries. What
        it does not cost you: the poller, per-line review comments (including `suggestion`
        blocks the author can click to commit), the fix branch and the fix PR. Those are
        arguably the better half — a suggestion is actionable where an annotation is not.
        """
        self._oauth_token = (oauth_token or "").strip()
        self._config = config
        self._transport = transport or _https_transport
        self._token = ""
        self._token_expiry = 0.0
        self._repo_cache: dict[str, dict] = {}

    # ── auth ──────────────────────────────────────────────────────────────────────
    def config(self) -> AppConfig:
        if self._config is None:
            self._config = app_config()
        if self._config is None:
            raise ScmError("not_configured",
                           "set DOCKET_GITHUB_APP_ID, DOCKET_GITHUB_APP_INSTALLATION_ID "
                           "and DOCKET_GITHUB_APP_PRIVATE_KEY (or _PRIVATE_KEY_PATH)")
        return self._config

    def installation_token(self, *, now: float | None = None) -> str:
        """A short-lived installation token, cached and refreshed before it expires.

        Never logged and never returned in an error message: GitHub installation tokens
        are write-capable for an hour.
        """
        # OAuth mode: the caller already holds a usable token, so there is nothing to
        # mint, cache or refresh. Returned from the same accessor so every write path
        # below is identical in both modes and cannot diverge.
        if self._oauth_token:
            return self._oauth_token
        moment = time.time() if now is None else now
        if self._token and moment < self._token_expiry - _TOKEN_SKEW_SECONDS:
            return self._token
        config = self.config()
        status, payload = self._transport(
            "POST",
            f"{GITHUB_API}/app/installations/{urllib.parse.quote(config.installation_id)}/access_tokens",
            b"",
            {"Authorization": f"Bearer {_app_jwt(config, moment)}",
             "Accept": "application/vnd.github+json",
             "X-GitHub-Api-Version": "2022-11-28",
             "User-Agent": "docket"},
        )
        token = payload.get("token") if isinstance(payload, dict) else None
        if status >= 300 or not token:
            raise ScmError("app_auth",
                           f"no installation token (HTTP {status}): {_message(payload)}")
        self._token = token
        self._token_expiry = _epoch(payload.get("expires_at")) or moment + 3600
        logger.debug("installation token refreshed, valid for %.0fs",
                     self._token_expiry - moment)
        return token

    # ── raw calls ─────────────────────────────────────────────────────────────────
    def _request(self, method: str, path: str,
                 body: dict | list | None = None) -> tuple[int, Any]:
        encoded = json.dumps(body).encode() if body is not None else None
        return self._transport(
            method, f"{GITHUB_API}{path}", encoded,
            {"Authorization": f"Bearer {self.installation_token()}",
             "Accept": "application/vnd.github+json",
             "X-GitHub-Api-Version": "2022-11-28",
             "Content-Type": "application/json",
             "User-Agent": "docket"},
        )

    def _checked(self, method: str, path: str, body: dict | list | None = None) -> Any:
        status, payload = self._request(method, path, body)
        if status >= 300:
            raise ScmError("http", f"{method} {path} -> HTTP {status}: {_message(payload)}")
        return payload

    def get(self, path: str) -> Any:
        return self._checked("GET", path)

    def post(self, path: str, body: dict | list | None = None) -> Any:
        return self._checked("POST", path, body if body is not None else {})

    def patch(self, path: str, body: dict | list | None = None) -> Any:
        return self._checked("PATCH", path, body if body is not None else {})

    # ── reads that guard the writes ───────────────────────────────────────────────
    def _repo(self, repo: str) -> dict:
        """Repository metadata, cached per process (default_branch + permissions)."""
        # ponytail: process-lifetime cache, ceiling is "a permission revoked mid-run is
        # not noticed". Add a TTL if the service ever runs for days.
        if repo not in self._repo_cache:
            meta = self.get(f"/repos/{_checked_repo(repo)}")
            self._repo_cache[repo] = meta if isinstance(meta, dict) else {}
        return self._repo_cache[repo]

    def repo_permissions(self, repo: str) -> dict[str, bool]:
        """{admin, push, pull}. Fails closed: no permissions block means no push.

        An archived repository reports push=true and 403s on write, so it is folded in
        here rather than surfacing as a mid-flow failure.
        """
        meta = self._repo(repo)
        perms = meta.get("permissions") or {}
        return {"admin": bool(perms.get("admin")),
                "push": bool(perms.get("push")) and not meta.get("archived"),
                "pull": bool(perms.get("pull"))}

    def branch_protected(self, repo: str, branch: str) -> bool:
        status, payload = self._request(
            "GET", f"/repos/{_checked_repo(repo)}/branches/{_checked_ref(branch)}")
        if status == 404:
            return False  # no such branch: nothing to protect
        if status >= 300:
            raise ScmError("http", f"branch lookup {repo}#{branch} -> HTTP {status}: "
                                   f"{_message(payload)}")
        return bool(payload.get("protected")) if isinstance(payload, dict) else False

    def _require_push(self, repo: str) -> None:
        if not self.repo_permissions(repo)["push"]:
            raise ScmError(
                "repo_read_only",
                f"docket has no write access to {repo} (or it is archived). Repos are "
                "listed with affiliation=owner,collaborator,organization_member, which "
                "includes repos you can only read — this one is one of them.",
            )

    # ── writes ────────────────────────────────────────────────────────────────────
    def create_commit_status(self, repo: str, sha: str, *, state: str, context: str,
                              description: str = "", target_url: str = "") -> dict:
        """The pass/fail signal an OAuth token CAN write.

        A check run is App-only. A commit status is not, and it lands in the same section
        of the pull request, participates in branch protection the same way, and carries a
        description and a click-through URL. What it cannot carry is per-line annotations —
        those go as review comments instead, which is the trade OAuth mode makes.

        `state` is one of error | failure | pending | success — GitHub's vocabulary, not
        the check-run vocabulary, so the caller maps `action_required` to `error`.
        """
        if state not in ("error", "failure", "pending", "success"):
            raise ScmError("bad_state",
                           f"commit status state must be error|failure|pending|success, "
                           f"not {state!r}")
        body: dict = {"state": state, "context": context}
        # GitHub truncates description at 140 chars server-side; truncate here so the
        # operator sees the same string that was sent.
        if description:
            body["description"] = description[:140]
        if target_url:
            body["target_url"] = target_url
        return self._checked(
            "POST", f"/repos/{_checked_repo(repo)}/statuses/{_checked_ref(sha)}", body)

    def create_branch(self, repo: str, name: str, from_sha: str) -> dict:
        """Create refs/heads/{name} at from_sha, or adopt it if it is already there.

        Returns {"ref", "sha", "created"}. `created` is False when an existing ref with
        the same SHA was adopted — a re-run of the same scan must not make a second
        branch. An existing ref at a DIFFERENT sha raises branch_stale, because
        overwriting it would need a force update and there is no method for that.
        """
        repo = _checked_repo(repo)
        ref = _checked_ref(name)
        self._require_push(repo)
        default = self._repo(repo).get("default_branch")
        if default and ref == default:
            raise ScmError("default_branch",
                           f"refused: {ref!r} is {repo}'s default branch. Docket never "
                           "writes to it.")
        if self.branch_protected(repo, ref):
            raise ScmError("branch_protected", f"refused: {repo}#{ref} is protected.")

        status, payload = self._request("POST", f"/repos/{repo}/git/refs",
                                       {"ref": f"refs/heads/{ref}", "sha": from_sha})
        if status < 300:
            return {"ref": ref, "sha": from_sha, "created": True}
        if status == 422:
            existing_status, existing = self._request(
                "GET", f"/repos/{repo}/git/ref/heads/{ref}")
            sha = ((existing or {}).get("object") or {}).get("sha") if existing_status < 300 else None
            if sha is None:
                # 422 for some other reason (a bad from_sha, most likely).
                raise ScmError("http", f"create branch {ref} -> HTTP 422: {_message(payload)}")
            if sha == from_sha:
                return {"ref": ref, "sha": sha, "created": False}
            raise ScmError(
                "branch_stale",
                f"{repo}#{ref} already exists at {sha[:8]}, not {from_sha[:8]}. Some "
                "other run (or a human) moved it; docket will not force it.",
            )
        raise ScmError("http", f"create branch {ref} -> HTTP {status}: {_message(payload)}")

    def commit_files(self, repo: str, branch: str, changes: list[FileChange],
                     message: str, *, root: str | Path | None = None) -> dict:
        """One commit on `branch`: blobs -> tree -> commit -> update ref.

        The ref update is a plain fast-forward. There is no force parameter, so a branch
        someone else moved fails the update instead of losing their commit.
        """
        repo = _checked_repo(repo)
        branch = _checked_ref(branch)
        self._require_push(repo)
        if not changes:
            raise ScmError("bad_change", "commit_files needs at least one FileChange")

        entries = []
        for change in changes:
            if not isinstance(change, FileChange):
                raise ScmError("bad_change",
                               f"commit_files takes FileChange, not {type(change).__name__}")
            if change.mode not in _MODES:
                raise ScmError("bad_change",
                               f"refused mode {change.mode!r}: only {_MODES} are files")
            path = _checked_path(change.path)
            content = change.content
            if content is None:
                if root is None:
                    raise ScmError("bad_change",
                                   f"{path} has no content and no root to read it from")
                try:
                    # The one containment check in the repo: parent traversal, not a
                    # string prefix, and it refuses symlinks out of the tree.
                    content = resolve_in_root(root, path).read_text()
                except (SourceAccessError, OSError) as exc:
                    raise ScmError("refused_path", f"cannot read {path}: {exc}") from exc
            blob = self.post(f"/repos/{repo}/git/blobs",
                             {"content": base64.b64encode(content.encode()).decode(),
                              "encoding": "base64"})
            entries.append({"path": path, "mode": change.mode, "type": "blob",
                            "sha": blob["sha"]})

        head = (self.get(f"/repos/{repo}/git/ref/heads/{branch}") or {}).get("object", {}).get("sha")
        if not head:
            raise ScmError("http", f"{repo}#{branch} has no head commit to build on")
        base_tree = (self.get(f"/repos/{repo}/git/commits/{head}") or {}).get("tree", {}).get("sha")
        tree = self.post(f"/repos/{repo}/git/trees",
                         {"base_tree": base_tree, "tree": entries})
        commit = self.post(f"/repos/{repo}/git/commits",
                           {"message": message, "tree": tree["sha"], "parents": [head]})
        self.patch(f"/repos/{repo}/git/refs/heads/{branch}", {"sha": commit["sha"]})
        return commit

    def open_pr(self, repo: str, head: str, base: str, title: str, body: str) -> dict:
        repo = _checked_repo(repo)
        self._require_push(repo)
        return self.post(f"/repos/{repo}/pulls",
                         {"title": title, "head": _checked_ref(head),
                          "base": _checked_ref(base), "body": body})

    def create_check_run(self, repo: str, head_sha: str, *, name: str = "docket",
                         conclusion: str | None = None, title: str | None = None,
                         summary: str = "", annotations: list[dict] | None = None,
                         details_url: str | None = None) -> dict:
        """Create a check run. Annotations beyond 50 follow as update requests."""
        repo = _checked_repo(repo)
        self._require_push(repo)
        rows = list(annotations or [])
        body: dict[str, Any] = {
            "name": name, "head_sha": head_sha,
            "status": "completed" if conclusion else "in_progress",
            "output": {"title": title or name, "summary": summary,
                       "annotations": rows[:ANNOTATION_LIMIT]},
        }
        if conclusion:
            body["conclusion"] = _checked_conclusion(conclusion)
        if details_url:
            body["details_url"] = details_url
        run = self.post(f"/repos/{repo}/check-runs", body)
        self._add_annotations(repo, run.get("id"), rows[ANNOTATION_LIMIT:],
                             title or name, summary)
        return run

    def update_check_run(self, repo: str, check_run_id: int | str, *,
                         conclusion: str | None = None, title: str | None = None,
                         summary: str | None = None,
                         annotations: list[dict] | None = None,
                         status: str | None = None) -> dict:
        repo = _checked_repo(repo)
        self._require_push(repo)
        rows = list(annotations or [])
        body: dict[str, Any] = {}
        if conclusion:
            body["conclusion"] = _checked_conclusion(conclusion)
            body["status"] = "completed"
        if status:
            body["status"] = status
        if title is not None or summary is not None or rows:
            body["output"] = {"title": title or "docket", "summary": summary or "",
                              "annotations": rows[:ANNOTATION_LIMIT]}
        run = self.patch(f"/repos/{repo}/check-runs/{check_run_id}", body)
        self._add_annotations(repo, check_run_id, rows[ANNOTATION_LIMIT:],
                             title or "docket", summary or "")
        return run

    def _add_annotations(self, repo: str, check_run_id: object, rows: list[dict],
                         title: str, summary: str) -> None:
        """Remaining annotations, 50 at a time. GitHub appends them to the run."""
        for start in range(0, len(rows), ANNOTATION_LIMIT):
            self.patch(f"/repos/{repo}/check-runs/{check_run_id}",
                       {"output": {"title": title, "summary": summary,
                                   "annotations": rows[start:start + ANNOTATION_LIMIT]}})

    def create_review_comment(self, repo: str, pr: int, path: str, line: int,
                              body: str, *, commit_id: str | None = None,
                              side: str = "RIGHT") -> dict:
        repo = _checked_repo(repo)
        self._require_push(repo)
        if commit_id is None:
            commit_id = ((self.get(f"/repos/{repo}/pulls/{int(pr)}") or {})
                         .get("head", {}).get("sha", ""))
        return self.post(f"/repos/{repo}/pulls/{int(pr)}/comments",
                         {"path": path, "line": int(line), "side": side,
                          "body": body, "commit_id": commit_id})


def _checked_conclusion(conclusion: str) -> str:
    if conclusion not in CONCLUSIONS:
        raise ScmError("bad_change", f"{conclusion!r} is not a check-run conclusion "
                                     f"({', '.join(CONCLUSIONS)})")
    return conclusion


def _message(payload: object) -> str:
    if isinstance(payload, dict):
        return str(payload.get("message") or payload)[:300]
    return str(payload)[:300]


# ──────────────────────────────────────────────────────────────────────────────────
# In-memory GitHub, for demo() here and for tests/test_scm.py and service/delivery.py.
# Private on purpose: it is a test double, not part of the client surface.
# ──────────────────────────────────────────────────────────────────────────────────
class _FakeTransport:
    """Enough of the REST API to exercise every path, with no network."""

    def __init__(self, *, push: bool = True, default_branch: str = "main",
                 protected: tuple[str, ...] = (), refs: dict | None = None,
                 pulls: dict | None = None, open_pulls: list | None = None,
                 archived: bool = False) -> None:
        self.push = push
        self.default_branch = default_branch
        self.protected = protected
        self.archived = archived
        self.refs: dict[str, str] = dict(refs or {})          # branch -> sha
        self.pulls: dict[int, dict] = dict(pulls or {})        # number -> pr payload
        self.open_pulls = list(open_pulls or [])               # GET /pulls?state=open
        self.head_pulls: list[dict] = []                       # GET /pulls?head=...
        self.calls: list[tuple[str, str]] = []
        self.commits: list[dict] = []
        self.check_runs: list[dict] = []
        self.comments: list[dict] = []
        self.created_pulls: list[dict] = []
        self._n = 0

    def _next(self, kind: str) -> str:
        self._n += 1
        return f"{kind}{self._n:040d}"

    def __call__(self, method: str, url: str, body: bytes | None,
                 headers: dict) -> tuple[int, Any]:
        assert "Authorization" in headers, "every call must be authenticated"
        split = urllib.parse.urlsplit(url)
        path, query = split.path, urllib.parse.parse_qs(split.query)
        self.calls.append((method, split.path + (("?" + split.query) if split.query else "")))
        payload = json.loads(body) if body else {}
        parts = [p for p in path.strip("/").split("/") if p]

        if method == "POST" and parts[:2] == ["app", "installations"]:
            return 201, {"token": "ghs_fake", "expires_at": "2099-01-01T00:00:00Z"}
        if parts[0] != "repos":
            return 404, {"message": "no route"}
        tail = parts[3:]  # after repos/{owner}/{repo}

        if not tail:
            return 200, {"default_branch": self.default_branch, "archived": self.archived,
                         "permissions": {"admin": False, "push": self.push, "pull": True}}
        if tail[0] == "branches":
            branch = "/".join(tail[1:])
            if branch in self.protected:
                return 200, {"name": branch, "protected": True}
            if branch in self.refs or branch == self.default_branch:
                return 200, {"name": branch, "protected": False}
            return 404, {"message": "Branch not found"}
        if tail[:2] == ["git", "refs"] and method == "POST":
            branch = str(payload.get("ref", "")).removeprefix("refs/heads/")
            if branch in self.refs:
                return 422, {"message": "Reference already exists"}
            self.refs[branch] = payload["sha"]
            return 201, {"ref": payload["ref"], "object": {"sha": payload["sha"]}}
        if tail[:3] == ["git", "ref", "heads"] or (tail[:2] == ["git", "refs"] and tail[2:3] == ["heads"]):
            branch = "/".join(tail[3:])
            if method == "PATCH":
                if branch not in self.refs:
                    return 422, {"message": "Reference does not exist"}
                self.refs[branch] = payload["sha"]
                return 200, {"object": {"sha": payload["sha"]}}
            if branch not in self.refs:
                return 404, {"message": "Not Found"}
            return 200, {"object": {"sha": self.refs[branch]}}
        if tail[:2] == ["git", "blobs"]:
            return 201, {"sha": self._next("blob")}
        if tail[:2] == ["git", "trees"]:
            return 201, {"sha": self._next("tree")}
        if tail[:2] == ["git", "commits"] and method == "POST":
            sha = self._next("commit")
            self.commits.append({"sha": sha, **payload})
            return 201, {"sha": sha, "tree": {"sha": payload.get("tree")}}
        if tail[:2] == ["git", "commits"]:
            return 200, {"sha": tail[2], "tree": {"sha": self._next("tree")}}
        if tail[0] == "check-runs":
            if method == "POST":
                run = {"id": len(self.check_runs) + 1, **payload}
                self.check_runs.append(run)
                return 201, run
            self.check_runs.append({"id": tail[1], **payload})
            return 200, {"id": tail[1]}
        if tail[0] == "pulls" and len(tail) >= 3 and tail[2] == "comments":
            self.comments.append({"pr": int(tail[1]), **payload})
            return 201, {"id": len(self.comments)}
        if tail[0] == "pulls" and len(tail) == 2:
            pr = self.pulls.get(int(tail[1]))
            return (200, pr) if pr else (404, {"message": "Not Found"})
        if tail == ["pulls"] and method == "POST":
            number = 900 + len(self.created_pulls)
            pr = {"number": number, "html_url": f"https://example.test/pull/{number}", **payload}
            self.created_pulls.append(pr)
            return 201, pr
        if tail == ["pulls"]:
            return 200, (self.head_pulls if "head" in query else self.open_pulls)
        return 404, {"message": f"fake has no route for {method} {path}"}


def _fake_config() -> AppConfig:
    """A throwaway 2048-bit RSA key, so demo()/tests sign a real RS256 JWT offline."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    return AppConfig("123456", pem, "789")


def demo() -> None:
    # ── path denylist: CI config and credentials, at any depth ────────────────────
    for bad in (".github/workflows/ci.yml", ".env", "app/.env.local", "deploy/key.pem",
                "secrets/id_rsa", "certs/client.p12", ".git/config", "Jenkinsfile",
                "../etc/passwd", "/abs/path", "", "sub/.gitlab-ci.yml"):
        try:
            _checked_path(bad)
            raise AssertionError(f"should have refused {bad!r}")
        except ScmError as exc:
            assert exc.code == "refused_path", (bad, exc.code)
    for good in ("app/main.py", "src/a/b.ts", "README.md"):
        assert _checked_path(good) == good

    # ── real RS256 signing, then a real installation-token exchange ───────────────
    config = _fake_config()
    fake = _FakeTransport(refs={"main": "a" * 40}, default_branch="main")
    app = GitHubApp(config=config, transport=fake)
    token = app.installation_token()
    assert token == "ghs_fake"
    import jwt as _jwt  # the JWT we minted must actually verify as RS256
    from cryptography.hazmat.primitives import serialization

    public_pem = (serialization
                  .load_pem_private_key(config.private_key.encode(), password=None)
                  .public_key()
                  .public_bytes(serialization.Encoding.PEM,
                                serialization.PublicFormat.SubjectPublicKeyInfo)
                  .decode())
    signed = _app_jwt(config, time.time())
    claims = _jwt.decode(signed, public_pem, algorithms=["RS256"])
    assert claims["iss"] == "123456" and claims["exp"] - claims["iat"] <= 600, claims
    # cached: a second call mints nothing
    minted = sum(1 for _, path in fake.calls if "access_tokens" in path)
    app.installation_token()
    assert sum(1 for _, path in fake.calls if "access_tokens" in path) == minted

    # ── guards ────────────────────────────────────────────────────────────────────
    assert app.repo_permissions("o/r") == {"admin": False, "push": True, "pull": True}
    for code, call in (
        ("default_branch", lambda: app.create_branch("o/r", "main", "b" * 40)),
        ("bad_repo", lambda: app.create_branch("not-a-repo", "x", "b" * 40)),
        ("bad_ref", lambda: app.create_branch("o/r", "../x", "b" * 40)),
    ):
        try:
            call()
            raise AssertionError(f"expected {code}")
        except ScmError as exc:
            assert exc.code == code, (code, exc.code)

    # ── the happy path: branch, commit, PR, check run ─────────────────────────────
    made = app.create_branch("o/r", "docket/fix/7-abcd1234", "a" * 40)
    assert made["created"] is True
    again = app.create_branch("o/r", "docket/fix/7-abcd1234", "a" * 40)
    assert again["created"] is False, "same sha must be adopted, not an error"
    commit = app.commit_files("o/r", "docket/fix/7-abcd1234",
                              [FileChange("app/main.py", "print('fixed')\n")],
                              "fix: escape the query")
    assert fake.refs["docket/fix/7-abcd1234"] == commit["sha"]
    assert app.open_pr("o/r", "docket/fix/7-abcd1234", "feature", "t", "b")["number"] == 900

    run = app.create_check_run("o/r", "a" * 40, conclusion="failure", summary="1 finding",
                               annotations=[{"path": "a.py", "start_line": i,
                                             "end_line": i, "annotation_level": "failure",
                                             "message": "x"} for i in range(1, 131)])
    assert run["output"]["annotations"] and len(run["output"]["annotations"]) == 50
    follow_ups = [c for c in fake.check_runs[1:] if c.get("output")]
    assert [len(c["output"]["annotations"]) for c in follow_ups] == [50, 30], follow_ups
    app.update_check_run("o/r", run["id"], conclusion="success", summary="fixed")

    # ── read-only repo: every write refuses before touching anything ──────────────
    ro = GitHubApp(config=config, transport=_FakeTransport(push=False, refs={"main": "a" * 40}))
    for call in (lambda: ro.create_branch("o/r", "x", "a" * 40),
                 lambda: ro.commit_files("o/r", "x", [FileChange("a.py", "x")], "m"),
                 lambda: ro.open_pr("o/r", "x", "main", "t", "b"),
                 lambda: ro.create_check_run("o/r", "a" * 40, conclusion="success"),
                 lambda: ro.create_review_comment("o/r", 1, "a.py", 2, "b")):
        try:
            call()
            raise AssertionError("expected repo_read_only")
        except ScmError as exc:
            assert exc.code == "repo_read_only", exc.code

    print("interface.scm: ok")


if __name__ == "__main__":
    demo()
