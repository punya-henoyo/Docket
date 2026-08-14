"""Host side of the SonarQube Community Build server the sonar scanner analyses against.

WHY THIS EXISTS AT ALL, WHEN THE OTHER SCANNERS NEED NOTHING LIKE IT
-------------------------------------------------------------------
nuclei, trivy and semgrep are one-shot binaries: run, write JSON, exit. SonarQube is
client/server. `sonar-scanner` analyses nothing locally — it uploads source to a server,
which queues a Compute Engine task and analyses asynchronously, and the findings come
back over the Web API. There is no offline mode that writes a findings file. So the
scanner in tools/scanners/sonar.py needs a server to exist, and this module is how one
comes to exist.

LONG-LIVED, NOT PER-SCAN
------------------------
Unlike Sandbox — one container per run, deliberately, so no state bleeds between runs —
this container is reused. SonarQube takes 2-3 minutes to boot (Elasticsearch), which is
tolerable once per machine and absurd once per scan. Reuse also keeps SonarQube's own
analysis history, which is what makes its new-code comparisons mean anything.

The consequence is that it is NOT registered in sandbox._LIVE and NOT torn down by the
signal handlers: outliving the process is the entire point. stop() is explicit, and
`docker rm -f docket-sonarqube` is the manual equivalent.
"""
from __future__ import annotations

import json
import os
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from docket.runtime.sandbox import HOST_ALIAS, SandboxError, _docker

# Pinned, for the same reason nuclei/trivy/semgrep are pinned: the same commit must not
# produce different findings next month because a rolling tag moved underneath it.
# `sonarqube:community` is that rolling tag; this is the build it pointed at.
DEFAULT_IMAGE = "sonarqube:26.8.0.126808-community"

# Fixed, not random like Sandbox's name — a container that is reused has to be findable
# on the next run, by this process or by a human with `docker ps`.
CONTAINER_NAME = "docket-sonarqube"
HOST_PORT = 9000

# Named volumes, so a restart does not re-index from scratch and history survives.
VOLUMES = {
    "docket-sonar-data": "/opt/sonarqube/data",
    "docket-sonar-extensions": "/opt/sonarqube/extensions",
    "docket-sonar-logs": "/opt/sonarqube/logs",
}

# Boot is genuinely slow: Elasticsearch starts, the DB migrates on a fresh volume, and
# only then does the web API answer. Measured well under this on a warm volume; the
# ceiling is for the first-ever start.
BOOT_TIMEOUT_SEC = 420

# SonarQube ships this and forces a change on first use. It is not a secret and treating
# it as one would only hide what the bootstrap below is doing.
_DEFAULT_LOGIN = ("admin", "admin")


class SonarError(RuntimeError):
    """The SonarQube server could not be brought up or talked to.

    Distinct from "analysed and found nothing": the scanner converts this into a
    ScannerError so the stage reports `error`, never a green `done` over an analysis
    that never happened.
    """


def _state_dir() -> Path:
    """Where the generated API token is cached between runs.

    Under the user's home rather than the repo: the token belongs to the machine's
    SonarQube instance, not to a checkout, and a repo-local file is one `git add -A`
    away from being committed.
    """
    override = os.environ.get("DOCKET_STATE_DIR", "").strip()
    root = Path(override) if override else Path.home() / ".docket"
    return root


def _token_file() -> Path:
    return _state_dir() / "sonar-token"


def enabled() -> bool:
    """The off valve. The stage runs automatically whenever source is mounted, so this
    is the only way to decline a 2GB Java service — CI and no-Docker environments need
    one."""
    return os.environ.get("DOCKET_SONAR", "").strip() not in ("0", "false", "no")


def host_url() -> str:
    """The URL the HOST uses. Overridable so an existing company SonarQube can be used
    instead of the container this module manages."""
    return os.environ.get("DOCKET_SONAR_URL", "").strip() or f"http://127.0.0.1:{HOST_PORT}"


def container_url() -> str:
    """The same server, as the SANDBOX must address it.

    Not the same string: the sandbox's own loopback is not the host's. sandbox.py
    already solved this for target URLs; this is the same rewrite for the same reason.
    """
    from docket.runtime.sandbox import rewrite_for_container

    return rewrite_for_container(host_url())


def _managed() -> bool:
    """True when docket owns the server's lifecycle. A user-supplied DOCKET_SONAR_URL
    means someone else runs it, and starting a container would be both useless and
    rude."""
    return not os.environ.get("DOCKET_SONAR_URL", "").strip()


def api(path: str, *, token: str | None = None, auth: tuple[str, str] | None = None,
        data: dict[str, str] | None = None, timeout: float = 30.0) -> Any:
    """One call to the SonarQube Web API. POST when `data` is given, else GET.

    Returns parsed JSON, or None for the empty bodies several endpoints answer with.
    """
    url = f"{host_url().rstrip('/')}{path}"
    body = urllib.parse.urlencode(data).encode() if data is not None else None
    request = urllib.request.Request(url, data=body, method="POST" if body else "GET")
    if token:
        # Bearer token auth (SonarQube 9.5+). Preferred over the older
        # token-as-basic-username form, which is deprecated.
        request.add_header("Authorization", f"Bearer {token}")
    elif auth:
        import base64

        pair = base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode()
        request.add_header("Authorization", f"Basic {pair}")
    with urllib.request.urlopen(request, timeout=timeout) as response:
        raw = response.read().decode("utf-8", "replace").strip()
    return json.loads(raw) if raw else None


def _http_message(exc: urllib.error.HTTPError) -> str:
    """SonarQube's own explanation, not our guess at one.

    Every 4xx from this API carries `{"errors": [{"msg": ...}]}`. Discarding it and
    printing an assumption is how a password-policy rejection got reported as "the
    password is already set" — a message that sent the reader somewhere else entirely.
    """
    try:
        doc = json.loads(exc.read().decode("utf-8", "replace"))
        messages = [str(e.get("msg", "")).strip() for e in doc.get("errors") or []]
        joined = "; ".join(m for m in messages if m)
    except (OSError, ValueError):
        joined = ""
    return joined or f"HTTP {exc.code}"


def _new_admin_password() -> str:
    """A password SonarQube will accept.

    SonarQube 2025+ enforces a policy: length plus an uppercase, a lowercase, a digit
    and a special character. A hex string has no uppercase, which is exactly how the
    first version of this failed — with a 400 that said so and was thrown away.
    """
    return "Docket-" + os.urandom(12).hex().upper() + "-a1!"


def _status() -> str | None:
    """"UP", "STARTING", "DB_MIGRATION_NEEDED", ... or None when nothing answers.

    Unauthenticated on purpose: this is the one endpoint that must work before a token
    exists.
    """
    try:
        doc = api("/api/system/status", timeout=5)
    except (OSError, json.JSONDecodeError):
        # Nothing listening yet, or a half-started server answering with HTML. Both mean
        # "not up", which is what the boot loop is polling for.
        return None
    return str((doc or {}).get("status") or "") or None


def _container_state() -> str | None:
    """"running", "exited", ... or None when the container does not exist."""
    try:
        return _docker("inspect", "-f", "{{.State.Status}}", CONTAINER_NAME, timeout=30)
    except SandboxError:
        return None


def _start_container() -> None:
    state = _container_state()
    if state == "running":
        return
    if state is not None:
        # Exists but stopped: start it rather than recreating, so the volumes and the
        # analysis history they hold stay attached.
        _docker("start", CONTAINER_NAME, timeout=120)
        return
    # Pulled as its own step, with its own generous timeout. The image is close to a
    # gigabyte, so on a first run this is the long part — folding it into `docker run`
    # made a slow connection look like a container that failed to start.
    _docker("pull", DEFAULT_IMAGE, timeout=1800)
    mounts: list[str] = []
    for volume, mountpoint in VOLUMES.items():
        mounts += ["-v", f"{volume}:{mountpoint}"]
    _docker(
        "run", "-d",
        "--name", CONTAINER_NAME,
        "--add-host", f"{HOST_ALIAS}:host-gateway",
        # Loopback only, like everything else docket starts. A SonarQube holding a
        # customer's source has no business being reachable off this machine.
        "-p", f"127.0.0.1:{HOST_PORT}:9000",
        # The embedded Elasticsearch refuses to start under a low mmap limit on Linux
        # hosts. Disabling its bootstrap check is the documented escape for exactly the
        # single-node, loopback-only case this is; the alternative is telling every
        # user to sysctl their host.
        "-e", "SONAR_ES_BOOTSTRAP_CHECKS_DISABLE=true",
        *mounts,
        DEFAULT_IMAGE,
        timeout=300,
    )


def _await_up(timeout: float) -> None:
    deadline = time.monotonic() + timeout
    last: str | None = None
    while time.monotonic() < deadline:
        last = _status()
        if last == "UP":
            return
        time.sleep(2.0)
    logs = ""
    try:
        logs = _docker("logs", "--tail", "20", CONTAINER_NAME, timeout=30)
    except SandboxError:
        pass
    raise SonarError(
        f"SonarQube never came up (last status: {last or 'no response'}). "
        f"It needs ~2GB of free memory.\nlogs:\n{logs}"
    )


def _bootstrap_token() -> str:
    """Generate an API token, changing the forced default password on the way.

    SonarQube ships admin/admin and refuses most API calls until that password is
    changed, so a first run has to do both. The result is cached because the second
    attempt would fail: admin/admin no longer works once step one has run.
    """
    token_file = _token_file()
    if token_file.is_file():
        cached = token_file.read_text().strip()
        if cached:
            return cached

    supplied = os.environ.get("DOCKET_SONAR_TOKEN", "").strip()
    if supplied:
        return supplied

    new_password = _new_admin_password()
    try:
        api("/api/users/change_password", auth=_DEFAULT_LOGIN, data={
            "login": _DEFAULT_LOGIN[0],
            "previousPassword": _DEFAULT_LOGIN[1],
            "password": new_password,
        })
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403):
            # The default credentials no longer work: a human changed the password, or a
            # prior run did and its token file has since been deleted. Neither is
            # recoverable here, and retrying would only lock the account.
            raise SonarError(
                "SonarQube's admin password is already set, and no cached token was "
                "found. Generate a token in the SonarQube UI and set DOCKET_SONAR_TOKEN."
            ) from exc
        # Anything else is the server telling us precisely what it disliked — a password
        # policy, usually. Pass its words through rather than guessing at them.
        raise SonarError(
            f"SonarQube rejected the initial password change: {_http_message(exc)}"
        ) from exc
    except (OSError, ValueError) as exc:
        raise SonarError(f"could not initialise SonarQube admin: {exc}") from exc

    try:
        doc = api("/api/user_tokens/generate", auth=(_DEFAULT_LOGIN[0], new_password),
                  data={"name": f"docket-{os.urandom(4).hex()}"})
        token = str((doc or {}).get("token") or "")
    except urllib.error.HTTPError as exc:
        raise SonarError(f"could not generate a SonarQube token: {_http_message(exc)}") from exc
    except (OSError, ValueError) as exc:
        raise SonarError(f"could not generate a SonarQube token: {exc}") from exc
    if not token:
        raise SonarError("SonarQube returned no token")

    token_file.parent.mkdir(parents=True, exist_ok=True)
    token_file.write_text(token)
    # The token can create projects and read every analysed repository on this server.
    token_file.chmod(0o600)
    # Written alongside so a human who deletes the token knows the password it belongs
    # to; without it the instance is unadministerable after a token loss.
    password_file = token_file.with_name("sonar-admin-password")
    password_file.write_text(new_password)
    password_file.chmod(0o600)
    return token


def ensure(*, timeout: float = BOOT_TIMEOUT_SEC) -> str:
    """The server is up and we hold a token for it. Returns the token.

    Idempotent and cheap on the common path: an already-running server costs one
    unauthenticated status call and a file read.
    """
    if not enabled():
        raise SonarError("SonarQube is disabled (DOCKET_SONAR=0)")

    if _status() != "UP":
        if not _managed():
            raise SonarError(
                f"no SonarQube answering at {host_url()} "
                "(DOCKET_SONAR_URL is set, so docket will not start one)"
            )
        # Every docker failure becomes a SonarError, which the scanner turns into a
        # ScannerError, which drain() turns into stage `error`. Without this funnel a
        # SandboxError or a subprocess timeout escapes the scanner entirely and takes
        # down a scan that was otherwise fine — the exact opposite of what a scanner
        # that cannot run is supposed to do.
        try:
            _start_container()
        except SonarError:
            raise
        except subprocess.TimeoutExpired as exc:
            raise SonarError(
                f"timed out pulling or starting {DEFAULT_IMAGE} after {exc.timeout:.0f}s"
            ) from exc
        except SandboxError as exc:
            raise SonarError(f"could not start SonarQube: {exc}") from exc
        _await_up(timeout)
    return _bootstrap_token()


def stop(*, remove: bool = False) -> None:
    """Explicit teardown. Never called by a scan — see the module docstring."""
    for args in (("stop", "-t", "10", CONTAINER_NAME),) + (
        (("rm", "-f", CONTAINER_NAME),) if remove else ()
    ):
        try:
            _docker(*args, timeout=120)
        except SandboxError:
            pass


def demo() -> None:
    saved = {k: os.environ.pop(k, None)
             for k in ("DOCKET_SONAR", "DOCKET_SONAR_URL", "DOCKET_SONAR_TOKEN")}
    try:
        # The off valve is the only way to decline the stage, so its parsing must not
        # be clever: anything that is not an explicit "no" leaves it on.
        assert enabled()
        for off in ("0", "false", "no"):
            os.environ["DOCKET_SONAR"] = off
            assert not enabled(), off
        for on in ("1", "true", "yes", ""):
            os.environ["DOCKET_SONAR"] = on
            assert enabled(), on
        os.environ.pop("DOCKET_SONAR")

        # Default: docket owns the server, and the host reaches it on loopback.
        assert _managed()
        assert host_url() == f"http://127.0.0.1:{HOST_PORT}"
        # The sandbox CANNOT use that string — its loopback is its own. This rewrite is
        # the whole reason container_url() exists separately.
        assert container_url() == f"http://{HOST_ALIAS}:{HOST_PORT}", container_url()
        assert "127.0.0.1" not in container_url()

        # A supplied URL means someone else runs it; starting a container would be wrong.
        os.environ["DOCKET_SONAR_URL"] = "https://sonar.corp.example"
        assert not _managed()
        assert host_url() == "https://sonar.corp.example"
        # Nothing to rewrite in a real hostname.
        assert container_url() == "https://sonar.corp.example", container_url()
        os.environ.pop("DOCKET_SONAR_URL")

        # An unmanaged server that is not answering must fail loudly rather than
        # silently starting a competing local one.
        os.environ["DOCKET_SONAR_URL"] = "http://127.0.0.1:9"  # discard port, never up
        try:
            ensure(timeout=0.1)
            raise AssertionError("expected SonarError")
        except SonarError as exc:
            assert "will not start one" in str(exc), exc
        os.environ.pop("DOCKET_SONAR_URL")

        # Disabled must refuse before touching Docker at all.
        os.environ["DOCKET_SONAR"] = "0"
        try:
            ensure()
            raise AssertionError("expected SonarError")
        except SonarError as exc:
            assert "disabled" in str(exc), exc
        os.environ.pop("DOCKET_SONAR")

        # The generated admin password must satisfy SonarQube's policy. The first version
        # was hex-only, so it had no uppercase, and every fresh instance rejected it.
        password = _new_admin_password()
        assert len(password) >= 12, password
        assert any(c.isupper() for c in password), password
        assert any(c.islower() for c in password), password
        assert any(c.isdigit() for c in password), password
        assert any(not c.isalnum() for c in password), password
        assert _new_admin_password() != password, "must not be a constant"

        # Every way Docker can fail must arrive as a SonarError, because that is the only
        # exception the scanner converts into a ScannerError — and a ScannerError is what
        # marks the stage `error` instead of killing an otherwise fine scan.
        global _status, _start_container
        real_status, real_start = _status, _start_container
        try:
            def _never_up() -> str | None:
                return None

            _status = _never_up
            for boom, expected in (
                (SandboxError("no such image"), "could not start SonarQube"),
                (subprocess.TimeoutExpired("docker pull", 1800.0), "timed out pulling"),
            ):
                def _raise(_exc=boom):
                    raise _exc

                _start_container = _raise
                try:
                    ensure(timeout=0.1)
                    raise AssertionError(f"expected SonarError for {boom!r}")
                except SonarError as exc:
                    assert expected in str(exc), (expected, str(exc))
        finally:
            _status, _start_container = real_status, real_start

        # Volumes are what make reuse worth having; losing one silently would turn every
        # scan back into a cold boot.
        assert set(VOLUMES.values()) == {
            "/opt/sonarqube/data", "/opt/sonarqube/extensions", "/opt/sonarqube/logs",
        }
        # Pinned, not rolling: `sonarqube:community` would move under us.
        assert DEFAULT_IMAGE.endswith("-community") and ":" in DEFAULT_IMAGE
        assert DEFAULT_IMAGE != "sonarqube:community"
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
    print("runtime.sonar_service: ok")


if __name__ == "__main__":
    demo()
