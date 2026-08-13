"""Keep the console's session across a restart.

Every restart used to cost a reconnect and a re-enable: the GitHub token and the
watched-repository list lived in memory only, so `docket connect` coming back up meant
clicking through OAuth again and re-ticking every repository. During development that
happens constantly, and it is the single largest source of the console feeling flaky.

WHAT IS STORED, AND THE HONEST RISK
A GitHub `repo` token. That scope is read AND WRITE — GitHub has no read-only scope for
private code — so this file is the most sensitive thing docket writes. It is created
0600 (owner read/write only), which is the same protection `gh` uses for its own
fallback token file and roughly what an SSH private key gets.

It is NOT encrypted, and pretending otherwise would be worse than saying so. Encrypting
with a key stored beside it protects against nothing; doing it properly needs an OS
keyring or a KMS, which is a real dependency and a decision for whoever runs this
multi-tenant. Until then: single operator, own machine, 0600, and this docstring.

Set DOCKET_NO_SESSION_FILE=1 to disable persistence entirely — the token then lives
only in memory and every restart requires reconnecting, which is the old behaviour and
a legitimate choice on a shared machine.
"""
from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

FILENAME = "session.json"
# Owner read/write only. The token in here can write to every repository the operator
# can reach.
FILE_MODE = 0o600


def disabled() -> bool:
    return os.environ.get("DOCKET_NO_SESSION_FILE", "").strip().lower() in {"1", "true", "yes"}


def session_file() -> Path:
    from docket.core.paths import runs_root

    return runs_root() / FILENAME


def save(*, token: str | None, login: str | None, watch: dict[str, Any]) -> None:
    """Persist the session. Never raises — losing persistence must not break a scan."""
    if disabled():
        return
    path = session_file()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "token": token,
            "login": login,
            # Only the operator's CHOICES, never the verdicts. Results are a live view
            # of work this process did; replaying yesterday's on a fresh start would
            # show a stream that is not happening.
            "watch": {
                "enabled": bool(watch.get("enabled")),
                "repos": list(watch.get("repos") or []),
                "interval_sec": int(watch.get("interval_sec") or 30),
                "triage_max": int(watch.get("triage_max") or 5),
                "autofix": bool(watch.get("autofix")),
            },
        }
        # Written 0600 BEFORE the token goes in: creating the file then chmod'ing it
        # leaves a window where it is world-readable, which on a shared machine is the
        # whole exposure.
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, FILE_MODE)
        with os.fdopen(fd, "w") as handle:
            json.dump(payload, handle, indent=1)
        os.chmod(path, FILE_MODE)  # in case the file already existed with wider bits
    except OSError as exc:
        logger.warning("could not persist the session: %s", exc)


def load() -> dict[str, Any] | None:
    """The saved session, or None. A corrupt or unreadable file is not fatal."""
    if disabled():
        return None
    path = session_file()
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("ignoring an unreadable session file: %s", exc)
        return None
    if not isinstance(data, dict) or not data.get("token"):
        return None
    return data


def clear() -> None:
    """Forget the session. Used on disconnect, so "log out" actually logs out."""
    try:
        session_file().unlink(missing_ok=True)
    except OSError:
        pass


def demo() -> None:
    import stat
    import tempfile

    from docket.core import paths as _paths

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        original = _paths.runs_root
        _paths.runs_root = lambda **_k: root  # type: ignore[assignment]
        os.environ.pop("DOCKET_NO_SESSION_FILE", None)
        try:
            assert load() is None, "nothing saved yet"

            save(token="gho_secret", login="garsar07",
                 watch={"enabled": True, "repos": ["o/r"], "interval_sec": 30,
                        "triage_max": 5, "results": [{"repo": "o/r"}]})

            back = load()
            assert back["token"] == "gho_secret" and back["login"] == "garsar07"
            assert back["watch"]["repos"] == ["o/r"] and back["watch"]["enabled"]
            # Verdicts are a live view of THIS process's work. Replaying them on a
            # fresh start would show a stream that is not happening.
            assert "results" not in back["watch"], back["watch"]

            # A token that can write to every repo the operator can reach must not be
            # world-readable, and must never have been.
            mode = stat.S_IMODE(session_file().stat().st_mode)
            assert mode == FILE_MODE, oct(mode)

            # A corrupt file is ignored, not fatal — refusing to start is worse than
            # asking for one reconnect.
            session_file().write_text("{ not json")
            assert load() is None

            # A file with no token is not a session.
            session_file().write_text('{"login": "x"}')
            assert load() is None

            save(token="t", login="l", watch={})
            assert load() is not None
            clear()
            assert load() is None and not session_file().exists()

            # Opting out means nothing touches the disk at all.
            os.environ["DOCKET_NO_SESSION_FILE"] = "1"
            save(token="should-not-be-written", login="x", watch={})
            assert not session_file().exists(), "opt-out must not write"
            assert load() is None
            os.environ.pop("DOCKET_NO_SESSION_FILE")
        finally:
            _paths.runs_root = original  # type: ignore[assignment]

    print("interface.session_store: ok")


if __name__ == "__main__":
    demo()
