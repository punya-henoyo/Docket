"""Service state: which repos are watched, and which commits have been scanned.

One SQLite file under docket_runs/.docket/, next to the run directories it refers to.
SQLite because core/sessions.py already puts run state in SQLite (there is no new
dependency and no new operational story), and because the two things this table has to
guarantee are exactly the two things a database does better than Python:

  * a UNIQUE index on (repo, pr, head_sha) means one commit is scanned ONCE. Not
    "usually once" — a duplicate insert is refused by the schema, so a poll loop that
    fires twice, or two consoles polling at the same time, cannot spend money twice.
  * claim() is ONE conditional UPDATE. rowcount == 1 means you own the row; nobody else
    got it. The lease has an expiry, so a worker that is killed mid-scan does not leave
    the row locked forever — the next claim after the lease lapses takes it over.

States: queued -> scanning -> delivered | failed | abandoned, with failed -> queued the
only way back. Transitions are checked, so a caller cannot mark a row delivered without
it ever having been scanned.
"""
from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from docket.core.paths import runs_root

SERVICE_DIR_NAME = ".docket"
SERVICE_DB_NAME = "service.db"

STATES = ("queued", "scanning", "delivered", "failed", "abandoned")

# The only legal moves. delivered/abandoned are terminal; failed can be requeued.
TRANSITIONS: dict[str, set[str]] = {
    "queued": {"scanning", "abandoned"},
    "scanning": {"delivered", "failed", "abandoned"},
    "failed": {"queued", "abandoned"},
    "delivered": set(),
    "abandoned": set(),
}

_SETTABLE = ("run_name", "conclusion", "base_sha")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS watched_repos (
    full_name TEXT PRIMARY KEY,
    policy    TEXT NOT NULL DEFAULT '{}',
    enabled   INTEGER NOT NULL DEFAULT 1,
    added_at  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS pr_scans (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    repo             TEXT NOT NULL REFERENCES watched_repos(full_name) ON DELETE CASCADE,
    pr               INTEGER NOT NULL,
    head_sha         TEXT NOT NULL,
    base_sha         TEXT,
    state            TEXT NOT NULL DEFAULT 'queued'
                     CHECK (state IN ('queued','scanning','delivered','failed','abandoned')),
    run_name         TEXT,
    conclusion       TEXT,
    created_at       TEXT NOT NULL,
    updated_at       TEXT NOT NULL,
    lease_owner      TEXT,
    lease_expires_at TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS pr_scans_commit ON pr_scans (repo, pr, head_sha);
CREATE INDEX IF NOT EXISTS pr_scans_state ON pr_scans (state, id);
"""


class StateError(ValueError):
    """An illegal state transition. Refused rather than written."""


def db_path(*, cwd: Path | None = None) -> Path:
    return runs_root(cwd=cwd) / SERVICE_DIR_NAME / SERVICE_DB_NAME


def _now() -> str:
    """UTC ISO-8601 to the second. Fixed width, so string comparison IS time order."""
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _later(seconds: float) -> str:
    moment = datetime.now(UTC).replace(microsecond=0) + timedelta(seconds=seconds)
    return moment.isoformat().replace("+00:00", "Z")


class Store:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or db_path()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # isolation_level=None: autocommit, so claim()'s rowcount is the final word
        # rather than something a later rollback could undo.
        # check_same_thread=False because the console serves requests on its own threads;
        # SQLite serialises the writes itself.
        self.db = sqlite3.connect(self.path, isolation_level=None, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.execute("PRAGMA busy_timeout=5000")
        self.db.executescript(_SCHEMA)

    def close(self) -> None:
        self.db.close()

    # ── watched repos ─────────────────────────────────────────────────────────────
    def watch(self, full_name: str, policy: dict | None = None, *,
              enabled: bool = True) -> None:
        """Add or update a watched repo. Re-watching keeps added_at."""
        self.db.execute(
            "INSERT INTO watched_repos (full_name, policy, enabled, added_at) "
            "VALUES (?, ?, ?, ?) ON CONFLICT(full_name) DO UPDATE SET "
            "policy=excluded.policy, enabled=excluded.enabled",
            (full_name, json.dumps(policy or {}), int(enabled), _now()),
        )

    def set_enabled(self, full_name: str, enabled: bool) -> None:
        self.db.execute("UPDATE watched_repos SET enabled=? WHERE full_name=?",
                        (int(enabled), full_name))

    def unwatch(self, full_name: str) -> None:
        """Drops the repo and, by ON DELETE CASCADE, its scan rows."""
        self.db.execute("DELETE FROM watched_repos WHERE full_name=?", (full_name,))

    def watched(self, *, enabled_only: bool = True) -> list[dict]:
        sql = "SELECT * FROM watched_repos"
        if enabled_only:
            sql += " WHERE enabled=1"
        rows = [dict(r) for r in self.db.execute(sql + " ORDER BY full_name")]
        for row in rows:
            row["policy"] = json.loads(row["policy"] or "{}")
            row["enabled"] = bool(row["enabled"])
        return rows

    # ── scans ─────────────────────────────────────────────────────────────────────
    def enqueue(self, repo: str, pr: int, head_sha: str,
                base_sha: str | None = None) -> int | None:
        """Queue one commit. Returns the row id, or None if it is already known.

        None is the normal answer on a repeat poll, not an error: the UNIQUE index is
        what makes the poll loop idempotent.
        """
        cursor = self.db.execute(
            "INSERT OR IGNORE INTO pr_scans "
            "(repo, pr, head_sha, base_sha, state, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, 'queued', ?, ?)",
            (repo, int(pr), head_sha, base_sha, _now(), _now()),
        )
        return cursor.lastrowid if cursor.rowcount else None

    def scan(self, scan_id: int) -> dict | None:
        row = self.db.execute("SELECT * FROM pr_scans WHERE id=?", (scan_id,)).fetchone()
        return dict(row) if row else None

    def scans(self, *, state: str | None = None, repo: str | None = None,
              limit: int = 50) -> list[dict]:
        where, args = [], []
        if state:
            where.append("state=?")
            args.append(state)
        if repo:
            where.append("repo=?")
            args.append(repo)
        sql = "SELECT * FROM pr_scans"
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY id LIMIT ?"
        return [dict(r) for r in self.db.execute(sql, (*args, int(limit)))]

    def claim(self, scan_id: int, owner: str, *, lease_seconds: float = 900,
              expect_state: str = "queued") -> bool:
        """Take ownership of one scan. True means it is yours, False means someone else's.

        ONE conditional UPDATE does the whole thing, so there is no window between the
        check and the write. Pass expect_state="scanning" to reclaim a row whose worker
        died: the lease predicate only lets that through once the lease has expired.
        """
        if expect_state not in ("queued", "scanning", "failed"):
            raise StateError(f"cannot claim from state {expect_state!r}")
        now = _now()
        cursor = self.db.execute(
            "UPDATE pr_scans SET state='scanning', lease_owner=?, lease_expires_at=?, "
            "updated_at=? WHERE id=? AND state=? "
            "AND (lease_owner IS NULL OR lease_expires_at < ?)",
            (owner, _later(lease_seconds), now, int(scan_id), expect_state, now),
        )
        return cursor.rowcount == 1

    def set_state(self, scan_id: int, state: str, **fields: Any) -> dict:
        """Move a scan to `state`, checking the transition first.

        Terminal states clear the lease: a delivered row is nobody's work in progress,
        and leaving an owner on it would make a crashed-worker sweep look wrong.
        """
        row = self.scan(scan_id)
        if row is None:
            raise StateError(f"no scan {scan_id}")
        if state not in STATES:
            raise StateError(f"{state!r} is not a scan state ({', '.join(STATES)})")
        if state != row["state"] and state not in TRANSITIONS[row["state"]]:
            raise StateError(f"scan {scan_id}: {row['state']} -> {state} is not a legal "
                             f"transition (legal: {sorted(TRANSITIONS[row['state']]) or 'none'})")
        unknown = set(fields) - set(_SETTABLE)
        if unknown:
            raise StateError(f"cannot set {sorted(unknown)} — settable: {list(_SETTABLE)}")
        assignments = ["state=?", "updated_at=?"]
        args: list[Any] = [state, _now()]
        for name in _SETTABLE:
            if name in fields:
                assignments.append(f"{name}=?")
                args.append(fields[name])
        if state in ("delivered", "failed", "abandoned"):
            assignments += ["lease_owner=NULL", "lease_expires_at=NULL"]
        self.db.execute(f"UPDATE pr_scans SET {', '.join(assignments)} WHERE id=?",
                        (*args, int(scan_id)))
        return self.scan(scan_id)  # type: ignore[return-value]

    def next_queued(self) -> dict | None:
        """Oldest queued scan, or None. Claim it before working on it."""
        rows = self.scans(state="queued", limit=1)
        return rows[0] if rows else None


def demo() -> None:
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        store = Store(db_path(cwd=Path(tmp)))
        try:
            assert store.path.parent.name == ".docket"
            assert store.db.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
            assert store.db.execute("PRAGMA foreign_keys").fetchone()[0] == 1

            store.watch("o/r", {"triage_max": 5})
            store.watch("o/other", enabled=False)
            assert [r["full_name"] for r in store.watched()] == ["o/r"]
            assert store.watched()[0]["policy"] == {"triage_max": 5}
            assert len(store.watched(enabled_only=False)) == 2

            # A scan can only exist for a watched repo — enforced by the FK, not by a
            # caller remembering to check.
            try:
                store.enqueue("o/unwatched", 1, "a" * 40)
                raise AssertionError("FK should refuse an unwatched repo")
            except sqlite3.IntegrityError:
                pass

            first = store.enqueue("o/r", 7, "a" * 40, "b" * 40)
            assert first is not None
            assert store.enqueue("o/r", 7, "a" * 40) is None, "same commit inserts once"
            assert store.enqueue("o/r", 7, "c" * 40) is not None, "a new commit is new work"
            assert len(store.scans(repo="o/r")) == 2

            # claim is exclusive
            assert store.claim(first, "worker-1") is True
            assert store.claim(first, "worker-2") is False
            assert store.scan(first)["state"] == "scanning"
            assert store.scan(first)["lease_owner"] == "worker-1"

            # an expired lease is reclaimable, a live one is not
            assert store.claim(first, "worker-3", expect_state="scanning") is False
            store.db.execute("UPDATE pr_scans SET lease_expires_at=? WHERE id=?",
                             ("2000-01-01T00:00:00Z", first))
            assert store.claim(first, "worker-3", expect_state="scanning") is True
            assert store.scan(first)["lease_owner"] == "worker-3"

            # transitions
            row = store.set_state(first, "delivered", conclusion="failure", run_name="run-1")
            assert row["conclusion"] == "failure" and row["lease_owner"] is None
            for bad in ("scanning", "queued"):
                try:
                    store.set_state(first, bad)
                    raise AssertionError(f"delivered -> {bad} must raise")
                except StateError:
                    pass
            try:
                store.set_state(first, "nonsense")
                raise AssertionError("unknown state must raise")
            except StateError:
                pass
            second = store.next_queued()
            assert second and second["state"] == "queued"
            store.claim(second["id"], "w")
            store.set_state(second["id"], "failed")
            store.set_state(second["id"], "queued")  # retry is the one way back
            try:
                store.set_state(second["id"], "delivered")
                raise AssertionError("queued -> delivered must raise")
            except StateError:
                pass
            try:
                store.set_state(second["id"], "queued", head_sha="d" * 40)
                raise AssertionError("head_sha is not settable")
            except StateError:
                pass

            store.unwatch("o/r")
            assert store.scans(repo="o/r") == [], "cascade removes the scans too"
        finally:
            store.close()
    print("service.store: ok")


if __name__ == "__main__":
    demo()
