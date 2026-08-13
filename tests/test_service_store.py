"""Plain-assert checks for the service store and the poll pass.

Run: uv run python tests/test_service_store.py     (no network, no Docker)

What matters here is that money cannot be spent twice: one commit enqueues once, one
worker owns a scan at a time, and a crashed worker's scan comes back.
"""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from docket.service import poll
from docket.service.store import StateError, Store, db_path

HEAD = "a" * 40


def store_in(tmp: str) -> Store:
    store = Store(db_path(cwd=Path(tmp)))
    store.watch("o/r")
    return store


def test_same_commit_enqueues_once() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        store = store_in(tmp)
        try:
            first = store.enqueue("o/r", 7, HEAD, "b" * 40)
            assert isinstance(first, int)
            assert store.enqueue("o/r", 7, HEAD) is None
            assert store.enqueue("o/r", 7, HEAD, "c" * 40) is None
            assert len(store.scans()) == 1
            # A different PR, or a new commit on the same PR, IS new work.
            assert store.enqueue("o/r", 8, HEAD) is not None
            assert store.enqueue("o/r", 7, "d" * 40) is not None
            assert len(store.scans()) == 3
        finally:
            store.close()


def test_claim_is_exclusive_and_an_expired_lease_is_reclaimable() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        store = store_in(tmp)
        try:
            scan_id = store.enqueue("o/r", 7, HEAD)
            assert store.claim(scan_id, "worker-1") is True
            assert store.claim(scan_id, "worker-2") is False, "two workers, one scan"
            assert store.scan(scan_id)["lease_owner"] == "worker-1"
            # A live lease cannot be stolen, even by a reclaim.
            assert store.claim(scan_id, "worker-2", expect_state="scanning") is False

            # worker-1 is killed. Once the lease lapses the row is workable again.
            store.db.execute("UPDATE pr_scans SET lease_expires_at=? WHERE id=?",
                             ("2000-01-01T00:00:00Z", scan_id))
            assert store.claim(scan_id, "worker-2", expect_state="scanning") is True
            assert store.scan(scan_id)["lease_owner"] == "worker-2"

            store.set_state(scan_id, "delivered", conclusion="success")
            assert store.scan(scan_id)["lease_owner"] is None
            assert store.claim(scan_id, "worker-3", expect_state="scanning") is False
        finally:
            store.close()


def test_illegal_transitions_raise() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        store = store_in(tmp)
        try:
            scan_id = store.enqueue("o/r", 7, HEAD)
            for illegal in ("delivered", "failed"):
                try:
                    store.set_state(scan_id, illegal)
                    raise AssertionError(f"queued -> {illegal} must raise")
                except StateError:
                    pass
            assert store.scan(scan_id)["state"] == "queued"

            store.claim(scan_id, "w")
            store.set_state(scan_id, "failed")
            store.set_state(scan_id, "queued")  # a retry is the only way back
            store.claim(scan_id, "w")
            store.set_state(scan_id, "abandoned")
            for illegal in ("queued", "scanning", "delivered"):
                try:
                    store.set_state(scan_id, illegal)
                    raise AssertionError(f"abandoned -> {illegal} must raise")
                except StateError:
                    pass
            try:
                store.set_state(999, "scanning")
                raise AssertionError("unknown scan must raise")
            except StateError:
                pass
        finally:
            store.close()


def test_tick_twice_enqueues_one_row() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        store = store_in(tmp)
        try:
            scm = poll._FakeScm({"o/r": [poll._pull(7, HEAD)]})
            first = poll.tick(store, scm)
            assert len(first["enqueued"]) == 1, first
            second = poll.tick(store, scm)
            assert second["enqueued"] == [], second
            assert second["pull_requests"] == 1, "it still looked, it just found nothing new"
            assert len(store.scans()) == 1

            # A disabled repo is not polled at all.
            store.set_enabled("o/r", False)
            assert poll.tick(store, scm)["repos"] == 0
        finally:
            store.close()


if __name__ == "__main__":
    test_same_commit_enqueues_once()
    test_claim_is_exclusive_and_an_expired_lease_is_reclaimable()
    test_illegal_transitions_raise()
    test_tick_twice_enqueues_one_row()
    print("test_service_store: ok")
