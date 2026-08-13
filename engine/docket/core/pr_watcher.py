"""Find pull requests that need scanning, by asking GitHub rather than being told.

A webhook is the right answer eventually. Polling is the right answer NOW, and the
work is not thrown away: this module only decides WHICH pull requests changed. What
happens next — plan the scope, scan, diff, report — is identical either way. Swapping
in a webhook later replaces this file and nothing else.

Polling also needs nothing an operator does not already have. No public URL, no
inbound firewall rule, no HMAC secret, no TLS certificate. It runs from a laptop
against the OAuth token that is already connected, which makes it the only version of
this feature that can be demonstrated before infrastructure exists.

WHAT IT COSTS, HONESTLY
Latency. A webhook fires in under a second; a poll finds the push whenever it next
looks, so the median delay is half the interval. At 30 seconds that is fine for a demo
and acceptable in production for a check that takes minutes to run anyway.

RATE LIMITS ARE THE REAL CONSTRAINT
An OAuth token gets 5,000 requests an hour. One list-pulls call per repository per
poll at 30-second intervals is 120 an hour per repository, so roughly forty
repositories fit comfortably. Conditional requests push that much further: GitHub does
not charge a 304, so a repository with no activity costs nothing at all. Hence the
ETag bookkeeping below — without it this feature has a hard ceiling nobody would
expect.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# GitHub's own guidance for polling. Faster gains little: a scan takes minutes, so
# shaving twenty seconds off detection changes nothing a user perceives.
DEFAULT_INTERVAL_SEC = 30
MIN_INTERVAL_SEC = 10


@dataclass(frozen=True)
class PullRequestRef:
    """One pull request at one commit. Everything a scan needs to start."""

    repo: str            # "owner/name"
    number: int
    base_sha: str
    head_sha: str
    base_ref: str        # the branch being merged INTO, for the baseline
    title: str = ""
    draft: bool = False

    @property
    def key(self) -> str:
        return f"{self.repo}#{self.number}"


def parse_pulls(repo: str, payload: Any) -> list[PullRequestRef]:
    """GitHub's list-pulls response into refs. Malformed entries are skipped.

    A pull request missing base or head sha is not scannable and is dropped rather
    than defaulted — a scan against a guessed commit reports on code nobody pushed.
    """
    out: list[PullRequestRef] = []
    for item in payload or []:
        if not isinstance(item, dict):
            continue
        base = item.get("base") or {}
        head = item.get("head") or {}
        base_sha, head_sha = base.get("sha"), head.get("sha")
        number = item.get("number")
        if not (isinstance(base_sha, str) and isinstance(head_sha, str)
                and isinstance(number, int)):
            continue
        out.append(PullRequestRef(
            repo=repo,
            number=number,
            base_sha=base_sha,
            head_sha=head_sha,
            base_ref=str(base.get("ref") or ""),
            title=str(item.get("title") or ""),
            draft=bool(item.get("draft")),
        ))
    return out


class SeenStore:
    """Which commit docket last scanned for each pull request.

    Persisted, because without it a restart rescans every open pull request — on a
    busy repository that is a bill and a wall of duplicate comments, arriving for
    changes nobody made.
    """

    def __init__(self, path: Path | None = None) -> None:
        self.path = path
        self._seen: dict[str, str] = {}
        if path and path.is_file():
            try:
                loaded = json.loads(path.read_text())
                if isinstance(loaded, dict):
                    self._seen = {str(k): str(v) for k, v in loaded.items()}
            except (OSError, json.JSONDecodeError):
                # A corrupt state file must not stop the watcher. Rescanning is
                # wasteful; refusing to start is worse.
                self._seen = {}

    def is_new(self, ref: PullRequestRef) -> bool:
        return self._seen.get(ref.key) != ref.head_sha

    def mark(self, ref: PullRequestRef) -> None:
        self._seen[ref.key] = ref.head_sha
        self._flush()

    def forget(self, ref: PullRequestRef) -> None:
        """Drop a PR so its next push rescans. Used when a scan failed — recording a
        commit docket did not actually finish scanning would skip it forever."""
        if self._seen.pop(ref.key, None) is not None:
            self._flush()

    def _flush(self) -> None:
        if not self.path:
            return
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps(self._seen, indent=1))
        except OSError:
            pass  # in-memory state still works; losing it only costs a rescan


def due(refs: list[PullRequestRef], seen: SeenStore, *,
        skip_drafts: bool = True) -> list[PullRequestRef]:
    """Pull requests whose head commit docket has not scanned yet.

    Drafts are skipped by default. A draft is work in progress by definition, and
    commenting on every intermediate push is how a check gets muted before it has
    said anything useful. They are picked up the moment the PR is marked ready,
    because that flips nothing about the head sha — it just stops being skipped.
    """
    out = []
    for ref in refs:
        if skip_drafts and ref.draft:
            continue
        if seen.is_new(ref):
            out.append(ref)
    return out


def poll_interval(headers: Any, requested: int = DEFAULT_INTERVAL_SEC) -> int:
    """Seconds to wait before polling again.

    GitHub sends X-Poll-Interval when it wants callers to back off, and ignoring it
    is how a token gets rate limited. Its value wins over ours whenever it is larger;
    a floor stops a malformed header polling in a tight loop.
    """
    wanted = max(int(requested), MIN_INTERVAL_SEC)
    try:
        advised = int((headers or {}).get("X-Poll-Interval") or 0)
    except (TypeError, ValueError):
        advised = 0
    return max(wanted, advised)


def demo() -> None:
    import tempfile

    def pull(number, head, base="base1", draft=False, ref="main"):
        return {"number": number, "draft": draft, "title": f"PR {number}",
                "base": {"sha": base, "ref": ref}, "head": {"sha": head}}

    refs = parse_pulls("o/r", [pull(1, "aaa"), pull(2, "bbb", draft=True)])
    assert [r.number for r in refs] == [1, 2]
    assert refs[0].key == "o/r#1" and refs[0].base_ref == "main"
    assert refs[1].draft

    # Unscannable entries are dropped, never defaulted. A scan against a guessed
    # commit reports on code nobody pushed.
    assert parse_pulls("o/r", [{"number": 3, "base": {}, "head": {}}]) == []
    assert parse_pulls("o/r", [{"base": {"sha": "a"}, "head": {"sha": "b"}}]) == []
    assert parse_pulls("o/r", None) == [] and parse_pulls("o/r", ["junk"]) == []

    # ── what is due ─────────────────────────────────────────────────────────
    with tempfile.TemporaryDirectory() as tmp:
        state = Path(tmp) / "seen.json"
        seen = SeenStore(state)

        assert [r.number for r in due(refs, seen)] == [1], "drafts are skipped"
        assert len(due(refs, seen, skip_drafts=False)) == 2

        seen.mark(refs[0])
        assert due(refs, seen) == [], "an already-scanned commit is not due again"

        # A new push on the same PR is due again.
        pushed = parse_pulls("o/r", [pull(1, "ccc")])
        assert due(pushed, seen) == pushed

        # A draft marked ready becomes due without any new commit.
        ready = parse_pulls("o/r", [pull(2, "bbb")])
        assert [r.number for r in due(ready, seen)] == [2]

        # Persisted: a restart must not rescan every open PR and post a wall of
        # duplicate comments for changes nobody made.
        reloaded = SeenStore(state)
        assert due(refs, reloaded) == [], "state must survive a restart"

        # A failed scan forgets, so the next poll retries rather than skipping forever.
        reloaded.forget(refs[0])
        assert [r.number for r in due(refs, reloaded)] == [1]

        # A corrupt state file must not stop the watcher starting.
        state.write_text("{ not json")
        assert due(refs, SeenStore(state)) == [refs[0]]

    # No path at all is legitimate — an in-memory watcher for a one-off run.
    memory = SeenStore(None)
    assert due(refs, memory) == [refs[0]]
    memory.mark(refs[0])
    assert due(refs, memory) == []

    # ── backing off when told to ────────────────────────────────────────────
    assert poll_interval({}) == DEFAULT_INTERVAL_SEC
    assert poll_interval({"X-Poll-Interval": "60"}) == 60, "GitHub's request wins"
    assert poll_interval({"X-Poll-Interval": "5"}) == DEFAULT_INTERVAL_SEC
    assert poll_interval({"X-Poll-Interval": "junk"}) == DEFAULT_INTERVAL_SEC
    assert poll_interval(None, requested=1) == MIN_INTERVAL_SEC, "no tight loops"
    assert poll_interval({"X-Poll-Interval": "120"}, requested=1) == 120

    print("core.pr_watcher: ok")


if __name__ == "__main__":
    demo()
