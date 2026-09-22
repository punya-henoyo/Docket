"""Remember triage verdicts across runs, so a rescan only pays for what is new.

THE PROBLEM THIS EXISTS FOR. Triage is the only thing docket does that an ordinary
scanner cannot: an agent reads the code around each candidate and says whether untrusted
input can reach it. It costs about $0.018 and one sequential agent-run per finding.
Measured on kaizenmantra/everest-control-center: 176 findings, so judging all of them is
~$3.20 and roughly forty minutes. Nobody does that, so they pass `--triage 20` and 156
findings are never looked at.

And it had no memory. Scanning the same repository again re-judged the same findings from
scratch and charged again for answers it already had. The expensive half of the product
was also the half that repeated itself.

WHAT MAKES A CACHED VERDICT SAFE TO REUSE, WHICH IS THE WHOLE DESIGN

A stale "not reachable" is the dangerous direction: it would let docket skip a finding
that somebody has since made reachable, permanently and silently. So a verdict is reused
only when BOTH of these still hold:

  dedupe_key    the finding is the same finding — same rule, route, parameter and
                `path:line`. Already stable across runs and already the SARIF
                partialFingerprint, so it costs nothing to reuse here. If the line moves,
                the key changes and the verdict is re-earned.
  fingerprint   the matched CODE is byte-identical. semgrep puts the matched source line
                in `poc.request`, so this is free. Edit the line in place and the key is
                unchanged but the fingerprint is not — and the finding is re-judged.

Both must match. Either changing means the agent looks again.

WHAT IS NEVER CACHED

A verdict the RUNNER synthesised — the ones carrying core.triage.UNJUDGED_PREFIX, written
when an agent ran out of turns or budget. Those say "nobody looked", and caching them
would turn a one-off budget shortfall into a finding that is skipped forever. They are the
exact opposite of an answer.

Scoped by target, because `dedupe_key` is (rule, method, path, parameter, source_file) and
carries no repository. Two repositories with an `app.py:36` SQL injection produce the same
key, and one inheriting the other's verdict would be a cross-customer leak of a judgement.
"""
from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

CACHE_FILENAME = "verdicts.db"
SERVICE_DIR_NAME = ".docket"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS verdicts (
    scope       TEXT NOT NULL,
    dedupe_key  TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    verdict     TEXT NOT NULL,
    reasoning   TEXT NOT NULL,
    evidence    TEXT NOT NULL,
    judged_at   TEXT NOT NULL,
    PRIMARY KEY (scope, dedupe_key)
);
CREATE INDEX IF NOT EXISTS verdicts_scope ON verdicts (scope);
"""


def cache_path(*, cwd: Path | None = None) -> Path:
    """Beside service.db. A verdict outlives the run that produced it — that is the
    entire point — so it does not belong inside a run directory."""
    from docket.core.paths import runs_root

    return runs_root(cwd=cwd) / SERVICE_DIR_NAME / CACHE_FILENAME


def fingerprint(finding: dict[str, Any]) -> str:
    """A hash of the code the rule actually matched.

    From `poc.request`, which is where every scanner parser puts the matched source line
    (tools/scanners/semgrep.py). Falls back to the description, then to the empty string —
    and an empty fingerprint is still a usable one, because it only ever has to EQUAL the
    fingerprint stored beside the same dedupe_key. It is a change detector, not an
    identifier.
    """
    poc = finding.get("poc") or {}
    material = str(poc.get("request") or finding.get("description") or "")
    return hashlib.sha256(material.encode("utf-8", "replace")).hexdigest()[:32]


def is_synthesised(verdict: dict[str, Any]) -> bool:
    """True for a verdict the runner wrote because nobody looked.

    Matched on core.triage.UNJUDGED_PREFIX, which exists precisely so a synthesised
    `uncertain` stays distinguishable from one an agent reached.
    """
    from docket.core.triage import UNJUDGED_PREFIX

    return str(verdict.get("reasoning", "")).startswith(UNJUDGED_PREFIX)


class VerdictCache:
    """SQLite, one row per (scope, finding). Never raises on a cache fault.

    A cache that can fail a scan is worse than no cache: the scan is the thing the
    operator paid for, and a locked database or a read-only disk must degrade to "judge
    everything again", which is exactly today's behaviour.
    """

    def __init__(self, path: Path | None = None, *, cwd: Path | None = None) -> None:
        self.path = Path(path) if path is not None else cache_path(cwd=cwd)
        self.hits = 0
        self.misses = 0
        self.stored = 0
        self._db: sqlite3.Connection | None = None
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._db = sqlite3.connect(self.path, check_same_thread=False)
            self._db.row_factory = sqlite3.Row
            self._db.executescript(_SCHEMA)
            # WAL so a scan reading the cache does not block the watcher writing it, and
            # a busy timeout so two concurrent scans queue instead of failing.
            self._db.execute("PRAGMA journal_mode=WAL")
            self._db.execute("PRAGMA busy_timeout=5000")
            self._db.commit()
        except (sqlite3.Error, OSError):
            logger.warning("verdict cache unavailable at %s; every finding will be "
                           "judged fresh", self.path, exc_info=True)
            self._db = None

    @property
    def available(self) -> bool:
        return self._db is not None

    def get(self, scope: str, dedupe_key: str, mark: str) -> dict[str, Any] | None:
        """A previous verdict for this exact finding and this exact code, or None."""
        if self._db is None or not dedupe_key:
            return None
        try:
            row = self._db.execute(
                "SELECT fingerprint, verdict, reasoning, evidence FROM verdicts "
                "WHERE scope = ? AND dedupe_key = ?", (scope, dedupe_key)).fetchone()
        except sqlite3.Error:
            logger.debug("verdict cache read failed", exc_info=True)
            return None
        if row is None:
            self.misses += 1
            return None
        if row["fingerprint"] != mark:
            # Same finding, different code. The stored judgement was about text that is
            # no longer there, so it is not an answer to the current question.
            self.misses += 1
            return None
        self.hits += 1
        return {"verdict": row["verdict"], "reasoning": row["reasoning"],
                "evidence": row["evidence"], "cached": True}

    def put(self, scope: str, dedupe_key: str, mark: str,
            verdict: dict[str, Any]) -> None:
        """Store a verdict an AGENT reached. Synthesised ones are dropped."""
        if self._db is None or not dedupe_key or not verdict.get("verdict"):
            return
        if is_synthesised(verdict):
            return
        try:
            self._db.execute(
                "INSERT INTO verdicts (scope, dedupe_key, fingerprint, verdict, "
                "reasoning, evidence, judged_at) VALUES (?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(scope, dedupe_key) DO UPDATE SET "
                "fingerprint=excluded.fingerprint, verdict=excluded.verdict, "
                "reasoning=excluded.reasoning, evidence=excluded.evidence, "
                "judged_at=excluded.judged_at",
                (scope, dedupe_key, mark, str(verdict["verdict"]),
                 str(verdict.get("reasoning", "")), str(verdict.get("evidence", "")),
                 datetime.now(timezone.utc).isoformat()))
            self._db.commit()
            self.stored += 1
        except sqlite3.Error:
            logger.debug("verdict cache write failed", exc_info=True)

    def summary(self) -> dict[str, Any]:
        return {"available": self.available, "hits": self.hits,
                "misses": self.misses, "stored": self.stored}

    def close(self) -> None:
        if self._db is not None:
            try:
                self._db.close()
            except sqlite3.Error:
                pass
            self._db = None


def demo() -> None:
    import tempfile

    from docket.core.triage import UNJUDGED_PREFIX

    def finding(line: str) -> dict:
        return {"poc": {"request": line, "response": "msg"}}

    real = {"verdict": "not_reachable", "reasoning": "only called from tests",
            "evidence": "tests/conftest.py:14"}

    with tempfile.TemporaryDirectory() as tmp:
        cache = VerdictCache(cwd=Path(tmp))
        assert cache.available
        mark = fingerprint(finding("db.execute(q)"))

        # A miss costs nothing and says so.
        assert cache.get("acme/api", "k1", mark) is None
        assert (cache.hits, cache.misses) == (0, 1)

        cache.put("acme/api", "k1", mark, real)
        got = cache.get("acme/api", "k1", mark)
        assert got["verdict"] == "not_reachable", got
        assert got["cached"] is True, "a reused verdict must be identifiable as reused"
        assert got["evidence"] == "tests/conftest.py:14"
        assert cache.hits == 1

        # THE LOAD-BEARING CASE. Same finding, code edited in place: the dedupe_key is
        # unchanged but the judgement was about text that is no longer there. Reusing it
        # would let a line that somebody has since made reachable stay marked safe.
        changed = fingerprint(finding("db.execute(f'... {user}')"))
        assert cache.get("acme/api", "k1", changed) is None, \
            "an edited line must be re-judged, not inherited"

        # Scope: dedupe_key carries no repository, so app.py:36 in two repos collides.
        # One must never inherit the other's judgement.
        assert cache.get("other/repo", "k1", mark) is None, "verdicts must not cross repos"

        # A verdict the RUNNER synthesised is not an answer and must never be stored:
        # caching "nobody looked" turns one budget shortfall into a permanent skip.
        before = cache.stored
        cache.put("acme/api", "k2", mark,
                  {"verdict": "uncertain",
                   "reasoning": f"{UNJUDGED_PREFIX} It stopped before reaching one.",
                   "evidence": "agent outcome: MaxTurnsExceeded"})
        assert cache.stored == before, "a synthesised verdict must not be cached"
        assert cache.get("acme/api", "k2", mark) is None

        # ...but a genuine `uncertain` IS an answer and is kept.
        cache.put("acme/api", "k3", mark,
                  {"verdict": "uncertain", "reasoning": "entry point is in another repo",
                   "evidence": "routes.py:1-40"})
        assert cache.get("acme/api", "k3", mark)["verdict"] == "uncertain"

        # Re-judging the same finding overwrites rather than duplicating.
        cache.put("acme/api", "k1", changed, {"verdict": "exploitable",
                                              "reasoning": "now reachable", "evidence": "x.py:1"})
        assert cache.get("acme/api", "k1", changed)["verdict"] == "exploitable"
        assert cache.get("acme/api", "k1", mark) is None, "the old code must not resolve"

        # An empty key is not a key.
        cache.put("acme/api", "", mark, real)
        assert cache.get("acme/api", "", mark) is None
        cache.close()

        # Survives the process: that is the entire point.
        again = VerdictCache(cwd=Path(tmp))
        assert again.get("acme/api", "k3", mark)["verdict"] == "uncertain"
        again.close()

    # An unusable cache degrades to today's behaviour — judge everything — and never
    # raises. A cache that can fail a scan is worse than no cache.
    #
    # The warning it logs is correct in production and pure noise here, where the failure
    # is the thing being tested. Silenced for this one call so `make check` stays readable.
    logger.setLevel(logging.CRITICAL)
    broken = VerdictCache(Path("/proc/nonexistent/verdicts.db"))
    assert broken.available is False
    assert broken.get("s", "k", "f") is None
    broken.put("s", "k", "f", real)          # must not raise
    assert broken.summary()["available"] is False
    broken.close()
    logger.setLevel(logging.NOTSET)

    # The fingerprint is a CHANGE detector: same text same mark, different text different.
    assert fingerprint(finding("a")) == fingerprint(finding("a"))
    assert fingerprint(finding("a")) != fingerprint(finding("b"))
    assert fingerprint({}) == fingerprint({"poc": {}}), "no material is still a mark"
    print("core.verdict_cache: ok")


if __name__ == "__main__":
    demo()
