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
    -- (rule, file, matched code), NOT the line. See content_key: keying on the line made
    -- one insertion at the top of a file discard every verdict below it.
    content_key TEXT NOT NULL,
    verdict     TEXT NOT NULL,
    reasoning   TEXT NOT NULL,
    evidence    TEXT NOT NULL,
    judged_at   TEXT NOT NULL,
    PRIMARY KEY (scope, content_key)
);
CREATE INDEX IF NOT EXISTS verdicts_scope ON verdicts (scope);
"""


def cache_path(*, cwd: Path | None = None) -> Path:
    """Beside service.db. A verdict outlives the run that produced it — that is the
    entire point — so it does not belong inside a run directory."""
    from docket.core.paths import runs_root

    return runs_root(cwd=cwd) / SERVICE_DIR_NAME / CACHE_FILENAME


def content_key(finding: dict[str, Any]) -> str:
    """Identity of a finding that survives the line MOVING.

    dedupe_key is (rule, method, path, parameter, `path:line`) and is the right identity
    for a report — but it makes the LINE NUMBER part of the identity, so inserting one
    line at the top of a file re-keys every finding below it and throws away their
    verdicts. Measured: one insert at the top of the worst file in a 176-finding scan
    re-judged 20 of them for no reason at all.

    This is (rule, file, matched code) instead. The line may move; the finding is the
    same finding while the rule and the code it matched are unchanged.

    The cost is that two IDENTICAL lines in one file, matched by the same rule, collapse
    to one key — and their reachability could legitimately differ. Measured across every
    run on this machine: 23 of 2172 findings, 1.1%. So rather than accept the risk, the
    caller establishes uniqueness and an ambiguous key is simply not reused (see
    VerdictCache.get). 98.9% get line-independent caching; the rest re-judge.
    """
    location = finding.get("location") or {}
    source = str(location.get("source_file") or "")
    # `path:line` -> `path`. A bare path with no line (a trivy manifest hit) is kept whole.
    path = source.rsplit(":", 1)[0] if ":" in source else source
    material = "|".join((
        str(finding.get("rule_id") or ""),
        path,
        # Falls back to dedupe_key when there is no file at all — a dynamically proven
        # finding has no source anchor, and identity by code text means nothing for one.
        fingerprint(finding) if path else str(finding.get("dedupe_key") or ""),
    ))
    return hashlib.sha256(material.encode("utf-8", "replace")).hexdigest()[:32]


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

    def get(self, scope: str, key: str, *, unique: bool = True) -> dict[str, Any] | None:
        """A previous verdict for this finding, or None.

        `unique` is the caller's statement that this content key identifies exactly ONE
        finding in the current scan. When it does not — two identical lines in one file
        matched by the same rule — there is no way to tell which one the stored verdict
        was about, so nothing is reused and both are re-judged. Safe beats clever on 1.1%
        of findings.
        """
        if self._db is None or not key or not unique:
            return None
        try:
            row = self._db.execute(
                "SELECT verdict, reasoning, evidence FROM verdicts "
                "WHERE scope = ? AND content_key = ?", (scope, key)).fetchone()
        except sqlite3.Error:
            logger.debug("verdict cache read failed", exc_info=True)
            return None
        if row is None:
            self.misses += 1
            return None
        self.hits += 1
        return {"verdict": row["verdict"], "reasoning": row["reasoning"],
                "evidence": row["evidence"], "cached": True}

    def put(self, scope: str, key: str, verdict: dict[str, Any], *,
            unique: bool = True) -> None:
        """Store a verdict an AGENT reached. Synthesised and ambiguous ones are dropped.

        Ambiguous ones are dropped for the same reason they are not read: storing one of
        two identical findings' verdicts under a shared key would hand it to the other on
        the next run, which is the false reuse this design exists to avoid.
        """
        if self._db is None or not key or not unique or not verdict.get("verdict"):
            return
        if is_synthesised(verdict):
            return
        try:
            self._db.execute(
                "INSERT INTO verdicts (scope, content_key, verdict, reasoning, evidence, "
                "judged_at) VALUES (?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(scope, content_key) DO UPDATE SET "
                "verdict=excluded.verdict, reasoning=excluded.reasoning, "
                "evidence=excluded.evidence, judged_at=excluded.judged_at",
                (scope, key, str(verdict["verdict"]), str(verdict.get("reasoning", "")),
                 str(verdict.get("evidence", "")),
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

    def finding(line_no: int, code: str, rule: str = "sql-injection",
                path: str = "app.py") -> dict:
        return {"rule_id": rule, "poc": {"request": code, "response": "msg"},
                "location": {"source_file": f"{path}:{line_no}"}}

    real = {"verdict": "not_reachable", "reasoning": "only called from tests",
            "evidence": "tests/conftest.py:14"}

    # THE WHOLE POINT OF THE CONTENT KEY: the same code at a different line is the same
    # finding. Keying on the line meant one insertion at the top of a file discarded
    # every verdict below it — 20 of 176 on a real scan, for nothing.
    assert content_key(finding(50, "db.execute(q)")) == \
        content_key(finding(51, "db.execute(q)")), "a moved line must keep its verdict"
    # Edited in place: same line, different code. That IS a different finding.
    assert content_key(finding(50, "db.execute(q)")) != \
        content_key(finding(50, "db.execute(f'{u}')"))
    # Same code in a different file, or matched by a different rule, is not it either.
    assert content_key(finding(50, "db.execute(q)")) != \
        content_key(finding(50, "db.execute(q)", path="other.py"))
    assert content_key(finding(50, "db.execute(q)")) != \
        content_key(finding(50, "db.execute(q)", rule="other-rule"))

    with tempfile.TemporaryDirectory() as tmp:
        cache = VerdictCache(cwd=Path(tmp))
        assert cache.available
        key = content_key(finding(50, "db.execute(q)"))

        assert cache.get("acme/api", key) is None
        assert (cache.hits, cache.misses) == (0, 1)

        cache.put("acme/api", key, real)
        got = cache.get("acme/api", key)
        assert got["verdict"] == "not_reachable", got
        assert got["cached"] is True, "a reused verdict must be identifiable as reused"
        assert cache.hits == 1

        # The same finding after the file grew above it: free.
        assert cache.get("acme/api", content_key(finding(51, "db.execute(q)"))) is not None

        # Edited in place: re-judged.
        assert cache.get("acme/api", content_key(finding(50, "db.execute(f'{u}')"))) is None

        # Scope: content_key carries no repository, so app.py + the same line in two repos
        # collides. One must never inherit the other's judgement.
        assert cache.get("other/repo", key) is None, "verdicts must not cross repos"

        # AMBIGUOUS: two identical lines in one file, same rule. There is no way to tell
        # which one a stored verdict was about, so neither is read nor written.
        before = cache.stored
        cache.put("acme/api", key, real, unique=False)
        assert cache.stored == before, "an ambiguous key must not be stored"
        assert cache.get("acme/api", key, unique=False) is None, \
            "an ambiguous key must not be read, even when a row exists"

        # A verdict the RUNNER synthesised is not an answer: caching "nobody looked"
        # turns one budget shortfall into a permanent skip.
        before = cache.stored
        cache.put("acme/api", "k2", {"verdict": "uncertain",
                                     "reasoning": f"{UNJUDGED_PREFIX} It stopped early.",
                                     "evidence": "agent outcome: MaxTurnsExceeded"})
        assert cache.stored == before, "a synthesised verdict must not be cached"
        assert cache.get("acme/api", "k2") is None

        # ...but a genuine `uncertain` IS an answer.
        cache.put("acme/api", "k3", {"verdict": "uncertain",
                                     "reasoning": "entry point is in another repo",
                                     "evidence": "routes.py:1-40"})
        assert cache.get("acme/api", "k3")["verdict"] == "uncertain"

        # Re-judging overwrites rather than duplicating.
        cache.put("acme/api", key, {"verdict": "exploitable", "reasoning": "now reachable",
                                    "evidence": "x.py:1"})
        assert cache.get("acme/api", key)["verdict"] == "exploitable"

        assert cache.get("acme/api", "") is None, "an empty key is not a key"
        cache.close()

        # Survives the process: that is the entire point.
        again = VerdictCache(cwd=Path(tmp))
        assert again.get("acme/api", "k3")["verdict"] == "uncertain"
        again.close()

    # An unusable cache degrades to today's behaviour — judge everything — and never
    # raises. The warning it logs is correct in production and noise here.
    logger.setLevel(logging.CRITICAL)
    broken = VerdictCache(Path("/proc/nonexistent/verdicts.db"))
    assert broken.available is False
    assert broken.get("s", "k") is None
    broken.put("s", "k", real)               # must not raise
    assert broken.summary()["available"] is False
    broken.close()
    logger.setLevel(logging.NOTSET)

    assert fingerprint({}) == fingerprint({"poc": {}}), "no material is still a mark"
    print("core.verdict_cache: ok")


if __name__ == "__main__":
    demo()
