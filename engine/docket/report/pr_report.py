"""Report a pull-request verdict back to GitHub.

Three surfaces, all reachable with the OAuth token docket already holds. Check Runs
are not — those need a GitHub App — but nothing here needs them:

  commit status          the MERGE GATE. Branch protection on the context name below
                         turns this into a real block.
  one PR comment         the summary, EDITED IN PLACE on every push. A check that
                         appends a comment per push trains people to collapse it.
  PR review comments     inline on the exact changed line.

WHAT THE COMMENT SAYS, AND WHAT IT REFUSES TO SAY
The whole thesis is that a check people leave enabled is one that is quiet when there
is nothing to say. So this never prints the backlog. It reports what the change
introduced, what it fixed, and nothing else. A clean PR gets a one-line comment, or no
comment at all if docket has never spoken on that PR.

And it never reports "clean" for a scan that did not finish. An inconclusive result is
posted as `error`, not `success` — the failure mode strix's CI docs warn about, where
a budget-exhausted run exits zero and is read as "no vulnerabilities".
"""
from __future__ import annotations

from typing import Any

from docket.report.diff import EXIT_CLEAN, EXIT_FOUND, EXIT_INCONCLUSIVE

# Branch protection targets this string. Changing it silently disables every gate
# already configured against it, so it is a constant and not a setting.
STATUS_CONTEXT = "docket/security"

# How docket finds its own comment to edit. Invisible in rendered markdown, and it
# survives a user editing the body around it.
COMMENT_MARKER = "<!-- docket:pr-scan -->"

# GitHub truncates a commit status description at 140 characters.
MAX_DESCRIPTION = 140

_SEVERITY_MARK = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}


def _cause_note(finding: dict[str, Any]) -> str:
    """The real location, and whether the change caused it.

    `location` has to stay the anchor the diff scoped on, so a cause in an untouched
    file cannot replace it — but sending a reviewer to the wrong file is worse than a
    longer cell. Mendor-lab#2 changed only app/services/db.py while the missing
    authorization lived in app/profiles.py:47.
    """
    cause = str(finding.get("root_cause") or "").strip()
    origin = str(finding.get("origin") or "").strip()
    parts = []
    if cause and cause != str((finding.get("location") or {}).get("source_file") or ""):
        parts.append(f"cause `{cause}`")
    if origin == "pre-existing":
        parts.append("**pre-existing**")
    return ("<br><sub>" + " · ".join(parts) + "</sub>") if parts else ""


def _cell(finding: dict[str, Any]) -> str:
    """Rule ids are code and get backticks; a recon title is prose and does not."""
    name = _rule(finding)
    return name if finding.get("discovered_by") == "recon" else f"`{name}`"


def status_for(exit_code: int, reason: str) -> tuple[str, str]:
    """(state, description) for the commit status API.

    INCONCLUSIVE maps to `error`, never `success` and never `failure`. It is not the
    author's code that failed, it is docket's ability to judge it, and saying so is the
    difference between a check that is trusted and one that quietly passes everything
    when it breaks.
    """
    state = {
        EXIT_CLEAN: "success",
        EXIT_FOUND: "failure",
        EXIT_INCONCLUSIVE: "error",
    }.get(exit_code, "error")

    text = reason.strip() or "no result"
    if len(text) > MAX_DESCRIPTION:
        text = text[: MAX_DESCRIPTION - 1].rstrip() + "…"
    return state, text


def _location(finding: dict[str, Any]) -> str:
    location = finding.get("location") or {}
    where = location.get("source_file") or location.get("path") or "?"
    return str(where).replace("/work/source/", "")


def _rule(finding: dict[str, Any]) -> str:
    """What to call this finding in one cell.

    A recon candidate has no rule — its rule_id is a slug OF its own title, so
    printing that gives an unreadable
    "no-function-level-authorization-anywhere-all-routes-are-worl". The title is the
    finding, so use it.
    """
    if finding.get("discovered_by") == "recon" and finding.get("title"):
        title = str(finding["title"])
        return title if len(title) <= 60 else title[:59].rstrip() + "…"
    return str(finding.get("rule_id", "?")).rsplit("/", 1)[-1].rsplit(".", 1)[-1]


def _verdict_note(finding: dict[str, Any]) -> str:
    verdict = (finding.get("triage") or {}).get("verdict")
    return {
        "exploitable": "**reachable**",
        "not_reachable": "ruled out",
        "uncertain": "uncertain",
    }.get(verdict, "not triaged")


def render_comment(verdict: dict[str, Any], *, run_url: str | None = None) -> str:
    """The PR comment body. Markdown, and deliberately short.

    Returns the body for ANY outcome including clean, because the comment is edited in
    place: a PR that was blocked and is now fixed must have its old comment replaced
    with the good news, not left showing a stale failure.
    """
    new = verdict.get("new") or []
    fixed = verdict.get("fixed") or []
    caveats = verdict.get("caveats") or []
    reachable = verdict.get("new_reachable") or []
    # Fall back to `new` when the split is absent, so a verdict built by an older caller
    # (or a hand-written one in a test) still renders every finding rather than none.
    gating = verdict.get("gating")
    observations = verdict.get("observations")
    if gating is None and observations is None:
        gating, observations = new, []
    gating, observations = list(gating or []), list(observations or [])

    lines = [COMMENT_MARKER, "## docket security check", ""]

    if caveats:
        lines += [
            "### Could not complete",
            "",
            "This check could not reach a verdict, so it is **not** a pass:",
            "",
            *(f"- {c}" for c in caveats),
            "",
        ]
    elif not gating and not observations:
        done = f" {len(fixed)} finding(s) fixed by this change." if fixed else ""
        lines += [f"No new findings introduced by this change.{done}", ""]
    else:
        def _table(rows: list[dict[str, Any]]) -> list[str]:
            out = ["| | Finding | Where | Triage |", "|---|---|---|---|"]
            for finding in rows[:10]:
                mark = _SEVERITY_MARK.get(str(finding.get("severity")), "⚪")
                out.append(
                    f"| {mark} {finding.get('severity','?')} | {_cell(finding)} "
                    f"| `{_location(finding)}`{_cause_note(finding)} "
                f"| {_verdict_note(finding)} |"
                )
            if len(rows) > 10:
                out.append(f"| | …and {len(rows) - 10} more | | |")
            return [*out, ""]

        if gating:
            lines += [
                (f"**{len(reachable)} of {len(gating)} new finding(s) are reachable "
                 "by untrusted input.**" if reachable
                 else f"{len(gating)} new finding(s), none judged reachable."),
                "",
                *_table(gating),
            ]
        elif not caveats:
            lines += ["No new scanner findings introduced by this change.", ""]
        if fixed:
            lines += [f"{len(fixed)} finding(s) fixed by this change.", ""]

        # Reported, never blocking, and labelled so nobody reads them as "you did this".
        # The base scan runs recon=False (core/pr_service.py), so these have no baseline
        # to be compared against and are `new` on every pull request by construction.
        # kaizenmantra/vulnshop#25 was a one-line fix blocked on a missing ownership
        # check that was already in the branch it targeted.
        if observations:
            lines += [
                f"<details><summary>{len(observations)} agent observation(s) — "
                "not blocking</summary>",
                "",
                "Agent findings docket could not tie to a specific line this change "
                "touched — no line was cited, or this was a whole-repository fallback "
                "scan. Reported so a reviewer sees them; they do not affect the check. "
                "Agent findings that DO sit on a changed line are in the table above and "
                "block like any other.",
                "",
                *_table(observations),
                "</details>",
                "",
            ]

    scoped = verdict.get("scoped_to") or []
    if scoped:
        lines.append(
            f"<sub>Scanned {len(scoped)} changed file(s). Pre-existing findings "
            "elsewhere in the repository are not shown — this check reports only what "
            "this change introduced.</sub>"
        )
    if run_url:
        lines.append(f"<sub>[Full report]({run_url})</sub>")
    return "\n".join(lines).rstrip() + "\n"


def should_comment(verdict: dict[str, Any], *, already_commented: bool) -> bool:
    """Whether to say anything at all.

    A clean PR docket has never spoken on gets NO comment. The commit status already
    carries the result, and an unprompted "nothing to report" on every pull request is
    how a bot gets muted. Once docket HAS commented, it must keep that comment current
    — leaving a stale "1 reachable finding" over a PR that has since fixed it is worse
    than any amount of noise.
    """
    if already_commented:
        return True
    return bool(verdict.get("new") or verdict.get("caveats"))


def inline_comments(verdict: dict[str, Any], commit_sha: str,
                    changed_lines: dict[str, set[int]] | None = None) -> list[dict[str, Any]]:
    """Review-comment payloads, one per new finding, for lines inside the diff.

    GitHub rejects a review comment on a line that is not part of the diff with a 422,
    and one rejection fails the whole review. So a finding whose line was not changed
    is skipped here rather than posted and hoped for; it still appears in the summary
    table, which is why dropping it loses nothing.
    """
    out: list[dict[str, Any]] = []
    for finding in verdict.get("new") or []:
        location = finding.get("location") or {}
        source = str(location.get("source_file") or "").replace("/work/source/", "")
        if ":" not in source:
            continue
        path, _, raw_line = source.rpartition(":")
        if not raw_line.isdigit() or not path:
            continue
        line = int(raw_line)
        if changed_lines is not None and line not in changed_lines.get(path, set()):
            continue
        out.append({
            "path": path,
            "line": line,
            "side": "RIGHT",
            "commit_id": commit_sha,
            "body": (
                f"**{finding.get('severity','?')} · {_rule(finding)}** "
                f"— {_verdict_note(finding)}\n\n"
                f"{str(finding.get('description', '')).strip()[:400]}"
            ),
        })
    return out


def demo() -> None:
    def finding(rule, path, line=10, severity="high", verdict=None):
        f = {"rule_id": rule, "severity": severity,
             "description": "user input reaches a raw SQL string",
             "location": {"method": "STATIC", "path": path, "parameter": None,
                          "source_file": f"{path}:{line}"}}
        if verdict:
            f["triage"] = {"verdict": verdict, "reasoning": "r", "evidence": "e"}
        return f

    # ── the gate ────────────────────────────────────────────────────────────
    assert status_for(EXIT_CLEAN, "No new findings")[0] == "success"
    assert status_for(EXIT_FOUND, "1 blocks this merge")[0] == "failure"
    # Never success, never failure: docket could not judge, and must say so.
    assert status_for(EXIT_INCONCLUSIVE, "scan did not complete")[0] == "error"
    assert status_for(999, "?")[0] == "error", "an unknown code is not a pass"

    state, text = status_for(EXIT_FOUND, "x" * 400)
    assert len(text) <= MAX_DESCRIPTION and text.endswith("…"), len(text)

    # ── clean ───────────────────────────────────────────────────────────────
    clean = {"new": [], "fixed": [finding("a", "x.py")], "caveats": [],
             "new_reachable": [], "scoped_to": ["x.py"]}
    body = render_comment(clean)
    assert "No new findings introduced" in body and "1 finding(s) fixed" in body
    assert COMMENT_MARKER in body
    # The backlog is never printed. That is the whole product.
    assert "pre-existing" in body.lower() and "not shown" in body

    # Silent on a clean PR docket has not spoken on; keeps it current once it has.
    assert not should_comment(clean, already_commented=False)
    assert should_comment(clean, already_commented=True), "a stale failure must be replaced"

    # ── something introduced ────────────────────────────────────────────────
    reachable = finding("semgrep/py.sqli", "app/auth.py", line=41, verdict="exploitable")
    found = {"new": [reachable, finding("semgrep/py.xss", "app/s.py", severity="medium")],
             "fixed": [], "caveats": [], "new_reachable": [reachable],
             "scoped_to": ["app/auth.py", "app/s.py"]}
    body = render_comment(found, run_url="http://localhost:8765/#/findings")
    assert "1 of 2 new finding(s) are reachable" in body
    assert "`sqli`" in body and "`app/auth.py:41`" in body
    assert "**reachable**" in body and "Full report" in body
    assert should_comment(found, already_commented=False)

    # New but nothing reachable reads differently, and does not shout.
    quiet = dict(found, new_reachable=[])
    assert "none judged reachable" in render_comment(quiet)
    assert "reachable by untrusted input" not in render_comment(quiet)

    # Long lists are truncated in the comment, never in the count.
    many = {"new": [finding(f"r{i}", f"f{i}.py") for i in range(25)],
            "fixed": [], "caveats": [], "new_reachable": [], "scoped_to": []}
    body = render_comment(many)
    assert "…and 15 more" in body and body.count("| 🟠 high |") == 10

    # ── never fail open ─────────────────────────────────────────────────────
    stopped = {"new": [], "fixed": [], "new_reachable": [],
               "caveats": ["the head scan did not complete successfully"]}
    body = render_comment(stopped)
    assert "Could not complete" in body and "**not** a pass" in body
    assert "No new findings" not in body, "an unfinished scan must never read as clean"
    assert should_comment(stopped, already_commented=False)

    # ── inline comments ─────────────────────────────────────────────────────
    payloads = inline_comments(found, "abc123")
    assert len(payloads) == 2
    assert payloads[0] == {
        "path": "app/auth.py", "line": 41, "side": "RIGHT", "commit_id": "abc123",
        "body": payloads[0]["body"],
    }
    assert "sqli" in payloads[0]["body"] and "reachable" in payloads[0]["body"]

    # A line outside the diff is skipped, not posted: GitHub 422s it and one
    # rejection fails the whole review. It still shows in the summary table.
    limited = inline_comments(found, "abc123", changed_lines={"app/auth.py": {41}})
    assert [p["path"] for p in limited] == ["app/auth.py"]
    assert inline_comments(found, "abc", changed_lines={"app/auth.py": {9}}) == []

    # A finding with no line cannot be anchored and is dropped rather than guessed at.
    noline = {"new": [{"rule_id": "r", "severity": "high",
                       "location": {"path": "a.py", "source_file": "a.py"}}]}
    assert inline_comments(noline, "abc") == []

    print("report.pr_report: ok")


if __name__ == "__main__":
    demo()
