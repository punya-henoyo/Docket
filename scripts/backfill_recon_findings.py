"""Promote recon candidates to findings in reports written before that was wired in.

Not a re-scan and not a re-judgement: this re-reads each run's OWN surface — the map
that run's recon agent produced — and converts its candidates through exactly the same
code path a live scan now uses (core/surface_findings.candidates_to_findings). The
findings were always there, sitting on the surface object where only the Attack surface
tab looked.

Idempotent: a run whose candidates are already promoted is skipped, matched by
discovered_by == "recon", so re-running this cannot duplicate them.

report.sarif is regenerated too. Leaving it stale would mean the console and the file
GitHub ingests disagree about what the scan found, which is worse than not backfilling
at all.

Usage:  python scripts/backfill_recon_findings.py [--apply] [run_name ...]
        Dry run by default.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "engine"))

from docket.core.surface_findings import candidates_to_findings  # noqa: E402

RUNS = Path(__file__).resolve().parent.parent / "docket_runs"

_ORDER = ["critical", "high", "medium", "low", "info"]


def backfill(run_dir: Path, apply: bool) -> tuple[int, str]:
    report = run_dir / "report.json"
    if not report.is_file():
        return 0, "no report"
    try:
        data = json.loads(report.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        return 0, f"unreadable ({type(exc).__name__})"

    surface = data.get("surface") or {}
    if not surface.get("candidates"):
        return 0, "no candidates"
    if any(f.get("discovered_by") == "recon" for f in data.get("findings", [])):
        return 0, "already promoted"

    promoted = candidates_to_findings(surface)
    if not promoted:
        # Candidates exist but none cite a file, so none are findings. Worth saying
        # out loud rather than reporting "0" as if there had been nothing to do.
        return 0, f"{len(surface['candidates'])} candidate(s), none cite a file"

    if not apply:
        return len(promoted), "would promote"

    data["findings"].extend(f.model_dump(mode="json") for f in promoted)
    data["finding_count"] = len(data["findings"])
    counts: dict[str, int] = {}
    for finding in data["findings"]:
        severity = str(finding.get("severity", "info"))
        counts[severity] = counts.get(severity, 0) + 1
    data["severity_counts"] = {s: counts[s] for s in _ORDER if s in counts}
    report.write_text(json.dumps(data, indent=2))

    # The brief is a cached render of this report; a stale one would now under-report.
    brief = run_dir / "brief.html"
    if brief.exists():
        brief.unlink()

    try:
        from docket.report.models import Finding
        from docket.report.sarif import to_sarif

        findings = [Finding.model_validate(f) for f in data["findings"]]
        (run_dir / "report.sarif").write_text(
            json.dumps(to_sarif(findings, target=data.get("target")), indent=2)
        )
    except Exception as exc:  # noqa: BLE001 — a stale SARIF must not lose the promotion
        return len(promoted), f"promoted, but SARIF not regenerated ({exc})"
    return len(promoted), "promoted"


def main() -> None:
    args = [a for a in sys.argv[1:] if a != "--apply"]
    apply = "--apply" in sys.argv
    targets = [RUNS / a for a in args] if args else sorted(
        p for p in RUNS.iterdir() if p.is_dir()
    )
    total = 0
    for run_dir in targets:
        count, note = backfill(run_dir, apply)
        total += count
        if count or "unreadable" in note or "none cite" in note:
            print(f"{run_dir.name}: {count} — {note}")
    print(f"\n{total} candidate(s) {'promoted' if apply else 'would be promoted'}"
          f"{'' if apply else ' — re-run with --apply'}")


if __name__ == "__main__":
    main()
