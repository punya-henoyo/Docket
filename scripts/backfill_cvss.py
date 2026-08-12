"""Add CVSS to trivy findings in reports written before the parser extracted it.

Not a rescore and not an invention: this re-reads each run's OWN raw trivy.json — the
artifact that run produced — and copies across the CVSS the advisory always carried
but the parser discarded. A run with no trivy artifact is left untouched.

Usage:  python scripts/backfill_cvss.py [--apply] [run_name ...]
Default is a dry run.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "engine"))

from docket.tools.scanners.trivy import parse_trivy_json  # noqa: E402

RUNS = Path(__file__).resolve().parent.parent / "docket_runs"


def backfill(run_dir: Path, apply: bool) -> tuple[int, str]:
    report = run_dir / "report.json"
    raw = run_dir / "sandbox" / "artifacts" / "scanners" / "trivy.json"
    if not report.is_file():
        return 0, "no report"
    if not raw.is_file():
        return 0, "no trivy artifact"
    try:
        data = json.loads(report.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        return 0, f"unreadable report ({type(exc).__name__})"

    # rule_id is "trivy/CVE-..." and is unique per advisory within a run.
    scores = {f.rule_id: f.cvss.model_dump() for f in parse_trivy_json(raw.read_text())
              if f.cvss}
    if not scores:
        return 0, "no CVSS in artifact"

    changed = 0
    for finding in data.get("findings", []):
        if finding.get("cvss") is None and finding.get("rule_id") in scores:
            finding["cvss"] = scores[finding["rule_id"]]
            changed += 1
    if changed and apply:
        report.write_text(json.dumps(data, indent=2))
    return changed, "written" if (changed and apply) else "would change"


def main() -> None:
    args = [a for a in sys.argv[1:] if a != "--apply"]
    apply = "--apply" in sys.argv
    targets = [RUNS / a for a in args] if args else sorted(p for p in RUNS.iterdir() if p.is_dir())
    total = 0
    for run_dir in targets:
        changed, note = backfill(run_dir, apply)
        total += changed
        if changed or "unreadable" in note:
            print(f"{run_dir.name}: {changed} finding(s) — {note}")
    print(f"\n{total} finding(s) {'updated' if apply else 'would be updated'}"
          f"{'' if apply else ' — re-run with --apply'}")


if __name__ == "__main__":
    main()
