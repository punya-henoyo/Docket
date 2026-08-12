"""Derive docket's recon and triage playbooks from strix's vulnerability skills.

WHY A GENERATOR AND NOT HAND-WRITTEN FILES
------------------------------------------
The source is ~4,900 lines of security knowledge across 25 files. Retyping that from
memory would introduce errors in exactly the details that matter — parameter names,
the shapes a bug takes, the conditions that make it a false alarm. Extraction copies
the text verbatim, so a claim in a docket playbook is a claim strix's authors wrote.

WHAT IS SPLIT, AND WHY
----------------------
Every strix vulnerability skill has the same skeleton. Half of it is procedure for a
live target — sending requests, replaying them, bypassing WAFs — which docket cannot
do: recon and triage read source and execute nothing. Loading that half would put
instructions in front of an agent that cannot follow them, and an agent told to "swap
the object ID and replay" with no HTTP tool is an agent that starts narrating attacks
it never ran.

So the source-readable half is extracted and split by CONSUMER rather than by
vulnerability:

  recon/<class>.md   Attack Surface, Key Vulnerabilities, High-Value Targets
                     -> where the bug lives and what it looks like in code
  triage/<class>.md  False Positives, Impact
                     -> what makes this NOT a bug, which is triage's whole job

The live-target sections (Testing Methodology, Validation, Bypass Techniques, active
Reconnaissance) are deliberately dropped. They become the specialists' playbooks when
docket grows a dynamic half; until then they are omitted, not stubbed.

LICENCE
-------
strix is Apache-2.0 and so is docket. Adaptation is permitted with attribution and a
statement of changes; every generated file carries both, and NOTICE records it.

Usage:  python scripts/build_skills.py [--strix PATH] [--check]
        --check verifies the committed files match what the generator produces.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
OUT = REPO / "engine" / "docket" / "skills"
DEFAULT_STRIX = Path.home() / "strix" / "strix" / "skills" / "vulnerabilities"

# Sections an agent that only reads source can act on.
RECON_SECTIONS = ["Attack Surface", "Key Vulnerabilities", "High-Value Targets",
                  "Special Contexts"]
TRIAGE_SECTIONS = ["False Positives", "Impact"]

# Sections dropped on purpose. Named here so the omission is a decision on the record
# rather than something that looks like an oversight.
LIVE_ONLY = ["Testing Methodology", "Validation", "Bypass Techniques", "Reconnaissance",
             "Advanced Techniques", "Chaining Attacks", "Pro Tips", "Summary"]

# Minimum useful size, per kind. These differ because the two shapes differ: a recon
# playbook is prose describing where a bug lives and needs room, while a triage
# playbook is a bullet list of conditions and is naturally short. Measured across the
# 25 sources, triage sections run 403-1173 characters with no gap in the distribution,
# so a single shared threshold silently dropped sql_injection, xss and mass_assignment
# — the three classes carrying most of semgrep's output, and the ones triage most
# needs help with. A size bar was simply the wrong instrument there.
MIN_CHARS = {"recon": 600, "triage": 150}

RECON_HEADER = """You are READING SOURCE, not sending requests. Nothing below is a
step to perform against a running application; it is a description of where this class
of bug lives and what it looks like in code.

Use it to decide **where to read** and **what to compare**. The highest-value finding
in this class is usually an ABSENCE — a check that every sibling handler performs and
this one does not. You cannot grep for a line that was never written, so find it by
reading neighbours and noticing the disagreement.

Record what you find with `record_surface` as a candidate, citing file and line. A
candidate is a suspicion with evidence, never a proven vulnerability."""

TRIAGE_HEADER = """You are judging whether a reported finding is REACHABLE by
untrusted input, by reading source. You execute nothing.

The "Not a bug when" list below is the important half. Your job is as much ruling
things out as confirming them: a finding you can show is unreachable saves someone a
day, and a wrong `exploitable` verdict costs the same person a day. When the source
does not settle it, return `uncertain` — that is a real answer, not a failure."""


def split_sections(text: str) -> dict[str, str]:
    """{heading: body} for every `## ` section."""
    parts = re.split(r"^## +(.+?)\s*$", text, flags=re.M)
    out: dict[str, str] = {}
    for i in range(1, len(parts) - 1, 2):
        out[parts[i].strip()] = parts[i + 1].strip()
    return out


def front_matter(text: str) -> tuple[str, str]:
    """(name, description) from the YAML front matter, or ('', '')."""
    match = re.match(r"^---\s*\n(.*?)\n---\s*\n", text, flags=re.S)
    if not match:
        return "", ""
    block = match.group(1)
    name = re.search(r"^name:\s*(.+)$", block, flags=re.M)
    desc = re.search(r"^description:\s*(.+)$", block, flags=re.M)
    return (name.group(1).strip() if name else "",
            desc.group(1).strip() if desc else "")


def render(kind: str, stem: str, description: str, sections: dict[str, str],
           wanted: list[str], source_file: str) -> str | None:
    kept = [(h, sections[h]) for h in wanted if sections.get(h)]
    # Triage hinges on one section. A playbook with an Impact paragraph and no
    # "False Positives" list teaches an agent what a bug costs, not how to rule it
    # out — which is the opposite of what triage is for.
    if kind == "triage" and not sections.get("False Positives", "").strip():
        return None
    if sum(len(b) for _, b in kept) < MIN_CHARS[kind]:
        return None

    title = stem.replace("_", " ")
    header = RECON_HEADER if kind == "recon" else TRIAGE_HEADER
    # "False Positives" is the section triage needs most, and its strix title reads as
    # a category label. Renamed to the question the agent is actually answering.
    rename = {"False Positives": "Not a bug when", "Impact": "Impact if it IS real",
              "Attack Surface": "Where this lives",
              "Key Vulnerabilities": "Shapes this takes in code",
              "High-Value Targets": "Where to look first"}

    body = "\n\n".join(f"## {rename.get(h, h)}\n\n{b}" for h, b in kept)
    verb = "map" if kind == "recon" else "judge"
    return f"""---
name: {kind}-{stem}
description: {description or f'{title} — source-reading notes for {verb}ing this class'}
---

# {title} — for {'reconnaissance over source' if kind == 'recon' else 'triage over source'}

{header}

{body}

---

Adapted from the strix project's `{source_file}` (Apache-2.0). Changes: sections
covering live-target testing, validation and bypass techniques were removed, because
docket's {kind} agent reads source and executes nothing; the remaining text is
unmodified. See NOTICE.
"""


def build(strix_dir: Path, check: bool) -> int:
    if not strix_dir.is_dir():
        print(f"strix skills not found at {strix_dir}", file=sys.stderr)
        return 2

    written, skipped, stale = 0, [], []
    for source in sorted(strix_dir.glob("*.md")):
        text = source.read_text()
        _, description = front_matter(text)
        sections = split_sections(text)
        for kind, wanted in (("recon", RECON_SECTIONS), ("triage", TRIAGE_SECTIONS)):
            content = render(kind, source.stem, description, sections, wanted,
                             f"skills/vulnerabilities/{source.name}")
            target = OUT / kind / f"{source.stem}.md"
            if content is None:
                skipped.append(f"{kind}/{source.stem}")
                continue
            if check:
                if not target.is_file() or target.read_text() != content:
                    stale.append(str(target.relative_to(REPO)))
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content)
            written += 1

    if check:
        if stale:
            print("out of date:\n  " + "\n  ".join(stale), file=sys.stderr)
            return 1
        print("skills are up to date")
        return 0

    print(f"wrote {written} playbook(s) to {OUT.relative_to(REPO)}/")
    if skipped:
        # Named, not silent: a class with no source-readable content is a real gap in
        # docket's coverage and should be visible, not look like it was forgotten.
        print(f"skipped {len(skipped)} (nothing usable without a live target):")
        for s in sorted(skipped):
            print(f"  {s}")
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--strix", type=Path, default=DEFAULT_STRIX)
    parser.add_argument("--check", action="store_true",
                        help="verify committed files match the generator")
    args = parser.parse_args()
    raise SystemExit(build(args.strix, args.check))


if __name__ == "__main__":
    main()
