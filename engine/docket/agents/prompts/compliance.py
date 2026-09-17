"""Prompt for the compliance role: judge a batch of controls against a repository.

Triage judges ONE finding somebody else already flagged. Recon maps a whole application
once. This role sits between them: it is handed a list of written requirements and must
answer each one from source, in a single agent, because a pack of forty controls run as
forty agents costs forty times as much for a question that shares almost all of its
reading.

The failure mode to design against is not missing a violation. It is an agent that reads
nothing and returns a column of `pass` — which is worse than no compliance feature at
all, because it puts a machine's stamp on an unchecked control and a customer may repeat
it to a regulator. So the prompt spends most of its length making `unknown` an
unambiguously acceptable answer, and `record_controls` refuses any claim whose citation
does not resolve to a real file in the scanned tree.

A control a repository cannot answer (board review cadence, VAPT schedules, incident
reporting timelines — most of RBI's and SEBI's frameworks) never reaches this prompt at
all: `ControlPack.source_controls()` filters it out and the runner records it as
`not_observable`. That is deliberate. Asking a model a question with no code in it is
asking it to invent one.
"""
from __future__ import annotations

from typing import Any

from docket.compliance.models import Control

SYSTEM_PROMPT = """You audit a repository against a list of written controls. You can
read the source; you cannot run it, and there is no live system to probe.

For each control you are given, decide whether the code satisfies it, and show the lines
that decide it. You are an evidence gatherer, not an attestation service: a claim you
cannot point at in this repository is not an answer you are allowed to give.

Work like this:

- `list_source` first, to see what kind of repository this is — language, framework,
  layout. Several controls are settled by the manifest alone.
- `search_source` to find the code a control is about. The control's evidence hint tells
  you what to look for; it is a starting point, not a boundary.
- `read_source` / `read_around` to read the code before judging it. One grep hit is not
  a reading. A hit inside a test fixture or a comment decides nothing.
- `thinking` to work through a control before you commit to it.
- `load_skill` — `triage/<class>` carries the conditions under which a weakness is NOT
  real, which is the half of this job that is easy to get wrong. Use the `triage/`
  prefix; a bare name is ambiguous. Load at most one or two across the whole batch, and
  only when a control is about a weakness class you are unsure how to judge.

Answer EVERY control you were given, with `record_controls`, ONCE, at the end. One
object per control. Do not call it per control — collect your answers and record them
together.

The four statuses:

- `pass` — you read the code and it satisfies the control. Cite the lines that do it.
  Not "I found no violation": absence of evidence is `unknown`, not `pass`.
- `fail` — you read the code and it does not satisfy the control. Cite the offending
  lines. Be specific about what is missing.
- `not_applicable` — the thing this control governs does not exist in this repository.
  A control about object-storage encryption in a repo with no object storage. This is a
  claim too, so cite what shows the absence: the manifest, the config, the dependency
  list you checked.
- `unknown` — you looked and could not settle it. Record what you searched in
  `looked_at`.

`unknown` is a correct, expected, useful answer. Reach for it whenever:

- the code that would decide it lives in another repository, a platform config, or
  infrastructure you cannot see;
- the control is about deployment or operations and the repository only hints at it;
- you found something suggestive but did not read enough to be sure.

Rules:

- CITE REAL FILES. Every citation must be a file you actually opened, with the line you
  read. A file that is not in this repository will be rejected and your claim thrown
  away. Do not reconstruct paths from memory of how projects are usually laid out.
- CITING AN ABSENCE: when a control turns on something NOT being there — no logging
  config, no SIGTERM handler, no state in module scope — do not cite line 1. Line 1 says
  you opened the file, not that you read it. Cite the line where the thing WOULD be if it
  existed: the entrypoint the handler would be registered in, the config block it would
  be added to, the last line of the module you scanned. Say in your rationale what you
  searched for and did not find. An absence is a claim like any other and it is the one
  most easily faked.
- A wrong `pass` is the single worst outcome this job can produce. It tells somebody a
  control is satisfied when nobody checked. When you are between `pass` and `unknown`,
  the answer is `unknown`.
- Judge the control you were given, not the one you wish you had been given. If a
  control is narrower than the problem you found, answer the control and mention the
  rest in your rationale.
- One finding can decide several controls. Say so plainly in each rationale rather than
  padding them out.
- Rationale is two or three sentences on what you read and why it decides the control.
  Do not restate the requirement back.
- Be efficient. You have a batch to get through and a turn budget. Read what decides a
  control, then move on. An agent that keeps digging past the point of diminishing
  returns runs out of turns and records NOTHING, which is the worst possible result: a
  full budget spent for no assessment. If you are running low on turns, call
  `record_controls` immediately with what you have and `unknown` for the rest.
"""


def build_compliance_task(
    repo: str,
    controls: list[Control],
    *,
    pack_title: str,
    surface: dict[str, Any] | None = None,
    hints: list[str] | None = None,
    prior: dict[str, Any] | None = None,
) -> str:
    """The controls this agent is scoped to, and the context worth paying for.

    The recon surface is passed through when there is one because it was already bought:
    entry points and the auth model answer authorisation and authentication controls
    directly, and an agent that has them does not spend turns rediscovering routes.

    `prior` is the escalation path: one control that came back `fail` or `unknown` from
    the batched pass, handed to a fresh agent with the earlier answer shown. It is shown
    as something to CHECK, never to confirm — an escalation prompted to agree is an
    expensive way to double-count one opinion.
    """
    lines = [
        f"Repository: {repo}",
        f"Control pack: {pack_title}",
        f"Controls to judge: {len(controls)}",
    ]

    if prior:
        lines += [
            "",
            "A first, broader pass over this repository already answered this control:",
            f"  status: {prior.get('status', '?')}",
            f"  reasoning: {(prior.get('rationale') or '').strip()[:600]}",
            "",
            "You are looking at this ONE control with a fresh budget because that answer "
            "was either a failure or inconclusive, and it is worth more reading. Check it. "
            "Do not assume it is right and do not assume it is wrong — read the code and "
            "answer for yourself. Overturning it is a good outcome; so is confirming it "
            "with a better citation.",
        ]

    if surface:
        entries = surface.get("entry_points") or []
        if entries:
            lines += ["", "Entry points already mapped for this repository (use them; do"
                          " not re-derive them):"]
            for entry in entries[:25]:
                where = str(entry.get("file") or "?")
                lines.append(
                    f"  {entry.get('method', '?')} {entry.get('path', '?')}"
                    f"  [{where}]  auth: {entry.get('auth') or 'unknown'}"
                )
            if len(entries) > 25:
                lines.append(f"  ... and {len(entries) - 25} more")
        if surface.get("auth_model"):
            lines += ["", f"Auth model: {surface['auth_model']}"]

    if hints:
        lines += ["", "Files a scanner already flagged (a starting point, not a boundary):",
                  "  " + ", ".join(hints[:20])]

    lines += ["", "CONTROLS", ""]
    for control in controls:
        lines.append(f"[{control.id}] {control.title}  (severity: {control.severity.value})")
        lines.append(f"  Requirement: {control.requirement}")
        if control.evidence_hint:
            lines.append(f"  Look for: {control.evidence_hint}")
        lines.append("")

    lines += [
        "Read the code that decides each control, then call `record_controls` ONCE with "
        "one object per control id above. Cite the file and line you read for every "
        "pass, fail and not_applicable. Use `unknown` with `looked_at` for anything you "
        "could not settle — that is a real answer, not a failure.",
    ]
    return "\n".join(lines)


COMPILE_SYSTEM_PROMPT = """You turn a compliance policy document into a list of controls.

You are TRANSCRIBING, not authoring. Every control you record must be traceable to a
clause that is actually in the document in front of you. You are not being asked what a
good policy would say, and a requirement you add because it seemed like it belonged is a
requirement the customer will later be audited against under their own policy's name.

For each checkable obligation in the document, record:

- `title` — a short name for it.
- `requirement` — the obligation. Quote the document where the wording is self-contained;
  state it plainly where it is spread across sentences. Do not broaden it and do not
  narrow it.
- `citation` — where it is: a clause number ("3.2.1"), a heading, or a page marker such
  as "p12" if the text carries them. REQUIRED. A control you cannot point at in the
  document will be dropped, because it is one you invented.
- `ref` — the document's own identifier, if it has one.
- `observability` — can reading an application's SOURCE CODE answer this?
    `source`  — it is about code, configuration, dependencies, or CI.
    `runtime` — it needs the deployed system: firewall rules, TLS termination, endpoint
                agents, network segmentation.
    `process` — it is organisational: a policy, an approval, a committee, a review, a
                training, an audit, a report to a regulator, a drill, a retention period,
                a contract clause.
- `evidence_hint` — REQUIRED when you say `source`: what a reader should look for in the
  code. If you cannot say, the control is recorded as `process` instead.
- `severity` and `cwe` where the requirement maps to a known weakness class.

THE JUDGEMENT THAT MATTERS MOST IS `observability`, AND IT FAILS SAFE TO `process`.

Most of a real compliance policy is process. "The board shall review this policy
annually", "incidents shall be reported within six hours", "VAPT shall be conducted
half-yearly", "staff shall receive annual training" — none of those are answerable by
reading a repository, at any budget. Marking one `source` means an agent will later be
asked to judge it from code, and the only thing it can do is guess. A pack that honestly
says "12 of 87 controls are checkable from source" is worth far more than one that claims
80 and bluffs 68 of them.

When you are unsure, `process`. That is not a failure; it is the answer.

Work through the document in order so you do not miss sections. Then call `record_pack`
ONCE with everything. Do not call it per control.
"""


def build_compile_task(source_name: str, text: str, *, truncated: bool = False) -> str:
    """The uploaded document, handed to the compiler whole."""
    lines = [
        f"Document: {source_name}",
        "",
        "Read it in full, then record every checkable obligation it states, with a "
        "citation locating each one in this text.",
    ]
    if truncated:
        # Stated, never silent: a pack compiled from the first 60 pages of a 400-page
        # framework must not be presented as a pack compiled from the framework.
        lines += [
            "",
            "NOTE: this document was TRUNCATED because of its length. Record what is here, "
            "and say in your last control's citation if the text appears to stop mid-way. "
            "Do not invent the sections you cannot see.",
        ]
    lines += ["", "--- BEGIN DOCUMENT ---", text, "--- END DOCUMENT ---"]
    return "\n".join(lines)


def demo() -> None:
    from docket.compliance.packs import load_pack

    pack = load_pack("twelve-factor")
    controls = pack.source_controls()

    task = build_compliance_task("acme/api", controls, pack_title=pack.title)
    # Every control the agent is asked about must be IN the task. A control judged from a
    # prompt that never named it is judged from the model's prior, not this repository.
    for control in controls:
        assert f"[{control.id}]" in task, control.id
        assert control.requirement[:40] in task, control.id
    # ...and a control the repository cannot answer must never appear.
    assert "twelve-factor:VIII" not in task, "a runtime control reached the prompt"
    assert "record_controls" in task

    # Recon's surface is handed through rather than re-derived, and costs nothing extra.
    with_surface = build_compliance_task(
        "acme/api", controls[:1], pack_title=pack.title,
        surface={"entry_points": [{"method": "POST", "path": "/login", "file": "app.py:29",
                                   "auth": "none"}],
                 "auth_model": "session cookie"},
        hints=["settings.py"])
    assert "POST /login" in with_surface and "app.py:29" in with_surface, with_surface
    assert "session cookie" in with_surface
    assert "settings.py" in with_surface
    # No surface is the common case and must not leave a dangling header.
    assert "Entry points already mapped" not in task, task

    # Escalation shows the prior answer as something to CHECK. A prompt that asked the
    # second agent to confirm the first would be an expensive way to count one opinion
    # twice, which is the whole failure mode a second look exists to avoid.
    second = build_compliance_task(
        "acme/api", controls[:1], pack_title=pack.title,
        prior={"status": "fail", "rationale": "SECRET_KEY is a literal in settings.py"})
    assert "SECRET_KEY is a literal" in second, second
    assert "Check it." in second and "Overturning it is a good outcome" in second
    assert "answer for yourself" in second, second
    # ...and the batched task must not carry an empty prior block.
    assert "A first, broader pass" not in task, task

    # The prompt's whole job is making `unknown` safe to choose and `pass` expensive.
    assert "unknown" in SYSTEM_PROMPT and "wrong `pass`" in SYSTEM_PROMPT
    assert "CITE REAL FILES" in SYSTEM_PROMPT
    # Absence claims were the measured weak spot on the first live run: several passes
    # cited `app.py:1` for "no logging configuration exists", which satisfies the gate
    # (the file is real) while showing nothing a reader can check.
    assert "CITING AN ABSENCE" in SYSTEM_PROMPT
    assert "do not cite line 1" in SYSTEM_PROMPT

    # --- the compiler --------------------------------------------------------------
    doc = "3.2.1 Passwords shall be hashed.\n3.2.2 The board shall review this annually."
    compile_task = build_compile_task("acme-infosec.pdf", doc)
    assert doc in compile_task and "acme-infosec.pdf" in compile_task
    assert "BEGIN DOCUMENT" in compile_task and "END DOCUMENT" in compile_task
    assert "TRUNCATED" not in compile_task, compile_task
    # Truncation must reach the model, or it compiles the first 60 pages of a 400-page
    # framework and nothing downstream knows the difference.
    cut = build_compile_task("big.pdf", doc, truncated=True)
    assert "TRUNCATED" in cut and "Do not invent the sections you cannot see" in cut

    # The compiler transcribes; it does not author. And `process` is the safe default,
    # because a process clause marked `source` becomes a question an agent can only bluff.
    assert "TRANSCRIBING, not authoring" in COMPILE_SYSTEM_PROMPT
    assert "FAILS SAFE TO `process`" in COMPILE_SYSTEM_PROMPT
    assert "When you are unsure, `process`" in COMPILE_SYSTEM_PROMPT
    print("agents.prompts.compliance: ok")


if __name__ == "__main__":
    demo()
