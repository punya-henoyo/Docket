"""`record_controls`: the only way a compliance agent can end its turn.

Same stance as `finding`, `triage_verdict` and `record_surface` — a claim must cite the
code it came from. The bar here is stronger than triage's in one specific way, and the
reason is what the output is used for: a triage verdict is read by an engineer who still
has the finding in front of them, while a compliance result may be handed to an auditor
as the reason a control was marked satisfied. So a cited file is not merely required, it
is RESOLVED against the scanned tree via `resolve_in_root`. A plausible-looking path that
does not exist is a fabrication with a filename attached, and it must not survive.

REFUSE vs DOWNGRADE, which is the whole design of this module.

`_finish_tool_use_behavior` (agents/factory.py) ends the run the moment a finish tool
returns a dict — `ok: False` included. A refusal is therefore not a retry prompt; it is
the end of the agent. Recon can afford that because it records one object. This tool
records a batch of up to a dozen control results, so refusing the whole batch to punish
one bad row throws away every good row with it.

  refuse    only when nothing is lost: an empty batch, or a batch where no row survived.
  downgrade every per-row problem to `unknown`, recording `downgraded_from` and why.

Never silently drop a row. A dropped row is indistinguishable from a control nobody
looked at, which is exactly the distinction `triage_unjudged` exists to draw one layer up.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from agents import RunContextWrapper, function_tool

from docket.compliance.models import (
    CLAIMS,
    Citation,
    ControlPack,
    ControlResult,
    ControlStatus,
    Observability,
    parse_status,
)
from docket.report.models import Severity
from docket.core.execution import ScanContext
from docket.tools.source_read.tools import SourceAccessError, resolve_in_root

# A batch beyond this is a model repeating itself or answering controls it was not given.
MAX_RESULTS = 200
# Line clamping reads the cited file to count its lines. Skip that for anything large
# enough that the read is the expensive part; the citation keeps its line unverified,
# which is a weaker citation rather than a wrong one.
MAX_CLAMP_BYTES = 2_000_000


def _verify_citations(raw: Any, source_root: str | Path | None) -> list[Citation]:
    """Citations that resolve to a real file in the scanned tree, and nothing else.

    Reuses `resolve_in_root` — the one containment check in this codebase, which already
    refuses symlinks out of tree and uses parent traversal rather than a string prefix.
    A second containment check written here would be a second thing to get wrong.

    A line past end-of-file is dropped while the file is kept: the model read the right
    file and mis-stated where, which is a weaker citation, not a fake one. The `quote` is
    deliberately NOT required to match byte for byte — models normalise whitespace, and
    rejecting that would downgrade honest work.
    """
    verified: list[Citation] = []
    for item in raw or []:
        if not isinstance(item, dict):
            continue
        name = str(item.get("file") or "").strip()
        if not name:
            continue
        try:
            path = resolve_in_root(source_root or "", name)
        except SourceAccessError:
            continue  # outside the tree, or there is no tree — either way, unverifiable
        if not path.is_file():
            continue
        line = item.get("line")
        try:
            line = int(line) if line is not None else None
        except (TypeError, ValueError):
            line = None
        if line is not None and line < 1:
            line = None
        if line is not None and path.stat().st_size <= MAX_CLAMP_BYTES:
            try:
                if line > len(path.read_text(encoding="utf-8", errors="replace").splitlines()):
                    line = None
            except OSError:
                pass
        verified.append(Citation(file=name, line=line, quote=str(item.get("quote") or "").strip()))
    return verified


def _downgraded(control_id: str, status: ControlStatus, why: str, said: str) -> ControlResult:
    """A row kept, with its claim removed and the reason recorded. Kept rather than
    dropped so `unjudged` keeps meaning "nobody looked" and nothing else."""
    return ControlResult(
        control_id=control_id or "unknown",
        status=ControlStatus.UNKNOWN,
        downgraded_from=status,
        rationale=f"Downgraded: {why}. The agent said: {said[:400] or '(nothing)'}",
        looked_at=f"claim not accepted — {why}",
    )


def build_control_results(
    results: list[dict[str, Any]] | None,
    *,
    pack: ControlPack,
    source_root: str | Path | None,
    judged_by: str = "",
) -> dict[str, Any]:
    """The gate, separate from the SDK wrapper so the rule is testable and readable."""
    if not results:
        return {
            "ok": False,
            "error": (
                "refused — no control results recorded. An empty assessment is "
                "indistinguishable from not having looked. If no control in this pack "
                "could be settled from this repository, say so: one row per control with "
                "status='unknown' and `looked_at` describing what you searched."
            ),
        }

    known = {control.id: control for control in pack.controls}
    kept: list[ControlResult] = []
    downgraded: list[dict[str, str]] = []
    seen: set[str] = set()

    for row in results[:MAX_RESULTS]:
        if not isinstance(row, dict):
            continue
        control_id = str(row.get("control_id") or "").strip()
        status = parse_status(row.get("status"))  # anything unrecognised is already UNKNOWN
        rationale = str(row.get("rationale") or "").strip()
        looked_at = str(row.get("looked_at") or "").strip()
        citations = _verify_citations(row.get("citations"), source_root)

        control = known.get(control_id)
        why: str | None = None
        if control is None:
            # An id that is not in this pack. The model either invented a control or
            # answered one from a different pack; neither is an answer to what was asked.
            why = "no control with that id exists in this pack"
        elif control.observability is not Observability.SOURCE:
            # This control was never in the prompt. A verdict on it is invented by
            # definition, and it is the exact failure this feature exists to avoid.
            why = (
                f"this control is {control.observability.value}, not answerable by reading "
                "source, and was never in scope"
            )
        elif control_id in seen:
            why = "a result for this control was already recorded in this batch"
        elif not rationale:
            why = "no rationale given"
        elif status in CLAIMS and not citations:
            why = (
                f"a '{status.value}' asserts something about this codebase, and no citation "
                "resolved to a file in the scanned tree"
            )
        elif status is ControlStatus.UNKNOWN and not (looked_at or citations):
            why = "`unknown` must record what was looked at before giving up"

        if why is not None:
            downgraded.append({"control_id": control_id or "(unnamed)",
                               "from": status.value, "reason": why})
            # Two rows have nowhere to go, and both must be reported-but-not-recorded:
            #   - a control outside this pack: a row would invent a result for a control
            #     the report does not contain;
            #   - a control that is not source-observable: the runner already authored its
            #     result as `not_observable`, by code, before any agent ran. Returning a
            #     downgraded `unknown` here would OVERWRITE that with a weaker, wronger
            #     answer — the report would then say docket tried and could not tell,
            #     about a question no repository can answer. Caught by
            #     tests/test_compliance.py.
            in_scope = control is not None and control.observability is Observability.SOURCE
            if in_scope and control_id not in seen:
                seen.add(control_id)
                kept.append(_downgraded(control_id, status, why, rationale))
            continue

        seen.add(control_id)
        kept.append(ControlResult(
            control_id=control_id,
            status=status,
            rationale=rationale,
            citations=citations,
            looked_at=looked_at,
            judged_by=judged_by,
        ))

    if not kept or all(row.downgraded_from is not None for row in kept):
        return {
            "ok": False,
            "error": (
                "refused — nothing was actually assessed. Every result either named a "
                "control outside this pack or asserted a status without a citation that "
                "resolves to a file in the scanned tree. Cite the file and line you read."
            ),
            "downgraded": downgraded,
        }

    return {
        "ok": True,
        "results": [row.model_dump(mode="json") for row in kept],
        # Reported, never hidden. A run where half the batch was downgraded is a run whose
        # coverage number should be looked at, and silence about it reads as a clean pass.
        "downgraded": downgraded,
    }


@function_tool(strict_mode=False)  # open-ended dicts; a strict schema cannot express them
async def record_controls(
    ctx: RunContextWrapper[ScanContext],
    results: list[dict],
) -> dict:
    """Record your judgement on each control you were given, and finish.

    Args:
        results: one object per control you were asked about. Fields:
            `control_id` (REQUIRED — exactly as given to you),
            `status` — one of:
                pass            you read the code and it satisfies the control
                fail            you read the code and it does not
                not_applicable  the thing the control governs does not exist here
                unknown         you looked and could not settle it
            `rationale` (REQUIRED) — two or three sentences on what you read and why it
                decides the control. Not a restatement of the requirement.
            `citations` — a list of `{"file": "app/views.py", "line": 42,
                "quote": "the line itself"}`. REQUIRED for pass, fail and
                not_applicable: every file must be one you actually opened, and a file
                that is not in this repository will be rejected. Cite the absence too —
                for not_applicable, point at the manifest or config that shows the thing
                is not here.
            `looked_at` — REQUIRED for `unknown`: what you searched before giving up.
                `unknown` is a real answer and it still owes its work.

        Answer EVERY control you were given. `unknown` for one you could not settle is
        correct and expected; guessing `pass` is not. A wrong `pass` is the one outcome
        that gets somebody fined.
    """
    context = ctx.context
    return build_control_results(
        results,
        pack=context.compliance_pack,
        source_root=context.source_root,
        judged_by=context.agent_id,
    )


# --- compiling an uploaded policy into a pack --------------------------------------------

# A policy longer than this is being summarised rather than transcribed, and a pack nobody
# can review is a pack nobody can defend to an auditor.
MAX_COMPILED_CONTROLS = 300
_SLUG = re.compile(r"[^a-z0-9]+")


def _slug(text: str, fallback: str) -> str:
    out = _SLUG.sub("-", str(text).lower()).strip("-")[:48]
    return out or fallback


def build_pack(
    controls: list[dict[str, Any]] | None,
    *,
    pack_id: str,
    title: str,
    authority: str,
    source_name: str,
) -> dict[str, Any]:
    """Gate for `record_pack`: turn a model's reading of a policy into a ControlPack.

    The load-bearing rule is `citation`. A control nobody can trace back to a clause in
    the uploaded document is OUR INVENTION, not the customer's policy, and it would be
    audited against under their own framework's name. So an uncited control is dropped —
    not downgraded, dropped, because unlike a verdict there is no weaker honest form of
    "we made this requirement up".

    Two things the model is NOT trusted to get right and which are done here instead:
    control ids are assigned (prefixed with the pack id, slugged, de-duplicated), and
    `observability` fails safe to `process` — including when the model claims `source` but
    cannot say what to look for, since a source control with no starting point is a
    question an agent can only bluff.
    """
    rows = controls or []
    if not rows:
        return {"ok": False, "error": (
            "refused — no controls extracted. If this document genuinely states no "
            "checkable requirements, say so rather than inventing some.")}

    out: list[dict[str, Any]] = []
    dropped: list[dict[str, str]] = []
    seen: set[str] = set()

    for index, row in enumerate(rows[:MAX_COMPILED_CONTROLS], 1):
        if not isinstance(row, dict):
            continue
        control_title = str(row.get("title") or "").strip()
        requirement = str(row.get("requirement") or "").strip()
        citation = str(row.get("citation") or "").strip()
        if not control_title or not requirement:
            dropped.append({"title": control_title or f"#{index}",
                            "reason": "a control needs a title and its requirement text"})
            continue
        if not citation:
            dropped.append({"title": control_title, "reason": (
                "no citation locating this in the uploaded document — a control nobody "
                "can trace back to a clause is invented, not theirs")})
            continue

        hint = str(row.get("evidence_hint") or "").strip()
        try:
            observability = Observability(str(row.get("observability") or "").strip().lower())
        except ValueError:
            observability = Observability.PROCESS  # fails safe: assume unanswerable
        if observability is Observability.SOURCE and not hint:
            # Kept in the pack so the count stays honest, but never handed to an agent:
            # a source control with no starting point is one an agent can only bluff.
            observability = Observability.PROCESS

        try:
            severity = Severity(str(row.get("severity") or "").strip().lower())
        except ValueError:
            severity = Severity.MEDIUM

        control_id = f"{pack_id}:{_slug(row.get('ref') or control_title, f'c{index}')}"
        if control_id in seen:
            control_id = f"{control_id}-{index}"
        seen.add(control_id)
        out.append({
            "id": control_id, "title": control_title[:200], "requirement": requirement,
            "observability": observability.value, "severity": severity.value,
            "citation": f"{source_name}: {citation}"[:300], "evidence_hint": hint,
            "cwe": [c for c in (row.get("cwe") or []) if isinstance(c, str)],
            "rule_ids": [r for r in (row.get("rule_ids") or []) if isinstance(r, str)],
        })

    if not out:
        return {"ok": False, "error": (
            "refused — no control survived. Every row was missing its requirement text or "
            "a citation locating it in the document."), "dropped": dropped}

    return {
        "ok": True,
        "pack": {
            "id": pack_id, "title": title.strip() or source_name, "authority": authority.strip()
            or "customer", "origin": "uploaded", "source_url": "",
            "notes": (
                f"Compiled by docket from an uploaded document ({source_name}). Requirement "
                "text and citations come from that document; `observability` is docket's "
                "judgement of whether a repository can answer each one, and defaults to "
                "`process` where it could not tell. Review before relying on it."),
            "controls": out,
        },
        # Reported, never hidden: a customer must be able to see which of their clauses
        # did not make it into the pack and why.
        "dropped": dropped,
    }


@function_tool(strict_mode=False)
async def record_pack(
    ctx: RunContextWrapper[ScanContext],
    title: str,
    authority: str,
    controls: list[dict],
) -> dict:
    """Record the controls you extracted from the policy document, and finish.

    Args:
        title: what to call this control pack, from the document's own title.
        authority: who issued the policy — the organisation named in it.
        controls: one object per checkable requirement. Fields:
            `title` (REQUIRED) — a short name for the requirement.
            `requirement` (REQUIRED) — the obligation, quoted from the document where you
                can and stated plainly where the wording is spread across sentences.
            `citation` (REQUIRED) — where it is in the document: a clause number, a
                heading, or a page marker such as "p12". A control you cannot locate in
                the document is one you invented, and it will be DROPPED.
            `ref` — the document's own identifier for it, if it has one ("3.2.1").
            `observability` — can reading an application's SOURCE CODE answer it?
                `source`  — yes: it is about code, configuration, dependencies or CI.
                `runtime` — it needs the deployed system: firewalls, TLS termination.
                `process` — it is organisational: a policy, a review, a training, an
                            audit, a report to a regulator, a drill, a retention period.
                WHEN IN DOUBT, `process`. Most of a real policy is process, and marking a
                process clause as `source` makes an agent guess at something no repository
                contains.
            `evidence_hint` — REQUIRED if you say `source`: what a reader should look for
                in the code. Without it the control is recorded as `process`.
            `severity` — critical | high | medium | low | info.
            `cwe` — CWE ids, if the requirement maps to a known weakness class.
    """
    context = ctx.context
    meta = getattr(context, "compliance_pack", None) or {}
    return build_pack(
        controls, pack_id=str(meta.get("pack_id", "uploaded-policy")),
        title=title, authority=authority,
        source_name=str(meta.get("source_name", "uploaded document")),
    )


def demo() -> None:
    import tempfile

    from docket.compliance.packs import load_pack

    pack = load_pack("twelve-factor")
    config = "twelve-factor:III"  # Config — the one with hardcoded secrets
    process = "twelve-factor:VIII"  # runtime, never handed to an agent

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "settings.py").write_text("DEBUG = True\nSECRET_KEY = 'hunter2'\n")

        def build(rows):
            return build_control_results(rows, pack=pack, source_root=root, judged_by="c1")

        cite = [{"file": "settings.py", "line": 2, "quote": "SECRET_KEY = 'hunter2'"}]

        # --- refusals: only where nothing is lost -------------------------------------
        for empty in (None, []):
            out = build(empty)
            assert out["ok"] is False and "no control results" in out["error"], out

        # --- the load-bearing one: a claim whose citation is not in the tree ----------
        # This is the difference between an auditable result and a plausible sentence.
        for bad_file in ("/etc/passwd", "does-not-exist.py", "../../../etc/hosts"):
            out = build([{"control_id": config, "status": "pass", "rationale": "all good",
                          "citations": [{"file": bad_file, "line": 1}]}])
            assert out["ok"] is False, (bad_file, out)
            assert out["downgraded"][0]["reason"].startswith("a 'pass' asserts"), out

        # ...and an uncited claim at all.
        out = build([{"control_id": config, "status": "pass", "rationale": "looks fine"}])
        assert out["ok"] is False, out

        # --- a good row survives a batch containing bad ones --------------------------
        mixed = build([
            {"control_id": config, "status": "fail",
             "rationale": "SECRET_KEY is a literal in settings.py, not read from the env.",
             "citations": cite},
            # invented control id
            {"control_id": "twelve-factor:XIII", "status": "pass", "rationale": "x",
             "citations": cite},
            # a control the agent was never given, because source cannot answer it
            {"control_id": process, "status": "pass", "rationale": "scales fine",
             "citations": cite},
            # no rationale
            {"control_id": "twelve-factor:II", "status": "pass", "rationale": "",
             "citations": cite},
            # unknown that records nothing
            {"control_id": "twelve-factor:IV", "status": "unknown", "rationale": "dunno"},
            # free text is not a verdict
            {"control_id": "twelve-factor:VI", "status": "mostly compliant",
             "rationale": "seems stateless", "citations": cite},
        ])
        assert mixed["ok"] is True, mixed
        rows = {r["control_id"]: r for r in mixed["results"]}
        assert rows[config]["status"] == "fail", rows[config]
        assert rows[config]["judged_by"] == "c1"
        assert rows[config]["downgraded_from"] is None

        # Every bad row was KEPT as unknown, not dropped — except the one naming a control
        # this pack does not contain, which has nowhere to be recorded.
        assert "twelve-factor:XIII" not in rows, rows
        # ...and neither does a verdict on a control that is not source-observable. The
        # runner already wrote that one as `not_observable` before any agent ran, and a
        # downgraded `unknown` here would overwrite it with a weaker, wronger answer.
        assert process not in rows, rows
        for control_id, was in (("twelve-factor:II", "pass"),
                                ("twelve-factor:IV", "unknown")):
            assert rows[control_id]["status"] == "unknown", rows[control_id]
            assert rows[control_id]["downgraded_from"] == was, rows[control_id]
        # Free text never reaches the gate as a claim: parse_status landed "mostly
        # compliant" on `unknown` first, and this row cited code, so it is a legitimate
        # unknown rather than a downgrade. What matters is that it is NOT a pass.
        assert rows["twelve-factor:VI"]["status"] == "unknown", rows["twelve-factor:VI"]
        assert rows["twelve-factor:VI"]["downgraded_from"] is None, rows["twelve-factor:VI"]
        assert len(mixed["downgraded"]) == 4, mixed["downgraded"]
        # A verdict on an out-of-scope control must say so in the reason, so a human can
        # see the model answered a question it was never asked.
        reasons = {d["control_id"]: d["reason"] for d in mixed["downgraded"]}
        assert "never in scope" in reasons[process], reasons

        # --- a batch where nothing survives is a refusal, and says why ----------------
        out = build([{"control_id": "twelve-factor:XIII", "status": "pass", "rationale": "x"},
                     {"control_id": config, "status": "pass", "rationale": "fine"}])
        assert out["ok"] is False and "nothing was actually assessed" in out["error"], out

        # --- citations: line clamped past EOF, file kept -----------------------------
        out = build([{"control_id": config, "status": "fail", "rationale": "literal secret",
                      "citations": [{"file": "settings.py", "line": 9000}]}])
        assert out["ok"] is True, out
        only = out["results"][0]["citations"][0]
        assert only["file"] == "settings.py" and only["line"] is None, only

        # A duplicate row must not let a later guess overwrite an earlier cited answer.
        out = build([
            {"control_id": config, "status": "fail", "rationale": "literal secret",
             "citations": cite},
            {"control_id": config, "status": "pass", "rationale": "actually fine",
             "citations": cite},
        ])
        assert len(out["results"]) == 1 and out["results"][0]["status"] == "fail", out

        # --- unknown is a real answer and is accepted when it shows its work ----------
        out = build([{"control_id": config, "status": "unknown",
                      "rationale": "Config loading happens in a module not in this repo.",
                      "looked_at": "grepped os.environ, settings/, config/"}])
        assert out["ok"] is True and out["results"][0]["status"] == "unknown", out

    # No source tree means no citation can be verified, so no claim can be made. Failing
    # closed here beats accepting every claim in the one situation nothing is checkable.
    out = build_control_results(
        [{"control_id": config, "status": "pass", "rationale": "fine",
          "citations": [{"file": "settings.py", "line": 1}]}],
        pack=pack, source_root=None)
    assert out["ok"] is False, out

    # --- compiling an uploaded policy -------------------------------------------------
    def compile(rows):
        return build_pack(rows, pack_id="acme-policy", title="ACME Policy",
                          authority="ACME Bank", source_name="acme-infosec.pdf")

    empty = compile([])
    assert empty["ok"] is False and "no controls extracted" in empty["error"], empty

    built = compile([
        {"ref": "3.2.1", "title": "Password storage", "observability": "source",
         "requirement": "Passwords shall be stored using a salted key derivation function.",
         "citation": "p12 §3.2.1", "evidence_hint": "hashlib/bcrypt use on a password",
         "severity": "critical", "cwe": ["CWE-916"]},
        # No citation: invented, not theirs. DROPPED, not downgraded — there is no weaker
        # honest form of "we made this requirement up".
        {"title": "Annual review", "requirement": "The policy shall be reviewed annually.",
         "observability": "process"},
        # Claims source but cannot say what to look for -> recorded as process, so no
        # agent is ever handed a question with no starting point.
        {"title": "Encryption", "requirement": "Data shall be encrypted.",
         "citation": "p14", "observability": "source"},
        # Unrecognised observability and severity fail safe.
        {"title": "Board oversight", "requirement": "The board shall oversee cyber risk.",
         "citation": "p3", "observability": "maybe", "severity": "extreme"},
        {"title": "", "requirement": "nameless", "citation": "p1"},
    ])
    assert built["ok"] is True, built
    controls = {c["title"]: c for c in built["pack"]["controls"]}
    assert set(controls) == {"Password storage", "Encryption", "Board oversight"}, controls
    # Ids are ASSIGNED here, never taken from the model: always prefixed, always slugged.
    assert controls["Password storage"]["id"] == "acme-policy:3-2-1", controls
    assert controls["Password storage"]["observability"] == "source"
    # The citation carries the document name, so a control traces back to a file a human
    # can open, not just to a page number floating free.
    assert controls["Password storage"]["citation"] == "acme-infosec.pdf: p12 §3.2.1"
    assert controls["Encryption"]["observability"] == "process", controls["Encryption"]
    assert controls["Board oversight"]["observability"] == "process"
    assert controls["Board oversight"]["severity"] == "medium"
    # Drops are REPORTED. A customer must be able to see which clauses did not make it.
    reasons = {d["title"]: d["reason"] for d in built["dropped"]}
    assert "no citation" in reasons["Annual review"], reasons
    assert "title and its requirement" in reasons["#5"], reasons
    # The compiled pack must survive the same validation a shipped pack does.
    ControlPack.model_validate(built["pack"])

    nothing = compile([{"title": "x", "requirement": "y"}, {"nope": 1}])
    assert nothing["ok"] is False and "no control survived" in nothing["error"], nothing

    print("tools.compliance: ok")


if __name__ == "__main__":
    demo()
