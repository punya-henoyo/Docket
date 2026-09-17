"""Find, load and validate control packs.

A pack is a JSON file, not code — the same stance as skills, which register by being
dropped into a directory. Adding OWASP's next edition or a new regulator is a file, and
the `demo()` at the bottom validates every shipped pack on every `make check`, so a pack
with a duplicate control id or a `source` control carrying no evidence hint fails the
build rather than reaching a customer.

Two roots, searched in a fixed order:

  builtin   engine/docket/compliance/builtin/*.json   shipped, reviewed, reproducible
  uploaded  docket_runs/.docket/packs/*.json        compiled from a customer's policy

Builtins win a collision. An uploaded pack that names itself `sebi-cscrf` must not
silently replace the reviewed one — a customer would then be audited against a pack
nobody at docket ever read, under a name that says otherwise.

JSON rather than YAML because `json` is stdlib and a pack has no need for anchors or
multi-line folding; the one place prose matters (`requirement`) is a single string.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from pydantic import ValidationError

from docket.compliance.models import ControlPack, Observability
from docket.core.paths import runs_root

BUILTIN_ROOT = Path(__file__).resolve().parent / "builtin"
UPLOADED_DIR_NAME = "packs"
SERVICE_DIR_NAME = ".docket"

# A pack id becomes a filename and a control-id prefix, so it may not contain a path
# separator, a leading dot, or anything that would need escaping in either place.
PACK_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")


class PackError(Exception):
    """A pack could not be found or is not usable. Carries a message meant for a human."""


def uploaded_root(*, cwd: Path | None = None) -> Path:
    """Where compiled customer packs live. Alongside service.db, not inside a run:
    a pack outlives the scan that first used it."""
    return runs_root(cwd=cwd) / SERVICE_DIR_NAME / UPLOADED_DIR_NAME


def _pack_files(*, cwd: Path | None = None) -> dict[str, Path]:
    """Pack id -> file. Builtins first, so `setdefault` makes them win a collision."""
    found: dict[str, Path] = {}
    for root in (BUILTIN_ROOT, uploaded_root(cwd=cwd)):
        if not root.is_dir():
            continue  # no uploads yet is the normal case, not an error
        for path in sorted(root.glob("*.json")):
            found.setdefault(path.stem, path)
    return found


def list_packs(*, cwd: Path | None = None) -> list[dict[str, object]]:
    """Every available pack, as summary rows for a picker.

    Summaries, not whole packs: the console lists seven packs to choose from and has no
    use for four hundred control bodies to do it. A pack that fails to parse is reported
    with its error rather than omitted — a pack silently missing from a list is how
    somebody concludes they were checked against it.
    """
    rows: list[dict[str, object]] = []
    for pack_id, path in sorted(_pack_files(cwd=cwd).items()):
        try:
            pack = _parse(path)
        except PackError as exc:
            rows.append({"id": pack_id, "error": str(exc), "usable": False})
            continue
        source = pack.source_controls()
        rows.append({
            "id": pack.id,
            "title": pack.title,
            "authority": pack.authority,
            "version": pack.version,
            "origin": pack.origin,
            "source_url": pack.source_url,
            "total_controls": len(pack.controls),
            # The honest headline for a regulatory pack, and the number a picker must
            # show BEFORE a customer chooses it: 13 of 45, not 45.
            "source_controls": len(source),
            "usable": True,
        })
    return rows


def load_pack(pack_id: str, *, cwd: Path | None = None) -> ControlPack:
    """One pack, validated. Raises PackError with the available ids on a miss."""
    files = _pack_files(cwd=cwd)
    path = files.get(str(pack_id).strip())
    if path is None:
        available = ", ".join(sorted(files)) or "none"
        raise PackError(f"no control pack named {pack_id!r}. Available: {available}")
    return _parse(path)


def load_packs(pack_ids: list[str], *, cwd: Path | None = None) -> list[ControlPack]:
    """Several packs, in the order asked for, de-duplicated. Any miss raises: a scan
    requested against four packs that silently runs three is a report about a different
    question than the one asked."""
    seen: set[str] = set()
    packs: list[ControlPack] = []
    for pack_id in pack_ids:
        key = str(pack_id).strip()
        if not key or key in seen:
            continue
        seen.add(key)
        packs.append(load_pack(key, cwd=cwd))
    return packs


def _parse(path: Path) -> ControlPack:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PackError(f"{path.name}: not readable as JSON ({exc})") from exc
    try:
        pack = ControlPack.model_validate(raw)
    except ValidationError as exc:
        raise PackError(f"{path.name}: {exc.error_count()} invalid field(s) — {exc}") from exc
    _check(pack, path)
    return pack


def _check(pack: ControlPack, path: Path) -> None:
    """Invariants a pack file must hold. Separate from pydantic because these are
    relationships between fields, and because the failure messages name the file."""
    if not PACK_ID.match(pack.id):
        raise PackError(f"{path.name}: pack id {pack.id!r} must be lowercase [a-z0-9._-]")
    if pack.id != path.stem:
        # Otherwise load_pack("x") and the pack's own self-reported id disagree, and every
        # control id prefix, report row and dashboard filter picks a different one.
        raise PackError(f"{path.name}: pack id {pack.id!r} must match the filename")
    if not pack.controls:
        raise PackError(f"{path.name}: a pack with no controls checks nothing")

    seen: set[str] = set()
    for control in pack.controls:
        if control.id in seen:
            # Results are keyed by control id. A duplicate means one control's verdict
            # silently overwrites another's.
            raise PackError(f"{path.name}: duplicate control id {control.id!r}")
        seen.add(control.id)
        if not control.id.startswith(f"{pack.id}:"):
            raise PackError(
                f"{path.name}: control id {control.id!r} must start with '{pack.id}:' so a "
                "result can be traced to its pack without carrying the pack alongside it"
            )
        if control.observability is Observability.SOURCE and not control.evidence_hint.strip():
            # A source control with no hint is a question with no starting point, and the
            # measured cost of that is an agent burning turns and recording nothing.
            raise PackError(
                f"{path.name}: {control.id} is observable from source but gives no "
                "evidence_hint — say what to look for"
            )


def save_uploaded(pack: ControlPack, *, cwd: Path | None = None) -> Path:
    """Persist a pack compiled from a customer policy. Refuses to shadow a builtin."""
    if pack.origin != "uploaded":
        raise PackError("save_uploaded is for compiled customer packs; origin must be 'uploaded'")
    if (BUILTIN_ROOT / f"{pack.id}.json").exists():
        raise PackError(
            f"{pack.id!r} is a built-in pack. Choose another id rather than replacing a "
            "reviewed pack with an uploaded one under the same name."
        )
    directory = uploaded_root(cwd=cwd)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{pack.id}.json"
    _check(pack, path)  # the same gate a shipped pack passes, before it hits disk
    path.write_text(pack.model_dump_json(indent=2), encoding="utf-8")
    return path


def demo() -> None:
    import tempfile

    # --- every shipped pack is valid, checked on every `make check` --------------------
    rows = list_packs()
    ids = {row["id"] for row in rows}
    assert {"owasp-api-2023", "twelve-factor"} <= ids, ids
    for row in rows:
        assert row["usable"] is True, row  # a broken shipped pack fails the build here
        assert row["source_controls"] <= row["total_controls"], row

    owasp = load_pack("owasp-api-2023")
    assert owasp.authority == "OWASP"
    assert len(owasp.controls) == 10, len(owasp.controls)
    # API9 is inventory and documentation governance. Marking it `source` would hand an
    # agent a question a repository cannot answer, which is where invented verdicts start.
    assert len(owasp.source_controls()) == 9, [c.id for c in owasp.source_controls()]
    assert all(c.id.startswith("owasp-api-2023:") for c in owasp.controls)

    twelve = load_pack("twelve-factor")
    assert len(twelve.controls) == 12, len(twelve.controls)
    assert len(twelve.source_controls()) == 11, [c.id for c in twelve.source_controls()]

    # --- the regulatory packs, and the ratio that is the honest product ----------------
    # A repository cannot answer "the board reviews the policy annually". Most of both
    # frameworks is that shape. This asserts the packs stay HONEST about it: if a later
    # edit flips process controls to `source` to make a dashboard number look better, the
    # build fails here rather than a customer being told 90% of SEBI was assessed.
    for pack_id, total, source_max in (("rbi-csf", 40, 16), ("sebi-cscrf", 43, 16)):
        pack = load_pack(pack_id)
        assert len(pack.controls) == total, (pack_id, len(pack.controls))
        checkable = pack.source_controls()
        assert len(checkable) <= source_max, (pack_id, len(checkable))
        # ...and it must still be a useful minority, not a token one.
        assert len(checkable) >= 10, (pack_id, len(checkable))
        # A regulatory pack must say plainly what it is not. This text is what stands
        # between an evidence report and something a customer waves at a regulator.
        assert "not an attestation" in pack.notes, pack_id
        assert "process" in pack.notes, pack_id

    # Every shipped pack carries its own provenance: who wrote the requirement, and where
    # to read the original. A control nobody can trace back to a clause is our invention.
    for row in rows:
        pack = load_pack(str(row["id"]))
        assert pack.source_url, pack.id
        for control in pack.controls:
            assert control.citation.strip(), (pack.id, control.id)

    # Order preserved, duplicates collapsed.
    both = load_packs(["twelve-factor", "owasp-api-2023", "twelve-factor", ""])
    assert [p.id for p in both] == ["twelve-factor", "owasp-api-2023"], both

    # --- a miss names what IS available, rather than failing blank ---------------------
    try:
        load_pack("pci-dss")
        raise AssertionError("loaded a pack that does not exist")
    except PackError as exc:
        assert "owasp-api-2023" in str(exc), exc

    # --- the file-level invariants, each proven to actually fire -----------------------
    base = ControlPack.model_validate(json.loads((BUILTIN_ROOT / "twelve-factor.json").read_text()))

    def refuses(pack: ControlPack, name: str, needle: str) -> None:
        try:
            _check(pack, Path(name))
            raise AssertionError(f"accepted a pack that should be refused: {needle}")
        except PackError as exc:
            assert needle in str(exc), exc

    refuses(base.model_copy(update={"id": "Twelve_Factor"}), "Twelve_Factor.json", "lowercase")
    refuses(base, "other-name.json", "must match the filename")
    refuses(base.model_copy(update={"controls": []}), "twelve-factor.json", "checks nothing")
    dupe = base.model_copy(update={"controls": [base.controls[0], base.controls[0]]})
    refuses(dupe, "twelve-factor.json", "duplicate control id")
    stray = base.controls[0].model_copy(update={"id": "somewhere-else:I"})
    refuses(base.model_copy(update={"controls": [stray]}), "twelve-factor.json", "must start with")
    hintless = base.controls[0].model_copy(
        update={"observability": Observability.SOURCE, "evidence_hint": "  "})
    refuses(base.model_copy(update={"controls": [hintless]}), "twelve-factor.json", "evidence_hint")

    # --- uploaded packs: found, but never allowed to shadow a builtin ------------------
    with tempfile.TemporaryDirectory() as tmp:
        cwd = Path(tmp)
        assert load_pack("twelve-factor", cwd=cwd).origin == "builtin"

        custom = base.model_copy(update={
            "id": "acme-policy", "title": "ACME internal policy", "authority": "customer",
            "origin": "uploaded",
            "controls": [base.controls[2].model_copy(update={"id": "acme-policy:C1"})],
        })
        written = save_uploaded(custom, cwd=cwd)
        assert written == uploaded_root(cwd=cwd) / "acme-policy.json", written
        assert "acme-policy" in {row["id"] for row in list_packs(cwd=cwd)}
        assert load_pack("acme-policy", cwd=cwd).origin == "uploaded"

        # The collision that matters: an upload claiming a reviewed pack's name.
        impostor = custom.model_copy(update={
            "id": "twelve-factor",
            "controls": [base.controls[2].model_copy(update={"id": "twelve-factor:C1"})],
        })
        try:
            save_uploaded(impostor, cwd=cwd)
            raise AssertionError("an upload shadowed a built-in pack")
        except PackError as exc:
            assert "built-in" in str(exc), exc
        # ...and even if a file appeared there some other way, the builtin still wins.
        (uploaded_root(cwd=cwd) / "twelve-factor.json").write_text(
            impostor.model_dump_json(), encoding="utf-8")
        assert load_pack("twelve-factor", cwd=cwd).origin == "builtin"

        # A malformed pack is listed as unusable, never silently dropped from the list.
        (uploaded_root(cwd=cwd) / "broken.json").write_text("{not json", encoding="utf-8")
        broken = [row for row in list_packs(cwd=cwd) if row["id"] == "broken"]
        assert broken and broken[0]["usable"] is False, broken

    print("compliance.packs: ok")


if __name__ == "__main__":
    demo()
