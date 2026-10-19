"""Policy writes and the "if you save" preview (docs/ui/policy-and-posture.md, section 3).

The console is local and single-user, with the same trust as the rest of connect.py. What
this module guards is the FILE, not the caller:

* A write PATCHES THE RAW JSON entry by id. It never round-trips through `load_policies`,
  which drops invalid policies with a warning: writing back what it returned would delete
  every policy the parser did not like, and every key it does not know. Other policies, and
  unknown keys on this one, are kept as the file had them.
* The new entry is validated by `parse_policy` exactly as it will be read back, so a policy
  that would be dropped on load is refused here with its reasons (400 `{errors}`), and so is a
  save that would make two policies equally specific for the same applications (a tie).
* The file is written to a temp file in the same directory and renamed over the old one, so a
  crash leaves the old file or the new one, never half of either. Nothing is written outside
  the working directory, and a `docket_policy.json` that is a symlink is not followed.
* `version` is owned by the server: it goes up by one on every save.

Functions return `(status, body)` and never raise for an expected failure, like `api.py`.
"""
from __future__ import annotations

import copy
import json
import os
import tempfile
from pathlib import Path
from typing import Any

from docket.portfolio import api, timeutil
from docket.portfolio.catalog import CATALOG, default_tool, slot_text, slot_tools
from docket.portfolio.model.derive import AppState, build_model
from docket.portfolio.policy import (
    MAX_POLICY_BYTES, POLICY_FILE, _ID, Policy, assign, find_ties, floor_warnings, parse_policy)

MAX_BODY_BYTES = 256 * 1024

# What a stored policy may carry. Anything else in a request body is ignored, so a client that
# posts back the read model (with its `label`, `n`, `applies_count`...) cannot write view
# fields into the file. Unknown keys ALREADY in the file are kept (see `_merge`).
_POLICY_KEYS = ("id", "name", "applies", "applies_when", "applies_tier", "cadence_days", "steps",
                "guidelines", "regulatory", "security", "thresholds", "approved", "default",
                "status")
_STEP_KEYS = ("id", "required", "cadence_days", "cadence", "on_fail", "why", "tool")


# --- the file ---------------------------------------------------------------------------------


def _path(cwd: Path | None) -> tuple[Path | None, str | None]:
    """(file, error). Refuses a policy file that is a symlink: following it could write
    outside the working directory."""
    root = (cwd or Path.cwd()).resolve()
    path = root / POLICY_FILE
    if path.is_symlink():
        return None, f"{POLICY_FILE} is a symbolic link; refusing to write through it"
    if path.exists() and not path.is_file():
        return None, f"{POLICY_FILE} is not a regular file"
    return path, None


def _read_raw(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    """The file's JSON as written (an empty skeleton when absent), or an error. A file that
    cannot be parsed is never overwritten: the operator may be mid-edit."""
    if not path.exists():
        return {"policies": []}, None
    try:
        if path.stat().st_size > MAX_POLICY_BYTES:
            return None, f"{POLICY_FILE} is larger than 1 MB; not touching it"
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return None, f"{POLICY_FILE} could not be read ({exc}); fix or remove it first"
    if not isinstance(raw, dict) or not isinstance(raw.get("policies", []), list):
        return None, f"{POLICY_FILE} must be an object with a policies list; not touching it"
    raw.setdefault("policies", [])
    return raw, None


def _write_atomic(path: Path, data: dict[str, Any]) -> str | None:
    text = json.dumps(data, indent=1, ensure_ascii=False) + "\n"
    tmp_name = None
    try:
        fd, tmp_name = tempfile.mkstemp(prefix=".docket_policy.", suffix=".tmp", dir=path.parent)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        if path.exists():
            os.chmod(tmp_name, path.stat().st_mode & 0o777)
        os.replace(tmp_name, path)
        return None
    except OSError as exc:
        if tmp_name:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
        return f"could not write {POLICY_FILE}: {exc}"


# --- merge and validate ------------------------------------------------------------------------


def _merge(old: dict[str, Any] | None, body: dict[str, Any]) -> dict[str, Any]:
    """The entry to store: the old entry with the body's known keys laid over it. A key the
    body leaves out is unchanged (an empty list clears it); steps are merged by id so a client
    that does not send a step's `why` does not erase it."""
    entry = copy.deepcopy(old) if isinstance(old, dict) else {}
    for key in _POLICY_KEYS:
        if key in body:
            entry[key] = copy.deepcopy(body[key])
    if "steps" in body and isinstance(body["steps"], list):
        was = {s.get("id"): s for s in (old or {}).get("steps", []) if isinstance(s, dict)}
        merged = []
        for step in body["steps"]:
            step = {"id": step} if isinstance(step, str) else step
            if not isinstance(step, dict):
                merged.append(step)         # parse_policy refuses it with a reason
                continue
            base = copy.deepcopy(was.get(step.get("id"), {}))
            base.update({k: copy.deepcopy(v) for k, v in step.items() if k in _STEP_KEYS})
            merged.append(base)
        entry["steps"] = merged
    if "applies_when" in body and "applies_tier" in entry and isinstance(body["applies_when"], dict):
        entry.pop("applies_tier")           # the new field supersedes the v1 one
    return entry


def _existing(raw: dict[str, Any], pid: str) -> int | None:
    return next((i for i, p in enumerate(raw["policies"])
                 if isinstance(p, dict) and p.get("id") == pid), None)


def _parsed_others(raw: dict[str, Any], skip: str, cwd: Path | None) -> list[Policy]:
    out: list[Policy] = []
    for item in raw["policies"]:
        if isinstance(item, dict) and item.get("id") != skip:
            got = parse_policy(item, cwd, [])
            if got is not None and all(p.id != got.id for p in out):
                out.append(got)
    return out


def _tie_errors(draft: Policy, others: list[Policy]) -> list[str]:
    names = {p.id: p.name for p in [*others, draft]}
    return [f"{names[a]} and {names[b]} would be equally specific for the same applications; "
            "make one of them narrower" for a, b in find_ties([*others, draft]) if draft.id in (a, b)]


def valid_id(pid: object) -> bool:
    return isinstance(pid, str) and bool(_ID.match(pid))


# --- PUT / DELETE ------------------------------------------------------------------------------


def put_policy(pid: str, body: Any, cwd: Path | None = None) -> tuple[int, dict[str, Any]]:
    """PUT /api/policy/<id>: create or replace one policy."""
    if not valid_id(pid):
        return 400, {"errors": [f"policy id {pid!r} must be lowercase [a-z0-9._-]"]}
    if not isinstance(body, dict):
        return 400, {"errors": ["the body must be a policy object"]}
    if body.get("id", pid) != pid:
        return 400, {"errors": [f"the body's id {body.get('id')!r} does not match the URL"]}
    path, err = _path(cwd)
    if err or path is None:
        return 409, {"errors": [err or "policy file unavailable"]}
    raw, err = _read_raw(path)
    if err or raw is None:
        return 409, {"errors": [err or "policy file unreadable"]}

    at = _existing(raw, pid)
    old = raw["policies"][at] if at is not None else None
    entry = _merge(old, {**body, "id": pid})
    previous = old.get("version") if isinstance(old, dict) else None
    entry["version"] = (previous if isinstance(previous, int) and not isinstance(previous, bool)
                        and previous >= 1 else 0) + 1
    warn: list[str] = []
    draft = parse_policy(entry, cwd, warn)
    if draft is None:
        return 400, {"errors": warn}
    ties = _tie_errors(draft, _parsed_others(raw, pid, cwd))
    if ties:
        return 400, {"errors": ties}

    if at is None:
        raw["policies"].append(entry)
    else:
        raw["policies"][at] = entry
    err = _write_atomic(path, raw)
    if err:
        return 500, {"errors": [err]}
    return 200, {"id": pid, "version": draft.version, "created": at is None,
                 "warnings": [*floor_warnings(draft), *warn]}


def delete_policy(pid: str, cwd: Path | None = None) -> tuple[int, dict[str, Any]]:
    """DELETE /api/policy/<id>. 404 when the file has no such entry."""
    if not valid_id(pid):
        return 404, {"error": "no such policy"}
    path, err = _path(cwd)
    if err or path is None:
        return 409, {"errors": [err or "policy file unavailable"]}
    raw, err = _read_raw(path)
    if err or raw is None:
        return 409, {"errors": [err or "policy file unreadable"]}
    at = _existing(raw, pid)
    if at is None:
        return 404, {"error": "no such policy"}
    del raw["policies"][at]
    err = _write_atomic(path, raw)
    if err:
        return 500, {"errors": [err]}
    return 200, {"id": pid, "deleted": True}


# --- POST /api/policy/preview ------------------------------------------------------------------


def _row(app: AppState) -> dict[str, Any]:
    """The application as `assign` reads it: profile plus its explicit pin, if any."""
    pinned = app.assignment and app.assignment["via"] == "pinned"
    return {"category": app.category, "exposure": app.exposure, "stack": app.stack,
            "tier": app.tier, "policy": app.policy.id if pinned else None}


def _outcome(app: AppState, pol: Policy, now: float, builtin: bool) -> str:
    if builtin:
        return "none"
    return "meets" if api.meets(app, now, pol) else "breaches"


def _why(app: AppState, before: Policy, after: Policy, now: float) -> str:
    parts = []
    if before.id != after.id:
        parts.append(f"Moves from {before.name} to {after.name}")
    cons = api._consequence(app, app.latest, now, after)
    if api.meets(app, now, after):
        parts.append("every required scanner is current")
    elif cons["effect"] == "flags" and cons["text"]:
        parts.append(cons["text"])
    else:
        parts.append("a required scanner is not current")
    text = ". ".join(parts)
    return text[0].upper() + text[1:] + "."


def _plan(pol: Policy) -> list[dict[str, Any]]:
    """What each step will do, in the order Docket runs them (catalog order, whatever order the
    draft lists them in). A plan, not a result: no outcome is invented."""
    steps = {s["id"]: s for s in pol.steps}
    out = []
    for sc in CATALOG:
        step = steps.get(sc.id)
        if step is None:
            continue
        tools = slot_tools(sc.id)
        tool = next((t for t in tools if t["id"] == step.get("tool")), None) or default_tool(sc.id) or {}
        what, produces, command = slot_text(sc.id)
        out.append({"id": sc.id, "n": len(out) + 1, "label": sc.label,
                    "tool": tool.get("name", sc.label), "tool_id": tool.get("id"),
                    "origin": tool.get("origin", sc.origin),
                    "availability": tool.get("availability"), "required": step["required"],
                    "command": command, "what": what, "produces": produces})
    return out


def preview_payload(draft: Any, cwd: Path | None = None,
                    now: float | None = None) -> tuple[int, dict[str, Any]]:
    """POST /api/policy/preview: who is affected if this draft were saved. No side effects:
    nothing is written, and the draft is parsed exactly as a save would parse it."""
    now = api._now(now)
    if not isinstance(draft, dict):
        return 400, {"errors": ["the body must be a draft policy object"]}
    warn: list[str] = []
    entry = _merge(None, draft)
    entry.setdefault("id", draft.get("id") or "draft")
    parsed = parse_policy(entry, cwd, warn)
    if parsed is None:
        return 400, {"errors": warn}

    model = build_model(cwd, now)
    saved = model.policies
    others = [p for p in saved if p.id != parsed.id]
    hypothetical = [*others, parsed]
    saved_ids = {p.id for p in saved}

    matches, changes = [], []
    would_meet = would_breach = 0
    for app in model.apps:
        after = assign(_row(app), hypothetical)["policy"]
        before = app.policy
        if after.id == parsed.id:
            matches.append({"id": app.id, "label": app.label, "tier": app.tier,
                            "category": app.category, "exposure": app.exposure})
            if api.meets(app, now, parsed):
                would_meet += 1
            else:
                would_breach += 1
        if before.id == after.id and before.id not in saved_ids:
            continue                        # under the built-in default before and after
        was = _outcome(app, before, now, before.id not in saved_ids)     # "none": no saved policy
        will = _outcome(app, after, now, False)
        if before.id != after.id or was != will:
            changes.append({"id": app.id, "label": app.label, "before": was, "after": will,
                            "why": _why(app, before, after, now)})
    ties = _tie_errors(parsed, others)
    return 200, {"matches": matches, "would_meet": would_meet, "would_breach": would_breach,
                 "changes": changes, "plan": _plan(parsed),
                 "warnings": [*floor_warnings(parsed), *warn], "conflicts": ties,
                 "generated_at": timeutil.iso(now)}


# --- self-check --------------------------------------------------------------------------------


def demo() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        step = [{"id": "trivy", "required": True}, {"id": "semgrep", "required": True}]
        # First write creates the file.
        st, body = put_policy("p1", {"name": "P1", "steps": step,
                                     "applies_when": {"exposure": ["Internal"]}}, root)
        assert st == 200 and body["version"] == 1 and body["created"], (st, body)
        # An unknown policy-level key already in the file survives a later write.
        raw = json.loads((root / POLICY_FILE).read_text())
        raw["sample"] = True
        raw["policies"][0]["note"] = "keep me"
        raw["policies"].append({"id": "broken", "name": "x", "steps": [{"id": "nope"}]})
        (root / POLICY_FILE).write_text(json.dumps(raw))
        st, body = put_policy("p1", {"name": "P1 renamed", "steps": step}, root)
        assert st == 200 and body["version"] == 2, (st, body)
        raw = json.loads((root / POLICY_FILE).read_text())
        assert raw["sample"] is True and raw["policies"][0]["note"] == "keep me"
        assert raw["policies"][0]["name"] == "P1 renamed" and raw["policies"][1]["id"] == "broken"
        # Invalid and tying writes are refused and leave the file untouched.
        before = (root / POLICY_FILE).read_text()
        assert put_policy("p2", {"name": "P2", "steps": [{"id": "nope"}]}, root)[0] == 400
        st, body = put_policy("p2", {"name": "P2", "steps": step,
                                     "applies_when": {"exposure": ["Internal"]}}, root)
        assert st == 400 and "equally specific" in body["errors"][0], body
        assert put_policy("Bad Id", {"name": "x", "steps": step}, root)[0] == 400
        assert put_policy("p3", {"id": "other", "name": "x", "steps": step}, root)[0] == 400
        assert (root / POLICY_FILE).read_text() == before
        # Preview has no side effects.
        st, prev = preview_payload({"id": "p9", "name": "Nine", "steps": step}, root, 1_800_000_000.0)
        assert st == 200 and prev["matches"] == [] and [p["id"] for p in prev["plan"]] == ["trivy", "semgrep"]
        assert (root / POLICY_FILE).read_text() == before
        assert delete_policy("p1", root)[0] == 200 and delete_policy("p1", root)[0] == 404
        # A corrupt file is never overwritten.
        (root / POLICY_FILE).write_text("{broken")
        assert put_policy("p1", {"name": "x", "steps": step}, root)[0] == 409
        assert (root / POLICY_FILE).read_text() == "{broken"
    print("portfolio.policy_write: ok")


if __name__ == "__main__":
    demo()
