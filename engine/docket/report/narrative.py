"""An LLM-written executive brief over a finished scan.

WHY THIS IS SAFE TO SHIP
------------------------
An LLM writing a security report can invent a vulnerability, and a fabricated finding
in a document with a company's name on it is the worst thing this product could
produce. Three constraints make that unlikely, and one makes it detectable:

1. The model never sees the repository. It is handed a digest built here from
   report.json — findings, counts, coverage, triage verdicts, CVSS — and nothing else.
2. It returns STRUCTURED sections, not free prose with headings. There is no place to
   slip in an extra finding, because the shape is fixed and the renderer is ours.
3. The prompt states, and the digest demonstrates, what was NOT examined.
4. verify_brief() re-reads the generated text and rejects any CVE id or source file
   that does not appear in the scan data. On rejection the caller falls back to the
   deterministic markdown report, which is always correct because nothing wrote it.

The brief is labelled as AI-written prose over measured data, in the document itself.
A reader must never have to guess which sentences a model composed.
"""
from __future__ import annotations

import json
import re
from html import escape
from typing import Any

MAX_FINDINGS_IN_DIGEST = 40

# Anything the model writes that looks like a CVE or a source path must exist in the
# scan. These are the two things it would be most tempting, and most damaging, to
# invent.
_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b")
_PATH = re.compile(r"\b[\w./-]+\.(?:py|js|ts|tsx|jsx|go|rb|java|php|rs|txt|yml|yaml|json)\b")

SCHEMA = {
    "type": "object",
    "required": ["headline", "posture", "key_risks", "recommendations", "caveats"],
    "additionalProperties": False,
    "properties": {
        "headline": {"type": "string"},
        "posture": {"type": "string"},
        "key_risks": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["title", "why_it_matters", "evidence"],
                "additionalProperties": False,
                "properties": {
                    "title": {"type": "string"},
                    "why_it_matters": {"type": "string"},
                    "evidence": {"type": "string"},
                },
            },
        },
        "recommendations": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["action", "rationale"],
                "additionalProperties": False,
                "properties": {
                    "action": {"type": "string"},
                    "rationale": {"type": "string"},
                },
            },
        },
        "caveats": {"type": "string"},
    },
}

PROMPT = """You are writing the executive summary of a security scan for a company's \
security lead. You are given the scan's own output as JSON. That JSON is the ONLY \
source of fact available to you.

Absolute rules:
- Never state a vulnerability, file, CVE, route or number that is not in the JSON.
- Never estimate, extrapolate, or fill a gap. If something was not measured, say so.
- A semgrep match is a PATTERN MATCH, not a proven vulnerability. A triage verdict is \
an agent's reasoning over source with nothing executed. Only findings with a \
reproduced request and response were proven. Do not blur these.
- If the data says nothing was executed, then NOTHING is proven, confirmed, verified, \
demonstrated, exploited or reproduced. Do not use those words, including in the \
headline. Say "reachable", "reported", "matched", or "judged reachable by an agent" \
instead. A headline that overclaims is the single worst failure this document can have.
- A CVSS score rates the vulnerability class, not this codebase's exposure to it.
- Write for someone who decides where engineering time goes, not for a pentester. \
Plain sentences, no marketing language, no scare words, no filler.

Guidance:
- headline: one sentence, the single thing that matters most about this scan.
- posture: 2-4 sentences. What state is this codebase in, and how confident can the \
reader be in that assessment given what was and was not examined?
- key_risks: at most 5. Order by what an attacker would reach first. `evidence` must \
cite a file:line or CVE that appears in the JSON.
- recommendations: at most 5, concrete and ordered. Each must trace to a finding.
- caveats: what this scan could NOT tell you. Be specific and honest; this section is \
what makes the rest trustworthy.

Return only the structured object.

SCAN DATA:
"""


def build_digest(report: dict[str, Any]) -> dict[str, Any]:
    """The only facts the model is allowed to see. Trimmed hard, because a 48-finding
    report with full descriptions and triage reasoning is mostly repetition and every
    token of it is paid for twice."""
    findings = report.get("findings", [])
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    ranked = sorted(findings, key=lambda f: order.get(str(f.get("severity")), 9))

    def summarise(f: dict[str, Any]) -> dict[str, Any]:
        location = (f.get("location") or {})
        entry: dict[str, Any] = {
            "rule": str(f.get("rule_id", "")).rsplit(".", 1)[-1],
            "severity": f.get("severity"),
            "where": (location.get("source_file")
                      or f"{location.get('method','')} {location.get('path','')}".strip()),
            "found_by": f.get("discovered_by"),
        }
        if f.get("cwe"):
            entry["cwe"] = f["cwe"]
        if f.get("merged_cwes"):
            entry["cwe_disputed_between"] = f["merged_cwes"]
        if f.get("cvss"):
            entry["cvss"] = {"score": f["cvss"].get("score"), "source": f["cvss"].get("source")}
        triage = f.get("triage")
        if triage:
            entry["triage"] = {"verdict": triage.get("verdict"),
                               "reasoning": (triage.get("reasoning") or "")[:400]}
        return entry

    triaged = [f for f in findings if f.get("triage")]
    return {
        "repository": str(report.get("target", "")).removeprefix("github:"),
        "scanned_at": report.get("generated_at"),
        "total_findings": report.get("finding_count", len(findings)),
        "severity_counts": report.get("severity_counts", {}),
        "triage": {
            "judged": len(triaged),
            "of_total": len(findings),
            "reachable": sum(1 for f in triaged if f["triage"].get("verdict") == "exploitable"),
            "not_reachable": sum(1 for f in triaged if f["triage"].get("verdict") == "not_reachable"),
            "uncertain": sum(1 for f in triaged if f["triage"].get("verdict") == "uncertain"),
        } if triaged else {"judged": 0, "of_total": len(findings)},
        "coverage": report.get("coverage") or "not recorded for this run",
        "attack_surface": report.get("surface") or "not mapped (AI recon did not run)",
        "nothing_was_executed": True,
        "no_live_target_was_tested": True,
        "findings": [summarise(f) for f in ranked[:MAX_FINDINGS_IN_DIGEST]],
        "findings_omitted_from_this_digest": max(0, len(findings) - MAX_FINDINGS_IN_DIGEST),
    }


def _facts(report: dict[str, Any]) -> tuple[set[str], set[str]]:
    """Every CVE id and source path the scan actually produced."""
    blob = json.dumps(report)
    return set(_CVE.findall(blob)), {p.rsplit("/", 1)[-1] for p in _PATH.findall(blob)}


# Words that assert a vulnerability was demonstrated. Legitimate when something was
# actually executed against a running target; a fabrication when nothing was.
_PROOF = re.compile(
    r"\b(proven|proved|confirms?|confirmed|verified|demonstrated|exploited|reproduced)\b",
    re.I)
# A lookbehind cannot express this: the negation can sit several words back, as in
# "nothing was proven by exploitation" or "no request was ever reproduced" — both of
# which the caveats section SHOULD say. So scan a window instead.
_NEGATION = re.compile(r"\b(no|not|nothing|never|none|without|un\w+|cannot|neither)\b", re.I)
_NEGATION_WINDOW = 40


def _executed_anything(report: dict[str, Any]) -> bool:
    """True only if some finding came from actually exercising a running target.

    semgrep and trivy read files. Nothing they produce is proof of exploitability,
    however confident the description sounds."""
    return any(str(f.get("discovered_by", "")) not in ("semgrep", "trivy")
               for f in report.get("findings", []))


def verify_brief(brief: dict[str, Any], report: dict[str, Any]) -> list[str]:
    """Claims in the brief that the scan does not support. Empty means it checks out.

    Filenames are compared on their basename: the model routinely writes `app/auth.py`
    for a finding recorded as `/work/source/app/auth.py:41`, and treating that as a
    fabrication would reject every correct brief."""
    known_cves, known_files = _facts(report)
    text = json.dumps(brief)
    problems = []
    for cve in set(_CVE.findall(text)):
        if cve not in known_cves:
            problems.append(f"cites {cve}, which is not in this scan")
    for path in set(_PATH.findall(text)):
        if path.rsplit("/", 1)[-1] not in known_files:
            problems.append(f"cites {path}, which is not in this scan")

    # The failure this catches, seen on a real run: a headline calling static matches
    # "proven, reachable injection vulnerabilities" three paragraphs above its own
    # posture section saying "no requests were reproduced". The prompt forbids it and
    # the model did it anyway, which is precisely why this is a check and not a
    # sentence in the prompt.
    if not _executed_anything(report):
        for match in _PROOF.finditer(text):
            preceding = text[max(0, match.start() - _NEGATION_WINDOW):match.start()]
            if _NEGATION.search(preceding):
                continue  # "nothing was proven", "no request was reproduced" — fine
            problems.append(
                f'says "{match.group(0).lower()}" when nothing was executed; this '
                "scan read source and demonstrated no vulnerability")
    return problems


def render_html(brief: dict[str, Any], report: dict[str, Any]) -> str:
    """A self-contained, printable document. No external requests, so it renders the
    same in an email client, a browser, and a print-to-PDF dialogue."""
    target = escape(str(report.get("target", "")).removeprefix("github:"))
    generated = escape(str(report.get("generated_at", ""))[:19].replace("T", " "))
    counts = report.get("severity_counts", {})
    total = report.get("finding_count", 0)

    def chips() -> str:
        colours = {"critical": "#b42318", "high": "#b54708", "medium": "#a15c07",
                   "low": "#175cd3", "info": "#475467"}
        return "".join(
            f'<span class="chip" style="--c:{colours.get(s, "#475467")}">'
            f'<b>{counts[s]}</b> {s}</span>'
            for s in ("critical", "high", "medium", "low", "info") if counts.get(s)
        )

    risks = "".join(
        f'<li><h3>{escape(r.get("title",""))}</h3>'
        f'<p>{escape(r.get("why_it_matters",""))}</p>'
        f'<p class="ev">{escape(r.get("evidence",""))}</p></li>'
        for r in brief.get("key_risks", [])
    )
    actions = "".join(
        f'<li><h3>{escape(a.get("action",""))}</h3>'
        f'<p>{escape(a.get("rationale",""))}</p></li>'
        for a in brief.get("recommendations", [])
    )

    return f"""<!doctype html>
<meta charset="utf-8">
<title>Security brief — {target}</title>
<style>
  :root {{ --ink:#101828; --ink2:#475467; --ink3:#98a2b3; --line:#e4e7ec; --accent:#12b76a; }}
  * {{ box-sizing:border-box }}
  body {{ margin:0; padding:48px 24px; background:#f9fafb; color:var(--ink);
         font:16px/1.65 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
         -webkit-font-smoothing:antialiased }}
  main {{ max-width:46rem; margin:0 auto; background:#fff; padding:56px 56px 64px;
          border:1px solid var(--line); border-radius:14px }}
  .eyebrow {{ font:600 12px/1 ui-sans-serif,system-ui,sans-serif; letter-spacing:.08em;
              text-transform:uppercase; color:var(--ink3) }}
  h1 {{ font-size:30px; line-height:1.2; letter-spacing:-.02em; margin:12px 0 6px;
        text-wrap:balance }}
  h2 {{ font-size:13px; letter-spacing:.06em; text-transform:uppercase; color:var(--ink3);
        margin:40px 0 12px; padding-bottom:8px; border-bottom:1px solid var(--line) }}
  h3 {{ font-size:16px; margin:0 0 4px }}
  p {{ margin:0 0 12px; color:var(--ink2) }}
  .lede {{ font-size:19px; line-height:1.5; color:var(--ink); text-wrap:pretty }}
  .meta {{ color:var(--ink3); font-size:13px }}
  .chips {{ display:flex; flex-wrap:wrap; gap:8px; margin:20px 0 4px }}
  .chip {{ font-size:13px; padding:3px 11px; border-radius:20px; color:var(--c);
           background:color-mix(in srgb, var(--c) 10%, transparent);
           border:1px solid color-mix(in srgb, var(--c) 25%, transparent) }}
  ol {{ margin:0; padding:0; list-style:none; counter-reset:n }}
  ol li {{ counter-increment:n; position:relative; padding:0 0 20px 42px }}
  ol li::before {{ content:counter(n); position:absolute; left:0; top:1px; width:26px;
                   height:26px; border-radius:50%; background:var(--ink); color:#fff;
                   font:600 13px/26px ui-sans-serif,system-ui,sans-serif;
                   text-align:center; font-variant-numeric:tabular-nums }}
  .ev {{ font:12.5px ui-monospace,SFMono-Regular,Menlo,monospace; color:var(--ink3);
         word-break:break-word }}
  .note {{ background:#fffaeb; border:1px solid #fedf89; border-radius:10px;
           padding:16px 18px; font-size:14px; color:#93370d }}
  .note p {{ color:inherit; margin:0 }}
  footer {{ margin-top:44px; padding-top:18px; border-top:1px solid var(--line);
            font-size:12.5px; color:var(--ink3) }}
  @media print {{ body {{ background:#fff; padding:0 }}
                  main {{ border:0; border-radius:0; padding:0; max-width:none }} }}
</style>
<main>
  <div class="eyebrow">Security brief</div>
  <h1>{escape(brief.get("headline", "Scan summary"))}</h1>
  <p class="meta">{target} · scanned {generated} UTC · {total} finding(s)</p>
  <div class="chips">{chips()}</div>

  <h2>Posture</h2>
  <p class="lede">{escape(brief.get("posture", ""))}</p>

  <h2>What an attacker reaches first</h2>
  <ol>{risks or "<li><p>Nothing was ranked as reachable.</p></li>"}</ol>

  <h2>Recommended order of work</h2>
  <ol>{actions or "<li><p>No actions proposed.</p></li>"}</ol>

  <h2>What this scan could not tell you</h2>
  <div class="note"><p>{escape(brief.get("caveats", ""))}</p></div>

  <footer>
    The prose in this brief was written by a language model from this scan's own
    output. It saw no source code and could add no finding. Every figure above comes
    from the scan; nothing here was proven by exploitation. The machine-readable
    report.json and report.sarif remain the authoritative record.
  </footer>
</main>
"""


def generate(report: dict[str, Any], config: Any) -> tuple[str | None, str]:
    """(html, note). html is None when a brief could not be produced honestly."""
    import litellm

    digest = build_digest(report)
    try:
        response = litellm.completion(
            model=config.llm,
            api_key=config.llm_api_key,
            base_url=config.llm_base_url,
            messages=[{"role": "user", "content": PROMPT + json.dumps(digest, indent=1)}],
            tools=[{"type": "function", "function": {
                "name": "write_brief",
                "description": "Return the executive brief.",
                "parameters": SCHEMA,
            }}],
            tool_choice={"type": "function", "function": {"name": "write_brief"}},
            temperature=0.2,
        )
        call = response.choices[0].message.tool_calls[0]
        brief = json.loads(call.function.arguments)
    except Exception as exc:  # noqa: BLE001 — a brief is a convenience, never the record
        return None, f"the model did not return a usable brief: {type(exc).__name__}: {exc}"

    problems = verify_brief(brief, report)
    if problems:
        # Refused, not repaired. A brief that cites something the scan never saw is
        # not a formatting problem, and quietly deleting the offending sentence would
        # leave the surrounding argument standing on a fact that does not exist.
        return None, "the brief was rejected: " + "; ".join(problems[:3])
    return render_html(brief, report), "ok"


def demo() -> None:
    report = {
        "target": "github:acme/api", "generated_at": "2026-08-12T09:00:00",
        "finding_count": 2, "severity_counts": {"high": 1, "medium": 1},
        "coverage": {"semgrep": {"files_scanned": 26}},
        "findings": [
            {"rule_id": "semgrep/x.tainted-sql-string", "severity": "high",
             "cwe": "CWE-89", "discovered_by": "semgrep",
             "location": {"source_file": "/work/source/app/auth.py:41"},
             "triage": {"verdict": "exploitable", "reasoning": "reached from /login"}},
            {"rule_id": "trivy/CVE-2024-56201", "severity": "medium",
             "discovered_by": "trivy", "location": {"source_file": "requirements.txt"},
             "cvss": {"score": 8.8, "source": "nvd"}},
        ],
    }

    digest = build_digest(report)
    assert digest["repository"] == "acme/api"
    assert digest["triage"]["reachable"] == 1 and digest["triage"]["judged"] == 1
    # The digest must never imply anything was executed.
    assert digest["nothing_was_executed"] is True
    assert digest["findings"][0]["severity"] == "high", "worst first"

    # ── the guard that matters ──────────────────────────────────────────────
    good = {"headline": "h", "posture": "p", "caveats": "c",
            "key_risks": [{"title": "SQLi", "why_it_matters": "w",
                           "evidence": "app/auth.py:41"}],
            "recommendations": [{"action": "parameterise", "rationale": "r"}]}
    assert verify_brief(good, report) == [], verify_brief(good, report)

    # A CVE the scan never saw is a fabrication, and must be caught.
    invented = dict(good, key_risks=[{"title": "t", "why_it_matters": "w",
                                      "evidence": "CVE-2021-44228 in log4j"}])
    problems = verify_brief(invented, report)
    assert any("CVE-2021-44228" in p for p in problems), problems

    # So is a file that does not exist.
    ghost = dict(good, key_risks=[{"title": "t", "why_it_matters": "w",
                                   "evidence": "app/payments.py:12"}])
    assert any("payments.py" in p for p in verify_brief(ghost, report)), "ghost file"

    # A real CVE from the scan passes.
    real = dict(good, caveats="CVE-2024-56201 was not reachability-checked.")
    assert verify_brief(real, report) == []

    # ── proof language over a static-only scan ──────────────────────────────
    assert _executed_anything(report) is False, "semgrep + trivy execute nothing"
    overclaim = dict(good, headline="Multiple proven, reachable injection flaws")
    assert any("proven" in p for p in verify_brief(overclaim, report)), verify_brief(overclaim, report)
    # Negated and prefixed forms are fine — the caveats section needs to say them.
    for safe in ("nothing was proven by exploitation",
                 "these are unconfirmed static matches",
                 "no request was ever reproduced" ):
        assert verify_brief(dict(good, caveats=safe), report) == [], safe
    # Once something really was executed, the words are allowed.
    live = dict(report, findings=report["findings"] + [
        {"rule_id": "nuclei/x", "severity": "high", "discovered_by": "nuclei",
         "location": {"path": "/x"}}])
    assert _executed_anything(live) is True
    assert verify_brief(overclaim, live) == []

    html = render_html(good, report)
    assert "acme/api" in html and "SQLi" in html
    assert "written by a language model" in html, "authorship must be stated"
    assert "nothing here was proven by exploitation" in html
    # Model output is escaped: a brief is rendered into a page someone opens.
    nasty = dict(good, headline="<script>alert(1)</script>")
    assert "<script>alert(1)</script>" not in render_html(nasty, report)
    assert "&lt;script&gt;" in render_html(nasty, report)
    # Self-contained: no external request can be made from the rendered page.
    for token in ("http://", "https://", "<img", "src="):
        assert token not in html, token
    print("report.narrative: ok")


if __name__ == "__main__":
    demo()
