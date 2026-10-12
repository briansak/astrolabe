"""Customer assessment and developer remediation handoff.

Assessment findings include only candidates a consultant confirmed on the
current snapshot. Stale and unreviewed candidates are omitted unless the
operator asks for unreviewed names, and even then they stay out of Findings.
"""

from __future__ import annotations

import html
import json
import re
from pathlib import Path

from astrolabe.advisories import ADVISORY_ID_PATTERN
from astrolabe.candidates import confirmed_for_report, list_candidates
from astrolabe.coverage import rebuild_coverage
from astrolabe.cwe import NO_MITIGATION, cwe_name, cwes_without_mitigations, displayed_mitigations
from astrolabe.cwe_catalog import load_cwe_catalog
from astrolabe.selection import EXPLORATORY_NOTE, SINGLE_FILE_NOTE, short_sha
from astrolabe.engagement import (
    EngagementError,
    append_durable_audit,
    engagement_dir,
    load_engagement,
    read_attestation,
    utc_now,
)
from astrolabe.redact import redact_text

INSTRUCTION = (
    "Confirm the weakness in the named file before changing code. "
    "This handoff is not a patch and it has no line numbers."
)
BENCHMARK = (
    "In our testing on 34 published vulnerabilities, advisory-guided investigation "
    "identified the affected file in roughly 7 of 10 runs, compared with about 1 in 4 "
    "without an advisory. Results on this codebase may differ."
)
def _schema_path() -> Path:
    """The handoff schema lives at the repo root. The package may sit at the root or under src/."""
    name = Path("data") / "schemas" / "remediation-handoff.schema.json"
    here = Path(__file__).resolve()
    for ancestor in here.parents:
        candidate = ancestor / name
        if candidate.is_file():
            return candidate
    return here.parents[1] / name


SCHEMA_PATH = _schema_path()
TEMPLATE_VERSION = "1"
UNREVIEWED_REFUSAL = "Unreviewed candidates are not included in customer reports."
_TEMPLATE_ZERO = "This assessment uses report template 0. It can't be regenerated or re-finalized."


def write_assessment(
    root: Path,
    engagement_id: str,
    *,
    actor: str,
    include_unreviewed: bool = False,
    html_path: Path | None = None,
    pdf_path: Path | None = None,
) -> dict[str, Path]:
    if not actor.strip():
        raise EngagementError("A report requires the consultant generating it")
    if include_unreviewed:
        raise EngagementError(UNREVIEWED_REFUSAL)
    directory = engagement_dir(root, engagement_id)
    _refuse_rewrite(directory)
    document = _document(root, engagement_id)
    html_target = html_path or (directory / "reports" / "assessment.html")
    pdf_target = pdf_path or (directory / "reports" / "assessment.pdf")
    page = _assessment_html(document, final=False, approver="", finalized_at="")
    _write_text(html_target, page)
    _render_pdf(page, pdf_target)
    _write_status(directory, status="draft", actor="", finalized_at="", include_unreviewed=False)
    _audit_report(root, engagement_id, actor=actor.strip(), kind="assessment", document=document)
    return {"html": html_target, "pdf": pdf_target}


def finalize_block_message(pending: int, needs_info: int, rereview: int) -> str:
    """Name each group that still blocks a final report. Counts use singular or plural."""
    parts: list[str] = []
    if pending:
        if pending == 1:
            parts.append("1 candidate is pending review")
        else:
            parts.append(f"{pending} candidates are pending review")
    if needs_info:
        if parts:
            verb = "needs" if needs_info == 1 else "need"
            parts.append(f"{needs_info} {verb} more information")
        elif needs_info == 1:
            parts.append("1 candidate needs more information")
        else:
            parts.append(f"{needs_info} candidates need more information")
    if rereview:
        if parts:
            verb = "needs" if rereview == 1 else "need"
            parts.append(f"{rereview} {verb} re-review on the current snapshot")
        elif rereview == 1:
            parts.append("1 candidate needs re-review on the current snapshot")
        else:
            parts.append(f"{rereview} candidates need re-review on the current snapshot")
    if not parts:
        return ""
    if len(parts) == 1:
        return parts[0] + "."
    return "; ".join(parts) + "."


def finalize_assessment(root: Path, engagement_id: str, *, actor: str) -> dict[str, str]:
    """Mark the assessment final, name the approving consultant, and audit it."""
    if not actor.strip():
        raise EngagementError("Finalizing a report requires the approving consultant")
    directory = engagement_dir(root, engagement_id)
    _refuse_rewrite(directory)
    if not (directory / "reports" / "assessment.html").is_file():
        raise EngagementError("Generate an assessment report before finalizing it")
    blocked = _unresolved_candidates(root, engagement_id)
    if blocked:
        raise EngagementError(blocked)
    document = _document(root, engagement_id)
    finalized_at = utc_now()
    page = _assessment_html(document, final=True, approver=actor.strip(), finalized_at=finalized_at)
    html_target = directory / "reports" / "assessment.html"
    pdf_target = directory / "reports" / "assessment.pdf"
    _write_text(html_target, page)
    _render_pdf(page, pdf_target)
    _write_status(
        directory,
        status="final",
        actor=actor.strip(),
        finalized_at=finalized_at,
        include_unreviewed=False,
    )
    append_durable_audit(
        root,
        engagement_id,
        {
            "action": "report_finalize",
            "actor": actor.strip(),
            "finalized_at": finalized_at,
        },
    )
    return {"html": str(html_target), "pdf": str(pdf_target), "finalized_at": finalized_at}


def assessment_is_draft(directory: Path) -> bool:
    html_path = directory / "reports" / "assessment.html"
    if not html_path.is_file():
        return False
    status = _read_status(directory)
    return status.get("status") != "final"


def write_remediation(
    root: Path,
    engagement_id: str,
    *,
    actor: str,
    markdown_path: Path | None = None,
    json_path: Path | None = None,
) -> dict[str, Path]:
    if not actor.strip():
        raise EngagementError("A report requires the consultant generating it")
    document = _document(root, engagement_id)
    directory = engagement_dir(root, engagement_id)
    markdown_target = markdown_path or (directory / "reports" / "remediation.md")
    json_target = json_path or (directory / "reports" / "remediation.json")
    _write_text(markdown_target, _remediation_markdown(document))
    _write_text(json_target, json.dumps(_remediation_json(document), indent=2) + "\n")
    _audit_report(root, engagement_id, actor=actor.strip(), kind="remediation", document=document)
    return {"markdown": markdown_target, "json": json_target}


def _document(root: Path, engagement_id: str) -> dict[str, object]:
    record = load_engagement(root, engagement_id)
    directory = engagement_dir(root, engagement_id)
    attestation = read_attestation(root, engagement_id) or {}
    candidates = list_candidates(root, engagement_id)
    investigations = _load_investigations(directory)
    coverage = rebuild_coverage(root, engagement_id)
    rows = [_candidate_row(candidate, investigations) for candidate in candidates]
    confirmed = [row for row in rows if row["confirmed_for_report"]]
    stale = [row for row in rows if row["stale"]]
    unreviewed = [row for row in rows if row["status"] == "candidate" and not row["stale"]]
    return {
        "engagement": record,
        "authorization_reference": redact_text(str(attestation.get("reference") or "")),
        "confirmed": confirmed,
        "stale": stale,
        "unreviewed": unreviewed,
        "advisory_ids": _advisory_ids(investigations),
        "coverage": coverage,
        "counts": {
            "confirmed": len(confirmed),
            "stale": len(stale),
            "unreviewed": len(unreviewed),
        },
    }


def _candidate_row(candidate: dict[str, object], investigations: list[dict[str, object]]) -> dict[str, object]:
    file_path = str(candidate["file_path"])
    cwe = str(candidate["cwe"])
    mode, advisory_id = _attribution(investigations, file_path, cwe)
    name = cwe_name(cwe)
    look_for = f"Look through {file_path} for {name or cwe}. Confirm the weakness before changing code."
    return {
        "file": redact_text(file_path),
        "cwe": cwe,
        "name": name,
        "status": str(candidate["state"]),
        "mode": mode,
        "advisory_id": advisory_id,
        "note": redact_text(str(candidate.get("note") or "")),
        "mitigations": [redact_text(item) for item in displayed_mitigations(cwe)],
        "what_to_look_for": redact_text(look_for),
        "stale": bool(candidate.get("stale")),
        "confirmed_for_report": confirmed_for_report(candidate),
    }


def _attribution(
    investigations: list[dict[str, object]],
    file_path: str,
    cwe: str,
) -> tuple[str, str]:
    """Mode and advisory id from the investigation that named this file."""
    matched: tuple[str, str] | None = None
    fallback: tuple[str, str] | None = None
    for investigation in investigations:
        if str(investigation.get("cwe")) != cwe:
            continue
        mode = "exploratory" if investigation.get("exploratory") else "advisory"
        pair = (mode, _advisory_id(investigation))
        fallback = pair
        for run in investigation.get("runs") or []:
            if isinstance(run, dict) and file_path in (run.get("candidate_paths") or []):
                matched = pair
    if matched is not None:
        return matched
    if fallback is not None:
        return fallback
    return "exploratory", ""


def _advisory_id(investigation: dict[str, object]) -> str:
    recorded = str(investigation.get("advisory_id") or "").strip()
    if recorded:
        return recorded
    source = str(investigation.get("selection_source") or "").strip()
    if ADVISORY_ID_PATTERN.fullmatch(source):
        return source
    return ""


def _advisory_ids(investigations: list[dict[str, object]]) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()
    for investigation in investigations:
        advisory_id = _advisory_id(investigation)
        if advisory_id and advisory_id not in seen:
            seen.add(advisory_id)
            found.append(advisory_id)
    return found


def _assessment_html(
    document: dict[str, object],
    *,
    final: bool,
    approver: str,
    finalized_at: str,
) -> str:
    engagement = document["engagement"]
    assert isinstance(engagement, dict)
    confirmed = document["confirmed"]
    assert isinstance(confirmed, list)
    findings = _finding_blocks(confirmed) if confirmed else "<p>No confirmed findings.</p>"
    approver_text = approver if final else "Not yet approved"
    finalized_text = finalized_at if final else "Draft"
    watermark = "" if final else _WATERMARK_CSS
    body_class = "" if final else ' class="draft"'
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Assessment {_esc(engagement.get("customer"))}</title>
<style>
@page {{
  margin: 18mm;
  @bottom-center {{ content: counter(page); font-family: Georgia, Palatino, serif; }}
}}
body {{
  font-family: Georgia, Palatino, serif;
  margin: 2rem auto;
  max-width: 40rem;
  line-height: 1.45;
  color: #1c1917;
  background: #fff;
}}
h1, h2, h3 {{ font-family: Palatino, Georgia, serif; }}
table {{ border-collapse: collapse; width: 100%; margin: 1rem 0; }}
th, td {{ border-bottom: 1px solid #d6d3d1; text-align: left; padding: 0.4rem; vertical-align: top; }}
.mono {{ font-family: ui-monospace, "Courier New", monospace; }}
article.finding {{ page-break-inside: avoid; margin: 0 0 1.5rem; }}
#sign-off {{ border: 2px solid #365314; padding: 0.6rem 1rem; }}
{watermark}</style>
</head>
<body{body_class}>
{_report_banner(final=final, approver=approver, finalized_at=finalized_at)}
<h1>Assessment</h1>
<p>Consultant-confirmed candidate files. This is not a merge decision and it does not waive anything.</p>
<h2>Header</h2>
<table>
<tr><th>Customer</th><td>{_esc(engagement.get("customer"))}</td></tr>
<tr><th>Engagement ID</th><td>{_esc(engagement.get("id"))}</td></tr>
<tr><th>Scope</th><td>{_esc(engagement.get("scope"))}</td></tr>
<tr><th>Snapshot</th><td class="mono">{_esc(short_sha(engagement.get("snapshot_sha256")))}</td></tr>
<tr><th>Start</th><td>{_esc(engagement.get("start_date"))}</td></tr>
<tr><th>End</th><td>{_esc(_end_label(engagement.get("end_date")))}</td></tr>
<tr><th>Approving consultant</th><td>{_esc(approver_text)}</td></tr>
<tr><th>Finalized</th><td>{_esc(finalized_text)}</td></tr>
</table>
<p>Authorization: {_esc(document.get("authorization_reference"))}</p>
<h2>Summary</h2>
<p>{_esc(_summary_paragraph(document))}</p>
<h2>Findings</h2>
{findings}
<h2>What was checked</h2>
<p>Advisory-guided and exploratory investigations are listed separately. They are not combined into one figure.</p>
{_coverage_html(document["coverage"], "advisory", "Advisory-guided")}
{_coverage_html(document["coverage"], "exploratory", "Exploratory", engagement=engagement)}
<h2>Method and limitations</h2>
{_methodology_html()}
<h2>Appendix</h2>
{_appendix_html(engagement)}
</body>
</html>
"""


def _summary_paragraph(document: dict[str, object]) -> str:
    counts = document.get("counts")
    confirmed = int(counts["confirmed"]) if isinstance(counts, dict) else 0
    finding = "1 confirmed finding" if confirmed == 1 else f"{confirmed} confirmed findings"
    advisory, exploratory = _check_counts(document.get("coverage"))
    advisory_text = "1 advisory check" if advisory == 1 else f"{advisory} advisory checks"
    exploratory_text = "1 exploratory check" if exploratory == 1 else f"{exploratory} exploratory checks"
    sentence = f"{finding}. {advisory_text} and {exploratory_text}."
    checked = _advisories_checked(document)
    if checked:
        return f"{sentence} {checked}"
    return sentence


def _advisories_checked(document: dict[str, object]) -> str:
    recorded = document.get("advisory_ids")
    ids = [str(item) for item in recorded] if isinstance(recorded, list) else []
    names = list(ids)
    if _pasted_advisory(document.get("coverage")):
        names.append("pasted advisory text")
    if not names:
        return ""
    return "Advisories checked: " + ", ".join(names) + "."


def _pasted_advisory(coverage: object) -> bool:
    if not isinstance(coverage, dict):
        return False
    for item in coverage.get("cwes") or []:
        if not isinstance(item, dict) or item.get("mode") != "advisory":
            continue
        if str(item.get("selection_source") or "") == "pasted":
            return True
    return False


def _more_mitigations(rest: int) -> str:
    word = "mitigation" if rest == 1 else "mitigations"
    return f"{rest} more {word} listed in the remediation handoff."


def _check_counts(coverage: object) -> tuple[int, int]:
    advisory = exploratory = 0
    if not isinstance(coverage, dict):
        return advisory, exploratory
    for item in coverage.get("cwes") or []:
        if not isinstance(item, dict):
            continue
        count = item.get("investigations")
        number = count if isinstance(count, int) and not isinstance(count, bool) else 0
        if item.get("mode") == "advisory":
            advisory += number
        elif item.get("mode") == "exploratory":
            exploratory += number
    return advisory, exploratory


def _finding_blocks(rows: list[object]) -> str:
    blocks: list[str] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        mitigations = row.get("mitigations")
        listed = [_render_mitigation(item) for item in mitigations] if isinstance(mitigations, list) and mitigations else [NO_MITIGATION]
        shown = listed[:3]
        rest = len(listed) - len(shown)
        items = "".join(f"<li>{html.escape(item)}</li>" for item in shown)
        more = f"<p>{_more_mitigations(rest)}</p>" if rest else ""
        name = str(row.get("name") or "") or cwe_name(str(row.get("cwe") or ""))
        cwe_line = " ".join(part for part in (str(row.get("cwe") or ""), name) if part)
        note = str(row.get("note") or "").strip()
        explanation = f"<p>Consultant explanation: {html.escape(note)}</p>" if note else ""
        look = str(row.get("what_to_look_for") or "").strip()
        look_html = f"<p>What to look for: {html.escape(look)}</p>" if look else ""
        blocks.append(
            '<article class="finding">'
            f'<h3 class="mono">{html.escape(str(row["file"]))}</h3>'
            f"<p>{html.escape(cwe_line)}</p>"
            f"<p>{html.escape(_found_by(str(row.get('mode') or ''), str(row.get('advisory_id') or '')))}</p>"
            f"{look_html}"
            f"{explanation}"
            f"<p>MITRE mitigations</p><ul>{items}</ul>"
            f"{more}"
            "</article>"
        )
    return "\n".join(blocks)


def _found_by(mode: str, advisory_id: str) -> str:
    if mode == "advisory":
        if advisory_id.strip():
            return f"Found by: advisory-guided check ({advisory_id.strip()})"
        return "Found by: advisory-guided check"
    return "Found by: exploratory check"


def _coverage_html(
    coverage: object,
    mode: str,
    title: str,
    engagement: dict[str, object] | None = None,
) -> str:
    if not isinstance(coverage, dict):
        return f"<h3>{html.escape(title)}</h3><p>No coverage record.</p>"
    rows = [item for item in coverage.get("cwes") or [] if isinstance(item, dict) and item.get("mode") == mode]
    verdicts = _verdicts_for_mode(coverage, mode)
    body = "".join(
        "<tr>"
        f"<td>{html.escape(str(item.get('cwe')))}</td>"
        f"<td>{html.escape(cwe_name(str(item.get('cwe') or '')))}</td>"
        f"<td>{html.escape(_selection_label(item.get('selection_source')))}</td>"
        f'<td class="mono">{html.escape(short_sha(item.get("snapshot_sha256")))}</td>'
        f"<td>{html.escape(str(item.get('investigations')))}</td>"
        f"<td>{html.escape(str(item.get('runs')))}</td>"
        "</tr>"
        for item in rows
    )
    if not body:
        body = "<tr><td colspan=\"6\">None.</td></tr>"
    verdict_text = ", ".join(f"{key} {value}" for key, value in sorted(verdicts.items())) or "none"
    note = ""
    if mode == "exploratory":
        note = f"<p>{html.escape(EXPLORATORY_NOTE)}</p>"
        if isinstance(engagement, dict) and engagement.get("label") == "single-file":
            note += f"<p>{html.escape(SINGLE_FILE_NOTE)}</p>"
    return (
        f"<h3>{html.escape(title)}</h3>"
        f"{note}"
        "<table><thead><tr><th>CWE</th><th>Name</th><th>Selection source</th><th>Snapshot</th>"
        "<th>Investigations</th><th>Runs</th></tr></thead>"
        f"<tbody>{body}</tbody></table>"
        f"<p>Verdicts in this mode: {html.escape(verdict_text)}.</p>"
    )


def _verdicts_for_mode(coverage: dict[str, object], mode: str) -> dict[str, int]:
    cwes = {str(item.get("cwe")) for item in coverage.get("cwes") or [] if isinstance(item, dict) and item.get("mode") == mode}
    counts: dict[str, int] = {}
    for candidate in coverage.get("candidates") or []:
        if not isinstance(candidate, dict) or str(candidate.get("cwe")) not in cwes:
            continue
        label = str(candidate.get("presentation_state") or candidate.get("state"))
        counts[label] = counts.get(label, 0) + 1
    return counts


def _methodology_html() -> str:
    paragraphs = [
        "Astrolabe asks Antares-1B, through the official CLI, to name files that may be relevant to one CWE. A consultant reads those candidates and confirms the ones that belong in this report. Model output by itself is not a finding.",
        BENCHMARK,
        "An empty findings list is not evidence that the snapshot has no weakness. The model has no line numbers. Re-running an investigation is recorded and does not increase CWE coverage. A verdict from an older snapshot is omitted here until a consultant re-confirms it.",
    ]
    missing = cwes_without_mitigations()
    if missing:
        paragraphs.append("These bundled CWEs have no MITRE mitigation text: " + ", ".join(missing) + ".")
    return "".join(f"<p>{html.escape(paragraph)}</p>" for paragraph in paragraphs)


def _appendix_html(engagement: dict[str, object]) -> str:
    version, released = _catalog_stamp()
    return (
        "<table>"
        f"<tr><th>Snapshot SHA-256</th><td class=\"mono\">{_esc(engagement.get('snapshot_sha256'))}</td></tr>"
        f"<tr><th>CWE catalog</th><td>{_esc(version)}, released {_esc(released)}</td></tr>"
        f"<tr><th>Report template</th><td>{_esc(TEMPLATE_VERSION)}</td></tr>"
        "</table>"
    )


def _catalog_stamp() -> tuple[str, str]:
    catalog = load_cwe_catalog()
    if not isinstance(catalog, dict):
        return "", ""
    return str(catalog.get("version") or ""), str(catalog.get("release_date") or "")


def _report_banner(*, final: bool, approver: str, finalized_at: str) -> str:
    if final:
        return f'<p id="sign-off">Final. Approved by {html.escape(approver)} at {html.escape(finalized_at)}.</p>'
    return '<p id="draft-marker">DRAFT</p>'


def _remediation_markdown(document: dict[str, object]) -> str:
    engagement = document["engagement"]
    assert isinstance(engagement, dict)
    lines = [
        f"# Remediation handoff for {engagement.get('customer')}",
        "",
        INSTRUCTION,
        "",
        "Candidates below are consultant-confirmed on the current snapshot. Stale and unreviewed candidates are omitted.",
        "",
    ]
    confirmed = document["confirmed"]
    if not confirmed:
        lines.append("No confirmed candidates.")
    else:
        assert isinstance(confirmed, list)
        for row in confirmed:
            if not isinstance(row, dict):
                continue
            mode = "advisory-guided" if row["mode"] == "advisory" else "exploratory"
            lines.extend(
                [
                    f"## {row['file']}",
                    "",
                    f"- Status: {row['status']}",
                    f"- Mode: {mode}",
                    f"- CWE: {row['cwe']}",
                    f"- What to look for: {row['what_to_look_for']}",
                    "",
                    "MITRE mitigations:",
                    "",
                ]
            )
            recorded = row["mitigations"]
            mitigations = [_render_mitigation(item) for item in recorded] if recorded else [NO_MITIGATION]
            lines.extend(f"- {item}" for item in mitigations)
            lines.append("")
    return "\n".join(lines)


def _remediation_json(document: dict[str, object]) -> dict[str, object]:
    engagement = document["engagement"]
    assert isinstance(engagement, dict)
    confirmed = document["confirmed"]
    candidates = []
    if isinstance(confirmed, list):
        for row in confirmed:
            if not isinstance(row, dict):
                continue
            recorded = row["mitigations"]
            mitigations = [_render_mitigation(item) for item in recorded] if recorded else [NO_MITIGATION]
            candidates.append(
                {
                    "file": row["file"],
                    "cwe": row["cwe"],
                    "status": row["status"],
                    "mode": row["mode"],
                    "mitigations": mitigations,
                    "what_to_look_for": row["what_to_look_for"],
                }
            )
    return {
        "verification_required": True,
        "instruction": INSTRUCTION,
        "engagement_id": str(engagement.get("id") or ""),
        "candidates": candidates,
    }


def _audit_report(
    root: Path,
    engagement_id: str,
    *,
    actor: str,
    kind: str,
    document: dict[str, object],
) -> None:
    counts = document["counts"]
    assert isinstance(counts, dict)
    append_durable_audit(
        root,
        engagement_id,
        {
            "action": "report",
            "kind": kind,
            "actor": actor,
            "confirmed": counts["confirmed"],
            "stale": counts["stale"],
            "unreviewed": counts["unreviewed"],
        },
    )


def _unresolved_candidates(root: Path, engagement_id: str) -> str:
    record = load_engagement(root, engagement_id)
    current = record.get("snapshot_sha256")
    current_text = current if isinstance(current, str) else ""
    investigations = _load_investigations(engagement_dir(root, engagement_id))
    pending = needs_info = rereview = 0
    for candidate in list_candidates(root, engagement_id):
        if candidate.get("stale"):
            if _stale_blocks(candidate, investigations, current_text):
                rereview += 1
            continue
        state = str(candidate.get("presentation_state") or candidate.get("state") or "")
        if state == "candidate":
            pending += 1
        elif state == "needs_more_info":
            needs_info += 1
    return finalize_block_message(pending, needs_info, rereview)


def _stale_blocks(
    candidate: dict[str, object],
    investigations: list[dict[str, object]],
    current_snapshot: str,
) -> bool:
    """A stale verdict blocks when a recorded run observed the file on this snapshot.

    Each run stores its snapshot. Run 1 written before that field uses the
    investigation snapshot. Any later run without a snapshot stays blocking.
    """
    file_path = str(candidate.get("file_path") or "")
    cwe = str(candidate.get("cwe") or "")
    attributed = False
    for investigation in investigations:
        if str(investigation.get("cwe") or "") != cwe:
            continue
        runs = investigation.get("runs")
        if not isinstance(runs, list):
            continue
        inv_snapshot = str(investigation.get("snapshot_sha256") or "")
        for index, run in enumerate(runs, start=1):
            if not isinstance(run, dict):
                continue
            paths = run.get("candidate_paths")
            if not isinstance(paths, list) or file_path not in paths:
                continue
            attributed = True
            recorded = run.get("snapshot_sha256")
            if isinstance(recorded, str) and recorded:
                if current_snapshot and recorded == current_snapshot:
                    return True
                continue
            if index == 1 and current_snapshot and inv_snapshot == current_snapshot:
                return True
            if index != 1:
                return True
    return not attributed


def _load_investigations(directory: Path) -> list[dict[str, object]]:
    path = directory / "investigations.json"
    if not path.is_file():
        return []
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        return []
    return [item for item in payload if isinstance(item, dict)]


_REF_MARKER = re.compile(r"\s*\[REF-\d+\]|\s*\[REF-\d+\.")


def _strip_ref_markers(text: str) -> str:
    """Drop MITRE reference markers, including a truncated `[REF-1481.` form."""
    cleaned = _REF_MARKER.sub("", text)
    cleaned = re.sub(r"[ \t]{2,}", " ", cleaned)
    cleaned = re.sub(r" +([.,;:!?])", r"\1", cleaned)
    cleaned = cleaned.strip()
    if cleaned and cleaned[-1] not in ".!?":
        cleaned += "."
    return cleaned


def _render_mitigation(item: object) -> str:
    return _strip_ref_markers(str(item))


def _selection_label(source: object) -> str:
    text = "" if source is None else str(source)
    if text == "pasted":
        return "Pasted advisory text"
    return text


def _end_label(value: object) -> str:
    text = "" if value is None else str(value).strip()
    return text or "Not set"


def _esc(value: object) -> str:
    return html.escape("" if value is None else str(value))


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _refuse_external_url(_url: str) -> dict[str, object]:
    raise EngagementError("Assessment PDF rendering does not load external URLs.")


_refuse_external_url._fail_on_errors = True  # type: ignore[attr-defined]


_WATERMARK_CSS = """
#draft-marker {
  position: fixed;
  top: 38%;
  left: 10%;
  margin: 0;
  border: none;
  color: rgba(159, 18, 57, 0.18);
  font-size: 5rem;
  font-weight: bold;
  letter-spacing: 0.12em;
  transform: rotate(-24deg);
}
"""


def _render_pdf(page: str, pdf_path: Path) -> bool:
    """Render the assessment PDF. A missing WeasyPrint or Pango leaves HTML in place."""
    try:
        from weasyprint import HTML
    except ImportError:
        pdf_path.unlink(missing_ok=True)
        return False
    pdf_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        HTML(string=page, url_fetcher=_refuse_external_url).write_pdf(pdf_path)
    except (KeyboardInterrupt, SystemExit):
        raise
    except BaseException as exc:
        pdf_path.unlink(missing_ok=True)
        found = _caused_by_engagement_error(exc)
        if found is not None:
            raise found from exc
        if _pdf_library_missing(exc):
            return False
        raise
    return True


def _pdf_library_missing(exc: BaseException) -> bool:
    text = f"{type(exc).__name__} {exc}".lower()
    return any(word in text for word in ("pango", "cairo", "gobject", "dlopen", "library not loaded", "weasyprint"))


def _caused_by_engagement_error(exc: BaseException) -> EngagementError | None:
    seen: set[int] = set()
    stack = [exc]
    while stack:
        current = stack.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        if isinstance(current, EngagementError):
            return current
        if current.__cause__ is not None:
            stack.append(current.__cause__)
        if current.__context__ is not None and current.__context__ is not current.__cause__:
            stack.append(current.__context__)
    return None


def _status_path(directory: Path) -> Path:
    return directory / "reports" / "assessment-status.json"


def _read_status(directory: Path) -> dict[str, object]:
    path = _status_path(directory)
    if not path.is_file():
        return {}
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        return {}
    return payload


def assessment_freeze_message(directory: Path, *, verdict: bool = False) -> str | None:
    """The refusal when a final assessment must stay as it was written."""
    status = _read_status(directory)
    if status.get("status") != "final":
        return None
    name = str(status.get("actor") or "")
    when = str(status.get("finalized_at") or "")
    if verdict:
        return f"This assessment is finalized by {name} at {when}. Verdicts can't be changed."
    return (
        f"This assessment is finalized by {name} at {when}. "
        "It can't be regenerated or re-finalized."
    )


def _template_version(status: dict[str, object]) -> str:
    value = status.get("template_version")
    if isinstance(value, str) and value.strip():
        return value.strip()
    return "0"


def _refuse_rewrite(directory: Path) -> None:
    status = _read_status(directory)
    frozen = assessment_freeze_message(directory)
    if frozen is not None:
        raise EngagementError(frozen)
    html_exists = (directory / "reports" / "assessment.html").is_file()
    if html_exists and _status_path(directory).is_file() and _template_version(status) == "0":
        raise EngagementError(_TEMPLATE_ZERO)


def _write_status(
    directory: Path,
    *,
    status: str,
    actor: str,
    finalized_at: str,
    include_unreviewed: bool,
) -> None:
    _write_text(
        _status_path(directory),
        json.dumps(
            {
                "status": status,
                "actor": actor,
                "finalized_at": finalized_at,
                "include_unreviewed": include_unreviewed,
                "template_version": TEMPLATE_VERSION,
            },
            indent=2,
        )
        + "\n",
    )
