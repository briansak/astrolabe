"""Advisory context for a candidate. Matching reads local text only."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

from astrolabe.engagement import advisory_cache_dir, engagement_dir, load_engagement

_COMPONENT = r"[A-Za-z0-9_.~-]*[A-Za-z0-9_~-]"
PATH_SPAN = re.compile(rf"{_COMPONENT}(?:[/\\]{_COMPONENT})+")
SENSITIVE = re.compile(
    r"-----BEGIN|ssh-[A-Za-z0-9]|ecdsa-sha2-|sk-ssh-|sk-ecdsa-|[A-Za-z0-9+/=]{40,}"
)
EXCERPT_LIMIT = 300
NOTE_MIN = 40
COMPARE_LABEL = (
    "I compared this file against the advisory and its fix, and it is not the affected code."
)
NOTE_HINT = (
    "The advisory names this file. The note must be at least 40 characters and say why this is not the affected code."
)
CHECKBOX_ERROR = "Confirm you compared this file against the advisory and its fix."
REVIEW_MATCH_NOTE = (
    "Path matches use the cached summary and details, or the pasted advisory. "
    "Sync does not store fix-commit references."
)


@dataclass(frozen=True)
class AdvisoryMatch:
    kind: str
    source: str
    excerpt: str


@dataclass(frozen=True)
class AdvisoryContext:
    label: str
    summary: str
    full_text: str
    match: AdvisoryMatch

    @property
    def names_file(self) -> bool:
        return self.match.kind == "path"


def normalize_repo_path(path: str, stripped_prefix: str | None = None) -> str:
    """Drop the intake prefix, use forward slashes, and strip a leading ./."""
    text = path.replace("\\", "/").strip()
    while text.startswith("./"):
        text = text[2:]
    text = text.lstrip("/")
    prefix = (stripped_prefix or "").replace("\\", "/").strip().strip("/")
    if prefix and (text == prefix or text.startswith(prefix + "/")):
        text = text[len(prefix) :].lstrip("/")
    parts = [part for part in text.split("/") if part and part != "."]
    return "/".join(parts)


def match_advisory_text(
    candidate_path: str,
    summary: str,
    details: str,
    *,
    stripped_prefix: str | None,
    source: str,
) -> AdvisoryMatch:
    """Match a whole path, or a component suffix of one. A bare filename is weaker."""
    candidate = normalize_repo_path(candidate_path, stripped_prefix)
    if not candidate:
        return AdvisoryMatch("", source, "")
    fields = (("details", details or ""), ("summary", summary or ""))
    for field_name, field in fields:
        for span in PATH_SPAN.findall(field):
            mentioned = normalize_repo_path(span, stripped_prefix)
            if not _is_component_suffix(mentioned, candidate):
                continue
            return AdvisoryMatch("path", source, _excerpt(field, span))
    basename = candidate.rsplit("/", 1)[-1]
    for _field_name, field in fields:
        if _basename_mentioned(field, basename):
            return AdvisoryMatch("filename", source, _excerpt(field, basename))
    return AdvisoryMatch("", source, "")


def advisory_contexts(root: Path, engagement_id: str, candidate: dict[str, object]) -> list[AdvisoryContext]:
    """Advisory-guided investigations that submitted this file and CWE."""
    record = load_engagement(root, engagement_id)
    prefix = _stripped_prefix(record)
    file_path = str(candidate.get("file_path") or "")
    cwe = str(candidate.get("cwe") or "")
    contexts: list[AdvisoryContext] = []
    for investigation in _investigations(root, engagement_id):
        if investigation.get("exploratory"):
            continue
        if str(investigation.get("cwe") or "") != cwe:
            continue
        if not _submitted(investigation, file_path):
            continue
        label, summary, details, full_text, source = _advisory_text(investigation)
        contexts.append(
            AdvisoryContext(
                label=label,
                summary=summary,
                full_text=full_text,
                match=match_advisory_text(
                    file_path,
                    summary,
                    details,
                    stripped_prefix=prefix,
                    source=source,
                ),
            )
        )
    return contexts


def dismissal_errors(
    root: Path,
    engagement_id: str,
    candidate: dict[str, object],
    *,
    state: str,
    note: str,
    confirmed: bool,
) -> dict[str, str]:
    """Field errors for not_actionable on an advisory-guided candidate."""
    if state != "not_actionable":
        return {}
    contexts = advisory_contexts(root, engagement_id, candidate)
    if not contexts:
        return {}
    errors: dict[str, str] = {}
    if not confirmed:
        errors["confirmed"] = CHECKBOX_ERROR
    if any(item.names_file for item in contexts) and len(note.strip()) < NOTE_MIN:
        errors["note"] = NOTE_HINT
    return errors


def _is_component_suffix(mentioned: str, candidate: str) -> bool:
    mentioned_parts = [part for part in mentioned.split("/") if part]
    candidate_parts = [part for part in candidate.split("/") if part]
    if not candidate_parts or len(mentioned_parts) < len(candidate_parts):
        return False
    return mentioned_parts[-len(candidate_parts) :] == candidate_parts


def _basename_mentioned(text: str, basename: str) -> bool:
    if not basename or "/" in basename or "\\" in basename:
        return False
    pattern = re.compile(rf"(?<![A-Za-z0-9_.~/-]){re.escape(basename)}(?![A-Za-z0-9_.~-])")
    return pattern.search(text) is not None


def _excerpt(text: str, span: str) -> str:
    sentence = _sentence(text, span)
    if not sentence or SENSITIVE.search(sentence):
        return ""
    return sentence[:EXCERPT_LIMIT]


def _sentence(text: str, span: str) -> str:
    index = text.find(span)
    if index < 0:
        return ""
    line_break = text.rfind("\n", 0, index)
    period = text.rfind(". ", 0, index)
    start = max(line_break, period)
    if start < 0:
        start = 0
    elif text[start] == "\n":
        start += 1
    else:
        start += 2
    next_break = text.find("\n", index + len(span))
    next_period = text.find(". ", index + len(span))
    ends = [pos for pos in (next_break, next_period) if pos != -1]
    end = len(text) if not ends else min(ends)
    if ends and end == next_period:
        end += 1
    return " ".join(text[start:end].split())


def _stripped_prefix(record: dict[str, object]) -> str | None:
    intake = record.get("intake")
    if not isinstance(intake, dict):
        return None
    prefix = intake.get("stripped_prefix")
    return prefix if isinstance(prefix, str) and prefix else None


def _investigations(root: Path, engagement_id: str) -> list[dict[str, object]]:
    path = engagement_dir(root, engagement_id) / "investigations.json"
    if not path.is_file():
        return []
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        return []
    return [item for item in payload if isinstance(item, dict)]


def _submitted(investigation: dict[str, object], file_path: str) -> bool:
    runs = investigation.get("runs")
    if not isinstance(runs, list):
        return False
    for run in runs:
        if not isinstance(run, dict):
            continue
        paths = run.get("candidate_paths")
        if isinstance(paths, list) and file_path in paths:
            return True
    return False


def _advisory_text(investigation: dict[str, object]) -> tuple[str, str, str, str, str]:
    advisory_id = investigation.get("advisory_id")
    if isinstance(advisory_id, str) and advisory_id.strip():
        payload = _cached_advisory(advisory_id.strip())
        summary = str(payload.get("summary") or "").strip()
        details = str(payload.get("details") or "").strip()
        full_text = "\n\n".join(part for part in (summary, details) if part)
        return advisory_id.strip(), summary, details, full_text, "advisory text"
    text = str(investigation.get("query_text") or "").strip()
    summary = text.split("\n", 1)[0][:EXCERPT_LIMIT]
    return "Pasted advisory", summary, text, text, "pasted advisory"


def _cached_advisory(advisory_id: str) -> dict[str, object]:
    path = advisory_cache_dir() / f"{advisory_id}.json"
    if not path.is_file():
        return {}
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        return {}
    return payload
