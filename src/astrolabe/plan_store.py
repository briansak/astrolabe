"""Stored plans for one engagement. The file lives in the engagement directory."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from astrolabe.engagement import _engagement_lock, _write_json

PLAN_FILE = "plans.json"
PASTED_FILE = "pasted-advisory.json"


def plan_path(directory: Path) -> Path:
    return directory / PLAN_FILE


def load_plan(directory: Path, picker: str) -> dict[str, object] | None:
    """Return one stored plan. A missing file or picker is absent, not an error."""
    payload = _read_plans(directory)
    item = payload.get(picker)
    if not isinstance(item, dict):
        return None
    return item


def save_plan(directory: Path, picker: str, payload: dict[str, object]) -> None:
    """Replace one picker under the engagement lock. Other pickers stay."""
    path = plan_path(directory)
    with _engagement_lock(directory):
        current = _read_plans(directory)
        current[picker] = payload
        _write_json(path, current)


def clear_plans(directory: Path) -> None:
    """Remove every stored plan and the pasted advisory body. Purge removes the directory itself."""
    path = plan_path(directory)
    pasted = directory / PASTED_FILE
    with _engagement_lock(directory):
        if path.is_file():
            path.unlink()
        if pasted.is_file():
            pasted.unlink()


def save_pasted_advisory(directory: Path, text: str) -> str:
    """Store pasted advisory text for the plan form. plans.json keeps the hash."""
    digest = pasted_advisory_digest(text)
    with _engagement_lock(directory):
        _write_json(directory / PASTED_FILE, {"text": text})
    return digest


def load_pasted_advisory(directory: Path, digest: str) -> str:
    """Return the pasted body when its hash matches. A mismatch is absent."""
    if not digest:
        return ""
    path = directory / PASTED_FILE
    if not path.is_file():
        return ""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return ""
    if not isinstance(payload, dict):
        return ""
    text = payload.get("text")
    if not isinstance(text, str) or pasted_advisory_digest(text) != digest:
        return ""
    return text


def clear_pasted_advisory(directory: Path) -> None:
    path = directory / PASTED_FILE
    with _engagement_lock(directory):
        if path.is_file():
            path.unlink()


def pasted_advisory_digest(text: str) -> str:
    """SHA-256 of the pasted advisory text. This is a content hash, not a secret."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _read_plans(directory: Path) -> dict[str, object]:
    path = plan_path(directory)
    if not path.is_file():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return {}
    if not isinstance(payload, dict):
        return {}
    return payload
