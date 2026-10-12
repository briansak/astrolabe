"""Candidate files and consultant verdicts.

The model can only introduce a candidate. A verdict is a consultant action and
is kept when the same engagement, file, and CWE appear on a later run.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from astrolabe.advisory_review import advisory_contexts, dismissal_errors
from astrolabe.engagement import (
    EngagementError,
    append_durable_audit,
    engagement_dir,
    load_engagement,
    utc_now,
)

VERDICT_STATES = ("candidate", "confirmed", "not_actionable", "needs_more_info")


class VerdictError(EngagementError):
    """A verdict form was refused. The posted state and note stay on the card."""

    def __init__(
        self,
        errors: dict[str, str],
        *,
        path: str,
        cwe: str,
        state: str,
        note: str,
        confirmed: bool,
    ) -> None:
        self.errors = errors
        self.path = path
        self.cwe = cwe
        self.state = state
        self.note = note
        self.confirmed = confirmed
        super().__init__("; ".join(errors.values()))


def fingerprint(engagement_id: str, file_path: str, cwe: str) -> str:
    normalized = file_path.lstrip("./")
    raw = f"{engagement_id}\0{normalized}\0{cwe}".encode()
    return hashlib.sha256(raw).hexdigest()


def observe_candidates(
    root: Path,
    engagement_id: str,
    *,
    file_paths: list[str],
    cwe: str,
    investigation_id: str,
    run: int,
) -> list[dict[str, object]]:
    directory = engagement_dir(root, engagement_id)
    store = _load(directory)
    observed: list[dict[str, object]] = []
    for file_path in file_paths:
        normalized = file_path.lstrip("./")
        if not normalized or normalized.startswith("/") or ".." in Path(normalized).parts:
            continue
        key = fingerprint(engagement_id, normalized, cwe)
        marker = f"{investigation_id}:{run}"
        existing = store.get(key)
        if existing is None:
            existing = {
                "fingerprint": key,
                "engagement_id": engagement_id,
                "file_path": normalized,
                "cwe": cwe,
                "state": "candidate",
                "actor": None,
                "note": None,
                "updated_at": utc_now(),
                "runs": [marker],
            }
            store[key] = existing
        elif marker not in existing["runs"]:
            existing["runs"].append(marker)
        observed.append(existing)
    _save(directory, store)
    return observed


def set_verdict(
    root: Path,
    engagement_id: str,
    *,
    file_path: str,
    cwe: str,
    state: str,
    actor: str,
    note: str,
    confirmed: bool = False,
) -> dict[str, object]:
    if state not in VERDICT_STATES:
        raise EngagementError(f"Verdict must be one of: {', '.join(VERDICT_STATES)}")
    if not actor.strip():
        raise EngagementError("A verdict requires a consultant and a note")
    record = load_engagement(root, engagement_id)
    snapshot = record.get("snapshot_sha256")
    if not isinstance(snapshot, str) or len(snapshot) != 64:
        raise EngagementError("A verdict requires the engagement snapshot content hash")
    directory = engagement_dir(root, engagement_id)
    from astrolabe.reports import assessment_freeze_message

    frozen = assessment_freeze_message(directory, verdict=True)
    if frozen:
        raise EngagementError(frozen)
    store = _load(directory)
    key = fingerprint(engagement_id, file_path, cwe)
    current = store.get(key)
    if current is None:
        raise EngagementError("No candidate for that engagement, file, and CWE")
    errors = dismissal_errors(
        root,
        engagement_id,
        current,
        state=state,
        note=note,
        confirmed=confirmed,
    )
    if not note.strip() and "note" not in errors:
        errors["note"] = "A verdict requires a consultant and a note"
    if errors:
        raise VerdictError(
            errors,
            path=str(current["file_path"]),
            cwe=str(current["cwe"]),
            state=state,
            note=note,
            confirmed=confirmed,
        )
    previous = current["state"]
    current["state"] = state
    current["actor"] = actor.strip()
    current["note"] = note.strip()
    current["snapshot_sha256"] = snapshot
    current["stale"] = False
    current["updated_at"] = utc_now()
    _save(directory, store)
    event: dict[str, object] = {
        "action": "verdict",
        "actor": actor.strip(),
        "fingerprint": key,
        "file_path": current["file_path"],
        "cwe": cwe,
        "from_state": previous,
        "to_state": state,
        "note": note.strip(),
        "snapshot_sha256": snapshot,
    }
    if (
        state == "not_actionable"
        and confirmed
        and advisory_contexts(root, engagement_id, current)
    ):
        event["confirmed"] = True
    append_durable_audit(root, engagement_id, event)
    return current


def presentation_state(candidate: dict[str, object]) -> str:
    """State a later assessment report may show. A stale verdict is never confirmed."""
    if candidate.get("stale"):
        return "stale"
    return str(candidate.get("state"))


def confirmed_for_report(candidate: dict[str, object]) -> bool:
    return presentation_state(candidate) == "confirmed"


def present_candidate(candidate: dict[str, object], current_snapshot: object) -> dict[str, object]:
    presented = dict(candidate)
    bound = presented.get("snapshot_sha256")
    stale = isinstance(bound, str) and isinstance(current_snapshot, str) and bound != current_snapshot
    presented["stale"] = stale
    presented["presentation_state"] = "stale" if stale else presented.get("state")
    return presented


def list_candidates(root: Path, engagement_id: str) -> list[dict[str, object]]:
    directory = engagement_dir(root, engagement_id)
    current = load_engagement(root, engagement_id).get("snapshot_sha256")
    return [present_candidate(item, current) for item in _load(directory).values()]


def _load(directory: Path) -> dict[str, dict[str, object]]:
    path = directory / "candidates.json"
    if not path.is_file():
        return {}
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise EngagementError("Candidate store is not an object")
    return payload


def _save(directory: Path, store: dict[str, dict[str, object]]) -> None:
    path = directory / "candidates.json"
    temporary = path.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(store, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)
