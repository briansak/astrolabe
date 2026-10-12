"""Line numbers from one named trace, and the snapshot lines those numbers refer to.

A tool result's matched text is discarded here. Review shows text only after
reading that line back from the snapshot.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from astrolabe.advisory_review import normalize_repo_path
from astrolabe.redact import redact_text

MAX_HITS = 5
MAX_LABEL = 120
MAX_SNAPSHOT_BYTES = 1024 * 1024
_BINARY_PROBE = 8192
_SEARCH_TOOLS = {"rg", "grep"}
_LINE_HIT = re.compile(r"^(.+?):(\d+):")


def same_repo_path(left: str, right: str, stripped_prefix: str | None = None) -> bool:
    """Whole path components, after the advisory matcher's prefix and ./ rules."""
    first = normalize_repo_path(left, stripped_prefix)
    second = normalize_repo_path(right, stripped_prefix)
    if not first or not second:
        return False
    return first.split("/") == second.split("/")


def line_hits(
    events: list[dict[str, object]],
    file_path: str,
    stripped_prefix: str | None = None,
) -> list[int]:
    """Up to five line numbers from rg or grep results that name this file."""
    pending = False
    found: list[int] = []
    seen: set[int] = set()
    for event in events:
        if not isinstance(event, dict):
            continue
        phase = str(event.get("phase") or "")
        payload = event.get("payload") if isinstance(event.get("payload"), dict) else {}
        if phase == "tool_call":
            pending = _is_search(payload)
            continue
        if phase != "tool_result" or not pending:
            continue
        pending = False
        summary = payload.get("result_summary")
        if not isinstance(summary, str):
            continue
        for raw in summary.splitlines():
            match = _LINE_HIT.match(raw)
            if match is None or not same_repo_path(match.group(1), file_path, stripped_prefix):
                continue
            number = int(match.group(2))
            if number < 1 or number in seen:
                continue
            seen.add(number)
            found.append(number)
            if len(found) >= MAX_HITS:
                return found
    return found


def model_title(
    events: list[dict[str, object]],
    file_path: str,
    stripped_prefix: str | None = None,
) -> str:
    """Redacted title from a matching finding event, at most 120 characters."""
    for event in events:
        if not isinstance(event, dict) or str(event.get("phase") or "") != "finding":
            continue
        payload = event.get("payload") if isinstance(event.get("payload"), dict) else {}
        path = payload.get("file_path")
        title = payload.get("title")
        if not isinstance(path, str) or not isinstance(title, str):
            continue
        if not same_repo_path(path, file_path, stripped_prefix):
            continue
        text = redact_text(title.strip())
        if text:
            return text[:MAX_LABEL]
    return ""


def resolve_inside(root: Path, relative: str) -> Path | None:
    """A path that stays inside root after resolution. Absolute paths and escapes are refused."""
    return _resolve_inside(root, relative)


def resolve_trace(traces_dir: Path, name: str) -> Path | None:
    """A trace file inside traces_dir. Anything that resolves outside is refused."""
    path = _resolve_inside(traces_dir, name)
    if path is None or not path.is_file():
        return None
    return path


def read_snapshot_lines(snapshot_root: Path, relative: str, numbers: list[int]) -> dict[int, str] | None:
    """Requested lines, or None when the file is outside, too large, or binary.

    Decoding uses errors="replace". Reading stops once every requested line
    has been seen.
    """
    path = _resolve_inside(snapshot_root, relative)
    if path is None or not path.is_file():
        return None
    try:
        if path.stat().st_size > MAX_SNAPSHOT_BYTES:
            return None
        with path.open("rb") as handle:
            if b"\0" in handle.read(_BINARY_PROBE):
                return None
    except OSError:
        return None
    wanted = {number for number in numbers if isinstance(number, int) and not isinstance(number, bool) and number >= 1}
    if not wanted:
        return {}
    found: dict[int, str] = {}
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for number, line in enumerate(handle, start=1):
                if number not in wanted:
                    continue
                found[number] = line.rstrip("\n\r")
                if len(found) == len(wanted):
                    break
    except OSError:
        return None
    return found


def trace_export_document(
    events: list[dict[str, object]],
    *,
    source_sha256: str,
    source_lines: int,
) -> str:
    """A one-line export header, then the redacted events."""
    body = "".join(json.dumps(event, ensure_ascii=False) + "\n" for event in events)
    header = {
        "astrolabe_trace_export": 1,
        "source_sha256": source_sha256,
        "source_lines": source_lines,
        "redacted": True,
        "body_sha256": hashlib.sha256(body.encode("utf-8")).hexdigest(),
    }
    return json.dumps(header, ensure_ascii=False) + "\n" + body


def _resolve_inside(root: Path, relative: str) -> Path | None:
    if not isinstance(relative, str) or not relative or "\x00" in relative:
        return None
    if Path(relative).is_absolute():
        return None
    try:
        base = root.resolve()
        candidate = (base / relative).resolve()
    except OSError:
        return None
    try:
        candidate.relative_to(base)
    except ValueError:
        return None
    return candidate


def _is_search(payload: dict[str, object]) -> bool:
    tool = Path(str(payload.get("tool_name") or "")).name
    if tool in _SEARCH_TOOLS:
        return True
    arguments = payload.get("arguments") if isinstance(payload.get("arguments"), dict) else {}
    command = arguments.get("command")
    if isinstance(command, list) and command:
        command = command[0]
    if not isinstance(command, str) or not command.strip():
        return False
    return Path(command.strip().split(None, 1)[0]).name in _SEARCH_TOOLS
