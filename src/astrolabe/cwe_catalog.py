"""Committed CWE catalog. One local read per process. No network."""

from __future__ import annotations

import json
import re
from functools import lru_cache
from importlib.resources import files

PAGE_SIZE = 100
TITLE_LIMIT = 160
QUERY_LIMIT = 100
ABSTRACTIONS = ("Pillar", "Class", "Base", "Variant", "Compound")
VIEWS = ("top25", "owasp")
VIEW_LABELS = {
    "top25": "CWE Top 25 (2025, CWE-1435)",
    "owasp": "OWASP Top Ten 2025 RC1 (CWE-1450)",
}
PARENTS_LABEL = "Parents (Research Concepts, CWE-1000)"
CATALOG_MISSING = "The local CWE catalog is missing or could not be read."
_ID = re.compile(r"^(?:CWE-)?(\d{1,5})$", re.IGNORECASE)


def catalog_from_text(raw: str) -> dict[str, object] | None:
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict):
        return None
    entries = payload.get("entries")
    if not isinstance(entries, dict) or not entries:
        return None
    return payload


@lru_cache(maxsize=1)
def load_cwe_catalog() -> dict[str, object] | None:
    try:
        raw = files("astrolabe").joinpath("data", "cwe-catalog.json").read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return None
    return catalog_from_text(raw)


def catalog_entry(cwe_id: str) -> dict[str, object] | None:
    catalog = load_cwe_catalog()
    if catalog is None:
        return None
    entries = catalog.get("entries")
    if not isinstance(entries, dict):
        return None
    entry = entries.get(cwe_id)
    return entry if isinstance(entry, dict) else None


def canonical_cwe_id(raw: str) -> str | None:
    match = _ID.fullmatch(raw.strip())
    if match is None:
        return None
    number = int(match.group(1))
    if number <= 0:
        return None
    return f"CWE-{number}"


def truncate_description(text: str, limit: int = TITLE_LIMIT) -> str:
    collapsed = " ".join(str(text).split())
    if len(collapsed) <= limit:
        return collapsed
    if collapsed[limit] == " ":
        return collapsed[:limit] + "…"
    if " " in collapsed[:limit]:
        return collapsed[:limit].rsplit(" ", 1)[0] + "…"
    return collapsed[:limit] + "…"


def cwe_title(entry: dict[str, object]) -> str:
    description = truncate_description(str(entry.get("description") or ""))
    return (
        f"{entry.get('id')} · {entry.get('name') or ''} "
        f"({entry.get('abstraction') or ''}). {description}"
    )


def filter_entries(query: str = "", abstraction: str = "", view: str = "") -> list[dict[str, object]]:
    catalog = load_cwe_catalog()
    if catalog is None:
        return []
    entries = catalog.get("entries")
    if not isinstance(entries, dict):
        return []
    rows = [item for item in entries.values() if isinstance(item, dict)]
    text = query.strip()[:QUERY_LIMIT]
    if text:
        lowered = text.lower()
        normalized = canonical_cwe_id(text)
        words = [word for word in lowered.split() if word]

        def matches(entry: dict[str, object]) -> bool:
            if normalized and str(entry.get("id") or "").upper() == normalized:
                return True
            name = str(entry.get("name") or "").lower()
            return bool(words) and all(word in name for word in words)

        rows = [entry for entry in rows if matches(entry)]
    if abstraction in ABSTRACTIONS:
        rows = [entry for entry in rows if entry.get("abstraction") == abstraction]
    if view in VIEWS:
        rows = [entry for entry in rows if view in (entry.get("views") or [])]
    return rows


def clamp_page(raw: str, total_pages: int) -> int:
    if not raw.isdigit():
        return 1
    number = int(raw)
    if number < 1:
        return 1
    if number > total_pages:
        return total_pages
    return number
