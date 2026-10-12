"""Bundled CWE names and potential mitigations. Lookup is a local file read."""

from __future__ import annotations

import json
from functools import lru_cache
from importlib.resources import files

_BROAD = {"Class", "Pillar"}
SEARCH_LIMIT = 40


class CweDataError(RuntimeError):
    """Bundled CWE data is missing or cannot be parsed."""


def _read_cwe_object(name: str) -> dict[str, dict[str, object]]:
    try:
        raw = files("astrolabe").joinpath("data", "cwe", name).read_text(encoding="utf-8")
    except (FileNotFoundError, OSError, ModuleNotFoundError) as exc:
        raise CweDataError(f"CWE data file {name} is missing from the astrolabe package.") from exc
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise CweDataError(f"CWE data file {name} could not be parsed.") from exc
    if not isinstance(payload, dict):
        raise CweDataError(f"CWE data file {name} is not a JSON object.")
    loaded = {str(key): value for key, value in payload.items() if isinstance(value, dict)}
    if not loaded:
        raise CweDataError(f"CWE data file {name} did not contain any entries.")
    return loaded


@lru_cache(maxsize=1)
def load_cwe_dictionary() -> dict[str, dict[str, object]]:
    return _read_cwe_object("cwe-dictionary.json")


NO_MITIGATION = "No MITRE mitigation available for this weakness"


def _mitigation_texts(entry: object) -> list[str]:
    if not isinstance(entry, dict):
        return []
    values = entry.get("potential_mitigations")
    if not isinstance(values, list):
        return []
    return [str(item).strip() for item in values if str(item).strip()]


def mitigations_for(cwe: str) -> list[str]:
    return _mitigation_texts(load_cwe_dictionary().get(cwe.strip().upper()))


def displayed_mitigations(cwe: str) -> list[str]:
    found = mitigations_for(cwe)
    return found if found else [NO_MITIGATION]


def cwes_without_mitigations() -> list[str]:
    missing: list[str] = []
    for key in sorted(load_cwe_dictionary()):
        if not _mitigation_texts(load_cwe_dictionary().get(key)):
            missing.append(key)
    return missing


def cwe_name(cwe: str) -> str:
    entry = load_cwe_dictionary().get(cwe.strip().upper())
    if not isinstance(entry, dict):
        return ""
    return str(entry.get("name") or "")


@lru_cache(maxsize=1)
def load_cwe_relations() -> dict[str, dict[str, object]]:
    return _read_cwe_object("cwe-relations.json")


def cwe_abstraction(cwe: str) -> str:
    entry = load_cwe_relations().get(cwe.strip().upper())
    if not isinstance(entry, dict):
        return ""
    return str(entry.get("abstraction") or "")


def is_broad_cwe(cwe: str) -> bool:
    return cwe_abstraction(cwe) in _BROAD


def base_variant_children(cwe: str) -> list[str]:
    entry = load_cwe_relations().get(cwe.strip().upper())
    if not isinstance(entry, dict):
        return []
    children = entry.get("children")
    if not isinstance(children, list):
        return []
    return [str(item) for item in children if str(item).strip()]


def search_cwes(query: str, *, limit: int = SEARCH_LIMIT) -> list[dict[str, str]]:
    text = query.strip().lower()
    if not text:
        return []
    relations = load_cwe_relations()
    found: list[dict[str, str]] = []
    for cwe_id, entry in load_cwe_dictionary().items():
        name = str(entry.get("name") or "")
        relation = relations.get(cwe_id) if isinstance(relations.get(cwe_id), dict) else {}
        description = str(relation.get("description") or "") if isinstance(relation, dict) else ""
        if text not in " ".join((cwe_id.lower(), name.lower(), description.lower())):
            continue
        found.append({"id": cwe_id, "name": name, "abstraction": cwe_abstraction(cwe_id)})
    found.sort(key=lambda item: item["id"])
    return found[:limit]
