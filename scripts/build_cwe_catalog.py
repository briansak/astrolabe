"""Write astrolabe/data/cwe-catalog.json from the committed CWE files and a local CLI database.

The vendor database is read only while this script runs. It is not imported at request time
and it is not written into the catalog output. SHA-256 values below are content hashes of
those input files.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
TOP25_VIEW = "CWE-1435"
OWASP_VIEW = "CWE-1450"
RESEARCH_VIEW = "CWE-1000"
EXPECTED_COUNT = 969
EXPECTED_VERSION = "4.20"
EXPECTED_RELEASE = "2026-04-30"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    digest.update(path.read_bytes())
    return digest.hexdigest()


def _load_object(path: Path) -> dict[str, object]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise SystemExit(f"{path} is not a JSON object")
    return payload


def _parents(entry: dict[str, object]) -> list[str]:
    related = entry.get("related_weaknesses")
    if not isinstance(related, list):
        return []
    found: list[str] = []
    for item in related:
        if not isinstance(item, dict):
            continue
        if item.get("nature") != "ChildOf" or item.get("view_id") != RESEARCH_VIEW:
            continue
        parent = str(item.get("cwe_id") or "")
        if parent and parent not in found:
            found.append(parent)
    return sorted(found)


def _views(entry: dict[str, object]) -> list[str]:
    raw = entry.get("view_ids")
    view_ids = {str(item) for item in raw} if isinstance(raw, list) else set()
    views: list[str] = []
    if TOP25_VIEW in view_ids:
        views.append("top25")
    if OWASP_VIEW in view_ids:
        views.append("owasp")
    return views


def build(dictionary_path: Path, relations_path: Path, database_path: Path, metadata_path: Path) -> dict[str, object]:
    dictionary = _load_object(dictionary_path)
    relations = _load_object(relations_path)
    database = json.loads(database_path.read_text(encoding="utf-8"))
    metadata = _load_object(metadata_path)
    if not isinstance(database, list):
        raise SystemExit(f"{database_path} is not a JSON list")
    if str(metadata.get("version") or "") != EXPECTED_VERSION:
        raise SystemExit(f"metadata version is {metadata.get('version')!r}, expected {EXPECTED_VERSION}")
    if str(metadata.get("release_date") or "") != EXPECTED_RELEASE:
        raise SystemExit(f"metadata release_date is {metadata.get('release_date')!r}, expected {EXPECTED_RELEASE}")
    if len(database) != EXPECTED_COUNT or len(dictionary) != EXPECTED_COUNT or len(relations) != EXPECTED_COUNT:
        raise SystemExit(
            f"expected {EXPECTED_COUNT} entries, found dictionary {len(dictionary)}, "
            f"relations {len(relations)}, database {len(database)}"
        )
    by_id: dict[str, dict[str, object]] = {}
    for item in database:
        if not isinstance(item, dict) or not item.get("id"):
            raise SystemExit("database entry is missing id")
        by_id[str(item["id"])] = item
    if set(by_id) != set(dictionary) or set(by_id) != set(relations):
        raise SystemExit("dictionary, relations, and database ids differ")
    entries: dict[str, dict[str, object]] = {}
    for cwe_id in sorted(by_id):
        source = by_id[cwe_id]
        name_entry = dictionary[cwe_id]
        relation = relations[cwe_id]
        if not isinstance(name_entry, dict) or not isinstance(relation, dict):
            raise SystemExit(f"{cwe_id} is not an object in the committed files")
        name = str(name_entry.get("name") or "")
        description = str(relation.get("description") or "")
        if name != str(source.get("name") or ""):
            raise SystemExit(f"{cwe_id} name differs from cwe-dictionary.json")
        if description != str(source.get("description") or ""):
            raise SystemExit(f"{cwe_id} short description differs from cwe-relations.json")
        children = relation.get("children")
        entries[cwe_id] = {
            "abstraction": str(relation.get("abstraction") or ""),
            "children": [str(item) for item in children] if isinstance(children, list) else [],
            "description": description,
            "id": cwe_id,
            "name": name,
            "parents": _parents(source),
            "views": _views(source),
        }
    if len(entries) != EXPECTED_COUNT:
        raise SystemExit(f"catalog has {len(entries)} entries, expected {EXPECTED_COUNT}")
    return {
        "entries": entries,
        "entry_count": EXPECTED_COUNT,
        "inputs": {
            dictionary_path.name: _sha256(dictionary_path),
            relations_path.name: _sha256(relations_path),
            database_path.name: _sha256(database_path),
            metadata_path.name: _sha256(metadata_path),
        },
        "release_date": EXPECTED_RELEASE,
        "version": EXPECTED_VERSION,
    }


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Build the committed CWE catalog.")
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--metadata", type=Path, required=True)
    parser.add_argument("--dictionary", type=Path, default=REPO / "src" / "astrolabe" / "data" / "cwe" / "cwe-dictionary.json")
    parser.add_argument("--relations", type=Path, default=REPO / "src" / "astrolabe" / "data" / "cwe" / "cwe-relations.json")
    parser.add_argument("--output", type=Path, default=REPO / "src" / "astrolabe" / "data" / "cwe-catalog.json")
    args = parser.parse_args(argv)
    catalog = build(args.dictionary, args.relations, args.database, args.metadata)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(catalog, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    args.output.write_text(text, encoding="utf-8")


if __name__ == "__main__":
    try:
        main()
    except BrokenPipeError:
        sys.exit(0)
