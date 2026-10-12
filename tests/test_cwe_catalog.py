"""The committed CWE catalog matches the local dictionary and relations files."""

from __future__ import annotations

import hashlib
import json
import os
import socket
import subprocess
import sys
import urllib.request
import zipfile
from pathlib import Path

import pytest

from astrolabe.cwe import base_variant_children, cwe_abstraction, cwe_name
from astrolabe.cwe_catalog import (
    catalog_entry,
    catalog_from_text,
    cwe_title,
    load_cwe_catalog,
    truncate_description,
)

REPO = Path(__file__).resolve().parents[1]


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_catalog_matches_cwe_name_abstraction_and_children() -> None:
    catalog = load_cwe_catalog()
    assert catalog is not None
    assert catalog["version"] == "4.20"
    assert catalog["release_date"] == "2026-04-30"
    assert catalog["entry_count"] == 969
    inputs = catalog["inputs"]
    assert isinstance(inputs, dict)
    assert inputs["cwe-dictionary.json"] == _sha256(REPO / "src" / "astrolabe" / "data" / "cwe" / "cwe-dictionary.json")
    assert inputs["cwe-relations.json"] == _sha256(REPO / "src" / "astrolabe" / "data" / "cwe" / "cwe-relations.json")
    entries = catalog["entries"]
    assert isinstance(entries, dict)
    assert len(entries) == 969
    for cwe_id, entry in entries.items():
        assert isinstance(entry, dict)
        assert entry["name"] == cwe_name(cwe_id)
        assert entry["abstraction"] == cwe_abstraction(cwe_id)
        assert entry["children"] == base_variant_children(cwe_id)


def test_catalog_parents_for_cwe_327_and_cwe_20() -> None:
    catalog = load_cwe_catalog()
    assert catalog is not None
    entries = catalog["entries"]
    assert isinstance(entries, dict)
    assert entries["CWE-327"]["parents"] == ["CWE-693"]
    assert entries["CWE-20"]["parents"] == ["CWE-707"]


def test_description_truncates_on_a_word_boundary() -> None:
    entry = catalog_entry("CWE-89")
    assert entry is not None
    full = " ".join(str(entry["description"]).split())
    assert len(full) > 160
    title = cwe_title(entry)
    prefix = f"CWE-89 · {entry['name']} ({entry['abstraction']}). "
    assert title.startswith(prefix)
    description = title[len(prefix) :]
    assert description == truncate_description(full)
    assert description.endswith("…")
    body = description[:-1]
    assert len(body) <= 160
    assert full.startswith(body)
    assert full[len(body)] == " "


def test_unparseable_catalog_text_is_unavailable() -> None:
    assert catalog_from_text("{") is None
    assert catalog_from_text("[]") is None
    assert catalog_from_text('{"entries": {}}') is None


def test_catalog_loader_does_not_open_a_connection(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("network")

    monkeypatch.setattr(socket, "create_connection", fail)
    monkeypatch.setattr(urllib.request, "urlopen", fail)
    load_cwe_catalog.cache_clear()
    loaded = load_cwe_catalog()
    assert loaded is not None
    assert catalog_entry("CWE-327") is not None


def test_catalog_loads_from_a_built_wheel(tmp_path: Path) -> None:
    wheel_dir = tmp_path / "wheels"
    wheel_dir.mkdir()
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "wheel",
            "--no-deps",
            "-w",
            str(wheel_dir),
            str(REPO),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr
    wheels = list(wheel_dir.glob("*.whl"))
    assert len(wheels) == 1
    script = (
        "import astrolabe.cwe_catalog as catalog\n"
        "loaded = catalog.load_cwe_catalog()\n"
        "assert loaded is not None\n"
        "assert loaded['entry_count'] == 969\n"
        "assert loaded['entries']['CWE-327']['parents'] == ['CWE-693']\n"
    )
    env = os.environ.copy()
    env["PYTHONPATH"] = str(wheels[0])
    imported = subprocess.run(
        [sys.executable, "-c", script],
        check=False,
        capture_output=True,
        text=True,
        cwd=tmp_path,
        env=env,
    )
    assert imported.returncode == 0, imported.stderr
    with zipfile.ZipFile(wheels[0]) as bundle:
        names = bundle.namelist()
        notice = next(name for name in names if name.endswith("CWE_NOTICE.txt"))
        third_party = next(name for name in names if name.endswith("THIRD_PARTY_NOTICES.md"))
        assert bundle.read(notice) == (REPO / "src" / "astrolabe" / "data" / "cwe" / "CWE_NOTICE.txt").read_bytes()
        assert bundle.read(third_party) == (REPO / "THIRD_PARTY_NOTICES.md").read_bytes()
