"""Public docs match the product: links, flags, environment variables, and the benchmark sentence."""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PUBLIC = [ROOT / "README.md", *sorted((ROOT / "docs").glob("*.md"))]
PUBLIC = [path for path in PUBLIC if path.name != "HANDOFF.md"]
PREFIXES = ("ANTARES_", "ASTROLABE_", "HF_", "GITHUB_TOKEN", "TRANSFORMERS_", "XDG_")
FORBIDDEN = ("File F1", "0.576", "74 of 102", "pyjwt")
BENCHMARK = (
    "In our testing on 34 published vulnerabilities, advisory-guided investigation "
    "identified the affected file in roughly 7 of 10 runs, compared with about 1 in 4 "
    "without an advisory. Results on this codebase may differ."
)
PRODUCT_ROOTS = (
    ROOT / "src" / "astrolabe",
    ROOT / "services" / "antares-server" / "antares_server",
    ROOT / "scripts",
    ROOT / "container",
)
ENV_CALL = re.compile(r"""os\.environ(?:\.get)?\(\s*["']([A-Z][A-Z0-9_]+)["']""")
QUOTED = re.compile(r"""["']((?:ANTARES|ASTROLABE|HF|TRANSFORMERS|XDG)_[A-Z0-9_]+|GITHUB_TOKEN)["']""")
SHELL_VAR = re.compile(r"""\$\{?((?:ANTARES|ASTROLABE|HF|TRANSFORMERS|XDG)_[A-Z0-9_]+|GITHUB_TOKEN)\}?""")
DICT_KEY = re.compile(
    r"""["']((?:ANTARES|ASTROLABE|HF|TRANSFORMERS|XDG)_[A-Z0-9_]+|GITHUB_TOKEN|HOME|PYTHONDONTWRITEBYTECODE)["']\s*:"""
)
LINK = re.compile(r"""\[[^\]]+\]\(([^)]+)\)""")
FLAG = re.compile(r"(?<![\w-])--[a-z0-9][a-z0-9-]*")


def _product_files() -> list[Path]:
    found: list[Path] = []
    for root in PRODUCT_ROOTS:
        for path in root.rglob("*"):
            if path.is_file() and path.suffix in {".py", ".sh"}:
                found.append(path)
    return found


def _env_names() -> set[str]:
    names: set[str] = set()
    for path in _product_files():
        text = path.read_text(encoding="utf-8")
        for pattern in (ENV_CALL, QUOTED, SHELL_VAR, DICT_KEY):
            names.update(pattern.findall(text))
        if path.suffix == ".py":
            tree = ast.parse(text)
            for node in ast.walk(tree):
                if not isinstance(node, ast.Assign):
                    continue
                if not any(isinstance(target, ast.Name) and target.id.endswith("_VARIABLES") for target in node.targets):
                    continue
                if isinstance(node.value, (ast.Tuple, ast.List)):
                    for item in node.value.elts:
                        if isinstance(item, ast.Constant) and isinstance(item.value, str):
                            names.add(item.value)
    return {name for name in names if name.startswith(PREFIXES) or name in {"HOME", "PYTHONDONTWRITEBYTECODE"}}


def _documented_env() -> str:
    return (ROOT / "docs" / "configuration.md").read_text(encoding="utf-8")


def _cli_flags() -> set[str]:
    flags = {
        "--version",
        "-V",
        "--model-path",
        "--engagement",
        "--max-tokens",
        "--download-weights",
        "--foreground",
        "--follow",
    }
    for path in (ROOT / "src" / "astrolabe" / "phase2_cli.py", ROOT / "src" / "astrolabe" / "ui.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if not isinstance(func, ast.Attribute) or func.attr != "add_argument":
                continue
            if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                option = node.args[0].value
                if option.startswith("-"):
                    flags.add(option)
    return flags


def test_public_docs_resolve_and_omit_internal_metrics() -> None:
    for path in PUBLIC:
        text = path.read_text(encoding="utf-8")
        for phrase in FORBIDDEN:
            assert phrase not in text, f"{path.name} contains {phrase}"
        for match in LINK.finditer(text):
            target = match.group(1).split()[0]
            if target.startswith(("http://", "https://", "mailto:")):
                continue
            target = target.split("#", 1)[0]
            if not target:
                continue
            resolved = (path.parent / target).resolve()
            assert resolved.is_file(), f"{path.relative_to(ROOT)} links to missing {target}"
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert BENCHMARK in readme
    assert "> **Important**" in readme
    assert "```mermaid" in readme
    assert "not a scanner of record" in readme
    assert "Apache License 2.0" in readme
    assert "TBD pending Cisco OSPO" not in readme


def test_configuration_documents_every_product_environment_variable() -> None:
    documented = _documented_env()
    missing = sorted(name for name in _env_names() if name not in documented)
    assert missing == []


def test_cli_documents_every_flag_diagnostics_and_the_actor_limitation() -> None:
    documented = (ROOT / "docs" / "cli.md").read_text(encoding="utf-8")
    missing = sorted(flag for flag in _cli_flags() if flag not in documented and flag != "-h")
    assert missing == []
    extra = sorted(set(FLAG.findall(documented)) - _cli_flags())
    assert extra == []
    assert "## Diagnostics" in documented
    assert "verify-isolation" in documented
    assert "long-generation" in documented
    assert "not checked against the engagement's consultant list" not in documented
    troubleshooting = (ROOT / "docs" / "troubleshooting.md").read_text(encoding="utf-8")
    assert "is inside the engagements directory" in troubleshooting
    install = (ROOT / "docs" / "install.md").read_text(encoding="utf-8")
    assert "ASTROLABE_ENGAGEMENTS_DIR" in install
    assert "PyPI" in install


def test_packaged_sandbox_matches_the_container_tree() -> None:
    for name in ("Dockerfile", "entrypoint.sh", "long_completion.py", "constraints.txt", "versions.lock"):
        packaged = (ROOT / "src" / "astrolabe" / "sandbox" / name).read_bytes()
        source = (ROOT / "container" / name).read_bytes()
        assert packaged == source


def test_missing_or_empty_cwe_data_raises_and_is_not_cached(monkeypatch: pytest.MonkeyPatch) -> None:
    from astrolabe.cwe import CweDataError, load_cwe_dictionary

    load_cwe_dictionary.cache_clear()

    class Broken:
        def __init__(self, payload: str) -> None:
            self.payload = payload

        def joinpath(self, *_parts: str) -> "Broken":
            return self

        def read_text(self, encoding: str = "utf-8") -> str:
            if self.payload == "missing":
                raise FileNotFoundError(self.payload)
            return self.payload

    try:
        monkeypatch.setattr("astrolabe.cwe.files", lambda _package: Broken("missing"))
        with pytest.raises(CweDataError, match="is missing"):
            load_cwe_dictionary()
        assert load_cwe_dictionary.cache_info().currsize == 0
        monkeypatch.setattr("astrolabe.cwe.files", lambda _package: Broken("{"))
        with pytest.raises(CweDataError, match="could not be parsed"):
            load_cwe_dictionary()
        assert load_cwe_dictionary.cache_info().currsize == 0
        monkeypatch.setattr("astrolabe.cwe.files", lambda _package: Broken("{}"))
        with pytest.raises(CweDataError, match="did not contain any entries"):
            load_cwe_dictionary()
        assert load_cwe_dictionary.cache_info().currsize == 0
    finally:
        load_cwe_dictionary.cache_clear()
