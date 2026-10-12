import json
import os
from pathlib import Path

from astrolabe.snapshot import is_git_metadata, materialize_snapshot


def _link_outside(entry: Path, source: Path) -> bool:
    if entry.is_symlink():
        return True
    try:
        stat = entry.stat()
    except OSError:
        return True
    if stat.st_nlink <= 1:
        return False
    inside = 0
    for path in source.rglob("*"):
        if path.is_symlink():
            continue
        try:
            other = path.stat()
        except OSError:
            continue
        if other.st_dev == stat.st_dev and other.st_ino == stat.st_ino:
            inside += 1
    return inside < stat.st_nlink


def test_drops_escaping_symlink_external_hardlink_and_git(tmp_path: Path) -> None:
    source = tmp_path / "repo"
    outside = tmp_path / "outside"
    source.mkdir()
    outside.mkdir()
    (source / "keep.py").write_text("print(1)\n", encoding="utf-8")
    (outside / "secret.txt").write_text("secret\n", encoding="utf-8")
    (source / "escape").symlink_to(outside / "secret.txt")
    (source / "inside.txt").write_text("inside\n", encoding="utf-8")
    (source / "alias.txt").hardlink_to(source / "inside.txt")
    (source / "shared.txt").hardlink_to(outside / "secret.txt")
    (source / ".git").mkdir()
    (source / ".git" / "config").write_text("git\n", encoding="utf-8")
    (source / "nested").mkdir()
    (source / "nested" / ".git").write_text("gitfile\n", encoding="utf-8")

    dest = tmp_path / "snap"
    materialize_snapshot(source, dest)

    assert (dest / "keep.py").read_text(encoding="utf-8") == "print(1)\n"
    assert not (dest / "escape").exists()
    assert not (dest / "shared.txt").exists()
    assert (dest / "alias.txt").read_text(encoding="utf-8") == "inside\n"
    assert not (dest / ".git").exists()
    assert not (dest / "nested" / ".git").exists()
    for path in dest.rglob("*"):
        assert not path.is_symlink()
        if path.is_file():
            assert not _link_outside(path, dest)


def test_test_paths_excluded_unless_opt_in(tmp_path: Path) -> None:
    source = tmp_path / "repo"
    (source / "tests").mkdir(parents=True)
    (source / "tests" / "test_app.py").write_text("x\n", encoding="utf-8")
    (source / "app.py").write_text("y\n", encoding="utf-8")
    (source / "test_helper.py").write_text("z\n", encoding="utf-8")

    excluded = tmp_path / "excluded"
    materialize_snapshot(source, excluded, include_test_paths=False)
    assert (excluded / "app.py").is_file()
    assert not (excluded / "tests").exists()
    assert not (excluded / "test_helper.py").exists()

    included = tmp_path / "included"
    materialize_snapshot(source, included, include_test_paths=True)
    assert (included / "tests" / "test_app.py").is_file()
    assert (included / "test_helper.py").is_file()


def test_git_file_is_metadata() -> None:
    assert is_git_metadata(".git")
    assert is_git_metadata("nested/.git")
    assert not is_git_metadata("gitignore")


def test_exclusions_file_is_json() -> None:
    path = Path(__file__).resolve().parents[1] / "src" / "astrolabe" / "data" / "test-path-exclusions.json"
    rules = json.loads(path.read_text(encoding="utf-8"))
    assert rules["enabled"] is True
    assert "tests" in rules["directory_segments"]
    assert os.access(path, os.R_OK)
