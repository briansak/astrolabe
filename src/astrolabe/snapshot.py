"""Host snapshot for a customer checkout.

Shift-Left discards every symlink (so none can leave the tree), omits hardlinks
whose inode also lives outside the checkout, and drops .git files and directories.
Test paths are excluded unless a run opts in.
"""

from __future__ import annotations

import fnmatch
import json
import os
import shutil
import tempfile
from importlib.resources import files
from pathlib import Path

_EXCLUSIONS_NAME = "test-path-exclusions.json"
DEFAULT_MAX_BYTES = 2 * 1024 * 1024 * 1024
DEFAULT_MAX_FILES = 100_000
GUIDANCE_BYTES = 10 * 1024 * 1024


def load_test_exclusions() -> dict:
    try:
        raw = files("astrolabe").joinpath("data", _EXCLUSIONS_NAME).read_text(encoding="utf-8")
    except (FileNotFoundError, OSError):
        return {"enabled": False}
    return json.loads(raw)


def is_excluded_test_path(rel_path: str, exclusions: dict | None = None) -> bool:
    rules = exclusions if exclusions is not None else load_test_exclusions()
    if not rules.get("enabled", True):
        return False
    normalized = rel_path.replace("\\", "/").lstrip("./")
    parts = Path(normalized).parts
    excluded_dirs = {str(segment) for segment in rules.get("directory_segments", [])}
    if excluded_dirs.intersection(parts):
        return True
    name = Path(normalized).name
    if name in {str(value) for value in rules.get("file_names", [])}:
        return True
    for pattern in rules.get("file_globs", []):
        if fnmatch.fnmatch(name, str(pattern)):
            return True
    return False


def is_git_metadata(rel_posix: str) -> bool:
    normalized = rel_posix.strip().replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    return normalized == ".git" or normalized.startswith(".git/") or "/.git/" in f"/{normalized}/"


def materialize_snapshot(
    source: Path,
    dest_root: Path,
    *,
    include_test_paths: bool = False,
    max_bytes: int = DEFAULT_MAX_BYTES,
) -> Path:
    """Copy ``source`` into ``dest_root``. ``dest_root`` is created and must not already exist."""
    source_root = source.resolve()
    if not source_root.is_dir():
        raise FileNotFoundError(f"Snapshot source is not a directory: {source_root}")
    if dest_root.exists():
        raise FileExistsError(f"Snapshot destination already exists: {dest_root}")
    dest_root.mkdir(parents=True)
    total = 0
    copied_files = 0
    exclusions = load_test_exclusions()

    for dirpath, dirnames, filenames in os.walk(source_root, topdown=True, followlinks=False):
        current = Path(dirpath)
        try:
            rel_dir = current.relative_to(source_root)
        except ValueError:
            continue
        kept_dirs: list[str] = []
        for name in dirnames:
            entry = current / name
            rel_posix = _relative_posix(rel_dir, name)
            if entry.is_symlink() or not entry.is_dir():
                continue
            if _resolved_inside(entry, source_root) is None:
                continue
            if is_git_metadata(rel_posix):
                continue
            if not include_test_paths and is_excluded_test_path(rel_posix, exclusions):
                continue
            kept_dirs.append(name)
        dirnames[:] = kept_dirs
        (dest_root / rel_dir).mkdir(parents=True, exist_ok=True)

        for name in filenames:
            rel_posix = _relative_posix(rel_dir, name)
            if is_git_metadata(rel_posix):
                continue
            if not include_test_paths and is_excluded_test_path(rel_posix, exclusions):
                continue
            copied = _copy_regular_file(
                current / name,
                dest_root / rel_dir / name,
                source_root=source_root,
                max_bytes=max_bytes,
                total_bytes=total,
            )
            if copied is None:
                continue
            total = copied
            copied_files += 1
            if copied_files > DEFAULT_MAX_FILES:
                raise ValueError(f"Snapshot exceeds max files ({DEFAULT_MAX_FILES})")
    return dest_root


def materialize_into_temp(
    source: Path,
    *,
    parent: Path,
    include_test_paths: bool = False,
    max_bytes: int = DEFAULT_MAX_BYTES,
) -> Path:
    parent.mkdir(parents=True, exist_ok=True)
    dest = Path(tempfile.mkdtemp(prefix="snapshot-", dir=parent))
    # mkdtemp creates the directory; materialize_snapshot requires a path that does not exist.
    dest.rmdir()
    return materialize_snapshot(
        source,
        dest,
        include_test_paths=include_test_paths,
        max_bytes=max_bytes,
    )


def _relative_posix(rel_dir: Path, name: str) -> str:
    if rel_dir == Path("."):
        return name
    return f"{rel_dir.as_posix()}/{name}"


def _resolved_inside(entry: Path, source_root: Path) -> Path | None:
    root = source_root.resolve()
    try:
        resolved = entry.resolve()
        resolved.relative_to(root)
    except (ValueError, OSError):
        return None
    return resolved


def _is_external_hardlink(entry: Path, source_root: Path) -> bool:
    try:
        stat = entry.stat(follow_symlinks=False)
    except OSError:
        return True
    if stat.st_nlink <= 1:
        return False
    inside = 0
    for path in source_root.rglob("*"):
        if path.is_symlink():
            continue
        try:
            other = path.stat(follow_symlinks=False)
        except OSError:
            continue
        if other.st_dev == stat.st_dev and other.st_ino == stat.st_ino:
            inside += 1
    return inside < stat.st_nlink


def _copy_regular_file(
    entry: Path,
    dest: Path,
    *,
    source_root: Path,
    max_bytes: int,
    total_bytes: int,
) -> int | None:
    if entry.is_symlink() or not entry.is_file():
        return None
    if _resolved_inside(entry, source_root) is None:
        return None
    if _is_external_hardlink(entry, source_root):
        return None
    try:
        payload = entry.read_bytes()
    except OSError:
        return None
    next_total = total_bytes + len(payload)
    if next_total > max_bytes:
        raise ValueError(f"Snapshot exceeds max bytes ({max_bytes})")
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(payload)
    return next_total


def remove_tree(path: Path) -> None:
    shutil.rmtree(path, ignore_errors=True)


def snapshot_preview(source: Path, *, include_test_paths: bool = False) -> dict[str, object]:
    """Describe what materialize_snapshot would keep, without copying."""
    source_root = source.resolve()
    if not source_root.is_dir():
        raise FileNotFoundError(f"Snapshot source is not a directory: {source_root}")
    exclusions = load_test_exclusions()
    included: list[dict[str, object]] = []
    excluded = {"tests": 0, "git": 0, "symlinks": 0, "external_hardlinks": 0}
    total = 0

    for dirpath, dirnames, filenames in os.walk(source_root, topdown=True, followlinks=False):
        current = Path(dirpath)
        try:
            rel_dir = current.relative_to(source_root)
        except ValueError:
            continue
        kept_dirs: list[str] = []
        for name in dirnames:
            entry = current / name
            rel_posix = _relative_posix(rel_dir, name)
            if entry.is_symlink() or not entry.is_dir():
                excluded["symlinks"] += _count_skipped_files(entry)
                continue
            if _resolved_inside(entry, source_root) is None:
                continue
            if is_git_metadata(rel_posix):
                excluded["git"] += _count_skipped_files(entry)
                continue
            if not include_test_paths and is_excluded_test_path(rel_posix, exclusions):
                excluded["tests"] += _count_skipped_files(entry)
                continue
            kept_dirs.append(name)
        dirnames[:] = kept_dirs

        for name in filenames:
            rel_posix = _relative_posix(rel_dir, name)
            entry = current / name
            if is_git_metadata(rel_posix):
                excluded["git"] += 1
                continue
            if not include_test_paths and is_excluded_test_path(rel_posix, exclusions):
                excluded["tests"] += 1
                continue
            if entry.is_symlink() or not entry.is_file():
                excluded["symlinks"] += 1
                continue
            if _resolved_inside(entry, source_root) is None:
                continue
            if _is_external_hardlink(entry, source_root):
                excluded["external_hardlinks"] += 1
                continue
            try:
                size = entry.stat().st_size
            except OSError:
                continue
            included.append({"path": rel_posix, "bytes": size})
            total += size
    included.sort(key=lambda item: str(item["path"]))
    return {
        "files": included,
        "total_bytes": total,
        "excluded": excluded,
        "guidance_bytes": GUIDANCE_BYTES,
    }


def _count_skipped_files(entry: Path) -> int:
    if entry.is_symlink() or not entry.is_dir():
        return 1
    count = 0
    for dirpath, dirnames, filenames in os.walk(entry, topdown=True, followlinks=False):
        current = Path(dirpath)
        count += sum(1 for name in dirnames if (current / name).is_symlink())
        dirnames[:] = [name for name in dirnames if not (current / name).is_symlink()]
        count += len(filenames)
    return count
